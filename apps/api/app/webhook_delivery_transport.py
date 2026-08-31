"""Direct, peer-pinned HTTPS transport for signed webhook deliveries."""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from .egress_canary_network_policy import (
    BoundedResponse,
    CanaryNetworkLimits,
    CanaryNetworkPolicyError,
    ValidatedCanaryTarget,
    normalize_canary_hostname,
    tls_client_context,
    validate_connected_peer,
    validate_dns_resolution,
)

_MAX_HEADER_BYTES = 32_768
_MAX_REQUEST_BYTES = 16_384
_READ_CHUNK_BYTES = 16_384


class WebhookTransportError(RuntimeError):
    pass


class WebhookDnsError(WebhookTransportError):
    pass


class WebhookTlsError(WebhookTransportError):
    pass


class WebhookTargetError(WebhookTransportError):
    pass


@dataclass(frozen=True)
class WebhookTransportResult:
    outcome: str
    status_code: int | None
    response_bytes: int


Resolver = Callable[[str], Awaitable[Iterable[str]]]
Connector = Callable[
    [str, str, ssl.SSLContext, float],
    Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]],
]


def _validated_url(value: str) -> SplitResult:
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise WebhookTargetError("Webhook target contains control characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise WebhookTargetError("Webhook target is malformed") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in {None, 443}
    ):
        raise WebhookTargetError("Webhook target must be exact HTTPS")
    normalize_canary_hostname(parsed.hostname)
    request_target = parsed.path or "/"
    if parsed.query:
        request_target = f"{request_target}?{parsed.query}"
    try:
        request_target.encode("ascii")
    except UnicodeEncodeError as exc:
        raise WebhookTargetError("Webhook request target must be ASCII") from exc
    if " " in request_target or "\t" in request_target:
        raise WebhookTargetError("Webhook request target contains unsafe whitespace")
    return parsed


def _validated_headers(headers: Mapping[str, str]) -> tuple[tuple[str, str], ...]:
    required = {
        "content-type",
        "rdc-delivery-id",
        "rdc-event-id",
        "rdc-signature",
        "rdc-timestamp",
        "user-agent",
    }
    normalized: list[tuple[str, str]] = []
    names: set[str] = set()
    for name, value in headers.items():
        folded = name.casefold()
        if (
            not name
            or not name.isascii()
            or any(not (character.isalnum() or character == "-") for character in name)
            or folded in {"host", "content-length", "connection", "transfer-encoding"}
            or not value
            or len(value) > 8192
            or "\r" in value
            or "\n" in value
        ):
            raise WebhookTargetError("Webhook request headers are unsafe")
        names.add(folded)
        normalized.append((name, value))
    if names != required:
        raise WebhookTargetError("Webhook request headers are incomplete")
    return tuple(normalized)


async def _resolve_global_addresses(hostname: str) -> Iterable[str]:
    loop = asyncio.get_running_loop()
    try:
        records = await loop.getaddrinfo(
            hostname,
            443,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
            proto=socket.IPPROTO_TCP,
        )
    except socket.gaierror as exc:
        raise WebhookDnsError("Webhook DNS resolution failed") from exc
    return [str(record[4][0]) for record in records]


async def _open_pinned_tls_connection(
    address: str,
    hostname: str,
    context: ssl.SSLContext,
    connect_timeout_seconds: float,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    try:
        async with asyncio.timeout(connect_timeout_seconds):
            return await asyncio.open_connection(
                host=address,
                port=443,
                ssl=context,
                server_hostname=hostname,
                ssl_handshake_timeout=connect_timeout_seconds,
                limit=_MAX_HEADER_BYTES,
            )
    except TimeoutError:
        raise
    except ssl.SSLError as exc:
        raise WebhookTlsError("Webhook TLS handshake failed") from exc
    except OSError as exc:
        raise WebhookTargetError("Webhook connection failed") from exc


def _status_and_headers(header_block: bytes) -> tuple[int, dict[str, list[str]]]:
    if len(header_block) > _MAX_HEADER_BYTES:
        raise WebhookTargetError("Webhook response headers exceeded their limit")
    lines = header_block.split(b"\r\n")
    try:
        status_parts = lines[0].decode("ascii").split(" ", 2)
    except (IndexError, UnicodeDecodeError) as exc:
        raise WebhookTargetError("Webhook status line was invalid") from exc
    if (
        len(status_parts) < 2
        or status_parts[0] not in {"HTTP/1.0", "HTTP/1.1"}
        or len(status_parts[1]) != 3
        or not status_parts[1].isdigit()
    ):
        raise WebhookTargetError("Webhook status line was invalid")
    status_code = int(status_parts[1])
    if not 100 <= status_code <= 599:
        raise WebhookTargetError("Webhook status code was invalid")
    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, separator, raw_value = line.partition(b":")
        if not separator:
            raise WebhookTargetError("Webhook response header was invalid")
        try:
            normalized_name = name.decode("ascii").strip().casefold()
        except UnicodeDecodeError as exc:
            raise WebhookTargetError("Webhook response header name was invalid") from exc
        if not normalized_name:
            raise WebhookTargetError("Webhook response header name was invalid")
        headers.setdefault(normalized_name, []).append(raw_value.decode("latin-1").strip())
    return status_code, headers


def _content_length(headers: dict[str, list[str]]) -> int | None:
    values = headers.get("content-length", [])
    if not values:
        return None
    if len(set(values)) != 1 or not values[0].isdigit():
        raise WebhookTargetError("Webhook Content-Length was invalid")
    return int(values[0])


async def _read_bounded_body(
    reader: asyncio.StreamReader,
    *,
    maximum_bytes: int,
    expected_bytes: int | None,
) -> int:
    if expected_bytes is not None and expected_bytes > maximum_bytes:
        raise WebhookTargetError("Webhook response exceeded its limit")
    limiter = BoundedResponse(maximum_bytes)
    remaining = expected_bytes
    while remaining is None or remaining > 0:
        read_size = _READ_CHUNK_BYTES if remaining is None else min(_READ_CHUNK_BYTES, remaining)
        chunk = await reader.read(read_size)
        if not chunk:
            if remaining not in {None, 0}:
                raise WebhookTargetError("Webhook response ended early")
            break
        try:
            limiter.accept(chunk)
        except CanaryNetworkPolicyError as exc:
            raise WebhookTargetError("Webhook response exceeded its limit") from exc
        if remaining is not None:
            remaining -= len(chunk)
    if expected_bytes is None and limiter.received_bytes == maximum_bytes and await reader.read(1):
        raise WebhookTargetError("Webhook response exceeded its limit")
    return limiter.received_bytes


async def _single_request(
    *,
    parsed: SplitResult,
    body: bytes,
    headers: tuple[tuple[str, str], ...],
    target: ValidatedCanaryTarget,
    address: str,
    limits: CanaryNetworkLimits,
    connector: Connector,
) -> tuple[int, int]:
    reader, writer = await connector(
        address,
        target.hostname,
        tls_client_context(),
        limits.connect_timeout_seconds,
    )
    try:
        peer = writer.get_extra_info("peername")
        if not isinstance(peer, tuple) or not peer:
            raise WebhookDnsError("Webhook peer address was unavailable")
        try:
            validate_connected_peer(target, str(peer[0]))
        except CanaryNetworkPolicyError as exc:
            raise WebhookDnsError("Webhook connected-peer validation failed") from exc
        request_target = parsed.path or "/"
        if parsed.query:
            request_target = f"{request_target}?{parsed.query}"
        header_lines = "".join(f"{name}: {value}\r\n" for name, value in headers)
        request = (
            f"POST {request_target} HTTP/1.1\r\n"
            f"Host: {target.hostname}\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"{header_lines}"
            "Connection: close\r\n\r\n"
        ).encode("ascii") + body
        writer.write(request)
        await writer.drain()
        try:
            header_block = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise WebhookTargetError("Webhook response headers were invalid") from exc
        status_code, response_headers = _status_and_headers(header_block[:-4])
        if 300 <= status_code <= 399 or "location" in response_headers:
            raise WebhookTargetError("Webhook redirects are disabled")
        response_bytes = await _read_bounded_body(
            reader,
            maximum_bytes=limits.max_response_bytes,
            expected_bytes=_content_length(response_headers),
        )
        return status_code, response_bytes
    finally:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()


def _outcome_for_status(status_code: int) -> str:
    if 200 <= status_code <= 299:
        return "DELIVERED"
    if status_code in {401, 403}:
        return "AUTH_REJECTED"
    if status_code in {408, 425, 429} or 500 <= status_code <= 599:
        return "HTTP_RETRY"
    return "HTTP_PERMANENT"


async def run_webhook_delivery_transport(
    *,
    target_url: str,
    body: bytes,
    headers: Mapping[str, str],
    limits: CanaryNetworkLimits,
    resolver: Resolver | None = None,
    connector: Connector | None = None,
) -> WebhookTransportResult:
    """Send exactly one bounded request; never redirect, proxy, or fail over."""
    try:
        if len(body) > _MAX_REQUEST_BYTES:
            raise WebhookTargetError("Webhook request exceeded its limit")
        parsed = _validated_url(target_url)
        safe_headers = _validated_headers(headers)
        hostname = normalize_canary_hostname(parsed.hostname or "")
        try:
            target = validate_dns_resolution(
                hostname, await (resolver or _resolve_global_addresses)(hostname)
            )
        except (CanaryNetworkPolicyError, WebhookDnsError, socket.gaierror):
            return WebhookTransportResult("DNS_FAILURE", None, 0)
        async with asyncio.timeout(limits.total_timeout_seconds):
            try:
                status_code, response_bytes = await _single_request(
                    parsed=parsed,
                    body=body,
                    headers=safe_headers,
                    target=target,
                    address=target.addresses[0],
                    limits=limits,
                    connector=connector or _open_pinned_tls_connection,
                )
            except WebhookDnsError:
                return WebhookTransportResult("DNS_FAILURE", None, 0)
            except WebhookTlsError:
                return WebhookTransportResult("TLS_FAILURE", None, 0)
            except TimeoutError:
                return WebhookTransportResult("TIMEOUT", None, 0)
            except (CanaryNetworkPolicyError, WebhookTargetError, OSError):
                return WebhookTransportResult("HTTP_PERMANENT", None, 0)
        return WebhookTransportResult(_outcome_for_status(status_code), status_code, response_bytes)
    except TimeoutError:
        return WebhookTransportResult("TIMEOUT", None, 0)
    except WebhookTlsError:
        return WebhookTransportResult("TLS_FAILURE", None, 0)
    except (CanaryNetworkPolicyError, WebhookTargetError, ValueError):
        return WebhookTransportResult("CONFIGURATION_ERROR", None, 0)
