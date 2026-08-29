"""Peer-pinned HTTPS transport for the trusted credential-canary runner.

The transport intentionally uses direct TLS sockets rather than an HTTP client so
ambient proxy configuration cannot affect routing and DNS resolution can be
validated before connecting to an exact address. Response bodies are discarded.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import ssl
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass
from urllib.parse import SplitResult, urlsplit

from .egress_canary_network_policy import (
    BoundedResponse,
    CanaryNetworkLimits,
    CanaryNetworkPolicyError,
    ValidatedCanaryTarget,
    normalize_canary_hostname,
    reject_redirect,
    tls_client_context,
    validate_connected_peer,
    validate_dns_resolution,
)

_MAX_HEADER_BYTES = 32_768
_READ_CHUNK_BYTES = 16_384


class CanaryTransportError(RuntimeError):
    pass


class CanaryDnsError(CanaryTransportError):
    pass


class CanaryTlsError(CanaryTransportError):
    pass


class CanaryTargetError(CanaryTransportError):
    pass


@dataclass(frozen=True)
class CanaryTransportResult:
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
        raise CanaryTargetError("credential canary target contains control characters")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise CanaryTargetError("credential canary target is malformed") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.port not in {None, 443}
    ):
        raise CanaryTargetError("credential canary target must be exact HTTPS")
    normalize_canary_hostname(parsed.hostname)
    try:
        (parsed.path or "/").encode("ascii")
    except UnicodeEncodeError as exc:
        raise CanaryTargetError("credential canary path must be ASCII") from exc
    if " " in parsed.path or "\t" in parsed.path:
        raise CanaryTargetError("credential canary path contains unsafe whitespace")
    return parsed


def _validated_authorization(value: str) -> str:
    if (
        not value
        or len(value) > 8192
        or "\r" in value
        or "\n" in value
        or any(ord(character) == 0 for character in value)
    ):
        raise CanaryTargetError("credential canary authorization value is unsafe")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanaryTargetError("credential canary authorization value is invalid") from exc
    return value


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
        raise CanaryDnsError("credential canary DNS resolution failed") from exc
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
        raise CanaryTlsError("credential canary TLS handshake failed") from exc
    except OSError as exc:
        raise CanaryTargetError("credential canary connection failed") from exc


def _status_and_headers(header_block: bytes) -> tuple[int, dict[str, list[str]]]:
    if len(header_block) > _MAX_HEADER_BYTES:
        raise CanaryTargetError("credential canary response headers exceeded their limit")
    lines = header_block.split(b"\r\n")
    if not lines:
        raise CanaryTargetError("credential canary response was empty")
    try:
        status_parts = lines[0].decode("ascii").split(" ", 2)
    except UnicodeDecodeError as exc:
        raise CanaryTargetError("credential canary status line was invalid") from exc
    if (
        len(status_parts) < 2
        or status_parts[0] not in {"HTTP/1.0", "HTTP/1.1"}
        or len(status_parts[1]) != 3
        or not status_parts[1].isdigit()
    ):
        raise CanaryTargetError("credential canary status line was invalid")
    status_code = int(status_parts[1])
    if not 100 <= status_code <= 599:
        raise CanaryTargetError("credential canary status code was invalid")

    headers: dict[str, list[str]] = {}
    for line in lines[1:]:
        if not line:
            continue
        name, separator, raw_value = line.partition(b":")
        if not separator:
            raise CanaryTargetError("credential canary response header was invalid")
        try:
            normalized_name = name.decode("ascii").strip().casefold()
        except UnicodeDecodeError as exc:
            raise CanaryTargetError("credential canary response header name was invalid") from exc
        if not normalized_name:
            raise CanaryTargetError("credential canary response header name was invalid")
        value = raw_value.decode("latin-1").strip()
        headers.setdefault(normalized_name, []).append(value)
    return status_code, headers


def _content_length(headers: dict[str, list[str]]) -> int | None:
    values = headers.get("content-length", [])
    if not values:
        return None
    if len(set(values)) != 1 or not values[0].isdigit():
        raise CanaryTargetError("credential canary Content-Length was invalid")
    return int(values[0])


async def _read_bounded_body(
    reader: asyncio.StreamReader,
    *,
    maximum_bytes: int,
    expected_bytes: int | None,
) -> int:
    if expected_bytes is not None and expected_bytes > maximum_bytes:
        raise CanaryTargetError("credential canary response exceeded its limit")
    limiter = BoundedResponse(maximum_bytes)
    remaining = expected_bytes
    while remaining is None or remaining > 0:
        read_size = _READ_CHUNK_BYTES if remaining is None else min(_READ_CHUNK_BYTES, remaining)
        chunk = await reader.read(read_size)
        if not chunk:
            if remaining not in {None, 0}:
                raise CanaryTargetError("credential canary response ended early")
            break
        try:
            limiter.accept(chunk)
        except CanaryNetworkPolicyError as exc:
            raise CanaryTargetError("credential canary response exceeded its limit") from exc
        if remaining is not None:
            remaining -= len(chunk)
    if expected_bytes is None and limiter.received_bytes == maximum_bytes:
        extra = await reader.read(1)
        if extra:
            raise CanaryTargetError("credential canary response exceeded its limit")
    return limiter.received_bytes


async def _single_request(
    *,
    parsed: SplitResult,
    authorization: str,
    target: ValidatedCanaryTarget,
    address: str,
    limits: CanaryNetworkLimits,
    connector: Connector,
) -> tuple[int, int]:
    context = tls_client_context()
    reader, writer = await connector(
        address,
        target.hostname,
        context,
        limits.connect_timeout_seconds,
    )
    try:
        peer = writer.get_extra_info("peername")
        if not isinstance(peer, tuple) or not peer:
            raise CanaryDnsError("credential canary peer address was unavailable")
        try:
            validate_connected_peer(target, str(peer[0]))
        except CanaryNetworkPolicyError as exc:
            raise CanaryDnsError("credential canary connected-peer validation failed") from exc

        path = parsed.path or "/"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {target.hostname}\r\n"
            f"Authorization: {authorization}\r\n"
            "Accept: */*\r\n"
            "User-Agent: rdc-credential-canary/1\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        writer.write(request)
        await writer.drain()
        try:
            header_block = await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError) as exc:
            raise CanaryTargetError("credential canary response headers were invalid") from exc
        status_code, headers = _status_and_headers(header_block[:-4])
        location_values = headers.get("location", [])
        location = location_values[0] if location_values else None
        try:
            reject_redirect(status_code, location)
        except CanaryNetworkPolicyError as exc:
            raise CanaryTargetError("credential canary redirect was rejected") from exc
        response_bytes = await _read_bounded_body(
            reader,
            maximum_bytes=limits.max_response_bytes,
            expected_bytes=_content_length(headers),
        )
        return status_code, response_bytes
    finally:
        writer.close()
        with contextlib.suppress(OSError, ssl.SSLError):
            await writer.wait_closed()


def _outcome_for_status(status_code: int) -> str:
    if 200 <= status_code <= 299:
        return "SUCCESS"
    if status_code in {401, 403}:
        return "AUTH_REJECTED"
    return "TARGET_ERROR"


async def run_credential_canary_transport(
    *,
    target_url: str,
    authorization: str,
    limits: CanaryNetworkLimits,
    resolver: Resolver | None = None,
    connector: Connector | None = None,
) -> CanaryTransportResult:
    """Run one bounded request and return only the persisted outcome taxonomy."""
    resolver_impl = resolver or _resolve_global_addresses
    connector_impl = connector or _open_pinned_tls_connection
    try:
        parsed = _validated_url(target_url)
        safe_authorization = _validated_authorization(authorization)
        hostname = normalize_canary_hostname(parsed.hostname or "")
        try:
            addresses = await resolver_impl(hostname)
            target = validate_dns_resolution(hostname, addresses)
        except (CanaryNetworkPolicyError, CanaryDnsError, socket.gaierror):
            return CanaryTransportResult("DNS_FAILURE", None, 0)

        attempts = min(len(target.addresses), limits.max_retries + 1)
        last_outcome = "TARGET_ERROR"
        async with asyncio.timeout(limits.total_timeout_seconds):
            for address in target.addresses[:attempts]:
                try:
                    status_code, response_bytes = await _single_request(
                        parsed=parsed,
                        authorization=safe_authorization,
                        target=target,
                        address=address,
                        limits=limits,
                        connector=connector_impl,
                    )
                    return CanaryTransportResult(
                        _outcome_for_status(status_code), status_code, response_bytes
                    )
                except CanaryDnsError:
                    return CanaryTransportResult("DNS_FAILURE", None, 0)
                except CanaryTlsError:
                    return CanaryTransportResult("TLS_FAILURE", None, 0)
                except TimeoutError:
                    last_outcome = "TIMEOUT"
                except (CanaryNetworkPolicyError, CanaryTargetError, OSError):
                    last_outcome = "TARGET_ERROR"
        return CanaryTransportResult(last_outcome, None, 0)
    except TimeoutError:
        return CanaryTransportResult("TIMEOUT", None, 0)
    except CanaryTlsError:
        return CanaryTransportResult("TLS_FAILURE", None, 0)
    except (CanaryNetworkPolicyError, CanaryTargetError, ValueError):
        return CanaryTransportResult("TARGET_ERROR", None, 0)
