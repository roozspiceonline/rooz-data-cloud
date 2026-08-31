from __future__ import annotations

import asyncio
import ssl
from collections.abc import Iterable

import pytest

from app.egress_canary_network_policy import CanaryNetworkLimits
from app.webhook_delivery_transport import (
    WebhookTlsError,
    run_webhook_delivery_transport,
)


class FakeWriter:
    def __init__(self, *, peer: str) -> None:
        self.peer = peer
        self.sent = bytearray()
        self.closed = False

    def get_extra_info(self, name: str) -> object:
        return (self.peer, 443) if name == "peername" else None

    def write(self, data: bytes) -> None:
        self.sent.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def response_connector(
    response: bytes, *, peer: str = "93.184.216.34"
) -> tuple[object, list[tuple[str, str, ssl.SSLContext, float, FakeWriter]]]:
    calls: list[tuple[str, str, ssl.SSLContext, float, FakeWriter]] = []

    async def connector(
        address: str, hostname: str, context: ssl.SSLContext, timeout: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader = asyncio.StreamReader()
        reader.feed_data(response)
        reader.feed_eof()
        writer = FakeWriter(peer=peer)
        calls.append((address, hostname, context, timeout, writer))
        return reader, writer  # type: ignore[return-value]

    return connector, calls


async def public_resolver(_: str) -> Iterable[str]:
    return ["93.184.216.34", "1.1.1.1"]


def limits(*, maximum: int = 1024) -> CanaryNetworkLimits:
    return CanaryNetworkLimits(
        connect_timeout_seconds=1,
        total_timeout_seconds=3,
        max_response_bytes=maximum,
        max_retries=0,
    )


def signed_headers() -> dict[str, str]:
    return {
        "Content-Type": "application/json",
        "RDC-Delivery-ID": "00000000-0000-0000-0000-000000000001",
        "RDC-Event-ID": "00000000-0000-0000-0000-000000000002",
        "RDC-Signature": "v1=" + "a" * 64,
        "RDC-Timestamp": "1788048000",
        "User-Agent": "rdc-webhook-canary/1",
    }


@pytest.mark.asyncio
async def test_transport_posts_exact_signed_bytes_over_peer_pinned_tls() -> None:
    connector, calls = response_connector(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n")
    result = await run_webhook_delivery_transport(
        target_url="https://hooks.example.com/delivery?tenant=one",
        body=b'{"exact":true}',
        headers=signed_headers(),
        limits=limits(),
        resolver=public_resolver,
        connector=connector,  # type: ignore[arg-type]
    )
    assert (result.outcome, result.status_code, result.response_bytes) == (
        "DELIVERED",
        204,
        0,
    )
    assert len(calls) == 1
    address, hostname, context, timeout, writer = calls[0]
    assert (address, hostname, timeout) == ("93.184.216.34", "hooks.example.com", 1)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert writer.sent.startswith(b"POST /delivery?tenant=one HTTP/1.1\r\n")
    assert b"RDC-Signature: v1=" + b"a" * 64 + b"\r\n" in writer.sent
    assert writer.sent.endswith(b'\r\n\r\n{"exact":true}')
    assert writer.closed is True


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "outcome"),
    [
        (200, "DELIVERED"),
        (401, "AUTH_REJECTED"),
        (429, "HTTP_RETRY"),
        (503, "HTTP_RETRY"),
        (404, "HTTP_PERMANENT"),
    ],
)
async def test_transport_classifies_bounded_statuses(status: int, outcome: str) -> None:
    connector, _ = response_connector(
        f"HTTP/1.1 {status} Result\r\nContent-Length: 0\r\n\r\n".encode()
    )
    result = await run_webhook_delivery_transport(
        target_url="https://hooks.example.com/",
        body=b"{}",
        headers=signed_headers(),
        limits=limits(),
        resolver=public_resolver,
        connector=connector,  # type: ignore[arg-type]
    )
    assert result.outcome == outcome
    assert result.status_code == status


@pytest.mark.asyncio
async def test_transport_rejects_private_dns_rebinding_redirects_and_large_bodies() -> None:
    async def private_resolver(_: str) -> Iterable[str]:
        return ["169.254.169.254"]

    connector, calls = response_connector(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    private = await run_webhook_delivery_transport(
        target_url="https://hooks.example.com/",
        body=b"{}",
        headers=signed_headers(),
        limits=limits(),
        resolver=private_resolver,
        connector=connector,  # type: ignore[arg-type]
    )
    assert private.outcome == "DNS_FAILURE"
    assert calls == []

    rebound_connector, _ = response_connector(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", peer="8.8.8.8"
    )
    rebound = await run_webhook_delivery_transport(
        target_url="https://hooks.example.com/",
        body=b"{}",
        headers=signed_headers(),
        limits=limits(),
        resolver=public_resolver,
        connector=rebound_connector,  # type: ignore[arg-type]
    )
    assert rebound.outcome == "DNS_FAILURE"

    redirect_connector, _ = response_connector(
        b"HTTP/1.1 302 Found\r\nLocation: https://evil.example/\r\nContent-Length: 0\r\n\r\n"
    )
    redirect = await run_webhook_delivery_transport(
        target_url="https://hooks.example.com/",
        body=b"{}",
        headers=signed_headers(),
        limits=limits(),
        resolver=public_resolver,
        connector=redirect_connector,  # type: ignore[arg-type]
    )
    assert redirect.outcome == "HTTP_PERMANENT"

    large_connector, _ = response_connector(
        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n123456789"
    )
    large = await run_webhook_delivery_transport(
        target_url="https://hooks.example.com/",
        body=b"{}",
        headers=signed_headers(),
        limits=limits(maximum=8),
        resolver=public_resolver,
        connector=large_connector,  # type: ignore[arg-type]
    )
    assert large.outcome == "HTTP_PERMANENT"


@pytest.mark.asyncio
async def test_transport_classifies_tls_timeout_and_unsafe_configuration() -> None:
    async def tls_failure(
        _: str, __: str, ___: ssl.SSLContext, ____: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        raise WebhookTlsError("sensitive detail")

    tls_result = await run_webhook_delivery_transport(
        target_url="https://hooks.example.com/",
        body=b"{}",
        headers=signed_headers(),
        limits=limits(),
        resolver=public_resolver,
        connector=tls_failure,
    )
    assert tls_result.outcome == "TLS_FAILURE"

    async def timeout_failure(
        _: str, __: str, ___: ssl.SSLContext, ____: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        raise TimeoutError

    timeout_result = await run_webhook_delivery_transport(
        target_url="https://hooks.example.com/",
        body=b"{}",
        headers=signed_headers(),
        limits=limits(),
        resolver=public_resolver,
        connector=timeout_failure,
    )
    assert timeout_result.outcome == "TIMEOUT"

    unsafe = signed_headers()
    unsafe["RDC-Signature"] = "safe\r\nX-Leak: yes"
    configured = await run_webhook_delivery_transport(
        target_url="https://hooks.example.com/",
        body=b"{}",
        headers=unsafe,
        limits=limits(),
        resolver=public_resolver,
    )
    assert configured.outcome == "CONFIGURATION_ERROR"

    oversized = await run_webhook_delivery_transport(
        target_url="https://hooks.example.com/",
        body=b"x" * 16_385,
        headers=signed_headers(),
        limits=limits(),
        resolver=public_resolver,
    )
    assert oversized.outcome == "CONFIGURATION_ERROR"
