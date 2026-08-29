from __future__ import annotations

import asyncio
import ssl
from collections.abc import Iterable

import pytest

from app.egress_canary_network_policy import CanaryNetworkLimits
from app.egress_credential_canary_transport import (
    CanaryTlsError,
    run_credential_canary_transport,
)


class FakeWriter:
    def __init__(self, *, peer: str) -> None:
        self.peer = peer
        self.sent = bytearray()
        self.closed = False

    def get_extra_info(self, name: str) -> object:
        if name == "peername":
            return (self.peer, 443)
        return None

    def write(self, data: bytes) -> None:
        self.sent.extend(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


def response_connector(
    response: bytes,
    *,
    peer: str = "93.184.216.34",
) -> tuple[
    object,
    list[tuple[str, str, ssl.SSLContext, float, FakeWriter]],
]:
    calls: list[tuple[str, str, ssl.SSLContext, float, FakeWriter]] = []

    async def connector(
        address: str,
        hostname: str,
        context: ssl.SSLContext,
        timeout: float,
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        reader = asyncio.StreamReader()
        reader.feed_data(response)
        reader.feed_eof()
        writer = FakeWriter(peer=peer)
        calls.append((address, hostname, context, timeout, writer))
        return reader, writer  # type: ignore[return-value]

    return connector, calls


async def public_resolver(_: str) -> Iterable[str]:
    return ["93.184.216.34"]


def limits(*, maximum: int = 1024) -> CanaryNetworkLimits:
    return CanaryNetworkLimits(
        connect_timeout_seconds=1,
        total_timeout_seconds=3,
        max_response_bytes=maximum,
    )


@pytest.mark.asyncio
async def test_transport_pins_peer_uses_verified_tls_and_discards_body() -> None:
    connector, calls = response_connector(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
    )
    result = await run_credential_canary_transport(
        target_url="https://canary.example.com/auth-check",
        authorization="Bearer private-value",
        limits=limits(),
        resolver=public_resolver,
        connector=connector,  # type: ignore[arg-type]
    )
    assert result.outcome == "SUCCESS"
    assert result.status_code == 200
    assert result.response_bytes == 2
    assert len(calls) == 1
    address, hostname, context, timeout, writer = calls[0]
    assert (address, hostname, timeout) == ("93.184.216.34", "canary.example.com", 1)
    assert context.check_hostname is True
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert b"Authorization: Bearer private-value\r\n" in writer.sent
    assert b"Connection: close\r\n" in writer.sent
    assert writer.closed is True
    assert "private-value" not in repr(result)


@pytest.mark.asyncio
async def test_transport_classifies_auth_rejection_without_body_persistence() -> None:
    connector, _ = response_connector(
        b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 6\r\n\r\ndenied"
    )
    result = await run_credential_canary_transport(
        target_url="https://canary.example.com/auth-check",
        authorization="Bearer private-value",
        limits=limits(),
        resolver=public_resolver,
        connector=connector,  # type: ignore[arg-type]
    )
    assert (result.outcome, result.status_code, result.response_bytes) == (
        "AUTH_REJECTED",
        401,
        6,
    )


@pytest.mark.asyncio
async def test_transport_rejects_redirects_and_oversized_responses() -> None:
    redirect_connector, _ = response_connector(
        b"HTTP/1.1 302 Found\r\nLocation: https://other.example.com/\r\nContent-Length: 0\r\n\r\n"
    )
    redirect = await run_credential_canary_transport(
        target_url="https://canary.example.com/auth-check",
        authorization="Bearer private-value",
        limits=limits(),
        resolver=public_resolver,
        connector=redirect_connector,  # type: ignore[arg-type]
    )
    assert redirect.outcome == "TARGET_ERROR"

    large_connector, _ = response_connector(
        b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n123456789"
    )
    large = await run_credential_canary_transport(
        target_url="https://canary.example.com/auth-check",
        authorization="Bearer private-value",
        limits=limits(maximum=8),
        resolver=public_resolver,
        connector=large_connector,  # type: ignore[arg-type]
    )
    assert large.outcome == "TARGET_ERROR"


@pytest.mark.asyncio
async def test_transport_rejects_private_dns_and_connected_peer_substitution() -> None:
    async def private_resolver(_: str) -> Iterable[str]:
        return ["169.254.169.254"]

    connector, calls = response_connector(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
    )
    private = await run_credential_canary_transport(
        target_url="https://canary.example.com/auth-check",
        authorization="Bearer private-value",
        limits=limits(),
        resolver=private_resolver,
        connector=connector,  # type: ignore[arg-type]
    )
    assert private.outcome == "DNS_FAILURE"
    assert calls == []

    rebound_connector, _ = response_connector(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        peer="1.1.1.1",
    )
    rebound = await run_credential_canary_transport(
        target_url="https://canary.example.com/auth-check",
        authorization="Bearer private-value",
        limits=limits(),
        resolver=public_resolver,
        connector=rebound_connector,  # type: ignore[arg-type]
    )
    assert rebound.outcome == "DNS_FAILURE"


@pytest.mark.asyncio
async def test_transport_classifies_tls_and_timeout_without_leaking_exception_text() -> None:
    async def tls_failure(
        _: str, __: str, ___: ssl.SSLContext, ____: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        raise CanaryTlsError("do-not-log-target-or-secret")

    tls_result = await run_credential_canary_transport(
        target_url="https://canary.example.com/auth-check",
        authorization="Bearer private-value",
        limits=limits(),
        resolver=public_resolver,
        connector=tls_failure,
    )
    assert tls_result.outcome == "TLS_FAILURE"

    async def timeout_failure(
        _: str, __: str, ___: ssl.SSLContext, ____: float
    ) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        raise TimeoutError

    timeout_result = await run_credential_canary_transport(
        target_url="https://canary.example.com/auth-check",
        authorization="Bearer private-value",
        limits=limits(),
        resolver=public_resolver,
        connector=timeout_failure,
    )
    assert timeout_result.outcome == "TIMEOUT"
