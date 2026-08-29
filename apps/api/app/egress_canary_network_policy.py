"""Fail-closed network primitives for the future trusted canary runner.

This module does not perform credential-bearing network requests. Issue #97 must
use these checks both after DNS resolution and against the connected peer.
"""

from __future__ import annotations

import ipaddress
import ssl
from collections.abc import Iterable, Mapping
from dataclasses import dataclass


class CanaryNetworkPolicyError(ValueError):
    pass


_FORBIDDEN_SUFFIXES = (
    ".home",
    ".internal",
    ".lan",
    ".local",
    ".localdomain",
    ".localhost",
)
_FORBIDDEN_HOSTS = {
    "instance-data",
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
}
_PROXY_VARIABLES = {
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
}


@dataclass(frozen=True)
class ValidatedCanaryTarget:
    hostname: str
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class CanaryNetworkLimits:
    connect_timeout_seconds: float
    total_timeout_seconds: float
    max_response_bytes: int
    max_redirects: int = 0
    max_retries: int = 0

    def __post_init__(self) -> None:
        if not 0.1 <= self.connect_timeout_seconds <= 10:
            raise CanaryNetworkPolicyError("connect timeout is outside the safe bound")
        if not self.connect_timeout_seconds <= self.total_timeout_seconds <= 30:
            raise CanaryNetworkPolicyError("total timeout is outside the safe bound")
        if not 1 <= self.max_response_bytes <= 1_048_576:
            raise CanaryNetworkPolicyError("response limit is outside the safe bound")
        if self.max_redirects != 0:
            raise CanaryNetworkPolicyError("credential canary redirects are disabled")
        if self.max_retries not in (0, 1):
            raise CanaryNetworkPolicyError("credential canary retries are bounded to one")


def normalize_canary_hostname(value: str) -> str:
    candidate = value.strip().rstrip(".").casefold()
    if not candidate or "*" in candidate or len(candidate) > 253:
        raise CanaryNetworkPolicyError("canary target requires an exact hostname")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise CanaryNetworkPolicyError("canary target cannot be an IP literal")
    try:
        normalized = candidate.encode("ascii").decode("ascii")
    except UnicodeError as exc:
        raise CanaryNetworkPolicyError("canary hostname must be ASCII") from exc
    labels = normalized.split(".")
    if (
        len(labels) < 2
        or normalized in _FORBIDDEN_HOSTS
        or normalized.endswith(_FORBIDDEN_SUFFIXES)
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(character.isalnum() or character == "-" for character in label)
            for label in labels
        )
    ):
        raise CanaryNetworkPolicyError("canary hostname is internal or special-use")
    return normalized


def validate_global_address(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise CanaryNetworkPolicyError("DNS returned an invalid address") from exc
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        mapped = address.ipv4_mapped
        if not mapped.is_global:
            raise CanaryNetworkPolicyError("DNS returned a non-global mapped address")
    if (
        not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise CanaryNetworkPolicyError("DNS returned a non-global address")
    return address.compressed


def validate_dns_resolution(
    hostname: str, addresses: Iterable[str]
) -> ValidatedCanaryTarget:
    normalized = normalize_canary_hostname(hostname)
    validated = tuple(dict.fromkeys(validate_global_address(value) for value in addresses))
    if not validated:
        raise CanaryNetworkPolicyError("DNS returned no usable address")
    return ValidatedCanaryTarget(hostname=normalized, addresses=validated)


def validate_connected_peer(target: ValidatedCanaryTarget, peer_address: str) -> str:
    """Revalidate the actual peer; this is the DNS-rebinding enforcement point."""
    connected = validate_global_address(peer_address)
    if connected not in target.addresses:
        raise CanaryNetworkPolicyError("connected peer was not in the validated DNS set")
    return connected


def reject_redirect(status_code: int, location: str | None) -> None:
    if 300 <= status_code <= 399:
        raise CanaryNetworkPolicyError(
            "credential canary redirects are disabled; credentials must not change origin"
        )
    if location is not None:
        raise CanaryNetworkPolicyError("unexpected redirect location was returned")


def tls_client_context() -> ssl.SSLContext:
    context = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def environment_without_proxies(environment: Mapping[str, str]) -> dict[str, str]:
    """Return an explicit subprocess environment that cannot inherit proxies."""
    return {
        key: value
        for key, value in environment.items()
        if key.casefold() not in _PROXY_VARIABLES
    }


class BoundedResponse:
    def __init__(self, maximum_bytes: int) -> None:
        if not 1 <= maximum_bytes <= 1_048_576:
            raise CanaryNetworkPolicyError("response limit is outside the safe bound")
        self.maximum_bytes = maximum_bytes
        self.received_bytes = 0

    def accept(self, chunk: bytes) -> None:
        self.received_bytes += len(chunk)
        if self.received_bytes > self.maximum_bytes:
            raise CanaryNetworkPolicyError("credential canary response exceeded its limit")
