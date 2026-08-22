from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .core.security import canonical_fingerprint

ALLOWED_METHODS = frozenset({"GET", "HEAD"})
FORBIDDEN_SUFFIXES = (
    ".example",
    ".internal",
    ".invalid",
    ".local",
    ".localhost",
    ".test",
)


class EgressPolicyProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedEgressPolicy:
    allowed_hosts: list[str]
    allowed_methods: list[str]
    max_requests: int
    max_response_bytes: int
    max_total_bytes: int
    max_redirects: int
    connect_timeout_seconds: int
    request_timeout_seconds: int
    policy_digest: str


def normalize_hostname(value: str) -> str:
    candidate = value.strip().rstrip(".").casefold()
    if (
        not candidate
        or len(candidate) > 253
        or "://" in candidate
        or "/" in candidate
        or "@" in candidate
        or "*" in candidate
    ):
        raise EgressPolicyProtocolError("Allowed hosts must be exact HTTPS hostnames.")
    try:
        ipaddress.ip_address(candidate.strip("[]"))
    except ValueError:
        pass
    else:
        raise EgressPolicyProtocolError("IP literals are not allowed in egress policies.")
    try:
        ascii_host = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise EgressPolicyProtocolError("Allowed host is not a valid hostname.") from exc
    labels = ascii_host.split(".")
    if len(labels) < 2 or any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or not all(character.isalnum() or character == "-" for character in label)
        for label in labels
    ):
        raise EgressPolicyProtocolError("Allowed host is not a valid public hostname.")
    if ascii_host == "localhost" or ascii_host.endswith(FORBIDDEN_SUFFIXES):
        raise EgressPolicyProtocolError("Special-use hostnames are not allowed.")
    return ascii_host


def validate_egress_policy(
    *,
    allowed_hosts: list[str],
    allowed_methods: list[str],
    max_requests: int,
    max_response_bytes: int,
    max_total_bytes: int,
    max_redirects: int,
    connect_timeout_seconds: int,
    request_timeout_seconds: int,
) -> ValidatedEgressPolicy:
    hosts = sorted({normalize_hostname(host) for host in allowed_hosts})
    methods = sorted({method.upper() for method in allowed_methods})
    if not hosts or len(hosts) != len(allowed_hosts):
        raise EgressPolicyProtocolError("Allowed hosts must be unique and non-empty.")
    if not methods or len(methods) != len(allowed_methods) or not set(methods) <= ALLOWED_METHODS:
        raise EgressPolicyProtocolError("Allowed methods must be unique GET or HEAD values.")
    if max_total_bytes < max_response_bytes:
        raise EgressPolicyProtocolError("max_total_bytes must be at least max_response_bytes.")
    canonical = {
        "allowed_hosts": hosts,
        "allowed_methods": methods,
        "connect_timeout_seconds": connect_timeout_seconds,
        "max_redirects": max_redirects,
        "max_requests": max_requests,
        "max_response_bytes": max_response_bytes,
        "max_total_bytes": max_total_bytes,
        "request_timeout_seconds": request_timeout_seconds,
        "schema_version": "rdc.egress-policy/v1",
    }
    return ValidatedEgressPolicy(
        allowed_hosts=hosts,
        allowed_methods=methods,
        max_requests=max_requests,
        max_response_bytes=max_response_bytes,
        max_total_bytes=max_total_bytes,
        max_redirects=max_redirects,
        connect_timeout_seconds=connect_timeout_seconds,
        request_timeout_seconds=request_timeout_seconds,
        policy_digest=canonical_fingerprint(canonical),
    )
