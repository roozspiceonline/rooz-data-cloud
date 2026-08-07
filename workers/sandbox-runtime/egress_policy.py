from __future__ import annotations

import hashlib
import ipaddress
import json
import socket
from dataclasses import dataclass
from typing import Callable, Iterable
from urllib.parse import SplitResult, urlsplit, urlunsplit


class EgressPolicyError(RuntimeError):
    pass


Resolver = Callable[..., list[tuple[object, ...]]]


def normalize_hostname(value: str) -> str:
    candidate = value.strip().rstrip(".").casefold()
    if not candidate:
        raise EgressPolicyError("Egress hostname cannot be blank.")
    if "*" in candidate:
        raise EgressPolicyError("Wildcard egress hostnames are not allowed.")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise EgressPolicyError("IP-literal egress destinations are not allowed.")
    try:
        normalized = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise EgressPolicyError("Egress hostname is not valid IDNA.") from exc
    if len(normalized) > 253:
        raise EgressPolicyError("Egress hostname is too long.")
    labels = normalized.split(".")
    if len(labels) < 2:
        raise EgressPolicyError("Single-label egress hostnames are not allowed.")
    if normalized.endswith(".local"):
        raise EgressPolicyError("Local-network egress hostnames are not allowed.")
    for label in labels:
        if not label or len(label) > 63:
            raise EgressPolicyError("Egress hostname contains an invalid label.")
        if label[0] == "-" or label[-1] == "-":
            raise EgressPolicyError("Egress hostname label cannot start or end with '-'.")
        if not all(character.isalnum() or character == "-" for character in label):
            raise EgressPolicyError("Egress hostname contains unsupported characters.")
    return normalized


def _require_global_address(value: str) -> None:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as exc:
        raise EgressPolicyError("DNS resolver returned an invalid IP address.") from exc
    if not address.is_global:
        raise EgressPolicyError(
            "Egress destination resolved to a non-global network address."
        )


def resolve_public_addresses(
    hostname: str,
    *,
    resolver: Resolver = socket.getaddrinfo,
) -> tuple[str, ...]:
    try:
        records = resolver(
            hostname,
            443,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise EgressPolicyError("Egress hostname DNS resolution failed.") from exc
    addresses: list[str] = []
    for record in records:
        if len(record) < 5:
            continue
        sockaddr = record[4]
        if not isinstance(sockaddr, tuple) or not sockaddr:
            continue
        address = str(sockaddr[0])
        _require_global_address(address)
        addresses.append(address)
    if not addresses:
        raise EgressPolicyError("Egress hostname resolved to no usable addresses.")
    return tuple(sorted(set(addresses)))


@dataclass(frozen=True)
class EgressPolicy:
    allowed_hosts: tuple[str, ...]
    max_requests: int = 8
    max_response_bytes: int = 1_048_576
    max_total_bytes: int = 4_194_304
    max_redirects: int = 3
    connect_timeout_seconds: int = 5
    request_timeout_seconds: int = 15

    @classmethod
    def create(
        cls,
        allowed_hosts: Iterable[str],
        *,
        max_requests: int = 8,
        max_response_bytes: int = 1_048_576,
        max_total_bytes: int = 4_194_304,
        max_redirects: int = 3,
        connect_timeout_seconds: int = 5,
        request_timeout_seconds: int = 15,
    ) -> "EgressPolicy":
        normalized = tuple(
            sorted({normalize_hostname(value) for value in allowed_hosts})
        )
        if not normalized:
            raise EgressPolicyError("Egress allowlist cannot be empty.")
        if len(normalized) > 32:
            raise EgressPolicyError("Egress allowlist cannot exceed 32 hosts.")
        if not 1 <= max_requests <= 32:
            raise EgressPolicyError("Egress request budget is outside the safe range.")
        if not 1_024 <= max_response_bytes <= 8_388_608:
            raise EgressPolicyError(
                "Per-response egress byte limit is outside the safe range."
            )
        if not max_response_bytes <= max_total_bytes <= 33_554_432:
            raise EgressPolicyError(
                "Total egress byte limit must cover one response and stay bounded."
            )
        if not 0 <= max_redirects <= 5:
            raise EgressPolicyError("Redirect budget is outside the safe range.")
        if not 1 <= connect_timeout_seconds <= 15:
            raise EgressPolicyError("Connect timeout is outside the safe range.")
        if not 1 <= request_timeout_seconds <= 30:
            raise EgressPolicyError("Request timeout is outside the safe range.")
        return cls(
            allowed_hosts=normalized,
            max_requests=max_requests,
            max_response_bytes=max_response_bytes,
            max_total_bytes=max_total_bytes,
            max_redirects=max_redirects,
            connect_timeout_seconds=connect_timeout_seconds,
            request_timeout_seconds=request_timeout_seconds,
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "rdc.egress/v1",
            "mode": "brokered",
            "allowed_schemes": ["https"],
            "allowed_methods": ["GET", "HEAD"],
            "allowed_hosts": list(self.allowed_hosts),
            "deny_ip_literals": True,
            "require_global_dns": True,
            "revalidate_redirects": True,
            "container_network": "none",
            "max_requests": self.max_requests,
            "max_response_bytes": self.max_response_bytes,
            "max_total_bytes": self.max_total_bytes,
            "max_redirects": self.max_redirects,
            "connect_timeout_seconds": self.connect_timeout_seconds,
            "request_timeout_seconds": self.request_timeout_seconds,
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(encoded).hexdigest()

    def validate_url(
        self,
        url: str,
        *,
        resolver: Resolver = socket.getaddrinfo,
    ) -> str:
        try:
            parsed = urlsplit(url)
        except ValueError as exc:
            raise EgressPolicyError("Egress URL is invalid.") from exc
        if parsed.scheme.casefold() != "https":
            raise EgressPolicyError("Phase 1J permits HTTPS URLs only.")
        if parsed.username is not None or parsed.password is not None:
            raise EgressPolicyError("Credentials in egress URLs are not allowed.")
        if not parsed.hostname:
            raise EgressPolicyError("Egress URL is missing a hostname.")
        host = normalize_hostname(parsed.hostname)
        if host not in self.allowed_hosts:
            raise EgressPolicyError("Egress hostname is not operator-allowlisted.")
        try:
            port = parsed.port
        except ValueError as exc:
            raise EgressPolicyError("Egress URL contains an invalid port.") from exc
        if port not in (None, 443):
            raise EgressPolicyError("Phase 1J permits HTTPS port 443 only.")
        resolve_public_addresses(host, resolver=resolver)

        netloc = host if port is None else f"{host}:{port}"
        path = parsed.path or "/"
        normalized = SplitResult(
            scheme="https",
            netloc=netloc,
            path=path,
            query=parsed.query,
            fragment="",
        )
        return urlunsplit(normalized)

    def validate_redirect(
        self,
        url: str,
        *,
        resolver: Resolver = socket.getaddrinfo,
    ) -> str:
        return self.validate_url(url, resolver=resolver)
