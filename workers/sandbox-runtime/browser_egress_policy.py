from __future__ import annotations

import hashlib
import json
import socket
from dataclasses import dataclass

from egress_policy import (
    EgressPolicy,
    EgressPolicyError,
    Resolver,
    ValidatedTarget,
)

_ALLOWED_RESOURCE_TYPES = frozenset(
    {
        "document",
        "stylesheet",
        "script",
        "image",
        "font",
        "xhr",
        "fetch",
    }
)
_ALLOWED_METHODS = frozenset({"GET", "HEAD"})


class BrowserEgressPolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class BrowserValidatedResource:
    resource_type: str
    method: str
    target: ValidatedTarget

    def as_dict(self) -> dict[str, object]:
        return {
            "resource_type": self.resource_type,
            "method": self.method,
            "url": self.target.url,
            "hostname": self.target.hostname,
            "addresses": list(self.target.addresses),
            "address_pin_required": True,
        }


@dataclass(frozen=True)
class BrowserEgressPolicy:
    base: EgressPolicy

    @classmethod
    def create(cls, base: EgressPolicy) -> "BrowserEgressPolicy":
        if not base.allowed_hosts:
            raise BrowserEgressPolicyError(
                "Browser egress requires a non-empty operator allowlist."
            )
        return cls(base=base)

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "rdc.browser-egress-policy/v1",
            "mode": "gateway-live-canary",
            "allowed_schemes": ["https"],
            "allowed_methods": list(self.base.allowed_methods),
            "allowed_resource_types": sorted(_ALLOWED_RESOURCE_TYPES),
            "allowed_hosts": list(self.base.allowed_hosts),
            "deny_ip_literals": True,
            "require_global_dns": True,
            "pin_validated_address": True,
            "revalidate_redirects": True,
            "revalidate_subresources": True,
            "strip_request_headers": [
                "authorization",
                "cookie",
                "proxy-authorization",
            ],
            "strip_response_headers": ["set-cookie"],
            "service_workers_enabled": False,
            "websockets_enabled": False,
            "webrtc_enabled": False,
            "proxy_override_enabled": False,
            "persistent_cookies_enabled": False,
            "max_requests": self.base.max_requests,
            "max_resource_bytes": self.base.max_response_bytes,
            "max_total_bytes": self.base.max_total_bytes,
            "max_redirects": self.base.max_redirects,
            "connect_timeout_seconds": self.base.connect_timeout_seconds,
            "request_timeout_seconds": self.base.request_timeout_seconds,
            "transport_wired": True,
            "browser_network": "none",
        }

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(encoded).hexdigest()

    def validate_resource(
        self,
        *,
        resource_type: str,
        method: str,
        url: str,
        resolver: Resolver = socket.getaddrinfo,
    ) -> BrowserValidatedResource:
        normalized_type = resource_type.strip().casefold()
        if normalized_type not in _ALLOWED_RESOURCE_TYPES:
            raise BrowserEgressPolicyError(
                "Browser resource type is not allowed by gateway policy."
            )
        normalized_method = method.strip().upper()
        if (
            normalized_method not in _ALLOWED_METHODS
            or normalized_method not in self.base.allowed_methods
        ):
            raise BrowserEgressPolicyError("Browser gateway permits GET and HEAD only.")
        try:
            target = self.base.validate_target(url, resolver=resolver)
        except EgressPolicyError as exc:
            raise BrowserEgressPolicyError(
                "Browser resource target failed egress policy."
            ) from exc
        return BrowserValidatedResource(
            resource_type=normalized_type,
            method=normalized_method,
            target=target,
        )

    def validate_redirect(
        self,
        *,
        resource_type: str,
        method: str,
        url: str,
        resolver: Resolver = socket.getaddrinfo,
    ) -> BrowserValidatedResource:
        return self.validate_resource(
            resource_type=resource_type,
            method=method,
            url=url,
            resolver=resolver,
        )
