from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

_ACTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class BrowserPolicyError(ValueError):
    pass


@dataclass(frozen=True)
class BrowserPolicy:
    enabled: bool
    allowed_hosts: tuple[str, ...]
    max_pages: int
    max_actions: int
    navigation_timeout_seconds: int
    max_dom_bytes: int
    max_screenshot_bytes: int

    def as_dict(self) -> dict[str, object]:
        return {
            "schema_version": "rdc.browser-policy/v1",
            "enabled": self.enabled,
            "allowed_hosts": list(self.allowed_hosts),
            "max_pages": self.max_pages,
            "max_actions": self.max_actions,
            "navigation_timeout_seconds": self.navigation_timeout_seconds,
            "max_dom_bytes": self.max_dom_bytes,
            "max_screenshot_bytes": self.max_screenshot_bytes,
            "agent_container_network": "none",
            "project_secrets_available": False,
            "persistent_profile": False,
            "downloads_enabled": False,
            "uploads_enabled": False,
            "remote_cdp_enabled": False,
        }

    @classmethod
    def create(
        cls,
        *,
        enabled: bool,
        allowed_hosts: tuple[str, ...],
        max_pages: int,
        max_actions: int,
        navigation_timeout_seconds: int,
        max_dom_bytes: int,
        max_screenshot_bytes: int,
    ) -> "BrowserPolicy":
        normalized_hosts = tuple(sorted({normalize_hostname(host) for host in allowed_hosts}))
        if enabled and not normalized_hosts:
            raise BrowserPolicyError("Enabled browser policy requires an operator allowlist.")
        if not 1 <= max_pages <= 2:
            raise BrowserPolicyError("Browser page limit is unsafe.")
        if not 1 <= max_actions <= 16:
            raise BrowserPolicyError("Browser action limit is unsafe.")
        if not 1 <= navigation_timeout_seconds <= 30:
            raise BrowserPolicyError("Browser navigation timeout is unsafe.")
        if not 65_536 <= max_dom_bytes <= 4_194_304:
            raise BrowserPolicyError("Browser DOM limit is unsafe.")
        if not 65_536 <= max_screenshot_bytes <= 4_194_304:
            raise BrowserPolicyError("Browser screenshot limit is unsafe.")
        return cls(
            enabled=enabled,
            allowed_hosts=normalized_hosts,
            max_pages=max_pages,
            max_actions=max_actions,
            navigation_timeout_seconds=navigation_timeout_seconds,
            max_dom_bytes=max_dom_bytes,
            max_screenshot_bytes=max_screenshot_bytes,
        )

    @property
    def digest(self) -> str:
        encoded = json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return hashlib.sha256(encoded).hexdigest()


def normalize_hostname(value: str) -> str:
    candidate = value.strip().rstrip(".").casefold()
    if not candidate or "*" in candidate:
        raise BrowserPolicyError("Browser host must be exact.")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        pass
    else:
        raise BrowserPolicyError("Browser host cannot be an IP literal.")
    normalized = candidate.encode("idna").decode("ascii")
    labels = normalized.split(".")
    if (
        len(labels) < 2
        or normalized.endswith(".local")
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(ch.isalnum() or ch == "-" for ch in label)
            for label in labels
        )
    ):
        raise BrowserPolicyError("Browser host is unsafe.")
    return normalized


def validate_browser_plan(raw: object, *, policy: BrowserPolicy) -> dict[str, object]:
    if not policy.enabled:
        raise BrowserPolicyError("Browser execution is disabled.")
    if not isinstance(raw, dict):
        raise BrowserPolicyError("Browser plan must be an object.")
    required = {"schema_version", "start_url", "wait_until", "actions"}
    if set(raw) != required:
        raise BrowserPolicyError("Browser plan fields are invalid.")
    if raw.get("schema_version") != "rdc.browser/v1":
        raise BrowserPolicyError("Unsupported browser protocol.")

    url = raw.get("start_url")
    if not isinstance(url, str) or not url.startswith("https://") or len(url) > 8192:
        raise BrowserPolicyError("Browser navigation requires HTTPS.")
    parsed = urlsplit(url)
    if not parsed.hostname:
        raise BrowserPolicyError("Browser URL requires a hostname.")
    if parsed.username is not None or parsed.password is not None:
        raise BrowserPolicyError("Browser URL credentials are prohibited.")
    host = normalize_hostname(parsed.hostname)
    if host not in policy.allowed_hosts:
        raise BrowserPolicyError("Browser hostname is not operator-allowlisted.")

    wait_until = raw.get("wait_until")
    if wait_until not in {"domcontentloaded", "load"}:
        raise BrowserPolicyError("Browser wait mode is unsupported.")

    actions = raw.get("actions")
    if not isinstance(actions, list) or not 1 <= len(actions) <= policy.max_actions:
        raise BrowserPolicyError("Browser action count exceeds policy.")

    seen: set[str] = set()
    normalized_actions: list[dict[str, object]] = []
    for action in actions:
        if not isinstance(action, dict) or set(action) != {"id", "type", "include_html"}:
            raise BrowserPolicyError("Browser snapshot fields are invalid.")
        action_id = action.get("id")
        if not isinstance(action_id, str) or _ACTION_ID.fullmatch(action_id) is None:
            raise BrowserPolicyError("Browser action id is invalid.")
        if action_id in seen:
            raise BrowserPolicyError("Browser action ids must be unique.")
        seen.add(action_id)
        if action.get("type") != "snapshot":
            raise BrowserPolicyError("Phase 1L permits snapshot actions only.")
        include_html = action.get("include_html")
        if not isinstance(include_html, bool):
            raise BrowserPolicyError("include_html must be boolean.")
        normalized_actions.append(
            {"id": action_id, "type": "snapshot", "include_html": include_html}
        )

    return {
        "schema_version": "rdc.browser/v1",
        "start_url": url,
        "hostname": host,
        "wait_until": wait_until,
        "actions": normalized_actions,
        "policy_digest": policy.digest,
    }
