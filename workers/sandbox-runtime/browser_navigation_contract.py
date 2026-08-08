from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import urlsplit

from browser_policy import BrowserPolicy, BrowserPolicyError, normalize_hostname

_ACTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_SELECTOR_CHARS = 512
_MAX_TEXT_CHARS = 131_072
_MAX_WAIT_MS = 15_000


class BrowserNavigationContractError(ValueError):
    pass


def _fail(message: str) -> None:
    raise BrowserNavigationContractError(message)


def _exact_keys(value: dict[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        _fail(f"{label} fields are invalid.")


def _action_id(value: object, seen: set[str]) -> str:
    if not isinstance(value, str) or _ACTION_ID.fullmatch(value) is None:
        _fail("Browser step id is invalid.")
    if value in seen:
        _fail("Browser step ids must be unique.")
    seen.add(value)
    return value


def _selector(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_SELECTOR_CHARS
        or "\x00" in value
        or "\r" in value
        or "\n" in value
    ):
        _fail("Browser selector is invalid.")
    return value


def _https_url(value: object, policy: BrowserPolicy) -> tuple[str, str]:
    if not isinstance(value, str) or not value.startswith("https://"):
        _fail("Browser navigation requires lowercase HTTPS.")
    if len(value) > 8192:
        _fail("Browser navigation URL is too long.")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise BrowserNavigationContractError(
            "Browser navigation URL is malformed."
        ) from exc
    if not parsed.hostname:
        _fail("Browser navigation URL requires a hostname.")
    if parsed.username is not None or parsed.password is not None:
        _fail("Browser navigation URL credentials are prohibited.")
    try:
        host = normalize_hostname(parsed.hostname)
    except BrowserPolicyError as exc:
        raise BrowserNavigationContractError(
            "Browser navigation hostname is unsafe."
        ) from exc
    if host not in policy.allowed_hosts:
        _fail("Browser navigation hostname is not operator-allowlisted.")
    return value, host


def _wait_until(value: object) -> str:
    if value not in {"domcontentloaded", "load"}:
        _fail("Browser navigation wait mode is unsupported.")
    return str(value)


def canonical_browser_navigation_digest(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode()
    except (TypeError, ValueError) as exc:
        raise BrowserNavigationContractError(
            "Browser navigation envelope must contain valid JSON values."
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def validate_browser_navigation_plan(
    raw: object,
    *,
    policy: BrowserPolicy,
) -> dict[str, object]:
    if not policy.enabled:
        _fail("Browser execution is disabled.")
    if not isinstance(raw, dict):
        _fail("Browser navigation plan must be an object.")
    _exact_keys(raw, {"schema_version", "steps"}, "Browser navigation plan")
    if raw.get("schema_version") != "rdc.browser/v2":
        _fail("Unsupported browser navigation protocol.")

    steps = raw.get("steps")
    if (
        not isinstance(steps, list)
        or not 1 <= len(steps) <= policy.max_actions
    ):
        _fail("Browser navigation step count exceeds policy.")

    seen: set[str] = set()
    normalized: list[dict[str, object]] = []
    hostnames: list[str] = []
    goto_count = 0

    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            _fail("Browser navigation step must be an object.")
        step_type = step.get("type")
        step_id = _action_id(step.get("id"), seen)

        if step_type == "goto":
            _exact_keys(
                step,
                {"id", "type", "url", "wait_until"},
                "Browser goto step",
            )
            url, hostname = _https_url(step.get("url"), policy)
            wait_until = _wait_until(step.get("wait_until"))
            goto_count += 1
            if goto_count > policy.max_pages:
                _fail("Browser navigation page count exceeds policy.")
            hostnames.append(hostname)
            normalized.append(
                {
                    "id": step_id,
                    "type": "goto",
                    "url": url,
                    "wait_until": wait_until,
                }
            )
            continue

        if index == 0:
            _fail("The first browser navigation step must be goto.")

        if step_type == "wait_for_selector":
            _exact_keys(
                step,
                {"id", "type", "selector", "state", "timeout_ms"},
                "Browser wait step",
            )
            selector = _selector(step.get("selector"))
            state = step.get("state")
            if state not in {"attached", "visible"}:
                _fail("Browser selector wait state is unsupported.")
            timeout_ms = step.get("timeout_ms")
            maximum = min(
                _MAX_WAIT_MS,
                policy.navigation_timeout_seconds * 1000,
            )
            if (
                isinstance(timeout_ms, bool)
                or not isinstance(timeout_ms, int)
                or not 100 <= timeout_ms <= maximum
            ):
                _fail("Browser selector wait timeout is unsafe.")
            normalized.append(
                {
                    "id": step_id,
                    "type": "wait_for_selector",
                    "selector": selector,
                    "state": str(state),
                    "timeout_ms": timeout_ms,
                }
            )
            continue

        if step_type == "extract_text":
            _exact_keys(
                step,
                {"id", "type", "selector", "max_chars"},
                "Browser text extraction step",
            )
            selector = _selector(step.get("selector"))
            max_chars = step.get("max_chars")
            if (
                isinstance(max_chars, bool)
                or not isinstance(max_chars, int)
                or not 1 <= max_chars <= _MAX_TEXT_CHARS
            ):
                _fail("Browser text extraction limit is unsafe.")
            normalized.append(
                {
                    "id": step_id,
                    "type": "extract_text",
                    "selector": selector,
                    "max_chars": max_chars,
                }
            )
            continue

        if step_type == "extract_html":
            _exact_keys(
                step,
                {"id", "type", "selector", "max_bytes"},
                "Browser HTML extraction step",
            )
            selector = _selector(step.get("selector"))
            max_bytes = step.get("max_bytes")
            if (
                isinstance(max_bytes, bool)
                or not isinstance(max_bytes, int)
                or not 1 <= max_bytes <= policy.max_dom_bytes
            ):
                _fail("Browser HTML extraction limit is unsafe.")
            normalized.append(
                {
                    "id": step_id,
                    "type": "extract_html",
                    "selector": selector,
                    "max_bytes": max_bytes,
                }
            )
            continue

        if step_type == "screenshot":
            _exact_keys(
                step,
                {"id", "type", "full_page"},
                "Browser screenshot step",
            )
            if step.get("full_page") is not False:
                _fail("Phase 1M foundation permits viewport screenshots only.")
            normalized.append(
                {
                    "id": step_id,
                    "type": "screenshot",
                    "full_page": False,
                }
            )
            continue

        _fail("Browser navigation step type is unsupported.")

    if goto_count < 1:
        _fail("Browser navigation requires at least one goto step.")

    normalized_envelope = {
        "schema_version": "rdc.browser/v2",
        "steps": normalized,
    }
    return {
        **normalized_envelope,
        "hostnames": hostnames,
        "policy_digest": policy.digest,
        "request_digest": canonical_browser_navigation_digest(
            normalized_envelope
        ),
        "execution_enabled": False,
        "browser_network": "none",
    }
