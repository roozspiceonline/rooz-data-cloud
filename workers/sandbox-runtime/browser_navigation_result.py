from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ACTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_RESULT_BYTES = 16_777_216


class BrowserNavigationResultError(ValueError):
    pass


def _fail(message: str) -> None:
    raise BrowserNavigationResultError(message)


def _canonical_digest(value: object) -> str:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise BrowserNavigationResultError(
            "Browser navigation plan contains invalid JSON values."
        ) from exc
    return hashlib.sha256(encoded).hexdigest()


def validate_browser_navigation_result(
    value: object,
    *,
    request_digest: str,
    browser_policy_digest: str,
    browser_egress_policy_digest: str,
    navigation_plan: object,
    max_screenshot_bytes: int,
) -> dict[str, object]:
    if not all(
        _DIGEST.fullmatch(item) is not None
        for item in (
            request_digest,
            browser_policy_digest,
            browser_egress_policy_digest,
        )
    ):
        _fail("Browser navigation result expected digest is invalid.")
    if (
        isinstance(max_screenshot_bytes, bool)
        or not 65_536 <= max_screenshot_bytes <= 4_194_304
    ):
        _fail("Browser navigation result screenshot limit is unsafe.")
    if (
        not isinstance(navigation_plan, dict)
        or set(navigation_plan) != {"schema_version", "steps"}
        or navigation_plan.get("schema_version") != "rdc.browser/v2"
    ):
        _fail("Browser navigation result plan is invalid.")
    plan_steps = navigation_plan.get("steps")
    if not isinstance(plan_steps, list) or not 1 <= len(plan_steps) <= 16:
        _fail("Browser navigation result plan step count is invalid.")
    if _canonical_digest(navigation_plan) != request_digest:
        _fail("Browser navigation result plan digest mismatch.")
    if not isinstance(value, dict) or set(value) != {
        "schema_version",
        "request_digest",
        "browser_policy_digest",
        "browser_egress_policy_digest",
        "browser_network",
        "gateway_transport",
        "gateway_live_forwarding",
        "final_url",
        "steps",
        "egress_budget",
    }:
        _fail("Browser navigation result fields are invalid.")
    if value.get("schema_version") != "rdc.browser-navigation-result/v1":
        _fail("Browser navigation result version is unsupported.")
    if value.get("request_digest") != request_digest:
        _fail("Browser navigation result request digest mismatch.")
    if value.get("browser_policy_digest") != browser_policy_digest:
        _fail("Browser navigation result browser-policy digest mismatch.")
    if value.get("browser_egress_policy_digest") != browser_egress_policy_digest:
        _fail("Browser navigation result egress-policy digest mismatch.")
    if value.get("browser_network") != "none":
        _fail("Browser navigation result network boundary changed.")
    if value.get("gateway_transport") != "unix":
        _fail("Browser navigation result gateway transport changed.")
    if value.get("gateway_live_forwarding") is not True:
        _fail("Browser navigation result did not use the gateway.")
    final_url = value.get("final_url")
    if not isinstance(final_url, str) or not final_url.startswith("https://"):
        _fail("Browser navigation result final URL is invalid.")

    raw_steps = value.get("steps")
    if (
        not isinstance(raw_steps, list)
        or len(raw_steps) != len(plan_steps)
    ):
        _fail("Browser navigation result step count does not match the plan.")
    seen: set[str] = set()
    normalized_steps: list[dict[str, object]] = []
    for plan_step, raw in zip(plan_steps, raw_steps, strict=True):
        if not isinstance(plan_step, dict) or not isinstance(raw, dict):
            _fail("Browser navigation result step is invalid.")
        step_id = raw.get("id")
        step_type = raw.get("type")
        if (
            not isinstance(step_id, str)
            or _ACTION_ID.fullmatch(step_id) is None
            or step_id in seen
            or not isinstance(step_type, str)
        ):
            _fail("Browser navigation result step identity is invalid.")
        seen.add(step_id)
        if (
            plan_step.get("id") != step_id
            or plan_step.get("type") != step_type
        ):
            _fail("Browser navigation result step does not match the plan.")

        if step_type == "goto":
            if set(raw) != {"id", "type", "url"}:
                _fail("Browser goto result fields are invalid.")
            url = raw.get("url")
            if not isinstance(url, str) or not url.startswith("https://"):
                _fail("Browser goto result URL is invalid.")
        elif step_type == "wait_for_selector":
            if set(raw) != {"id", "type", "matched"}:
                _fail("Browser wait result fields are invalid.")
            if raw.get("matched") is not True:
                _fail("Browser wait result is not matched.")
        elif step_type == "extract_text":
            if set(raw) != {"id", "type", "text", "truncated"}:
                _fail("Browser text result fields are invalid.")
            if not isinstance(raw.get("text"), str) or not isinstance(
                raw.get("truncated"), bool
            ):
                _fail("Browser text result values are invalid.")
            max_chars = plan_step.get("max_chars")
            if (
                isinstance(max_chars, bool)
                or not isinstance(max_chars, int)
                or len(raw["text"]) > max_chars
            ):
                _fail("Browser text result exceeded the plan limit.")
        elif step_type == "extract_html":
            if set(raw) != {"id", "type", "html", "truncated"}:
                _fail("Browser HTML result fields are invalid.")
            if not isinstance(raw.get("html"), str) or not isinstance(
                raw.get("truncated"), bool
            ):
                _fail("Browser HTML result values are invalid.")
            max_bytes = plan_step.get("max_bytes")
            if (
                isinstance(max_bytes, bool)
                or not isinstance(max_bytes, int)
                or len(raw["html"].encode("utf-8")) > max_bytes
            ):
                _fail("Browser HTML result exceeded the plan limit.")
        elif step_type == "screenshot":
            if set(raw) != {
                "id",
                "type",
                "media_type",
                "image_base64",
                "size_bytes",
                "sha256",
            }:
                _fail("Browser screenshot result fields are invalid.")
            if plan_step.get("full_page") is not False:
                _fail("Browser screenshot result plan is unsafe.")
            if raw.get("media_type") != "image/png":
                _fail("Browser screenshot media type is invalid.")
            image_base64 = raw.get("image_base64")
            size_bytes = raw.get("size_bytes")
            digest = raw.get("sha256")
            if (
                not isinstance(image_base64, str)
                or isinstance(size_bytes, bool)
                or not isinstance(size_bytes, int)
                or not 0 <= size_bytes <= max_screenshot_bytes
                or not isinstance(digest, str)
                or _DIGEST.fullmatch(digest) is None
            ):
                _fail("Browser screenshot result values are invalid.")
            try:
                image = base64.b64decode(image_base64, validate=True)
            except (binascii.Error, ValueError) as exc:
                raise BrowserNavigationResultError(
                    "Browser screenshot base64 is invalid."
                ) from exc
            if len(image) != size_bytes:
                _fail("Browser screenshot size does not match.")
            if hashlib.sha256(image).hexdigest() != digest:
                _fail("Browser screenshot digest does not match.")
        else:
            _fail("Browser navigation result step type is unsupported.")

        normalized_steps.append({str(key): item for key, item in raw.items()})

    raw_budget = value.get("egress_budget")
    expected_budget = {
        "requests_used",
        "bytes_received",
        "redirects_used",
        "max_requests",
        "max_total_bytes",
        "max_redirects",
    }
    if not isinstance(raw_budget, dict) or set(raw_budget) != expected_budget:
        _fail("Browser navigation result egress budget is invalid.")
    budget: dict[str, int] = {}
    for key in expected_budget:
        item = raw_budget.get(key)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            _fail("Browser navigation result budget value is invalid.")
        budget[key] = item
    if budget["requests_used"] > budget["max_requests"]:
        _fail("Browser navigation result request budget was exceeded.")
    if budget["bytes_received"] > budget["max_total_bytes"]:
        _fail("Browser navigation result byte budget was exceeded.")
    if budget["redirects_used"] > budget["max_redirects"]:
        _fail("Browser navigation result redirect budget was exceeded.")

    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    if len(encoded) > _MAX_RESULT_BYTES:
        _fail("Browser navigation result envelope is too large.")

    return {
        **{str(key): item for key, item in value.items()},
        "steps": normalized_steps,
        "egress_budget": budget,
    }
