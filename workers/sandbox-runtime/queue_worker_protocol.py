from __future__ import annotations

import hashlib
import ipaddress
import json
import math
from typing import NoReturn
from urllib.parse import urlsplit
from uuid import UUID

MAX_USER_DATA_BYTES = 65_536
MAX_DEPTH = 32


class QueueWorkerBoundaryError(ValueError):
    pass


def _fail(message: str) -> NoReturn:
    raise QueueWorkerBoundaryError(message)


def _json_value(value: object, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        _fail("Queue user data exceeds the maximum nesting depth.")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail("Queue user data contains a non-finite number.")
        return
    if isinstance(value, list):
        for item in value:
            _json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("Queue user data keys must be strings.")
            _json_value(item, depth=depth + 1)
        return
    _fail("Queue user data must be JSON-compatible.")


def _https_url(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 2_048:
        _fail("Queue request URL is invalid.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise QueueWorkerBoundaryError("Queue request URL is invalid.") from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or any(character.isspace() for character in value)
    ):
        _fail("Queue request URL is invalid.")
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        _fail("Queue request URL cannot use an IP literal.")
    return value


def validate_queue_claim_result(
    value: object,
    *,
    expected_queue_id: str,
) -> dict[str, object]:
    fields = {
        "id",
        "queue_id",
        "url",
        "user_data",
        "attempt_count",
        "claim_token",
    }
    if not isinstance(value, dict) or set(value) != fields:
        _fail("Queue claim result fields are invalid.")
    try:
        request_id = str(UUID(str(value["id"])))
        queue_id = str(UUID(str(value["queue_id"])))
        claim_token = str(UUID(str(value["claim_token"])))
    except ValueError as exc:
        raise QueueWorkerBoundaryError(
            "Queue claim identifiers are invalid."
        ) from exc
    if queue_id != expected_queue_id:
        _fail("Queue claim is outside the bound Queue.")
    attempt_count = value["attempt_count"]
    if (
        isinstance(attempt_count, bool)
        or not isinstance(attempt_count, int)
        or not 1 <= attempt_count <= 100
    ):
        _fail("Queue claim attempt count is invalid.")
    user_data = value["user_data"]
    _json_value(user_data)
    try:
        encoded = json.dumps(
            user_data,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise QueueWorkerBoundaryError(
            "Queue user data cannot be encoded."
        ) from exc
    if len(encoded) > MAX_USER_DATA_BYTES:
        _fail("Queue user data exceeds the worker limit.")
    return {
        "schema_version": "rdc.queue-worker-claim/v1",
        "request_id": request_id,
        "queue_id": queue_id,
        "url": _https_url(value["url"]),
        "user_data": user_data,
        "attempt_count": attempt_count,
        "claim_token": claim_token,
    }


def queue_completion_payload(
    claim: dict[str, object],
    *,
    handled: bool,
    failure_code: str = "AGENT_EXIT_NONZERO",
    failure_summary: str = "Queue-bound Agent execution failed.",
) -> dict[str, object]:
    return {
        "queue_id": str(claim["queue_id"]),
        "request_id": str(claim["request_id"]),
        "claim_token": str(claim["claim_token"]),
        "status": "HANDLED" if handled else "FAILED",
        "failure_code": None if handled else failure_code[:80],
        "failure_summary": (
            None if handled else failure_summary[:2000]
        ),
    }


def queue_dataset_idempotency_key(claim: dict[str, object]) -> str:
    if claim.get("schema_version") != "rdc.queue-worker-claim/v1":
        _fail("Queue Dataset persistence requires a validated claim.")
    request_id = str(claim.get("request_id", ""))
    queue_id = str(claim.get("queue_id", ""))
    try:
        UUID(request_id)
        UUID(queue_id)
    except ValueError as exc:
        raise QueueWorkerBoundaryError(
            "Queue Dataset persistence scope is invalid."
        ) from exc
    return f"queue:{request_id}"


def queue_http_fetch_envelope(
    claim: dict[str, object],
) -> dict[str, object]:
    if claim.get("schema_version") != "rdc.queue-worker-claim/v1":
        _fail("Queue HTTP acquisition requires a validated claim.")
    request_id = str(claim.get("request_id", ""))
    try:
        UUID(request_id)
    except ValueError as exc:
        raise QueueWorkerBoundaryError(
            "Queue HTTP acquisition request id is invalid."
        ) from exc
    return {
        "schema_version": "rdc.web-fetch/v1",
        "requests": [
            {
                "id": "queue-request",
                "method": "GET",
                "url": _https_url(claim.get("url")),
            }
        ],
    }


def queue_http_agent_result(
    claim: dict[str, object],
    web_fetch_result: object,
) -> dict[str, object]:
    envelope = queue_http_fetch_envelope(claim)
    expected_digest = hashlib.sha256(
        json.dumps(
            envelope,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    expected_fields = {
        "schema_version",
        "request_digest",
        "results",
        "budget",
    }
    if (
        not isinstance(web_fetch_result, dict)
        or set(web_fetch_result) != expected_fields
        or web_fetch_result.get("schema_version")
        != "rdc.web-fetch-result/v1"
        or web_fetch_result.get("request_digest") != expected_digest
    ):
        _fail("Queue HTTP result envelope is invalid.")
    results = web_fetch_result.get("results")
    budget = web_fetch_result.get("budget")
    if (
        not isinstance(results, list)
        or len(results) != 1
        or not isinstance(results[0], dict)
        or results[0].get("id") != "queue-request"
        or results[0].get("method") != "GET"
        or not isinstance(budget, dict)
    ):
        _fail("Queue HTTP result does not match its claim.")
    return {
        "schema_version": "rdc.queue-http-result/v1",
        "request_id": str(claim["request_id"]),
        "queue_id": str(claim["queue_id"]),
        "response": dict(results[0]),
        "budget": dict(budget),
    }


def queue_browser_navigation_plan(
    claim: dict[str, object],
    *,
    max_dom_bytes: int,
) -> dict[str, object]:
    if claim.get("schema_version") != "rdc.queue-worker-claim/v1":
        _fail("Queue browser acquisition requires a validated claim.")
    request_id = str(claim.get("request_id", ""))
    try:
        UUID(request_id)
    except ValueError as exc:
        raise QueueWorkerBoundaryError(
            "Queue browser acquisition request id is invalid."
        ) from exc
    if (
        isinstance(max_dom_bytes, bool)
        or not isinstance(max_dom_bytes, int)
        or not 65_536 <= max_dom_bytes <= 4_194_304
    ):
        _fail("Queue browser DOM limit is unsafe.")
    return {
        "schema_version": "rdc.browser/v2",
        "steps": [
            {
                "id": "queue-goto",
                "type": "goto",
                "url": _https_url(claim.get("url")),
                "wait_until": "domcontentloaded",
            },
            {
                "id": "queue-html",
                "type": "extract_html",
                "selector": "html",
                "max_bytes": max_dom_bytes,
            },
        ],
    }


def queue_browser_agent_result(
    claim: dict[str, object],
    navigation_plan: dict[str, object],
    browser_result: object,
) -> dict[str, object]:
    steps = navigation_plan.get("steps")
    if (
        not isinstance(steps, list)
        or len(steps) != 2
        or not isinstance(steps[1], dict)
    ):
        _fail("Queue browser navigation plan is invalid.")
    max_dom_bytes = steps[1].get("max_bytes")
    if isinstance(max_dom_bytes, bool) or not isinstance(max_dom_bytes, int):
        _fail("Queue browser navigation plan is invalid.")
    if navigation_plan != queue_browser_navigation_plan(
        claim,
        max_dom_bytes=max_dom_bytes,
    ):
        _fail("Queue browser navigation plan does not match its claim.")
    expected_fields = {
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
    }
    if (
        not isinstance(browser_result, dict)
        or set(browser_result) != expected_fields
        or browser_result.get("schema_version")
        != "rdc.browser-navigation-result/v1"
        or browser_result.get("browser_network") != "none"
        or browser_result.get("gateway_transport") != "unix"
        or browser_result.get("gateway_live_forwarding") is not True
        or browser_result.get("request_digest")
        != hashlib.sha256(
            json.dumps(
                navigation_plan,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
    ):
        _fail("Queue browser result does not match its claim-derived plan.")
    return {
        "schema_version": "rdc.queue-browser-result/v1",
        "request_id": str(claim["request_id"]),
        "queue_id": str(claim["queue_id"]),
        "navigation": dict(browser_result),
    }
