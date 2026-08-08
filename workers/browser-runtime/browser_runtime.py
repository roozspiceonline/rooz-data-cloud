from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import secrets
import socket
import sys
from pathlib import Path

from playwright.sync_api import Route, sync_playwright

_GATEWAY_SOCKET = "/rdc-ipc/gateway.sock"
_NAVIGATION_PLAN = "/rdc-ipc/navigation.json"
_RESULT_PATH = "/rdc-output/result.json"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_ACTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_MAX_SELF_TEST_MESSAGE_BYTES = 4_096
_MAX_LIVE_REQUEST_BYTES = 16_384
_MAX_LIVE_RESPONSE_BYTES = 11_300_000
_MAX_SELECTOR_CHARS = 512
_MAX_TEXT_CHARS = 131_072
_MAX_HTML_BYTES = 4_194_304
_MAX_SCREENSHOT_BYTES = 4_194_304
_ALLOWED_RESOURCE_TYPES = {
    "document",
    "stylesheet",
    "script",
    "image",
    "font",
    "xhr",
    "fetch",
}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


def _canonical_digest(value: object) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        allow_nan=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _read_socket_line(client: socket.socket, *, maximum: int) -> bytes:
    raw = bytearray()
    while b"\n" not in raw:
        chunk = client.recv(min(65_536, maximum + 1))
        if not chunk:
            break
        raw.extend(chunk)
        if len(raw) > maximum:
            raise RuntimeError(
                "Browser gateway response exceeded the safe size limit."
            )
    return bytes(raw).split(b"\n", 1)[0]


def _gateway_exchange(
    value: dict[str, object],
    *,
    maximum_request: int,
    maximum_response: int,
) -> dict[str, object]:
    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    if len(encoded) > maximum_request:
        raise RuntimeError("Browser gateway request is too large.")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(30.0)
        client.connect(_GATEWAY_SOCKET)
        client.sendall(encoded)
        raw = _read_socket_line(client, maximum=maximum_response)
    finally:
        client.close()
    try:
        response = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Browser gateway response is invalid JSON.") from exc
    if not isinstance(response, dict):
        raise RuntimeError("Browser gateway response must be an object.")
    return {str(key): item for key, item in response.items()}


def _chromium_about_blank() -> dict[str, object]:
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                accept_downloads=False,
                service_workers="block",
            )
            try:
                page = context.new_page()
                page.goto("about:blank", wait_until="load", timeout=5_000)
                return {
                    "browser": "chromium",
                    "page_url": page.url,
                    "downloads_enabled": False,
                    "service_workers": "blocked",
                    "remote_cdp": False,
                    "external_navigation": False,
                }
            finally:
                context.close()
        finally:
            browser.close()


def _self_test() -> dict[str, object]:
    return {
        "schema_version": "rdc.browser-runtime-self-test/v1",
        **_chromium_about_blank(),
    }


def _gateway_ping(*, gateway_policy_digest: str) -> dict[str, object]:
    if _DIGEST.fullmatch(gateway_policy_digest) is None:
        raise RuntimeError("Browser gateway policy digest is invalid.")
    nonce = secrets.token_hex(16)
    response = _gateway_exchange(
        {
            "schema_version": "rdc.browser-gateway-ping/v1",
            "nonce": nonce,
            "gateway_policy_digest": gateway_policy_digest,
        },
        maximum_request=_MAX_SELF_TEST_MESSAGE_BYTES,
        maximum_response=_MAX_SELF_TEST_MESSAGE_BYTES,
    )
    expected = {
        "schema_version": "rdc.browser-gateway-pong/v1",
        "nonce": nonce,
        "gateway_policy_digest": gateway_policy_digest,
        "transport": "unix",
        "policy_enforced": True,
        "external_request": False,
        "live_forwarding": False,
    }
    if response != expected:
        raise RuntimeError(
            "Browser gateway self-test response did not match the receipt."
        )
    return expected


def _transport_self_test(*, gateway_policy_digest: str) -> dict[str, object]:
    gateway = _gateway_ping(gateway_policy_digest=gateway_policy_digest)
    return {
        "schema_version": "rdc.browser-gateway-transport-self-test/v1",
        **_chromium_about_blank(),
        "gateway_transport": gateway["transport"],
        "gateway_policy_digest": gateway["gateway_policy_digest"],
        "gateway_policy_enforced": gateway["policy_enforced"],
        "gateway_external_request": gateway["external_request"],
        "gateway_live_forwarding": gateway["live_forwarding"],
        "browser_network": "none",
    }


def _selector(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > _MAX_SELECTOR_CHARS
        or "\x00" in value
        or "\r" in value
        or "\n" in value
    ):
        raise RuntimeError("Browser runtime selector is invalid.")
    return value


def _validate_runtime_plan(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {"schema_version", "steps"}:
        raise RuntimeError("Browser runtime plan fields are invalid.")
    if value.get("schema_version") != "rdc.browser/v2":
        raise RuntimeError("Browser runtime plan version is unsupported.")
    steps = value.get("steps")
    if not isinstance(steps, list) or not 1 <= len(steps) <= 16:
        raise RuntimeError("Browser runtime step count is invalid.")

    normalized: list[dict[str, object]] = []
    seen: set[str] = set()
    goto_count = 0
    for index, raw in enumerate(steps):
        if not isinstance(raw, dict):
            raise RuntimeError("Browser runtime step must be an object.")
        step_id = raw.get("id")
        if (
            not isinstance(step_id, str)
            or _ACTION_ID.fullmatch(step_id) is None
            or step_id in seen
        ):
            raise RuntimeError("Browser runtime step id is invalid.")
        seen.add(step_id)
        step_type = raw.get("type")

        if step_type == "goto":
            if set(raw) != {"id", "type", "url", "wait_until"}:
                raise RuntimeError("Browser runtime goto fields are invalid.")
            url = raw.get("url")
            wait_until = raw.get("wait_until")
            if (
                not isinstance(url, str)
                or not url.startswith("https://")
                or len(url) > 8192
                or wait_until not in {"domcontentloaded", "load"}
            ):
                raise RuntimeError("Browser runtime goto is invalid.")
            goto_count += 1
            normalized.append(dict(raw))
            continue

        if index == 0:
            raise RuntimeError("Browser runtime first step must be goto.")

        if step_type == "wait_for_selector":
            if set(raw) != {"id", "type", "selector", "state", "timeout_ms"}:
                raise RuntimeError("Browser runtime wait fields are invalid.")
            timeout_ms = raw.get("timeout_ms")
            if (
                raw.get("state") not in {"attached", "visible"}
                or isinstance(timeout_ms, bool)
                or not isinstance(timeout_ms, int)
                or not 100 <= timeout_ms <= 15_000
            ):
                raise RuntimeError("Browser runtime wait is unsafe.")
            _selector(raw.get("selector"))
            normalized.append(dict(raw))
            continue

        if step_type == "extract_text":
            if set(raw) != {"id", "type", "selector", "max_chars"}:
                raise RuntimeError(
                    "Browser runtime text extraction fields are invalid."
                )
            max_chars = raw.get("max_chars")
            if (
                isinstance(max_chars, bool)
                or not isinstance(max_chars, int)
                or not 1 <= max_chars <= _MAX_TEXT_CHARS
            ):
                raise RuntimeError(
                    "Browser runtime text extraction limit is unsafe."
                )
            _selector(raw.get("selector"))
            normalized.append(dict(raw))
            continue

        if step_type == "extract_html":
            if set(raw) != {"id", "type", "selector", "max_bytes"}:
                raise RuntimeError(
                    "Browser runtime HTML extraction fields are invalid."
                )
            max_bytes = raw.get("max_bytes")
            if (
                isinstance(max_bytes, bool)
                or not isinstance(max_bytes, int)
                or not 1 <= max_bytes <= _MAX_HTML_BYTES
            ):
                raise RuntimeError(
                    "Browser runtime HTML extraction limit is unsafe."
                )
            _selector(raw.get("selector"))
            normalized.append(dict(raw))
            continue

        if step_type == "screenshot":
            if set(raw) != {"id", "type", "full_page"}:
                raise RuntimeError("Browser runtime screenshot fields are invalid.")
            if raw.get("full_page") is not False:
                raise RuntimeError(
                    "Browser runtime permits viewport screenshots only."
                )
            normalized.append(dict(raw))
            continue

        raise RuntimeError("Browser runtime step type is unsupported.")

    if goto_count < 1:
        raise RuntimeError("Browser runtime requires a goto step.")
    return {"schema_version": "rdc.browser/v2", "steps": normalized}


def _load_runtime_plan(*, expected_request_digest: str) -> dict[str, object]:
    path = Path(_NAVIGATION_PLAN)
    if not path.is_file() or path.is_symlink():
        raise RuntimeError("Browser runtime navigation plan is unavailable.")
    raw = path.read_bytes()
    if not raw or len(raw) > 65_536:
        raise RuntimeError("Browser runtime navigation plan is too large.")
    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError("Browser runtime navigation plan is invalid JSON.") from exc
    plan = _validate_runtime_plan(value)
    if _canonical_digest(plan) != expected_request_digest:
        raise RuntimeError(
            "Browser runtime plan digest does not match the Run receipt."
        )
    return plan


def _decode_gateway_response(
    value: dict[str, object],
    *,
    request_id: str,
    gateway_policy_digest: str,
) -> tuple[int, dict[str, str], bytes, str | None, dict[str, int]]:
    if value.get("schema_version") == "rdc.browser-gateway-error/v1":
        if set(value) != {
            "schema_version",
            "request_id",
            "gateway_policy_digest",
            "error_code",
        }:
            raise RuntimeError("Browser gateway error fields are invalid.")
        raise RuntimeError("Browser gateway denied the network request.")

    expected = {
        "schema_version",
        "request_id",
        "gateway_policy_digest",
        "status",
        "headers",
        "redirect_url",
        "body_base64",
        "size_bytes",
        "body_sha256",
        "budget",
    }
    if set(value) != expected:
        raise RuntimeError("Browser gateway response fields are invalid.")
    if value.get("schema_version") != "rdc.browser-gateway-response/v1":
        raise RuntimeError("Browser gateway response version is unsupported.")
    if value.get("request_id") != request_id:
        raise RuntimeError("Browser gateway response id mismatch.")
    if value.get("gateway_policy_digest") != gateway_policy_digest:
        raise RuntimeError("Browser gateway response policy digest mismatch.")

    status = value.get("status")
    headers_raw = value.get("headers")
    redirect_url = value.get("redirect_url")
    body_base64 = value.get("body_base64")
    size_bytes = value.get("size_bytes")
    body_sha256 = value.get("body_sha256")
    budget_raw = value.get("budget")
    if (
        isinstance(status, bool)
        or not isinstance(status, int)
        or not 100 <= status <= 599
        or not isinstance(headers_raw, dict)
        or not isinstance(body_base64, str)
        or isinstance(size_bytes, bool)
        or not isinstance(size_bytes, int)
        or not isinstance(body_sha256, str)
        or _DIGEST.fullmatch(body_sha256) is None
        or not isinstance(budget_raw, dict)
    ):
        raise RuntimeError("Browser gateway response values are invalid.")
    if redirect_url is not None and not isinstance(redirect_url, str):
        raise RuntimeError("Browser gateway redirect URL is invalid.")
    try:
        body = base64.b64decode(body_base64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise RuntimeError("Browser gateway response body is invalid.") from exc
    if len(body) != size_bytes:
        raise RuntimeError("Browser gateway response size mismatch.")
    if hashlib.sha256(body).hexdigest() != body_sha256:
        raise RuntimeError("Browser gateway response digest mismatch.")

    headers: dict[str, str] = {}
    for key, item in headers_raw.items():
        if not isinstance(key, str) or not isinstance(item, str):
            raise RuntimeError("Browser gateway response header is invalid.")
        lowered = key.casefold()
        if lowered in {
            "set-cookie",
            "authorization",
            "proxy-authorization",
            "content-length",
            "location",
        }:
            raise RuntimeError(
                "Browser gateway response leaked a forbidden header."
            )
        headers[lowered] = item[:2048]

    expected_budget = {
        "requests_used",
        "bytes_received",
        "redirects_used",
        "max_requests",
        "max_total_bytes",
        "max_redirects",
    }
    if set(budget_raw) != expected_budget:
        raise RuntimeError("Browser gateway budget fields are invalid.")
    budget: dict[str, int] = {}
    for key in expected_budget:
        item = budget_raw.get(key)
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise RuntimeError("Browser gateway budget value is invalid.")
        budget[key] = item

    if status in _REDIRECT_STATUSES:
        if (
            not isinstance(redirect_url, str)
            or not redirect_url.startswith("https://")
            or body
        ):
            raise RuntimeError("Browser gateway redirect response is unsafe.")
    elif redirect_url is not None:
        raise RuntimeError(
            "Browser gateway non-redirect carried a redirect URL."
        )
    return status, headers, body, redirect_url, budget


def _live_gateway_request(
    *,
    request_id: str,
    gateway_policy_digest: str,
    resource_type: str,
    method: str,
    url: str,
) -> tuple[int, dict[str, str], bytes, str | None, dict[str, int]]:
    response = _gateway_exchange(
        {
            "schema_version": "rdc.browser-gateway-request/v1",
            "request_id": request_id,
            "gateway_policy_digest": gateway_policy_digest,
            "resource_type": resource_type,
            "method": method,
            "url": url,
        },
        maximum_request=_MAX_LIVE_REQUEST_BYTES,
        maximum_response=_MAX_LIVE_RESPONSE_BYTES,
    )
    return _decode_gateway_response(
        response,
        request_id=request_id,
        gateway_policy_digest=gateway_policy_digest,
    )


def _truncate_utf8(value: str, maximum_bytes: int) -> tuple[str, bool]:
    encoded = value.encode("utf-8")
    if len(encoded) <= maximum_bytes:
        return value, False
    return encoded[:maximum_bytes].decode("utf-8", errors="ignore"), True


def _live_navigation(
    *,
    gateway_policy_digest: str,
    browser_policy_digest: str,
    expected_request_digest: str,
    max_screenshot_bytes: int,
    navigation_timeout_ms: int,
) -> dict[str, object]:
    if any(
        _DIGEST.fullmatch(item) is None
        for item in (
            gateway_policy_digest,
            browser_policy_digest,
            expected_request_digest,
        )
    ):
        raise RuntimeError("Browser live-navigation digest is invalid.")
    if (
        isinstance(max_screenshot_bytes, bool)
        or not 65_536 <= max_screenshot_bytes <= _MAX_SCREENSHOT_BYTES
        or not 1_000 <= navigation_timeout_ms <= 30_000
    ):
        raise RuntimeError("Browser live-navigation limits are unsafe.")

    plan = _load_runtime_plan(expected_request_digest=expected_request_digest)
    request_counter = 0
    last_budget = {
        "requests_used": 0,
        "bytes_received": 0,
        "redirects_used": 0,
        "max_requests": 0,
        "max_total_bytes": 0,
        "max_redirects": 0,
    }

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            context = browser.new_context(
                accept_downloads=False,
                service_workers="block",
            )
            try:
                def _route_request(route: Route) -> None:
                    nonlocal request_counter, last_budget
                    request = route.request
                    request_counter += 1
                    request_id = f"net-{request_counter}"
                    try:
                        if request.resource_type not in _ALLOWED_RESOURCE_TYPES:
                            route.abort("blockedbyclient")
                            return
                        status, headers, body, redirect_url, budget = (
                            _live_gateway_request(
                                request_id=request_id,
                                gateway_policy_digest=gateway_policy_digest,
                                resource_type=request.resource_type,
                                method=request.method,
                                url=request.url,
                            )
                        )
                        last_budget = budget
                        if status in _REDIRECT_STATUSES:
                            route.fulfill(
                                status=status,
                                headers={"location": str(redirect_url)},
                                body=b"",
                            )
                            return
                        route.fulfill(status=status, headers=headers, body=body)
                    except RuntimeError:
                        route.abort("blockedbyclient")

                context.route("**/*", _route_request)
                page = context.new_page()
                step_results: list[dict[str, object]] = []

                for step in plan["steps"]:
                    if not isinstance(step, dict):
                        raise RuntimeError(
                            "Browser runtime normalized step is invalid."
                        )
                    step_id = str(step["id"])
                    step_type = str(step["type"])

                    if step_type == "goto":
                        page.goto(
                            str(step["url"]),
                            wait_until=str(step["wait_until"]),
                            timeout=navigation_timeout_ms,
                        )
                        step_results.append(
                            {"id": step_id, "type": "goto", "url": page.url}
                        )
                        continue
                    if step_type == "wait_for_selector":
                        page.wait_for_selector(
                            str(step["selector"]),
                            state=str(step["state"]),
                            timeout=int(step["timeout_ms"]),
                        )
                        step_results.append(
                            {
                                "id": step_id,
                                "type": "wait_for_selector",
                                "matched": True,
                            }
                        )
                        continue
                    if step_type == "extract_text":
                        text = page.locator(
                            str(step["selector"])
                        ).first.inner_text(timeout=navigation_timeout_ms)
                        maximum = int(step["max_chars"])
                        truncated = len(text) > maximum
                        if truncated:
                            text = text[:maximum]
                        step_results.append(
                            {
                                "id": step_id,
                                "type": "extract_text",
                                "text": text,
                                "truncated": truncated,
                            }
                        )
                        continue
                    if step_type == "extract_html":
                        html = page.locator(
                            str(step["selector"])
                        ).first.inner_html(timeout=navigation_timeout_ms)
                        html, truncated = _truncate_utf8(
                            html,
                            int(step["max_bytes"]),
                        )
                        step_results.append(
                            {
                                "id": step_id,
                                "type": "extract_html",
                                "html": html,
                                "truncated": truncated,
                            }
                        )
                        continue
                    if step_type == "screenshot":
                        image = page.screenshot(full_page=False, type="png")
                        if len(image) > max_screenshot_bytes:
                            raise RuntimeError(
                                "Browser screenshot exceeded policy."
                            )
                        step_results.append(
                            {
                                "id": step_id,
                                "type": "screenshot",
                                "media_type": "image/png",
                                "image_base64": base64.b64encode(image).decode("ascii"),
                                "size_bytes": len(image),
                                "sha256": hashlib.sha256(image).hexdigest(),
                            }
                        )
                        continue
                    raise RuntimeError(
                        "Browser runtime step type became unsupported."
                    )

                return {
                    "schema_version": "rdc.browser-navigation-result/v1",
                    "request_digest": expected_request_digest,
                    "browser_policy_digest": browser_policy_digest,
                    "browser_egress_policy_digest": gateway_policy_digest,
                    "browser_network": "none",
                    "gateway_transport": "unix",
                    "gateway_live_forwarding": True,
                    "final_url": page.url,
                    "steps": step_results,
                    "egress_budget": last_budget,
                }
            finally:
                context.close()
        finally:
            browser.close()


def _write_live_result(value: dict[str, object]) -> None:
    path = Path(_RESULT_PATH)
    parent = path.parent
    if not parent.is_dir() or parent.is_symlink():
        raise RuntimeError("Browser runtime output directory is unsafe.")
    encoded = (
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    if len(encoded) > 16_777_216:
        raise RuntimeError("Browser navigation result is too large.")
    path.write_bytes(encoded)


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--transport-self-test", action="store_true")
    mode.add_argument("--live-navigation", action="store_true")
    parser.add_argument("--gateway-socket")
    parser.add_argument("--gateway-policy-digest")
    parser.add_argument("--browser-policy-digest")
    parser.add_argument("--request-digest")
    parser.add_argument("--max-screenshot-bytes", type=int)
    parser.add_argument("--navigation-timeout-ms", type=int)
    args = parser.parse_args()

    try:
        if args.self_test:
            if any(
                value is not None
                for value in (
                    args.gateway_socket,
                    args.gateway_policy_digest,
                    args.browser_policy_digest,
                    args.request_digest,
                    args.max_screenshot_bytes,
                    args.navigation_timeout_ms,
                )
            ):
                raise RuntimeError(
                    "Phase 1L self-test cannot accept live arguments."
                )
            result = _self_test()
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0

        if args.transport_self_test:
            if (
                args.gateway_socket != _GATEWAY_SOCKET
                or args.gateway_policy_digest is None
                or any(
                    value is not None
                    for value in (
                        args.browser_policy_digest,
                        args.request_digest,
                        args.max_screenshot_bytes,
                        args.navigation_timeout_ms,
                    )
                )
            ):
                raise RuntimeError(
                    "Gateway transport self-test arguments are invalid."
                )
            result = _transport_self_test(
                gateway_policy_digest=args.gateway_policy_digest,
            )
            print(json.dumps(result, sort_keys=True, separators=(",", ":")))
            return 0

        required = (
            args.gateway_socket,
            args.gateway_policy_digest,
            args.browser_policy_digest,
            args.request_digest,
            args.max_screenshot_bytes,
            args.navigation_timeout_ms,
        )
        if any(value is None for value in required) or args.gateway_socket != _GATEWAY_SOCKET:
            raise RuntimeError(
                "Live navigation requires all immutable runtime arguments."
            )
        result = _live_navigation(
            gateway_policy_digest=str(args.gateway_policy_digest),
            browser_policy_digest=str(args.browser_policy_digest),
            expected_request_digest=str(args.request_digest),
            max_screenshot_bytes=int(args.max_screenshot_bytes),
            navigation_timeout_ms=int(args.navigation_timeout_ms),
        )
        _write_live_result(result)
        print(
            json.dumps(
                {
                    "schema_version": "rdc.browser-navigation-runtime-complete/v1",
                    "result_written": True,
                    "browser_network": "none",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        return 0
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 64


if __name__ == "__main__":
    raise SystemExit(main())
