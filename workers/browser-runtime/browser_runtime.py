from __future__ import annotations

import argparse
import json
import re
import secrets
import socket
import sys

from playwright.sync_api import sync_playwright

_GATEWAY_SOCKET = "/rdc-ipc/gateway.sock"
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_MAX_MESSAGE_BYTES = 4_096


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


def _gateway_ping(
    *,
    socket_path: str,
    gateway_policy_digest: str,
) -> dict[str, object]:
    if socket_path != _GATEWAY_SOCKET:
        raise RuntimeError("Browser gateway socket path is not allowed.")
    if _DIGEST.fullmatch(gateway_policy_digest) is None:
        raise RuntimeError("Browser gateway policy digest is invalid.")

    nonce = secrets.token_hex(16)
    request = {
        "schema_version": "rdc.browser-gateway-ping/v1",
        "nonce": nonce,
        "gateway_policy_digest": gateway_policy_digest,
    }
    encoded = (
        json.dumps(request, sort_keys=True, separators=(",", ":")).encode("utf-8")
        + b"\n"
    )
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(3.0)
        client.connect(socket_path)
        client.sendall(encoded)
        raw = bytearray()
        while b"\n" not in raw:
            chunk = client.recv(1024)
            if not chunk:
                break
            raw.extend(chunk)
            if len(raw) > _MAX_MESSAGE_BYTES:
                raise RuntimeError(
                    "Browser gateway self-test response is too large."
                )
    finally:
        client.close()

    line = bytes(raw).split(b"\n", 1)[0]
    try:
        response = json.loads(line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(
            "Browser gateway self-test response is invalid."
        ) from exc

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


def _transport_self_test(
    *,
    socket_path: str,
    gateway_policy_digest: str,
) -> dict[str, object]:
    gateway = _gateway_ping(
        socket_path=socket_path,
        gateway_policy_digest=gateway_policy_digest,
    )
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


def main() -> int:
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--self-test", action="store_true")
    mode.add_argument("--transport-self-test", action="store_true")
    parser.add_argument("--gateway-socket")
    parser.add_argument("--gateway-policy-digest")
    args = parser.parse_args()

    try:
        if args.self_test:
            if (
                args.gateway_socket is not None
                or args.gateway_policy_digest is not None
            ):
                raise RuntimeError(
                    "Phase 1L self-test cannot accept gateway arguments."
                )
            result = _self_test()
        else:
            if (
                args.gateway_socket is None
                or args.gateway_policy_digest is None
            ):
                raise RuntimeError(
                    "Gateway transport self-test requires exact IPC arguments."
                )
            result = _transport_self_test(
                socket_path=args.gateway_socket,
                gateway_policy_digest=args.gateway_policy_digest,
            )
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 64

    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
