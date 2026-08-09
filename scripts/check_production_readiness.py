#!/usr/bin/env python3
"""Bounded production readiness probe with redirect and payload controls."""

from __future__ import annotations

import argparse
import json
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

MAX_RESPONSE_BYTES = 65_536


class ReadinessError(RuntimeError):
    pass


class RejectRedirects(HTTPRedirectHandler):
    def redirect_request(self, *_: object, **__: object) -> None:
        return None


def validate_base_url(value: str, *, allow_loopback_http: bool) -> str:
    parsed = urlsplit(value)
    loopback = parsed.hostname in {"127.0.0.1", "::1", "localhost"}
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
        or parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or (parsed.scheme != "https" and not (loopback and allow_loopback_http))
    ):
        raise ReadinessError("Readiness base URL is invalid.")
    return value.rstrip("/")


def fetch_health(base_url: str, path: str) -> dict[str, object]:
    request = Request(
        base_url + path,
        headers={
            "Accept": "application/json",
            "User-Agent": "rdc-production-readiness/1",
        },
        method="GET",
    )
    try:
        with build_opener(RejectRedirects).open(request, timeout=5) as response:
            body = response.read(MAX_RESPONSE_BYTES + 1)
    except (HTTPError, URLError, OSError, TimeoutError) as exc:
        raise ReadinessError("Readiness endpoint is unavailable.") from exc
    if len(body) > MAX_RESPONSE_BYTES:
        raise ReadinessError("Readiness response is too large.")
    try:
        decoded = json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ReadinessError("Readiness response is invalid.") from exc
    if not isinstance(decoded, dict):
        raise ReadinessError("Readiness response is invalid.")
    return {str(key): value for key, value in decoded.items()}


def probe(base_url: str, mode: str) -> None:
    live = fetch_health(base_url, "/health/live")
    if live.get("service") != "rdc-api" or live.get("status") != "ok":
        raise ReadinessError("API liveness contract failed.")
    if mode in {"recovery", "all"}:
        recovery = fetch_health(base_url, "/health/recovery")
        if (
            recovery.get("service") != "rdc-execution-recovery"
            or recovery.get("status") != "ready"
        ):
            raise ReadinessError("Execution recovery contract failed.")
    if mode == "all":
        ready = fetch_health(base_url, "/health/ready")
        if ready.get("service") != "rdc-api" or ready.get("status") != "ready":
            raise ReadinessError("API readiness contract failed.")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--mode", choices=("live", "recovery", "all"), default="all")
    parser.add_argument("--attempts", type=int, default=1)
    parser.add_argument("--interval-seconds", type=float, default=1.0)
    parser.add_argument("--allow-loopback-http", action="store_true")
    arguments = parser.parse_args()
    if not 1 <= arguments.attempts <= 60:
        raise SystemExit("Attempts must be between 1 and 60.")
    if not 0.1 <= arguments.interval_seconds <= 5.0:
        raise SystemExit("Probe interval must be between 0.1 and 5 seconds.")
    try:
        base_url = validate_base_url(
            arguments.base_url,
            allow_loopback_http=arguments.allow_loopback_http,
        )
        for attempt in range(arguments.attempts):
            try:
                probe(base_url, arguments.mode)
                print(
                    json.dumps(
                        {
                            "schema_version": "rdc.production-readiness/v1",
                            "mode": arguments.mode,
                            "status": "ready",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                )
                return
            except ReadinessError:
                if attempt + 1 == arguments.attempts:
                    raise
                time.sleep(arguments.interval_seconds)
    except ReadinessError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
