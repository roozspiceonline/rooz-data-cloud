from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path


def _json_string_list(name: str, default: str = "[]") -> tuple[str, ...]:
    raw = os.environ.get(name, default)
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{name} must be a JSON string array.") from exc
    if not isinstance(value, list) or not all(
        isinstance(item, str) for item in value
    ):
        raise RuntimeError(f"{name} must be a JSON string array.")
    return tuple(item.strip() for item in value if item.strip())


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    normalized = raw.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise RuntimeError(f"{name} must be a boolean value.")


@dataclass(frozen=True)
class SandboxWorkerConfig:
    api_base_url: str
    worker_token: str
    software_version: str
    buildkit_address: str
    containerd_address: str
    namespace: str
    apparmor_profile: str
    seccomp_profile: Path
    workspace_root: Path
    approved_base_images: tuple[str, ...]
    poll_seconds: float
    heartbeat_seconds: float
    lease_renew_seconds: int
    web_egress_enabled: bool
    web_egress_allowed_hosts: tuple[str, ...]
    web_egress_max_requests: int
    web_egress_max_response_bytes: int
    web_egress_max_total_bytes: int
    web_egress_max_redirects: int
    web_egress_connect_timeout_seconds: int
    web_egress_request_timeout_seconds: int
    browser_enabled: bool
    browser_live_navigation_enabled: bool
    dataset_writes_enabled: bool
    key_value_store_enabled: bool
    browser_max_pages: int
    browser_max_actions: int
    browser_navigation_timeout_seconds: int
    browser_max_dom_bytes: int
    browser_max_screenshot_bytes: int
    browser_runtime_image_ref: str
    browser_seccomp_profile: Path
    browser_runtime_timeout_seconds: int

    @classmethod
    def from_env(cls) -> SandboxWorkerConfig:
        token = os.environ.get("RDC_WORKER_TOKEN", "").strip()
        if not token:
            raise RuntimeError("RDC_WORKER_TOKEN is required.")
        bases = tuple(
            value.strip()
            for value in os.environ.get(
                "RDC_SANDBOX_APPROVED_BASE_IMAGES",
                "python:3.12-slim,node:24-alpine",
            ).split(",")
            if value.strip()
        )
        browser_runtime_timeout_seconds = int(
            os.environ.get("RDC_BROWSER_RUNTIME_TIMEOUT_SECONDS", "20")
        )
        if not 1 <= browser_runtime_timeout_seconds <= 30:
            raise RuntimeError(
                "RDC_BROWSER_RUNTIME_TIMEOUT_SECONDS must be between 1 and 30."
            )
        heartbeat_seconds = float(
            os.environ.get("RDC_WORKER_HEARTBEAT_SECONDS", "10")
        )
        if not 5 <= heartbeat_seconds <= 30:
            raise RuntimeError(
                "RDC_WORKER_HEARTBEAT_SECONDS must be between 5 and 30."
            )
        lease_renew_seconds = int(
            os.environ.get("RDC_WORKER_LEASE_RENEW_SECONDS", "30")
        )
        if not 15 <= lease_renew_seconds <= 300:
            raise RuntimeError(
                "RDC_WORKER_LEASE_RENEW_SECONDS must be between 15 and 300."
            )
        return cls(
            api_base_url=os.environ.get(
                "RDC_INTERNAL_API_BASE_URL", "http://127.0.0.1:8000"
            ).rstrip("/"),
            worker_token=token,
            software_version=os.environ.get(
                "RDC_WORKER_SOFTWARE_VERSION", "phase1j-0.1"
            ),
            buildkit_address=os.environ.get(
                "RDC_BUILDKIT_ADDRESS",
                "unix:///run/user/1000/buildkit/buildkitd.sock",
            ),
            containerd_address=os.environ.get(
                "RDC_CONTAINERD_ADDRESS",
                "/run/user/1000/containerd/containerd.sock",
            ),
            namespace=os.environ.get(
                "RDC_CONTAINERD_NAMESPACE", "rdc-sandbox"
            ),
            apparmor_profile=os.environ.get(
                "RDC_APPARMOR_PROFILE", "rdc-agent-default"
            ),
            seccomp_profile=Path(
                os.environ.get(
                    "RDC_SECCOMP_PROFILE",
                    "infrastructure/sandbox/seccomp-rdc-default.json",
                )
            ).resolve(),
            workspace_root=Path(
                os.environ.get(
                    "RDC_SANDBOX_WORKSPACE_ROOT", "/tmp/rdc-sandbox"
                )
            ).resolve(),
            approved_base_images=bases,
            poll_seconds=float(
                os.environ.get("RDC_WORKER_POLL_SECONDS", "2")
            ),
            heartbeat_seconds=heartbeat_seconds,
            lease_renew_seconds=lease_renew_seconds,
            web_egress_enabled=_env_bool(
                "RDC_SANDBOX_CANARY_WEB_EGRESS_ENABLED",
                False,
            ),
            web_egress_allowed_hosts=_json_string_list(
                "RDC_SANDBOX_CANARY_WEB_EGRESS_ALLOWED_HOSTS"
            ),
            web_egress_max_requests=int(
                os.environ.get(
                    "RDC_SANDBOX_CANARY_WEB_EGRESS_MAX_REQUESTS",
                    "8",
                )
            ),
            web_egress_max_response_bytes=int(
                os.environ.get(
                    "RDC_SANDBOX_CANARY_WEB_EGRESS_MAX_RESPONSE_BYTES",
                    "1048576",
                )
            ),
            web_egress_max_total_bytes=int(
                os.environ.get(
                    "RDC_SANDBOX_CANARY_WEB_EGRESS_MAX_TOTAL_BYTES",
                    "4194304",
                )
            ),
            web_egress_max_redirects=int(
                os.environ.get(
                    "RDC_SANDBOX_CANARY_WEB_EGRESS_MAX_REDIRECTS",
                    "3",
                )
            ),
            web_egress_connect_timeout_seconds=int(
                os.environ.get(
                    "RDC_SANDBOX_CANARY_WEB_EGRESS_CONNECT_TIMEOUT_SECONDS",
                    "5",
                )
            ),
            web_egress_request_timeout_seconds=int(
                os.environ.get(
                    "RDC_SANDBOX_CANARY_WEB_EGRESS_REQUEST_TIMEOUT_SECONDS",
                    "15",
                )
            ),
            browser_enabled=_env_bool(
                "RDC_SANDBOX_CANARY_BROWSER_ENABLED",
                False,
            ),
            browser_live_navigation_enabled=_env_bool(
                "RDC_SANDBOX_CANARY_BROWSER_LIVE_NAVIGATION_ENABLED",
                False,
            ),
            dataset_writes_enabled=_env_bool(
                "RDC_SANDBOX_CANARY_DATASET_WRITES_ENABLED",
                False,
            ),
            key_value_store_enabled=_env_bool(
                "RDC_SANDBOX_CANARY_KEY_VALUE_STORE_ENABLED",
                False,
            ),
            browser_max_pages=int(os.environ.get("RDC_SANDBOX_CANARY_BROWSER_MAX_PAGES", "1")),
            browser_max_actions=int(os.environ.get("RDC_SANDBOX_CANARY_BROWSER_MAX_ACTIONS", "8")),
            browser_navigation_timeout_seconds=int(
                os.environ.get("RDC_SANDBOX_CANARY_BROWSER_NAVIGATION_TIMEOUT_SECONDS", "15")
            ),
            browser_max_dom_bytes=int(
                os.environ.get("RDC_SANDBOX_CANARY_BROWSER_MAX_DOM_BYTES", "2097152")
            ),
            browser_max_screenshot_bytes=int(
                os.environ.get("RDC_SANDBOX_CANARY_BROWSER_MAX_SCREENSHOT_BYTES", "2097152")
            ),
            browser_runtime_image_ref=os.environ.get(
                "RDC_SANDBOX_BROWSER_RUNTIME_IMAGE_REF",
                "",
            ).strip(),
            browser_seccomp_profile=Path(
                os.environ.get(
                    "RDC_BROWSER_SECCOMP_PROFILE",
                    "infrastructure/sandbox/seccomp-rdc-browser.json",
                )
            ).resolve(),
            browser_runtime_timeout_seconds=browser_runtime_timeout_seconds,
        )
