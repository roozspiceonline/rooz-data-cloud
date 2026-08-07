from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


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

    @classmethod
    def from_env(cls) -> "SandboxWorkerConfig":
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
        return cls(
            api_base_url=os.environ.get(
                "RDC_INTERNAL_API_BASE_URL", "http://127.0.0.1:8000"
            ).rstrip("/"),
            worker_token=token,
            software_version=os.environ.get("RDC_WORKER_SOFTWARE_VERSION", "phase1h-0.1"),
            buildkit_address=os.environ.get(
                "RDC_BUILDKIT_ADDRESS",
                "unix:///run/user/1000/buildkit/buildkitd.sock",
            ),
            containerd_address=os.environ.get(
                "RDC_CONTAINERD_ADDRESS",
                "/run/user/1000/containerd/containerd.sock",
            ),
            namespace=os.environ.get("RDC_CONTAINERD_NAMESPACE", "rdc-sandbox"),
            apparmor_profile=os.environ.get("RDC_APPARMOR_PROFILE", "rdc-agent-default"),
            seccomp_profile=Path(
                os.environ.get(
                    "RDC_SECCOMP_PROFILE",
                    "infrastructure/sandbox/seccomp-rdc-default.json",
                )
            ).resolve(),
            workspace_root=Path(
                os.environ.get("RDC_SANDBOX_WORKSPACE_ROOT", "/tmp/rdc-sandbox")
            ).resolve(),
            approved_base_images=bases,
            poll_seconds=float(os.environ.get("RDC_WORKER_POLL_SECONDS", "2")),
        )
