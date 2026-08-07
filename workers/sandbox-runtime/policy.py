from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from pathlib import Path

from config import SandboxWorkerConfig


class SandboxPolicyError(RuntimeError):
    pass


@dataclass(frozen=True)
class SandboxProbe:
    attestation: dict[str, object]


def _require_binary(name: str) -> str:
    value = shutil.which(name)
    if value is None:
        raise SandboxPolicyError(f"Required sandbox binary is missing: {name}")
    return value


def verify_host(config: SandboxWorkerConfig) -> SandboxProbe:
    if os.geteuid() == 0:
        raise SandboxPolicyError("The sandbox worker must run as a non-root user.")
    if Path("/var/run/docker.sock").exists() or Path("/run/docker.sock").exists():
        raise SandboxPolicyError("A host Docker socket is visible to the worker.")
    if not config.buildkit_address.startswith("unix:///run/user/"):
        raise SandboxPolicyError("BuildKit must use a rootless per-user Unix socket.")
    if not str(config.containerd_address).startswith("/run/user/"):
        raise SandboxPolicyError("containerd must use a rootless per-user Unix socket.")
    if not config.seccomp_profile.is_file():
        raise SandboxPolicyError("The RDC seccomp profile is missing.")
    _require_binary("buildctl")
    _require_binary("nerdctl")
    _require_binary("trivy")
    config.workspace_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(config.workspace_root, 0o700)
    attestation: dict[str, object] = {
        "schema_version": "rdc.sandbox/v1",
        "runtime": "containerd-rootless",
        "builder": "buildkit-rootless",
        "rootless": True,
        "no_host_docker_socket": True,
        "no_new_privileges": True,
        "read_only_rootfs": True,
        "drop_all_capabilities": True,
        "seccomp_profile": "rdc-default",
        "apparmor_profile": config.apparmor_profile,
        "network_policy": "deny-all",
        "max_memory_mb": 4096,
        "max_cpu_millis": 4000,
        "max_pids": 512,
        "max_ephemeral_disk_mb": 8192,
        "max_build_seconds": 900,
        "max_run_seconds": 600,
    }
    encoded = json.dumps(attestation, sort_keys=True, separators=(",", ":")).encode()
    hashlib.sha256(encoded).hexdigest()
    return SandboxProbe(attestation=attestation)
