from __future__ import annotations

import re
import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, Self
from uuid import uuid4

from config import SandboxWorkerConfig
from io_utils import cleanup_tree

MANAGED_LABEL = "io.rooz.rdc.managed=true"
MANAGED_NAME = re.compile(r"^rdc-(?:run|browser)-[A-Za-z0-9]{1,32}$")
WORKSPACE_PREFIXES = ("build-", "run-")
MAX_CLEANUP_TARGETS = 256


class WorkerRecoveryError(RuntimeError):
    pass


class RecoveryClient(Protocol):
    def heartbeat(
        self,
        *,
        software_version: str,
        active_lease_count: int,
        draining: bool = False,
        sandbox: dict[str, object] | None = None,
        recovery: dict[str, object] | None = None,
    ) -> dict[str, object]: ...

    def renew(
        self,
        lease_id: str,
        lease_token: str,
        *,
        extend_seconds: int = 60,
    ) -> dict[str, object]: ...


@dataclass(frozen=True)
class CleanupReport:
    startup_id: str
    managed_containers_removed: int
    workspace_directories_removed: int

    def as_protocol(self) -> dict[str, object]:
        return {
            "schema_version": "rdc.worker-recovery/v1",
            "startup_id": self.startup_id,
            "forced_cleanup_completed": True,
            "managed_containers_removed": self.managed_containers_removed,
            "workspace_directories_removed": (
                self.workspace_directories_removed
            ),
        }


def _nerdctl(config: SandboxWorkerConfig, *arguments: str) -> list[str]:
    return [
        "nerdctl",
        "--address",
        config.containerd_address,
        "--namespace",
        config.namespace,
        *arguments,
    ]


def cleanup_managed_containers(config: SandboxWorkerConfig) -> int:
    try:
        listed = subprocess.run(
            _nerdctl(
                config,
                "ps",
                "-a",
                "--filter",
                f"label={MANAGED_LABEL}",
                "--format",
                "{{.Names}}",
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise WorkerRecoveryError(
            "Managed container discovery failed."
        ) from exc
    if listed.returncode != 0:
        raise WorkerRecoveryError("Managed container discovery failed.")
    names = [line.strip() for line in listed.stdout.splitlines() if line.strip()]
    if len(names) > MAX_CLEANUP_TARGETS:
        raise WorkerRecoveryError("Managed container cleanup is unbounded.")
    if len(set(names)) != len(names) or any(
        MANAGED_NAME.fullmatch(name) is None for name in names
    ):
        raise WorkerRecoveryError("Managed container identity is invalid.")
    for name in names:
        try:
            removed = subprocess.run(
                _nerdctl(config, "rm", "--force", name),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=10,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise WorkerRecoveryError(
                "Managed container cleanup failed."
            ) from exc
        if removed.returncode != 0:
            raise WorkerRecoveryError("Managed container cleanup failed.")
    return len(names)


def cleanup_managed_workspaces(root: Path) -> int:
    if root == Path(root.anchor) or root.is_symlink():
        raise WorkerRecoveryError("Managed workspace root is invalid.")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    candidates = [
        path
        for path in root.iterdir()
        if path.name.startswith(WORKSPACE_PREFIXES)
    ]
    if len(candidates) > MAX_CLEANUP_TARGETS:
        raise WorkerRecoveryError("Managed workspace cleanup is unbounded.")
    if any(not path.is_dir() or path.is_symlink() for path in candidates):
        raise WorkerRecoveryError("Managed workspace identity is invalid.")
    for path in candidates:
        cleanup_tree(path)
        if path.exists():
            raise WorkerRecoveryError("Managed workspace cleanup failed.")
    return len(candidates)


def force_startup_cleanup(config: SandboxWorkerConfig) -> CleanupReport:
    containers = cleanup_managed_containers(config)
    workspaces = cleanup_managed_workspaces(config.workspace_root)
    return CleanupReport(
        startup_id=str(uuid4()),
        managed_containers_removed=containers,
        workspace_directories_removed=workspaces,
    )


class LeaseWatchdog:
    def __init__(
        self,
        *,
        client: RecoveryClient,
        config: SandboxWorkerConfig,
        lease_id: str,
        lease_token: str,
        sandbox: dict[str, object],
    ) -> None:
        self._client = client
        self._config = config
        self._lease_id = lease_id
        self._lease_token = lease_token
        self._sandbox = sandbox
        self._stop = threading.Event()
        self._completed = threading.Event()
        self._failed = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name="rdc-lease-watchdog",
            daemon=True,
        )

    def _run(self) -> None:
        while not self._stop.wait(self._config.heartbeat_seconds):
            try:
                self._client.heartbeat(
                    software_version=self._config.software_version,
                    active_lease_count=1,
                    sandbox=self._sandbox,
                )
                self._client.renew(
                    self._lease_id,
                    self._lease_token,
                    extend_seconds=self._config.lease_renew_seconds,
                )
            except (OSError, RuntimeError):
                if self._completed.is_set():
                    return
                self._failed.set()
                try:
                    cleanup_managed_containers(self._config)
                except WorkerRecoveryError:
                    pass
                return

    def __enter__(self) -> Self:
        self._thread.start()
        return self

    def mark_completed(self) -> None:
        self._completed.set()

    def __exit__(self, *_: object) -> None:
        self._stop.set()
        self._thread.join(timeout=self._config.heartbeat_seconds + 1)
        if self._thread.is_alive():
            raise WorkerRecoveryError("Lease watchdog did not stop.")
        if self._failed.is_set():
            raise WorkerRecoveryError("Lease heartbeat or renewal failed.")
