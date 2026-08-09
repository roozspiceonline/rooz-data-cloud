from __future__ import annotations

import importlib
import json
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.execution_schemas import WorkerHeartbeatRequest

API_ROOT = Path(__file__).parents[1]
REPO_ROOT = API_ROOT.parents[1]
WORKER_ROOT = REPO_ROOT / "workers/sandbox-runtime"


def test_worker_loss_migration_persists_recovery_evidence_and_rls_fence() -> None:
    migration = (
        API_ROOT
        / "migrations/versions/20260809_0020_worker_loss_recovery.py"
    ).read_text()
    for marker in (
        "last_lost_at",
        "last_recovered_at",
        "last_cleanup_at",
        "cleanup_generation",
        "ix_worker_identities_loss_detection",
        "last_workers_lost",
        "total_worker_leases_fenced",
        "worker.last_recovered_at >= worker.last_lost_at",
    ):
        assert marker in migration


def test_loss_detection_fences_leases_and_records_bounded_diagnostics() -> None:
    sweeper = (
        API_ROOT / "app/services/execution_recovery_sweeper.py"
    ).read_text()
    service = (API_ROOT / "app/services/execution_plane.py").read_text()
    for marker in (
        "detect_lost_workers",
        "FOR UPDATE SKIP LOCKED",
        "WORKER_LOST",
        "worker.lost",
        "worker_leases_fenced",
        "recovery_pending_workers",
    ):
        assert marker in sweeper
    for marker in (
        "WORKER_RECOVERY_REQUIRED",
        "worker.recovered",
        "cleanup_generation",
        "execution.lease.worker_lost",
    ):
        assert marker in service


def test_worker_recovery_report_is_strict_and_server_bounded() -> None:
    report = {
        "schema_version": "rdc.worker-recovery/v1",
        "startup_id": "0fb7d9f6-2257-4eed-a6fd-44f6e08f36c3",
        "forced_cleanup_completed": True,
        "managed_containers_removed": 2,
        "workspace_directories_removed": 3,
    }
    parsed = WorkerHeartbeatRequest(
        software_version="test",
        active_lease_count=0,
        recovery=report,
    )
    assert parsed.recovery is not None
    assert parsed.recovery.managed_containers_removed == 2
    with pytest.raises(ValidationError):
        WorkerHeartbeatRequest(
            software_version="test",
            active_lease_count=0,
            recovery={**report, "managed_containers_removed": 257},
        )
    with pytest.raises(ValidationError):
        WorkerHeartbeatRequest(
            software_version="test",
            active_lease_count=0,
            recovery={**report, "forced_cleanup_completed": False},
        )
    with pytest.raises(ValidationError):
        WorkerHeartbeatRequest(
            software_version="test",
            active_lease_count=0,
            metadata={"recovery_startup_id": report["startup_id"]},
        )


def test_worker_heartbeat_protocol_schema_is_strict_and_versioned() -> None:
    schema = json.loads(
        (
            REPO_ROOT
            / "packages/agent-protocol/schemas/worker-heartbeat.schema.json"
        ).read_text()
    )
    assert schema["additionalProperties"] is False
    recovery = schema["properties"]["recovery"]["anyOf"][0]
    assert recovery["additionalProperties"] is False
    assert recovery["properties"]["schema_version"]["const"] == (
        "rdc.worker-recovery/v1"
    )
    assert recovery["properties"]["forced_cleanup_completed"]["const"] is True
    assert "status" not in schema["required"]
    forbidden_metadata = schema["properties"]["metadata"]["propertyNames"][
        "not"
    ]["enum"]
    assert "recovery_startup_id" in forbidden_metadata


def test_worker_loss_configuration_is_validated_and_wired() -> None:
    with pytest.raises(ValidationError):
        Settings(worker_lost_after_seconds=14)
    with pytest.raises(ValidationError):
        Settings(worker_lost_after_seconds=301)
    for path in (".env.example", "docker-compose.yml", ".github/workflows/ci.yml"):
        assert "RDC_WORKER_LOST_AFTER_SECONDS" in (
            REPO_ROOT / path
        ).read_text()


def _worker_recovery_module() -> object:
    sys.path.insert(0, str(WORKER_ROOT))
    try:
        sys.modules.pop("worker_recovery", None)
        return importlib.import_module("worker_recovery")
    finally:
        sys.path.remove(str(WORKER_ROOT))


def test_startup_cleanup_is_label_scoped_validated_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    module = _worker_recovery_module()
    (tmp_path / "run-abandoned").mkdir()
    (tmp_path / "build-abandoned").mkdir()
    (tmp_path / "unmanaged").mkdir()
    calls: list[list[str]] = []

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        output = "rdc-run-a1\nrdc-browser-b2\n" if "ps" in argv else ""
        return subprocess.CompletedProcess(argv, 0, stdout=output)

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    config = SimpleNamespace(
        containerd_address="/run/user/1000/containerd/containerd.sock",
        namespace="rdc-sandbox",
        workspace_root=tmp_path,
    )
    report = module.force_startup_cleanup(config)
    assert report.managed_containers_removed == 2
    assert report.workspace_directories_removed == 2
    assert (tmp_path / "unmanaged").is_dir()
    assert not (tmp_path / "run-abandoned").exists()
    assert not (tmp_path / "build-abandoned").exists()
    assert "label=io.rooz.rdc.managed=true" in calls[0]
    assert [call[-1] for call in calls[1:]] == [
        "rdc-run-a1",
        "rdc-browser-b2",
    ]


def test_startup_cleanup_rejects_unexpected_labeled_container(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _worker_recovery_module()

    def fake_run(argv: list[str], **_: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(argv, 0, stdout="customer-container\n")

    monkeypatch.setattr(module.subprocess, "run", fake_run)
    config = SimpleNamespace(
        containerd_address="/run/user/1000/containerd/containerd.sock",
        namespace="rdc-sandbox",
    )
    with pytest.raises(module.WorkerRecoveryError):
        module.cleanup_managed_containers(config)


def test_startup_cleanup_rejects_filesystem_root() -> None:
    module = _worker_recovery_module()
    with pytest.raises(module.WorkerRecoveryError):
        module.cleanup_managed_workspaces(Path("/"))


def test_worker_runtime_has_watchdog_labels_signal_and_final_cleanup() -> None:
    worker = (WORKER_ROOT / "worker.py").read_text()
    recovery = (WORKER_ROOT / "worker_recovery.py").read_text()
    run_executor = (WORKER_ROOT / "run_executor.py").read_text()
    browser_executor = (WORKER_ROOT / "browser_executor.py").read_text()
    for marker in (
        "LeaseWatchdog",
        "signal.SIGTERM",
        "raise WorkerShutdown",
        "force_startup_cleanup",
        "draining=True",
    ):
        assert marker in worker
    for marker in (
        "active_lease_count=1",
        "lease_renew_seconds",
        "cleanup_managed_containers",
    ):
        assert marker in recovery
    assert "MANAGED_LABEL" in run_executor
    assert "cancel_run(config=config, run_id=run_id)" in run_executor
    assert browser_executor.count("MANAGED_LABEL") >= 4


def test_lease_watchdog_renews_until_work_completes() -> None:
    module = _worker_recovery_module()
    heartbeat = threading.Event()

    class Client:
        def heartbeat(self, **_: object) -> dict[str, object]:
            heartbeat.set()
            return {}

        def renew(self, *_: object, **__: object) -> dict[str, object]:
            return {}

    config = SimpleNamespace(
        heartbeat_seconds=0.01,
        lease_renew_seconds=30,
        software_version="test",
    )
    with module.LeaseWatchdog(
        client=Client(),
        config=config,
        lease_id="lease",
        lease_token="token",
        sandbox={},
    ) as watchdog:
        assert heartbeat.wait(timeout=1)
        watchdog.mark_completed()


def test_lease_watchdog_fails_closed_and_forces_runtime_cleanup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _worker_recovery_module()
    attempted = threading.Event()
    cleanup = threading.Event()

    class Client:
        def heartbeat(self, **_: object) -> dict[str, object]:
            attempted.set()
            raise RuntimeError("control plane unavailable")

        def renew(self, *_: object, **__: object) -> dict[str, object]:
            raise AssertionError("renew must not follow a failed heartbeat")

    monkeypatch.setattr(
        module,
        "cleanup_managed_containers",
        lambda _config: cleanup.set() or 0,
    )
    config = SimpleNamespace(
        heartbeat_seconds=0.01,
        lease_renew_seconds=30,
        software_version="test",
    )
    with pytest.raises(module.WorkerRecoveryError), module.LeaseWatchdog(
        client=Client(),
        config=config,
        lease_id="lease",
        lease_token="token",
        sandbox={},
    ):
        assert attempted.wait(timeout=1)
    assert cleanup.is_set()
