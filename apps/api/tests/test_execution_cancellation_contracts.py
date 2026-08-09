from __future__ import annotations

from pathlib import Path

API_ROOT = Path(__file__).parents[1]
REPO_ROOT = API_ROOT.parents[1]


def test_cancellation_migration_persists_immutable_deadline() -> None:
    source = (
        API_ROOT
        / "migrations/versions/20260809_0017_run_cancellation_convergence.py"
    ).read_text()
    for required in (
        '"cancel_deadline_at"',
        "cancel_deadline_at > cancel_requested_at",
        "run_cancellation_immutable",
        "Run cancellation deadline is immutable",
        "ix_runs_cancellation_deadline",
    ):
        assert required in source


def test_cancel_dispatch_is_locked_and_single_row_idempotent() -> None:
    source = (API_ROOT / "app/services/runs.py").read_text()
    for required in (
        "_ensure_cancel_command",
        ".execution_options(populate_existing=True)",
        ".with_for_update()",
        "worker_cancel_convergence_seconds",
        '"cancel_deadline_at"',
    ):
        assert required in source


def test_execution_plane_converges_and_fences_cancelled_runs() -> None:
    source = (API_ROOT / "app/services/execution_plane.py").read_text()
    for required in (
        "_fence_cancelled_run_leases",
        "_converge_cancelled_run",
        "reap_overdue_cancellations",
        '"RUN_CANCELLED"',
        '"run.cancellation_converged"',
        '"RUN_CANCELLATION_PENDING"',
        'reason="LATE_RUN_START_COMPLETION"',
    ):
        assert required in source


def test_cancellation_intent_removes_worker_api_and_rls_authority() -> None:
    dependency = (API_ROOT / "app/api/internal_dependencies.py").read_text()
    migration = (
        API_ROOT
        / "migrations/versions/20260809_0017_run_cancellation_convergence.py"
    ).read_text()
    assert "lease.work_kind == \"RUN_START\"" in dependency
    assert "Run.cancel_requested_at" in dependency
    assert "run.cancel_requested_at IS NULL" in migration


def test_cancellation_configuration_is_bounded_and_wired() -> None:
    config = (API_ROOT / "app/core/config.py").read_text()
    assert "worker_cancel_convergence_seconds" in config
    assert "30 <= self.worker_cancel_convergence_seconds <= 3600" in config
    for path in (".env.example", "docker-compose.yml", ".github/workflows/ci.yml"):
        assert "RDC_WORKER_CANCEL_CONVERGENCE_SECONDS" in (
            REPO_ROOT / path
        ).read_text()
