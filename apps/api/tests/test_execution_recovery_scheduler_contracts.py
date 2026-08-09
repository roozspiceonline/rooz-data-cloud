from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import Settings
from app.services.execution_recovery_sweeper import (
    ExecutionRecoveryHealth,
    execution_recovery_is_fresh,
)

API_ROOT = Path(__file__).parents[1]
REPO_ROOT = API_ROOT.parents[1]


def test_scheduler_is_a_dedicated_compose_process() -> None:
    compose = (REPO_ROOT / "docker-compose.yml").read_text()
    scheduler = (API_ROOT / "app/recovery_scheduler.py").read_text()
    for required in (
        "execution-recovery:",
        'command: ["python", "-m", "app.recovery_scheduler"]',
        'app.recovery_scheduler", "--healthcheck"',
    ):
        assert required in compose
    for required in (
        "run_sweep_loop",
        "record_execution_recovery_failure",
        "execution_recovery_sweep_interval_seconds",
        "asyncio.wait_for(stop.wait()",
    ):
        assert required in scheduler


def test_scheduler_uses_transaction_singleton_lock_and_bounded_batches() -> None:
    service = (
        API_ROOT / "app/services/execution_recovery_sweeper.py"
    ).read_text()
    plane = (API_ROOT / "app/services/execution_plane.py").read_text()
    assert "pg_try_advisory_xact_lock" in service
    assert "RECOVERY_LOCK_SCOPE" in service
    assert "1 <= batch_size <= 500" in service
    assert ".limit(batch_size)" in plane
    assert ".with_for_update(skip_locked=True)" in plane


def test_scheduler_migration_has_singleton_health_and_counters() -> None:
    migration = (
        API_ROOT
        / "migrations/versions/20260809_0018_execution_recovery_sweeps.py"
    ).read_text()
    for required in (
        "execution_recovery_state",
        "ck_execution_recovery_state_singleton",
        "last_heartbeat_at",
        "last_leases_reaped",
        "last_cancellations_converged",
        "total_sweeps",
        "total_failures",
        "NEVER_RUN",
    ):
        assert required in migration


def test_scheduler_configuration_is_bounded() -> None:
    with pytest.raises(ValidationError):
        Settings(execution_recovery_sweep_interval_seconds=0)
    with pytest.raises(ValidationError):
        Settings(execution_recovery_sweep_batch_size=501)
    with pytest.raises(ValidationError):
        Settings(
            execution_recovery_sweep_interval_seconds=30,
            execution_recovery_stale_after_seconds=59,
        )


def test_recovery_health_requires_recent_success() -> None:
    now = datetime.now(UTC)
    healthy = ExecutionRecoveryHealth(
        status="HEALTHY",
        last_started_at=now,
        last_completed_at=now,
        last_heartbeat_at=now,
        last_leases_reaped=2,
        last_cancellations_converged=1,
        last_workers_lost=0,
        last_worker_leases_fenced=0,
        total_sweeps=4,
        total_failures=0,
        total_workers_lost=0,
        total_worker_leases_fenced=0,
        last_error_code=None,
    )
    assert execution_recovery_is_fresh(
        healthy,
        now=now,
        stale_after_seconds=60,
    )
    stale = ExecutionRecoveryHealth(
        **{
            **healthy.__dict__,
            "last_heartbeat_at": now - timedelta(seconds=61),
        }
    )
    assert not execution_recovery_is_fresh(
        stale,
        now=now,
        stale_after_seconds=60,
    )
    failed = ExecutionRecoveryHealth(
        **{**healthy.__dict__, "status": "FAILED", "last_error_code": "Failure"}
    )
    assert not execution_recovery_is_fresh(
        failed,
        now=now,
        stale_after_seconds=60,
    )
