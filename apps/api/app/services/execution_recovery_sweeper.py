from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .execution_plane import reap_expired_leases, reap_overdue_cancellations
from .identity_tenancy import append_audit_event

RECOVERY_STATE_ID = 1
RECOVERY_LOCK_SCOPE = "rdc:execution-recovery-sweep:v1"


@dataclass(frozen=True)
class ExecutionRecoverySweepResult:
    acquired: bool
    leases_reaped: int = 0
    cancellations_converged: int = 0


@dataclass(frozen=True)
class ExecutionRecoveryHealth:
    status: str
    last_started_at: datetime | None
    last_completed_at: datetime | None
    last_heartbeat_at: datetime | None
    last_leases_reaped: int
    last_cancellations_converged: int
    total_sweeps: int
    total_failures: int
    last_error_code: str | None


async def run_execution_recovery_sweep(
    session: AsyncSession,
    *,
    now: datetime,
    owner_id: str,
    batch_size: int,
    request_id: str,
) -> ExecutionRecoverySweepResult:
    if not 1 <= batch_size <= 500:
        raise ValueError("Execution recovery batch size must be between 1 and 500.")
    acquired = bool(
        await session.scalar(
            text(
                "SELECT pg_try_advisory_xact_lock("
                "hashtextextended(:scope, 0))"
            ),
            {"scope": RECOVERY_LOCK_SCOPE},
        )
    )
    if not acquired:
        return ExecutionRecoverySweepResult(acquired=False)

    leases_reaped = await reap_expired_leases(
        session,
        now=now,
        request_id=request_id,
        batch_size=batch_size,
        reap_cancellations=False,
    )
    cancellations_converged = await reap_overdue_cancellations(
        session,
        now=now,
        request_id=request_id,
        batch_size=batch_size,
    )
    updated_state_id = await session.scalar(
        text(
            """
            UPDATE control.execution_recovery_state
            SET status = 'HEALTHY',
                owner_id = :owner_id,
                last_started_at = :now,
                last_completed_at = :now,
                last_heartbeat_at = :now,
                last_leases_reaped = :leases_reaped,
                last_cancellations_converged = :cancellations_converged,
                total_sweeps = total_sweeps + 1,
                last_error_code = NULL,
                last_error_summary = NULL,
                updated_at = :now
            WHERE id = :state_id
            RETURNING id
            """
        ),
        {
            "state_id": RECOVERY_STATE_ID,
            "owner_id": owner_id[:200],
            "now": now,
            "leases_reaped": leases_reaped,
            "cancellations_converged": cancellations_converged,
        },
    )
    if updated_state_id != RECOVERY_STATE_ID:
        raise RuntimeError("Execution recovery state is not initialized.")
    if leases_reaped or cancellations_converged:
        await append_audit_event(
            session,
            organization_id=None,
            project_id=None,
            actor_type="system",
            actor_id="execution-recovery-sweeper",
            action="execution.recovery.sweep_completed",
            resource_type="execution_recovery",
            resource_id="singleton",
            request_id=request_id,
            details={
                "leases_reaped": leases_reaped,
                "cancellations_converged": cancellations_converged,
                "batch_size": batch_size,
            },
        )
    return ExecutionRecoverySweepResult(
        acquired=True,
        leases_reaped=leases_reaped,
        cancellations_converged=cancellations_converged,
    )


async def record_execution_recovery_failure(
    session: AsyncSession,
    *,
    now: datetime,
    failed_started_at: datetime,
    owner_id: str,
    error_code: str,
) -> None:
    updated_state_id = await session.scalar(
        text(
            """
            UPDATE control.execution_recovery_state
            SET status = 'FAILED',
                owner_id = :owner_id,
                last_started_at = :failed_started_at,
                last_heartbeat_at = :now,
                total_failures = total_failures + 1,
                last_error_code = :error_code,
                last_error_summary = 'The execution recovery sweep failed.',
                updated_at = :now
            WHERE id = :state_id
              AND (
                last_heartbeat_at IS NULL
                OR last_heartbeat_at <= :failed_started_at
              )
            RETURNING id
            """
        ),
        {
            "state_id": RECOVERY_STATE_ID,
            "owner_id": owner_id[:200],
            "now": now,
            "failed_started_at": failed_started_at,
            "error_code": error_code[:80],
        },
    )
    if updated_state_id not in {None, RECOVERY_STATE_ID}:
        raise RuntimeError("Execution recovery failure state is invalid.")


async def read_execution_recovery_health(
    session: AsyncSession,
) -> ExecutionRecoveryHealth:
    row = (
        await session.execute(
            text(
                """
                SELECT status,
                       last_started_at,
                       last_completed_at,
                       last_heartbeat_at,
                       last_leases_reaped,
                       last_cancellations_converged,
                       total_sweeps,
                       total_failures,
                       last_error_code
                FROM control.execution_recovery_state
                WHERE id = :state_id
                """
            ),
            {"state_id": RECOVERY_STATE_ID},
        )
    ).one_or_none()
    if row is None:
        raise RuntimeError("Execution recovery state is not initialized.")
    return ExecutionRecoveryHealth(
        status=str(row.status),
        last_started_at=row.last_started_at,
        last_completed_at=row.last_completed_at,
        last_heartbeat_at=row.last_heartbeat_at,
        last_leases_reaped=int(row.last_leases_reaped),
        last_cancellations_converged=int(row.last_cancellations_converged),
        total_sweeps=int(row.total_sweeps),
        total_failures=int(row.total_failures),
        last_error_code=row.last_error_code,
    )


def execution_recovery_is_fresh(
    health: ExecutionRecoveryHealth,
    *,
    now: datetime,
    stale_after_seconds: int,
) -> bool:
    return (
        health.status == "HEALTHY"
        and health.last_heartbeat_at is not None
        and health.last_heartbeat_at
        >= now - timedelta(seconds=stale_after_seconds)
    )
