from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from .execution_plane import reap_expired_leases, reap_overdue_cancellations
from .identity_tenancy import append_audit_event

RECOVERY_STATE_ID = 1
RECOVERY_LOCK_SCOPE = "rdc:execution-recovery-sweep:v1"


@dataclass(frozen=True)
class ExecutionRecoverySweepResult:
    acquired: bool
    leases_reaped: int = 0
    cancellations_converged: int = 0
    workers_lost: int = 0
    worker_leases_fenced: int = 0


@dataclass(frozen=True)
class ExecutionRecoveryHealth:
    status: str
    last_started_at: datetime | None
    last_completed_at: datetime | None
    last_heartbeat_at: datetime | None
    last_leases_reaped: int
    last_cancellations_converged: int
    last_workers_lost: int
    last_worker_leases_fenced: int
    total_sweeps: int
    total_failures: int
    total_workers_lost: int
    total_worker_leases_fenced: int
    last_error_code: str | None


@dataclass(frozen=True)
class ExecutionAdmissionHealth:
    active_leases: int
    saturated_projects: int
    saturated_workers: int
    recovery_pending_workers: int


@dataclass(frozen=True)
class WorkerLossResult:
    workers_lost: int = 0
    leases_fenced: int = 0


async def detect_lost_workers(
    session: AsyncSession,
    *,
    now: datetime,
    lost_after_seconds: int,
    batch_size: int,
    request_id: str,
) -> WorkerLossResult:
    if not 15 <= lost_after_seconds <= 300:
        raise ValueError("Worker loss detection must be between 15 and 300 seconds.")
    if not 1 <= batch_size <= 500:
        raise ValueError("Worker loss batch size must be between 1 and 500.")
    worker_batch_size = max(1, batch_size // 16)
    rows = (
        await session.execute(
            text(
                """
                SELECT worker.id
                FROM security.worker_identities worker
                WHERE worker.status = 'ACTIVE'
                  AND worker.revoked_at IS NULL
                  AND worker.last_seen_at IS NOT NULL
                  AND worker.last_seen_at <= :lost_before
                  AND (
                    worker.last_lost_at IS NULL
                    OR worker.last_recovered_at >= worker.last_lost_at
                  )
                  AND EXISTS (
                    SELECT 1
                    FROM control.execution_leases lease
                    WHERE lease.worker_id = worker.id
                      AND lease.status = 'ACTIVE'
                      AND lease.expires_at > :now
                      AND lease.deadline_at > :now
                  )
                ORDER BY worker.last_seen_at, worker.id
                FOR UPDATE SKIP LOCKED
                LIMIT :worker_batch_size
                """
            ),
            {
                "now": now,
                "lost_before": now - timedelta(seconds=lost_after_seconds),
                "worker_batch_size": worker_batch_size,
            },
        )
    ).all()
    leases_fenced = 0
    for row in rows:
        await session.execute(
            text(
                """
                UPDATE security.worker_identities
                SET last_lost_at = :now,
                    sandbox_execution_enabled = false
                WHERE id = :worker_id
                """
            ),
            {"now": now, "worker_id": row.id},
        )
        result = await session.execute(
            text(
                """
                UPDATE control.execution_leases
                SET expires_at = LEAST(expires_at, :now),
                    failure_code = 'WORKER_LOST',
                    failure_summary = 'The execution worker heartbeat was lost.',
                    updated_at = :now
                WHERE worker_id = :worker_id
                  AND status = 'ACTIVE'
                  AND expires_at > :now
                  AND deadline_at > :now
                RETURNING id
                """
            ),
            {"now": now, "worker_id": row.id},
        )
        worker_leases = len(result.all())
        leases_fenced += worker_leases
        await append_audit_event(
            session,
            organization_id=None,
            project_id=None,
            actor_type="system",
            actor_id="worker-loss-detector",
            action="worker.lost",
            resource_type="worker",
            resource_id=str(row.id),
            request_id=request_id,
            details={
                "leases_fenced": worker_leases,
                "lost_after_seconds": lost_after_seconds,
            },
        )
    return WorkerLossResult(
        workers_lost=len(rows),
        leases_fenced=leases_fenced,
    )


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

    settings = get_settings()
    worker_loss = await detect_lost_workers(
        session,
        now=now,
        lost_after_seconds=settings.worker_lost_after_seconds,
        batch_size=batch_size,
        request_id=request_id,
    )
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
                last_workers_lost = :workers_lost,
                last_worker_leases_fenced = :worker_leases_fenced,
                total_sweeps = total_sweeps + 1,
                total_workers_lost = (
                  total_workers_lost + :total_workers_lost_increment
                ),
                total_worker_leases_fenced = (
                  total_worker_leases_fenced
                  + :total_worker_leases_fenced_increment
                ),
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
            "workers_lost": worker_loss.workers_lost,
            "worker_leases_fenced": worker_loss.leases_fenced,
            "total_workers_lost_increment": worker_loss.workers_lost,
            "total_worker_leases_fenced_increment": (
                worker_loss.leases_fenced
            ),
        },
    )
    if updated_state_id != RECOVERY_STATE_ID:
        raise RuntimeError("Execution recovery state is not initialized.")
    if (
        leases_reaped
        or cancellations_converged
        or worker_loss.workers_lost
    ):
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
                "workers_lost": worker_loss.workers_lost,
                "worker_leases_fenced": worker_loss.leases_fenced,
                "batch_size": batch_size,
            },
        )
    return ExecutionRecoverySweepResult(
        acquired=True,
        leases_reaped=leases_reaped,
        cancellations_converged=cancellations_converged,
        workers_lost=worker_loss.workers_lost,
        worker_leases_fenced=worker_loss.leases_fenced,
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
                       last_workers_lost,
                       last_worker_leases_fenced,
                       total_sweeps,
                       total_failures,
                       total_workers_lost,
                       total_worker_leases_fenced,
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
        last_workers_lost=int(row.last_workers_lost),
        last_worker_leases_fenced=int(row.last_worker_leases_fenced),
        total_sweeps=int(row.total_sweeps),
        total_failures=int(row.total_failures),
        total_workers_lost=int(row.total_workers_lost),
        total_worker_leases_fenced=int(row.total_worker_leases_fenced),
        last_error_code=row.last_error_code,
    )


async def read_execution_admission_health(
    session: AsyncSession,
) -> ExecutionAdmissionHealth:
    row = (
        await session.execute(
            text(
                """
                SELECT
                  (
                    SELECT count(*)
                    FROM control.execution_leases lease
                    WHERE lease.status = 'ACTIVE'
                      AND lease.expires_at > CURRENT_TIMESTAMP
                      AND lease.deadline_at > CURRENT_TIMESTAMP
                  ) AS active_leases,
                  (
                    SELECT count(*)
                    FROM control.projects project
                    WHERE project.status = 'ACTIVE'
                      AND project.deleted_at IS NULL
                      AND (
                        SELECT count(*)
                        FROM control.execution_leases lease
                        WHERE lease.project_id = project.id
                          AND lease.status = 'ACTIVE'
                          AND lease.work_kind IN ('BUILD', 'RUN_START')
                          AND lease.expires_at > CURRENT_TIMESTAMP
                          AND lease.deadline_at > CURRENT_TIMESTAMP
                      ) >= project.max_active_leases
                  ) AS saturated_projects,
                  (
                    SELECT count(*)
                    FROM security.worker_identities worker
                    WHERE worker.status = 'ACTIVE'
                      AND worker.revoked_at IS NULL
                      AND (
                        SELECT count(*)
                        FROM control.execution_leases lease
                        WHERE lease.worker_id = worker.id
                          AND lease.status = 'ACTIVE'
                          AND lease.expires_at > CURRENT_TIMESTAMP
                          AND lease.deadline_at > CURRENT_TIMESTAMP
                      ) >= worker.max_concurrency
                  ) AS saturated_workers,
                  (
                    SELECT count(*)
                    FROM security.worker_identities worker
                    WHERE worker.last_lost_at IS NOT NULL
                      AND (
                        worker.last_recovered_at IS NULL
                        OR worker.last_recovered_at < worker.last_lost_at
                      )
                  ) AS recovery_pending_workers
                """
            )
        )
    ).one()
    return ExecutionAdmissionHealth(
        active_leases=int(row.active_leases),
        saturated_projects=int(row.saturated_projects),
        saturated_workers=int(row.saturated_workers),
        recovery_pending_workers=int(row.recovery_pending_workers),
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
