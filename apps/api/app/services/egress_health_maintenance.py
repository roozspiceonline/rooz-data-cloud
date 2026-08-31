from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .identity_tenancy import append_audit_event


@dataclass(frozen=True)
class EgressHealthMaintenanceResult:
    acquired: bool
    buckets_rolled: int = 0
    raw_rows_purged: int = 0
    rollup_rows_purged: int = 0


@dataclass(frozen=True)
class EgressHealthMaintenanceHealth:
    status: str
    last_started_at: datetime | None
    last_completed_at: datetime | None
    last_heartbeat_at: datetime | None
    last_buckets_rolled: int
    last_raw_rows_purged: int
    last_rollup_rows_purged: int
    total_sweeps: int
    total_failures: int
    total_buckets_rolled: int
    total_raw_rows_purged: int
    total_rollup_rows_purged: int
    last_error_code: str | None


async def run_egress_health_maintenance(
    session: AsyncSession,
    *,
    now: datetime,
    owner_id: str,
    rollup_batch_size: int,
    purge_batch_size: int,
    raw_retention_hours: int,
    rollup_retention_days: int,
    request_id: str,
) -> EgressHealthMaintenanceResult:
    row = (
        await session.execute(
            text(
                """
                SELECT acquired,buckets_rolled,raw_rows_purged,rollup_rows_purged
                FROM control.run_egress_health_maintenance(
                  :now,:rollup_batch_size,:purge_batch_size,
                  :raw_retention_hours,:rollup_retention_days,:owner_id
                )
                """
            ),
            {
                "now": now,
                "owner_id": owner_id,
                "rollup_batch_size": rollup_batch_size,
                "purge_batch_size": purge_batch_size,
                "raw_retention_hours": raw_retention_hours,
                "rollup_retention_days": rollup_retention_days,
            },
        )
    ).one()
    result = EgressHealthMaintenanceResult(
        acquired=bool(row.acquired),
        buckets_rolled=int(row.buckets_rolled),
        raw_rows_purged=int(row.raw_rows_purged),
        rollup_rows_purged=int(row.rollup_rows_purged),
    )
    if result.acquired and (
        result.buckets_rolled
        or result.raw_rows_purged
        or result.rollup_rows_purged
    ):
        await append_audit_event(
            session,
            organization_id=None,
            project_id=None,
            actor_type="system",
            actor_id="egress-health-maintenance",
            action="egress_health.maintenance_completed",
            resource_type="egress_health_retention",
            resource_id="singleton",
            request_id=request_id,
            details={
                "buckets_rolled": result.buckets_rolled,
                "raw_rows_purged": result.raw_rows_purged,
                "rollup_rows_purged": result.rollup_rows_purged,
                "rollup_batch_size": rollup_batch_size,
                "purge_batch_size": purge_batch_size,
                "raw_retention_hours": raw_retention_hours,
                "rollup_retention_days": rollup_retention_days,
            },
        )
    return result


async def record_egress_health_maintenance_failure(
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
            UPDATE control.egress_health_maintenance_state
            SET status='FAILED',owner_id=:owner_id,last_started_at=:failed_started_at,
                last_heartbeat_at=:now,total_failures=total_failures+1,
                last_error_code=:error_code,
                last_error_summary='The egress health maintenance sweep failed.',
                updated_at=:now
            WHERE id=1 AND (last_heartbeat_at IS NULL OR last_heartbeat_at<=:failed_started_at)
            RETURNING id
            """
        ),
        {
            "now": now,
            "failed_started_at": failed_started_at,
            "owner_id": owner_id[:200],
            "error_code": error_code[:80],
        },
    )
    if updated_state_id not in {None, 1}:
        raise RuntimeError("Egress health maintenance failure state is invalid.")


async def read_egress_health_maintenance_health(
    session: AsyncSession,
) -> EgressHealthMaintenanceHealth:
    row = (
        await session.execute(
            text(
                """
                SELECT status,last_started_at,last_completed_at,last_heartbeat_at,
                       last_buckets_rolled,last_raw_rows_purged,last_rollup_rows_purged,
                       total_sweeps,total_failures,total_buckets_rolled,
                       total_raw_rows_purged,total_rollup_rows_purged,last_error_code
                FROM control.egress_health_maintenance_state WHERE id=1
                """
            )
        )
    ).one()
    return EgressHealthMaintenanceHealth(
        status=str(row.status),
        last_started_at=row.last_started_at,
        last_completed_at=row.last_completed_at,
        last_heartbeat_at=row.last_heartbeat_at,
        last_buckets_rolled=int(row.last_buckets_rolled),
        last_raw_rows_purged=int(row.last_raw_rows_purged),
        last_rollup_rows_purged=int(row.last_rollup_rows_purged),
        total_sweeps=int(row.total_sweeps),
        total_failures=int(row.total_failures),
        total_buckets_rolled=int(row.total_buckets_rolled),
        total_raw_rows_purged=int(row.total_raw_rows_purged),
        total_rollup_rows_purged=int(row.total_rollup_rows_purged),
        last_error_code=(str(row.last_error_code) if row.last_error_code else None),
    )


def egress_health_maintenance_is_fresh(
    health: EgressHealthMaintenanceHealth,
    *,
    now: datetime,
    stale_after_seconds: int,
) -> bool:
    return (
        health.status == "HEALTHY"
        and health.last_completed_at is not None
        and health.last_completed_at >= now - timedelta(seconds=stale_after_seconds)
    )
