from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ...core.config import get_settings
from ...core.database import check_database, session_factory
from ...core.redis_client import check_redis
from ...services.execution_recovery_sweeper import (
    execution_recovery_is_fresh,
    read_execution_admission_health,
    read_execution_recovery_health,
)

router = APIRouter(tags=["health"])
settings = get_settings()


@router.get("/health/live")
async def liveness() -> dict[str, str]:
    return {"service": "rdc-api", "status": "ok", "timestamp": datetime.now(UTC).isoformat()}


async def dependency_status() -> dict[str, str]:
    results: dict[str, str] = {}
    try:
        await check_database()
        results["postgres"] = "ready"
    except Exception:
        results["postgres"] = "unavailable"
    try:
        await check_redis()
        results["redis"] = "ready"
    except Exception:
        results["redis"] = "unavailable"
    if settings.execution_recovery_sweep_enabled:
        try:
            async with session_factory() as session:
                recovery = await read_execution_recovery_health(session)
            results["execution_recovery"] = (
                "ready"
                if execution_recovery_is_fresh(
                    recovery,
                    now=datetime.now(UTC),
                    stale_after_seconds=(
                        settings.execution_recovery_stale_after_seconds
                    ),
                )
                else "stale"
            )
        except Exception:
            results["execution_recovery"] = "unavailable"
    return results


@router.get("/health/recovery")
async def recovery_health() -> JSONResponse:
    if not settings.execution_recovery_sweep_enabled:
        return JSONResponse(
            status_code=200,
            content={"service": "rdc-execution-recovery", "status": "disabled"},
        )
    try:
        async with session_factory() as session:
            health = await read_execution_recovery_health(session)
            admission = await read_execution_admission_health(session)
        fresh = execution_recovery_is_fresh(
            health,
            now=datetime.now(UTC),
            stale_after_seconds=settings.execution_recovery_stale_after_seconds,
        )
        reported_status = (
            "ready"
            if fresh
            else "stale"
            if health.status == "HEALTHY"
            else health.status.lower()
        )
        body: dict[str, Any] = {
            "service": "rdc-execution-recovery",
            "status": reported_status,
            "last_started_at": (
                health.last_started_at.isoformat()
                if health.last_started_at is not None
                else None
            ),
            "last_completed_at": (
                health.last_completed_at.isoformat()
                if health.last_completed_at is not None
                else None
            ),
            "last_heartbeat_at": (
                health.last_heartbeat_at.isoformat()
                if health.last_heartbeat_at is not None
                else None
            ),
            "last_leases_reaped": health.last_leases_reaped,
            "last_cancellations_converged": (
                health.last_cancellations_converged
            ),
            "last_workers_lost": health.last_workers_lost,
            "last_worker_leases_fenced": (
                health.last_worker_leases_fenced
            ),
            "total_sweeps": health.total_sweeps,
            "total_failures": health.total_failures,
            "total_workers_lost": health.total_workers_lost,
            "total_worker_leases_fenced": (
                health.total_worker_leases_fenced
            ),
            "last_error_code": health.last_error_code,
            "active_execution_leases": admission.active_leases,
            "saturated_projects": admission.saturated_projects,
            "saturated_workers": admission.saturated_workers,
            "recovery_pending_workers": (
                admission.recovery_pending_workers
            ),
        }
        return JSONResponse(status_code=200 if fresh else 503, content=body)
    except Exception:
        return JSONResponse(
            status_code=503,
            content={
                "service": "rdc-execution-recovery",
                "status": "unavailable",
            },
        )


@router.get("/health/ready")
async def readiness() -> JSONResponse:
    dependencies = await dependency_status()
    ready = all(value == "ready" for value in dependencies.values())
    body: dict[str, Any] = {
        "dependencies": dependencies,
        "service": "rdc-api",
        "status": "ready" if ready else "degraded",
    }
    return JSONResponse(status_code=200 if ready else 503, content=body)
