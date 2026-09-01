from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse, PlainTextResponse

from ...core.config import get_settings
from ...core.database import check_database, session_factory
from ...core.redis_client import check_redis
from ...services.execution_recovery_sweeper import (
    ExecutionAdmissionHealth,
    ExecutionRecoveryHealth,
    execution_recovery_is_fresh,
    read_execution_admission_health,
    read_execution_recovery_health,
)
from ...services.runtime_metrics import RuntimeMetrics, read_runtime_metrics

router = APIRouter(tags=["health"])
settings = get_settings()
PROMETHEUS_CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"


def recovery_metrics_payload(
    health: ExecutionRecoveryHealth,
    admission: ExecutionAdmissionHealth,
    *,
    now: datetime,
) -> str:
    fresh = execution_recovery_is_fresh(
        health,
        now=now,
        stale_after_seconds=settings.execution_recovery_stale_after_seconds,
    )
    heartbeat_timestamp = (
        health.last_heartbeat_at.timestamp()
        if health.last_heartbeat_at is not None
        else 0.0
    )
    values: tuple[tuple[str, int | float], ...] = (
        ("rdc_execution_recovery_enabled", 1),
        ("rdc_execution_recovery_healthy", int(fresh)),
        ("rdc_execution_recovery_last_heartbeat_timestamp_seconds", heartbeat_timestamp),
        ("rdc_execution_recovery_sweeps_total", health.total_sweeps),
        ("rdc_execution_recovery_failures_total", health.total_failures),
        ("rdc_execution_recovery_workers_lost_total", health.total_workers_lost),
        (
            "rdc_execution_recovery_worker_leases_fenced_total",
            health.total_worker_leases_fenced,
        ),
        ("rdc_execution_active_leases", admission.active_leases),
        ("rdc_execution_saturated_projects", admission.saturated_projects),
        ("rdc_execution_saturated_workers", admission.saturated_workers),
        (
            "rdc_execution_recovery_pending_workers",
            admission.recovery_pending_workers,
        ),
    )
    return "".join(f"{name} {value}\n" for name, value in values)


def runtime_metrics_payload(metrics: RuntimeMetrics) -> str:
    values = (
        ("rdc_runtime_metrics_healthy", 1),
        ("rdc_runtime_execution_active_leases", metrics.active_execution_leases),
        ("rdc_runtime_workers_active", metrics.active_workers),
        ("rdc_runtime_build_dispatch_ready", metrics.build_dispatch_ready),
        ("rdc_runtime_run_commands_ready", metrics.run_commands_ready),
        ("rdc_runtime_schedules_due", metrics.schedules_due),
        ("rdc_runtime_request_queue_ready", metrics.request_queue_ready),
        (
            "rdc_runtime_credential_canaries_ready",
            metrics.credential_canaries_ready,
        ),
        (
            "rdc_runtime_credential_canaries_claimed",
            metrics.credential_canaries_claimed,
        ),
        ("rdc_runtime_webhook_deliveries_ready", metrics.webhook_deliveries_ready),
        (
            "rdc_runtime_webhook_deliveries_claimed",
            metrics.webhook_deliveries_claimed,
        ),
    )
    return "".join(f"{name} {value}\n" for name, value in values)


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


@router.get("/metrics/recovery", include_in_schema=False)
async def recovery_metrics() -> PlainTextResponse:
    if not settings.execution_recovery_sweep_enabled:
        return PlainTextResponse(
            "rdc_execution_recovery_enabled 0\n"
            "rdc_execution_recovery_healthy 1\n",
            media_type=PROMETHEUS_CONTENT_TYPE,
        )
    try:
        async with session_factory() as session:
            health = await read_execution_recovery_health(session)
            admission = await read_execution_admission_health(session)
        now = datetime.now(UTC)
        payload = recovery_metrics_payload(health, admission, now=now)
        status_code = (
            200
            if execution_recovery_is_fresh(
                health,
                now=now,
                stale_after_seconds=(
                    settings.execution_recovery_stale_after_seconds
                ),
            )
            else 503
        )
        return PlainTextResponse(
            payload,
            status_code=status_code,
            media_type=PROMETHEUS_CONTENT_TYPE,
        )
    except Exception:
        return PlainTextResponse(
            "rdc_execution_recovery_enabled 1\n"
            "rdc_execution_recovery_healthy 0\n",
            status_code=503,
            media_type=PROMETHEUS_CONTENT_TYPE,
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


@router.get("/metrics/runtime", include_in_schema=False)
async def runtime_metrics() -> PlainTextResponse:
    try:
        async with session_factory() as session:
            metrics = await read_runtime_metrics(
                session,
                worker_fresh_after_seconds=settings.worker_lost_after_seconds,
            )
        return PlainTextResponse(
            runtime_metrics_payload(metrics),
            media_type=PROMETHEUS_CONTENT_TYPE,
        )
    except Exception:
        return PlainTextResponse(
            "rdc_runtime_metrics_healthy 0\n",
            status_code=503,
            media_type=PROMETHEUS_CONTENT_TYPE,
        )
