from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select, tuple_
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.errors import ApiError
from ..core.security import canonical_fingerprint
from ..egress_health_protocol import (
    EgressHealthObservationRequest,
    EgressHealthObservationResult,
    classify_egress_health,
)
from ..models import EgressHealthObservation, ExecutionLease, WorkerIdentity
from .identity_tenancy import append_audit_event

settings = get_settings()
MAX_ROUTE_DIMENSIONS = 32


def _validate_reporting_context(
    lease: ExecutionLease,
    worker: WorkerIdentity,
) -> None:
    activation = lease.payload_snapshot.get("activation")
    enabled = (
        isinstance(activation, dict)
        and activation.get("capability_profile")
        in {"brokered-web-egress", "controlled-browser"}
        and isinstance(activation.get("egress_policy_digest"), str)
    )
    if (
        lease.work_kind != "RUN_START"
        or lease.run_id is None
        or "EVENT_INGEST" not in worker.capabilities
        or not enabled
    ):
        raise ApiError(
            status_code=403,
            code="EGRESS_HEALTH_REPORT_DENIED",
            message="The lease cannot report egress health observations.",
        )


async def record_egress_health_observation(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: EgressHealthObservationRequest,
    request_id: str,
) -> EgressHealthObservationResult:
    _validate_reporting_context(lease, worker)
    evidence = payload.evidence.model_dump(mode="json", exclude_none=True)
    evidence_digest = canonical_fingerprint(evidence)
    existing = await session.scalar(
        select(EgressHealthObservation).where(
            EgressHealthObservation.lease_id == lease.id,
            EgressHealthObservation.client_observation_id
            == payload.observation_id,
        )
    )
    if existing is not None:
        if existing.evidence_digest != evidence_digest:
            raise ApiError(
                status_code=409,
                code="EGRESS_HEALTH_REPLAY_CONFLICT",
                message="The observation ID was already used with different evidence.",
            )
        return _result(existing, replayed=True)

    classified = classify_egress_health(payload.evidence)
    assert lease.run_id is not None
    record = EgressHealthObservation(
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        run_id=lease.run_id,
        lease_id=lease.id,
        worker_id=worker.id,
        client_observation_id=payload.observation_id,
        evidence=evidence,
        evidence_digest=evidence_digest,
        outcome=classified.outcome,
        healthy=classified.healthy,
        retryable=classified.retryable,
        provider_key=settings.egress_route_provider_key,
        region_key=settings.egress_route_region_key,
        observed_at=datetime.now(UTC),
    )
    session.add(record)
    await session.flush()
    await append_audit_event(
        session,
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        actor_type="worker",
        actor_id=str(worker.id),
        action="egress_health.observed",
        resource_type="egress_health_observation",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "run_id": str(lease.run_id),
            "lease_id": str(lease.id),
            "outcome": classified.outcome,
            "healthy": classified.healthy,
            "retryable": classified.retryable,
        },
    )
    await session.commit()
    return _result(record, replayed=False)


def _result(
    record: EgressHealthObservation,
    *,
    replayed: bool,
) -> EgressHealthObservationResult:
    return EgressHealthObservationResult(
        id=record.id,
        observation_id=record.client_observation_id,
        outcome=record.outcome,
        healthy=record.healthy,
        retryable=record.retryable,
        provider_key=record.provider_key,
        region_key=record.region_key,
        replayed=replayed,
        observed_at=record.observed_at,
    )


async def summarize_egress_health(
    session: AsyncSession,
    *,
    project_id: UUID,
    window_hours: int,
) -> dict[str, object]:
    window_end = datetime.now(UTC)
    window_start = window_end - timedelta(hours=window_hours)
    totals = (
        await session.execute(
            select(
                func.count(EgressHealthObservation.id),
                func.count(EgressHealthObservation.id).filter(
                    EgressHealthObservation.healthy.is_(True)
                ),
                func.count(EgressHealthObservation.id).filter(
                    EgressHealthObservation.retryable.is_(True)
                ),
            ).where(
                EgressHealthObservation.project_id == project_id,
                EgressHealthObservation.observed_at >= window_start,
                EgressHealthObservation.observed_at < window_end,
            )
        )
    ).one()
    rows = (
        await session.execute(
            select(
                EgressHealthObservation.outcome,
                func.count(EgressHealthObservation.id),
            )
            .where(
                EgressHealthObservation.project_id == project_id,
                EgressHealthObservation.observed_at >= window_start,
                EgressHealthObservation.observed_at < window_end,
            )
            .group_by(EgressHealthObservation.outcome)
            .order_by(EgressHealthObservation.outcome)
        )
    ).all()
    total, healthy, retryable = (int(value or 0) for value in totals)
    return {
        "window": {
            "hours": window_hours,
            "starts_at": window_start.isoformat(),
            "ends_at": window_end.isoformat(),
        },
        "total": total,
        "healthy": healthy,
        "unhealthy": total - healthy,
        "retryable": retryable,
        "outcomes": {outcome: int(count) for outcome, count in rows},
    }


async def summarize_egress_health_routes(
    session: AsyncSession,
    *,
    project_id: UUID,
    window_hours: int,
) -> dict[str, object]:
    window_end = datetime.now(UTC)
    window_start = window_end - timedelta(hours=window_hours)
    route_rows = (
        await session.execute(
            select(
                EgressHealthObservation.provider_key,
                EgressHealthObservation.region_key,
                func.count(EgressHealthObservation.id),
                func.count(EgressHealthObservation.id).filter(
                    EgressHealthObservation.healthy.is_(True)
                ),
                func.count(EgressHealthObservation.id).filter(
                    EgressHealthObservation.retryable.is_(True)
                ),
            )
            .where(
                EgressHealthObservation.project_id == project_id,
                EgressHealthObservation.observed_at >= window_start,
                EgressHealthObservation.observed_at < window_end,
            )
            .group_by(
                EgressHealthObservation.provider_key,
                EgressHealthObservation.region_key,
            )
            .order_by(
                EgressHealthObservation.provider_key,
                EgressHealthObservation.region_key,
            )
            .limit(MAX_ROUTE_DIMENSIONS + 1)
        )
    ).all()
    if len(route_rows) > MAX_ROUTE_DIMENSIONS:
        raise ApiError(
            status_code=503,
            code="EGRESS_HEALTH_ROUTE_CARDINALITY_EXCEEDED",
            message="Route health aggregation is temporarily unavailable.",
        )

    released = [
        row
        for row in route_rows
        if int(row[2]) >= settings.egress_health_min_route_samples
    ]
    route_pairs = [(str(row[0]), str(row[1])) for row in released]
    outcomes: dict[tuple[str, str], dict[str, int]] = {
        pair: {} for pair in route_pairs
    }
    if route_pairs:
        outcome_rows = (
            await session.execute(
                select(
                    EgressHealthObservation.provider_key,
                    EgressHealthObservation.region_key,
                    EgressHealthObservation.outcome,
                    func.count(EgressHealthObservation.id),
                )
                .where(
                    EgressHealthObservation.project_id == project_id,
                    EgressHealthObservation.observed_at >= window_start,
                    EgressHealthObservation.observed_at < window_end,
                    tuple_(
                        EgressHealthObservation.provider_key,
                        EgressHealthObservation.region_key,
                    ).in_(route_pairs),
                )
                .group_by(
                    EgressHealthObservation.provider_key,
                    EgressHealthObservation.region_key,
                    EgressHealthObservation.outcome,
                )
                .order_by(
                    EgressHealthObservation.provider_key,
                    EgressHealthObservation.region_key,
                    EgressHealthObservation.outcome,
                )
            )
        ).all()
        for provider_key, region_key, outcome, count in outcome_rows:
            outcomes[(str(provider_key), str(region_key))][str(outcome)] = int(
                count
            )

    routes: list[dict[str, object]] = []
    for provider_key, region_key, total_value, healthy_value, retryable_value in released:
        total = int(total_value)
        healthy = int(healthy_value)
        routes.append(
            {
                "provider_key": str(provider_key),
                "region_key": str(region_key),
                "total": total,
                "healthy": healthy,
                "unhealthy": total - healthy,
                "retryable": int(retryable_value),
                "healthy_basis_points": healthy * 10_000 // total,
                "outcomes": outcomes[(str(provider_key), str(region_key))],
            }
        )
    return {
        "window": {
            "hours": window_hours,
            "starts_at": window_start.isoformat(),
            "ends_at": window_end.isoformat(),
        },
        "minimum_samples": settings.egress_health_min_route_samples,
        "routes": routes,
    }
