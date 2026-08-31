from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import select, text
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
        evidence=None,
        transport_failure=payload.evidence.transport_failure,
        http_status=payload.evidence.http_status,
        response_bytes=payload.evidence.response_bytes,
        latency_ms=payload.evidence.latency_ms,
        challenge_detected=payload.evidence.challenge_detected,
        login_required=payload.evidence.login_required,
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
    rows = await _egress_health_aggregate_rows(
        session,
        project_id=project_id,
        window_start=window_start,
        window_end=window_end,
    )
    total = sum(row[3] for row in rows)
    healthy = sum(row[4] for row in rows)
    retryable = sum(row[5] for row in rows)
    outcomes: dict[str, int] = {}
    for _, _, outcome, outcome_total, _, _ in rows:
        outcomes[outcome] = outcomes.get(outcome, 0) + outcome_total
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
        "outcomes": dict(sorted(outcomes.items())),
    }


async def summarize_egress_health_routes(
    session: AsyncSession,
    *,
    project_id: UUID,
    window_hours: int,
) -> dict[str, object]:
    window_end = datetime.now(UTC)
    window_start = window_end - timedelta(hours=window_hours)
    aggregate_rows = await _egress_health_aggregate_rows(
        session,
        project_id=project_id,
        window_start=window_start,
        window_end=window_end,
    )
    route_totals: dict[tuple[str, str], list[int]] = {}
    route_outcomes: dict[tuple[str, str], dict[str, int]] = {}
    for provider_key, region_key, outcome, total, healthy, retryable in aggregate_rows:
        pair = (provider_key, region_key)
        counts = route_totals.setdefault(pair, [0, 0, 0])
        counts[0] += total
        counts[1] += healthy
        counts[2] += retryable
        route_outcomes.setdefault(pair, {})[outcome] = total
    if len(route_totals) > MAX_ROUTE_DIMENSIONS:
        raise ApiError(
            status_code=503,
            code="EGRESS_HEALTH_ROUTE_CARDINALITY_EXCEEDED",
            message="Route health aggregation is temporarily unavailable.",
        )

    routes: list[dict[str, object]] = []
    for (provider_key, region_key), counts in sorted(route_totals.items()):
        total, healthy, retryable = counts
        if total < settings.egress_health_min_route_samples:
            continue
        routes.append(
            {
                "provider_key": str(provider_key),
                "region_key": str(region_key),
                "total": total,
                "healthy": healthy,
                "unhealthy": total - healthy,
                "retryable": retryable,
                "healthy_basis_points": healthy * 10_000 // total,
                "outcomes": dict(
                    sorted(route_outcomes[(provider_key, region_key)].items())
                ),
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


async def _egress_health_aggregate_rows(
    session: AsyncSession,
    *,
    project_id: UUID,
    window_start: datetime,
    window_end: datetime,
) -> list[tuple[str, str, str, int, int, int]]:
    rows = (
        await session.execute(
            text(
                """
                WITH rollup AS (
                  SELECT provider_key,region_key,outcome,
                         total_count,healthy_count,retryable_count
                  FROM control.egress_health_rollup_buckets
                  WHERE project_id=:project_id
                    AND bucket_start>=date_trunc(
                      'hour',CAST(:window_start AS timestamptz)
                    )+interval '1 hour'
                    AND bucket_start+interval '1 hour'<=:window_end
                ), raw AS (
                  SELECT observation.provider_key,observation.region_key,
                         observation.outcome,count(*) AS total_count,
                         count(*) FILTER (WHERE observation.healthy) AS healthy_count,
                         count(*) FILTER (WHERE observation.retryable) AS retryable_count
                  FROM control.egress_health_observations observation
                  WHERE observation.project_id=:project_id
                    AND observation.observed_at>=:window_start
                    AND observation.observed_at<:window_end
                    AND NOT EXISTS (
                      SELECT 1 FROM control.egress_health_rollup_buckets bucket
                      WHERE bucket.project_id=observation.project_id
                        AND bucket.bucket_start=date_trunc('hour',observation.observed_at)
                        AND bucket.bucket_start>=date_trunc(
                          'hour',CAST(:window_start AS timestamptz)
                        )+interval '1 hour'
                        AND bucket.bucket_start+interval '1 hour'<=:window_end
                    )
                  GROUP BY observation.provider_key,observation.region_key,
                           observation.outcome
                ), combined AS (
                  SELECT * FROM rollup UNION ALL SELECT * FROM raw
                )
                SELECT provider_key,region_key,outcome,sum(total_count),
                       sum(healthy_count),sum(retryable_count)
                FROM combined GROUP BY provider_key,region_key,outcome
                ORDER BY provider_key,region_key,outcome
                """
            ),
            {
                "project_id": project_id,
                "window_start": window_start,
                "window_end": window_end,
            },
        )
    ).all()
    return [
        (
            str(row.provider_key),
            str(row.region_key),
            str(row.outcome),
            int(row[3]),
            int(row[4]),
            int(row[5]),
        )
        for row in rows
    ]
