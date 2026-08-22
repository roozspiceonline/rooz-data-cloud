from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from pydantic import ValidationError
from sqlalchemy import and_, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import set_tenant_context
from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..core.security import canonical_fingerprint
from ..models import (
    AgentVersion,
    Build,
    IdempotencyRecord,
    Schedule,
    ScheduleTrigger,
)
from ..run_schemas import CreateRunRequest
from ..schedule_schemas import CreateScheduleRequest, ScheduleSummary
from .builds_secrets import acquire_idempotency_lock, validate_idempotency_key
from .identity_tenancy import append_audit_event
from .runs import create_run

SCHEDULE_DISPATCH_LOCK_SCOPE = "rdc:schedule-dispatch:v1"


@dataclass(frozen=True)
class ScheduleDispatchResult:
    acquired: bool
    examined: int = 0
    fired: int = 0
    skipped: int = 0
    failed: int = 0


def schedule_summary(record: Schedule) -> dict[str, object]:
    return ScheduleSummary.model_validate(record).model_dump(mode="json")


async def list_schedules(
    session: AsyncSession,
    *,
    project_id: UUID,
    status: str | None,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[Schedule], bool]:
    statement = select(Schedule).where(Schedule.project_id == project_id)
    if status is not None:
        statement = statement.where(Schedule.status == status)
    if cursor is not None:
        statement = statement.where(
            or_(
                Schedule.created_at < cursor.created_at,
                and_(
                    Schedule.created_at == cursor.created_at,
                    Schedule.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(Schedule.created_at.desc(), Schedule.id.desc()).limit(
                    limit + 1
                )
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def list_schedule_triggers(
    session: AsyncSession,
    *,
    schedule_id: UUID,
    outcome: str | None,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[ScheduleTrigger], bool]:
    statement = select(ScheduleTrigger).where(
        ScheduleTrigger.schedule_id == schedule_id
    )
    if outcome is not None:
        statement = statement.where(ScheduleTrigger.outcome == outcome)
    if cursor is not None:
        statement = statement.where(
            or_(
                ScheduleTrigger.created_at < cursor.created_at,
                and_(
                    ScheduleTrigger.created_at == cursor.created_at,
                    ScheduleTrigger.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    ScheduleTrigger.created_at.desc(), ScheduleTrigger.id.desc()
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def create_schedule(
    session: AsyncSession,
    *,
    version: AgentVersion,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    idempotency_key: str,
    request_id: str,
    payload: CreateScheduleRequest,
) -> dict[str, object]:
    validate_idempotency_key(idempotency_key)
    build = await session.scalar(
        select(Build).where(
            Build.id == payload.run.build_id,
            Build.organization_id == version.organization_id,
            Build.project_id == version.project_id,
            Build.agent_id == version.agent_id,
            Build.agent_version_id == version.id,
        )
    )
    if build is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    if build.status != "SUCCEEDED" or build.artifact_digest is None:
        raise ApiError(
            status_code=409,
            code="BUILD_NOT_READY",
            message="A successful Build artifact is required before scheduling Runs.",
        )

    endpoint = "POST:/api/v1/agent-versions/{version_id}/schedules"
    key_digest = hashlib.sha256(idempotency_key.encode()).hexdigest()
    fingerprint = canonical_fingerprint(
        {
            "agent_version_id": str(version.id),
            "schedule": payload.model_dump(mode="json"),
        }
    )
    await acquire_idempotency_lock(
        session,
        organization_id=version.organization_id,
        principal_id=str(user_id),
        endpoint=endpoint,
        key_digest=key_digest,
    )
    existing = await session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.organization_id == version.organization_id,
            IdempotencyRecord.principal_id == str(user_id),
            IdempotencyRecord.endpoint == endpoint,
            IdempotencyRecord.key_digest == key_digest,
        )
    )
    if existing is not None:
        if existing.request_fingerprint != fingerprint:
            raise ApiError(
                status_code=409,
                code="IDEMPOTENCY_CONFLICT",
                message="This idempotency key was used for a different request.",
            )
        if existing.response_snapshot is None:
            raise ApiError(
                status_code=409,
                code="RESOURCE_CONFLICT",
                message="The original idempotent result is unavailable.",
            )
        return dict(existing.response_snapshot)

    duplicate = await session.scalar(
        select(Schedule.id).where(
            Schedule.project_id == version.project_id,
            Schedule.name == payload.name,
        )
    )
    if duplicate is not None:
        raise ApiError(
            status_code=409,
            code="SCHEDULE_ALREADY_EXISTS",
            message="A schedule with that name already exists in the project.",
        )

    now = datetime.now(UTC)
    record = Schedule(
        id=uuid4(),
        organization_id=version.organization_id,
        project_id=version.project_id,
        agent_id=version.agent_id,
        agent_version_id=version.id,
        build_id=build.id,
        name=payload.name,
        status="ACTIVE",
        cadence_kind=payload.cadence_kind,
        starts_at=payload.starts_at.astimezone(UTC),
        interval_seconds=payload.interval_seconds,
        missed_run_policy=payload.missed_run_policy,
        misfire_grace_seconds=payload.misfire_grace_seconds,
        run_payload=payload.run.model_dump(mode="json"),
        next_fire_at=payload.starts_at.astimezone(UTC),
        last_triggered_at=None,
        fired_count=0,
        skipped_count=0,
        failed_count=0,
        created_by_user_id=user_id,
        created_at=now,
        updated_at=now,
        version=1,
    )
    session.add(record)
    await session.flush()
    snapshot = schedule_summary(record)
    session.add(
        IdempotencyRecord(
            organization_id=record.organization_id,
            principal_id=str(user_id),
            endpoint=endpoint,
            key_digest=key_digest,
            request_fingerprint=fingerprint,
            resource_type="schedule",
            resource_id=str(record.id),
            response_status=201,
            response_snapshot=snapshot,
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
    )
    await append_audit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="schedule.created",
        resource_type="schedule",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "agent_version_id": str(record.agent_version_id),
            "build_id": str(record.build_id),
            "cadence_kind": record.cadence_kind,
            "missed_run_policy": record.missed_run_policy,
        },
    )
    return snapshot


async def set_schedule_paused(
    session: AsyncSession,
    *,
    schedule_id: UUID,
    paused: bool,
    actor_type: str,
    actor_id: str,
    request_id: str,
) -> Schedule:
    record = await session.scalar(
        select(Schedule).where(Schedule.id == schedule_id).with_for_update()
    )
    if record is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    if record.status == "COMPLETED":
        raise ApiError(
            status_code=409,
            code="SCHEDULE_COMPLETED",
            message="A completed one-time schedule cannot be resumed or paused.",
        )
    target = "PAUSED" if paused else "ACTIVE"
    if record.status == target:
        return record
    record.status = target
    record.updated_at = datetime.now(UTC)
    record.version += 1
    await append_audit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="schedule.paused" if paused else "schedule.resumed",
        resource_type="schedule",
        resource_id=str(record.id),
        request_id=request_id,
        details={"version": record.version},
    )
    return record


def _advance_schedule(record: Schedule, *, scheduled_for: datetime, now: datetime) -> None:
    if record.cadence_kind == "ONCE":
        record.status = "COMPLETED"
        record.next_fire_at = None
        return
    if record.interval_seconds is None:
        raise RuntimeError("Recurring schedule is missing its interval")
    elapsed = max(0.0, (now - scheduled_for).total_seconds())
    jumps = int(elapsed // record.interval_seconds) + 1
    record.next_fire_at = scheduled_for + timedelta(
        seconds=jumps * record.interval_seconds
    )


async def dispatch_due_schedules(
    session: AsyncSession,
    *,
    now: datetime,
    batch_size: int,
    request_id: str,
) -> ScheduleDispatchResult:
    if not 1 <= batch_size <= 500:
        raise ValueError("Schedule dispatch batch size must be between 1 and 500.")
    await session.execute(
        text("SELECT set_config('rdc.schedule_dispatcher', '1', true)")
    )
    acquired = bool(
        await session.scalar(
            text(
                "SELECT pg_try_advisory_xact_lock("
                "hashtextextended(:scope, 0))"
            ),
            {"scope": SCHEDULE_DISPATCH_LOCK_SCOPE},
        )
    )
    if not acquired:
        return ScheduleDispatchResult(acquired=False)

    rows = list(
        (
            await session.scalars(
                select(Schedule)
                .where(
                    Schedule.status == "ACTIVE",
                    Schedule.next_fire_at.is_not(None),
                    Schedule.next_fire_at <= now,
                )
                .order_by(Schedule.next_fire_at, Schedule.id)
                .with_for_update(skip_locked=True)
                .limit(batch_size)
            )
        ).all()
    )
    fired = skipped = failed = 0
    for record in rows:
        scheduled_for = record.next_fire_at
        if scheduled_for is None:
            continue
        await set_tenant_context(
            session,
            user_id=record.created_by_user_id,
            organization_id=record.organization_id,
        )
        existing = await session.scalar(
            select(ScheduleTrigger.id).where(
                ScheduleTrigger.schedule_id == record.id,
                ScheduleTrigger.scheduled_for == scheduled_for,
            )
        )
        _advance_schedule(record, scheduled_for=scheduled_for, now=now)
        record.last_triggered_at = now
        record.updated_at = now
        record.version += 1
        if existing is not None:
            continue

        missed = scheduled_for < now - timedelta(
            seconds=record.misfire_grace_seconds
        )
        if missed and record.missed_run_policy == "SKIP":
            outcome, reason, error_code, run_id = (
                "SKIPPED",
                "MISSED_WINDOW",
                None,
                None,
            )
            record.skipped_count += 1
            skipped += 1
        else:
            try:
                version = await session.scalar(
                    select(AgentVersion).where(
                        AgentVersion.id == record.agent_version_id,
                        AgentVersion.organization_id == record.organization_id,
                    )
                )
                if version is None:
                    raise ApiError(
                        status_code=409,
                        code="SCHEDULE_VERSION_UNAVAILABLE",
                        message="The immutable Agent version is unavailable.",
                    )
                run_snapshot = await create_run(
                    session,
                    version=version,
                    user_id=record.created_by_user_id,
                    idempotency_key=(
                        f"schedule:{record.id}:{scheduled_for.isoformat()}"
                    ),
                    payload=CreateRunRequest.model_validate(record.run_payload),
                    request_id=request_id,
                    actor_type="system",
                    actor_id="schedule-dispatcher",
                )
            except (ApiError, ValidationError) as exc:
                code = (
                    exc.code
                    if isinstance(exc, ApiError)
                    else "SCHEDULE_RUN_PAYLOAD_INVALID"
                )
                outcome, reason, error_code, run_id = (
                    "FAILED",
                    "RUN_CREATION_REJECTED",
                    code,
                    None,
                )
                record.failed_count += 1
                failed += 1
            else:
                outcome = "FIRED"
                reason = "MISSED_FIRE_ONCE" if missed else "DUE"
                error_code = None
                run_id = UUID(str(run_snapshot["id"]))
                record.fired_count += 1
                fired += 1

        trigger = ScheduleTrigger(
            organization_id=record.organization_id,
            project_id=record.project_id,
            schedule_id=record.id,
            run_id=run_id,
            scheduled_for=scheduled_for,
            observed_at=now,
            outcome=outcome,
            reason=reason,
            error_code=error_code,
            created_at=now,
        )
        session.add(trigger)
        await session.flush()
        await append_audit_event(
            session,
            organization_id=record.organization_id,
            project_id=record.project_id,
            actor_type="system",
            actor_id="schedule-dispatcher",
            action=f"schedule.trigger_{outcome.casefold()}",
            resource_type="schedule_trigger",
            resource_id=str(trigger.id),
            request_id=request_id,
            details={
                "schedule_id": str(record.id),
                "scheduled_for": scheduled_for.isoformat(),
                "run_id": str(run_id) if run_id is not None else None,
                "reason": reason,
                "error_code": error_code,
            },
        )
    return ScheduleDispatchResult(
        acquired=True,
        examined=len(rows),
        fired=fired,
        skipped=skipped,
        failed=failed,
    )
