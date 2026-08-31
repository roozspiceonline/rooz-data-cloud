from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import and_, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import set_project_context
from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..core.security import canonical_fingerprint
from ..event_protocol import (
    EVENT_DEFINITIONS,
    EVENT_SCHEMA_VERSION,
    EventProtocolError,
    validate_event_payload,
)
from ..event_schemas import EventSummary
from ..models import Event
from .webhook_deliveries import enqueue_matching_webhook_deliveries


def event_summary(event: Event) -> dict[str, object]:
    return EventSummary.model_validate(event).model_dump(mode="json")


async def emit_event(
    session: AsyncSession,
    *,
    organization_id: UUID,
    project_id: UUID,
    event_type: str,
    subject_type: str,
    subject_id: UUID,
    payload: dict[str, object],
    request_id: str,
    idempotent: bool = True,
) -> Event:
    """Transactionally append or replay one exact server-derived lifecycle event."""
    try:
        validated_payload = validate_event_payload(
            event_type=event_type,
            subject_type=subject_type,
            payload=payload,
        )
    except EventProtocolError as exc:
        raise ApiError(
            status_code=422,
            code="EVENT_ENVELOPE_INVALID",
            message="The event envelope is invalid.",
        ) from exc
    if not 1 <= len(request_id) <= 100 or any(
        not (character.isalnum() or character in "._-") for character in request_id
    ):
        raise ApiError(
            status_code=422,
            code="EVENT_ENVELOPE_INVALID",
            message="The event envelope is invalid.",
        )

    await set_project_context(session, project_id)
    occurred_at = datetime.now(UTC)
    proposed_digest = canonical_fingerprint(validated_payload)
    if not idempotent:
        pending_event = Event(
            organization_id=organization_id,
            project_id=project_id,
            event_type=event_type,
            schema_version=EVENT_SCHEMA_VERSION,
            subject_type=subject_type,
            subject_id=subject_id,
            payload=validated_payload,
            payload_digest=proposed_digest,
            emitter="control-plane",
            request_id=request_id,
            occurred_at=occurred_at,
            created_at=occurred_at,
        )
        session.add(pending_event)
        await session.flush()
        await enqueue_matching_webhook_deliveries(session, event=pending_event)
        return pending_event

    inserted_id = await session.scalar(
        pg_insert(Event)
        .values(
            organization_id=organization_id,
            project_id=project_id,
            event_type=event_type,
            schema_version=EVENT_SCHEMA_VERSION,
            subject_type=subject_type,
            subject_id=subject_id,
            payload=validated_payload,
            payload_digest=proposed_digest,
            emitter="control-plane",
            request_id=request_id,
            occurred_at=occurred_at,
            created_at=occurred_at,
        )
        .on_conflict_do_nothing(
            constraint="uq_events_project_type_subject"
        )
        .returning(Event.id)
    )
    if inserted_id is not None:
        inserted_event = await session.scalar(select(Event).where(Event.id == inserted_id))
        if inserted_event is None:
            raise RuntimeError("Inserted event could not be read")
        await enqueue_matching_webhook_deliveries(session, event=inserted_event)
        return inserted_event

    existing = await session.scalar(
        select(Event).where(
            Event.project_id == project_id,
            Event.event_type == event_type,
            Event.subject_type == subject_type,
            Event.subject_id == subject_id,
        )
    )
    if existing is None or existing.payload != validated_payload:
        raise ApiError(
            status_code=409,
            code="EVENT_REPLAY_CONFLICT",
            message="The lifecycle event already exists with different content.",
        )
    return existing


async def list_events(
    session: AsyncSession,
    *,
    project_id: UUID,
    event_type: str | None,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[Event], bool]:
    if not 1 <= limit <= 100:
        raise ValueError("Event page size must be between 1 and 100")
    if event_type is not None and event_type not in EVENT_DEFINITIONS:
        raise ApiError(
            status_code=422,
            code="EVENT_TYPE_INVALID",
            message="The event type filter is invalid.",
        )
    await set_project_context(session, project_id)
    statement = select(Event).where(Event.project_id == project_id)
    if event_type is not None:
        statement = statement.where(Event.event_type == event_type)
    if cursor is not None:
        statement = statement.where(
            or_(
                Event.occurred_at < cursor.created_at,
                and_(
                    Event.occurred_at == cursor.created_at,
                    Event.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(Event.occurred_at.desc(), Event.id.desc()).limit(
                    limit + 1
                )
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit
