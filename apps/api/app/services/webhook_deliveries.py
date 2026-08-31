from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import set_project_context
from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..models import (
    Event,
    WebhookDeliveryAttempt,
    WebhookDeliveryTransition,
    WebhookDestination,
)
from ..webhook_delivery_schemas import (
    WebhookDeliverySummary,
    WebhookDeliveryTransitionSummary,
)
from .identity_tenancy import append_audit_event

CLAIMABLE = frozenset({"PENDING", "RETRY_WAIT"})
TERMINAL = frozenset({"SUCCEEDED", "DEAD_LETTERED", "CANCELLED"})


@dataclass(frozen=True)
class ClaimedWebhookDelivery:
    delivery: WebhookDeliveryAttempt
    claim_token: str = field(repr=False)


def _validate_idempotency_key(value: str) -> None:
    if not 8 <= len(value) <= 200:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="Idempotency-Key must contain between 8 and 200 characters.",
        )


def _claim_digest(claim_token: str) -> str:
    try:
        encoded = claim_token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Webhook claim token is invalid") from exc
    return hashlib.sha256(encoded).hexdigest()


def delivery_summary(delivery: WebhookDeliveryAttempt) -> dict[str, object]:
    return WebhookDeliverySummary.model_validate(delivery, from_attributes=True).model_dump(
        mode="json"
    )


def transition_summary(transition: WebhookDeliveryTransition) -> dict[str, object]:
    return WebhookDeliveryTransitionSummary.model_validate(
        transition, from_attributes=True
    ).model_dump(mode="json")


async def _append_transition(
    session: AsyncSession,
    *,
    delivery: WebhookDeliveryAttempt,
    from_status: str | None,
    reason_code: str,
) -> None:
    latest = await session.scalar(
        select(func.max(WebhookDeliveryTransition.sequence)).where(
            WebhookDeliveryTransition.delivery_id == delivery.id
        )
    )
    session.add(
        WebhookDeliveryTransition(
            organization_id=delivery.organization_id,
            project_id=delivery.project_id,
            delivery_id=delivery.id,
            sequence=int(latest or 0) + 1,
            from_status=from_status,
            to_status=delivery.status,
            reason_code=reason_code,
            attempt_count=delivery.attempt_count,
            claim_token=None,
        )
    )
    await session.flush()


async def enqueue_webhook_delivery(
    session: AsyncSession,
    *,
    project_id: UUID,
    destination_id: UUID,
    event_id: UUID,
    max_attempts: int = 5,
) -> WebhookDeliveryAttempt:
    if not 1 <= max_attempts <= 8:
        raise ValueError("Webhook max attempts must be between 1 and 8")
    await set_project_context(session, project_id)
    existing = await session.scalar(
        select(WebhookDeliveryAttempt).where(
            WebhookDeliveryAttempt.destination_id == destination_id,
            WebhookDeliveryAttempt.event_id == event_id,
        )
    )
    if existing is not None:
        return existing
    destination = await session.scalar(
        select(WebhookDestination).where(
            WebhookDestination.id == destination_id,
            WebhookDestination.project_id == project_id,
            WebhookDestination.status.in_(("PENDING_VERIFICATION", "ACTIVE")),
        )
    )
    event = await session.scalar(
        select(Event).where(Event.id == event_id, Event.project_id == project_id)
    )
    if destination is None or event is None or event.event_type not in destination.event_types:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    now = datetime.now(UTC)
    delivery = WebhookDeliveryAttempt(
        organization_id=destination.organization_id,
        project_id=project_id,
        destination_id=destination_id,
        event_id=event_id,
        endpoint_url=destination.endpoint_url,
        signing_secret_id=destination.signing_secret_id,
        signing_secret_version=destination.signing_secret_version,
        status="PENDING",
        attempt_count=0,
        max_attempts=max_attempts,
        available_at=now,
        claim_token=None,
        claim_token_digest=None,
        claimed_by=None,
        claim_expires_at=None,
        last_error_code=None,
        last_http_status=None,
        completed_at=None,
        replay_count=0,
        last_replayed_at=None,
        last_replay_key_digest=None,
        replay_requested_by_user_id=None,
        created_at=now,
        updated_at=now,
        version=1,
    )
    session.add(delivery)
    await session.flush()
    await _append_transition(session, delivery=delivery, from_status=None, reason_code="ENQUEUED")
    return delivery


async def enqueue_matching_webhook_deliveries(
    session: AsyncSession, *, event: Event
) -> list[WebhookDeliveryAttempt]:
    """Append delivery intents in the event transaction for every active match."""
    destinations = list(
        (
            await session.scalars(
                select(WebhookDestination).where(
                    WebhookDestination.project_id == event.project_id,
                    WebhookDestination.status == "ACTIVE",
                    WebhookDestination.event_types.op("?")(event.event_type),
                )
            )
        ).all()
    )
    return [
        await enqueue_webhook_delivery(
            session,
            project_id=event.project_id,
            destination_id=destination.id,
            event_id=event.id,
        )
        for destination in destinations
    ]


async def list_webhook_deliveries(
    session: AsyncSession,
    *,
    project_id: UUID,
    status: str | None,
    destination_id: UUID | None,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[WebhookDeliveryAttempt], bool]:
    await set_project_context(session, project_id)
    statement = select(WebhookDeliveryAttempt).where(
        WebhookDeliveryAttempt.project_id == project_id
    )
    if status is not None:
        statement = statement.where(WebhookDeliveryAttempt.status == status)
    if destination_id is not None:
        statement = statement.where(WebhookDeliveryAttempt.destination_id == destination_id)
    if cursor is not None:
        statement = statement.where(
            or_(
                WebhookDeliveryAttempt.created_at < cursor.created_at,
                and_(
                    WebhookDeliveryAttempt.created_at == cursor.created_at,
                    WebhookDeliveryAttempt.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    WebhookDeliveryAttempt.created_at.desc(),
                    WebhookDeliveryAttempt.id.desc(),
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def get_webhook_delivery(
    session: AsyncSession, *, project_id: UUID, delivery_id: UUID
) -> WebhookDeliveryAttempt:
    await set_project_context(session, project_id)
    delivery = await session.scalar(
        select(WebhookDeliveryAttempt).where(
            WebhookDeliveryAttempt.id == delivery_id,
            WebhookDeliveryAttempt.project_id == project_id,
        )
    )
    if delivery is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    return delivery


async def list_webhook_delivery_transitions(
    session: AsyncSession, *, project_id: UUID, delivery_id: UUID
) -> list[WebhookDeliveryTransition]:
    await get_webhook_delivery(session, project_id=project_id, delivery_id=delivery_id)
    return list(
        (
            await session.scalars(
                select(WebhookDeliveryTransition)
                .where(WebhookDeliveryTransition.delivery_id == delivery_id)
                .order_by(WebhookDeliveryTransition.sequence)
            )
        ).all()
    )


async def replay_webhook_delivery(
    session: AsyncSession,
    *,
    project_id: UUID,
    delivery_id: UUID,
    expected_version: int,
    idempotency_key: str,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    request_id: str,
) -> WebhookDeliveryAttempt:
    _validate_idempotency_key(idempotency_key)
    await set_project_context(session, project_id)
    key_digest = hashlib.sha256(idempotency_key.encode()).hexdigest()
    delivery = await session.scalar(
        select(WebhookDeliveryAttempt)
        .where(
            WebhookDeliveryAttempt.id == delivery_id,
            WebhookDeliveryAttempt.project_id == project_id,
        )
        .with_for_update()
    )
    if delivery is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    if delivery.last_replay_key_digest == key_digest:
        return delivery
    if delivery.version != expected_version:
        raise ApiError(
            status_code=409,
            code="VERSION_CONFLICT",
            message="The webhook delivery changed. Reload it and try again.",
        )
    if delivery.status != "DEAD_LETTERED":
        raise ApiError(
            status_code=409,
            code="WEBHOOK_REPLAY_INVALID",
            message="Only a failed terminal delivery can be replayed.",
        )
    destination = await session.scalar(
        select(WebhookDestination)
        .where(WebhookDestination.id == delivery.destination_id)
        .with_for_update()
    )
    if (
        destination is None
        or destination.disabled_reason not in {None, "AUTO_FAILURE_THRESHOLD"}
        or destination.endpoint_url != delivery.endpoint_url
        or destination.signing_secret_id != delivery.signing_secret_id
        or destination.signing_secret_version != delivery.signing_secret_version
    ):
        raise ApiError(
            status_code=409,
            code="WEBHOOK_REPLAY_CONFIGURATION_CHANGED",
            message="The delivery configuration changed.",
        )
    if destination.status == "DISABLED":
        destination.status = (
            "ACTIVE" if destination.verified_at is not None else "PENDING_VERIFICATION"
        )
        destination.consecutive_failure_count = 0
        destination.disabled_reason = None
        destination.version += 1
        destination.updated_at = datetime.now(UTC)
    previous = delivery.status
    now = datetime.now(UTC)
    delivery.status = "PENDING"
    delivery.attempt_count = 0
    delivery.available_at = now
    delivery.claim_token = None
    delivery.claim_token_digest = None
    delivery.claimed_by = None
    delivery.claim_expires_at = None
    delivery.last_error_code = None
    delivery.last_http_status = None
    delivery.completed_at = None
    delivery.replay_count += 1
    delivery.last_replayed_at = now
    delivery.last_replay_key_digest = key_digest
    delivery.replay_requested_by_user_id = user_id
    delivery.updated_at = now
    delivery.version += 1
    await session.flush()
    await _append_transition(
        session, delivery=delivery, from_status=previous, reason_code="MANUAL_REPLAY"
    )
    await append_audit_event(
        session,
        organization_id=delivery.organization_id,
        project_id=delivery.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="webhook.delivery.replayed",
        resource_type="webhook_delivery",
        resource_id=str(delivery.id),
        request_id=request_id,
        details={
            "destination_id": str(delivery.destination_id),
            "replay_count": delivery.replay_count,
        },
    )
    return delivery


async def claim_webhook_delivery(
    session: AsyncSession,
    *,
    project_id: UUID,
    worker_id: str,
    lease_seconds: int = 30,
) -> ClaimedWebhookDelivery | None:
    if (
        not 15 <= lease_seconds <= 120
        or re.fullmatch(r"[a-z0-9][a-z0-9._-]{0,63}", worker_id) is None
    ):
        raise ValueError("Webhook claim parameters are invalid")
    await set_project_context(session, project_id)
    now = datetime.now(UTC)
    delivery = await session.scalar(
        select(WebhookDeliveryAttempt)
        .join(
            WebhookDestination,
            WebhookDestination.id == WebhookDeliveryAttempt.destination_id,
        )
        .where(
            WebhookDeliveryAttempt.project_id == project_id,
            or_(
                (
                    WebhookDeliveryAttempt.status.in_(CLAIMABLE)
                    & (WebhookDeliveryAttempt.available_at <= now)
                    & WebhookDestination.status.in_(("PENDING_VERIFICATION", "ACTIVE"))
                ),
                (
                    (WebhookDeliveryAttempt.status == "CLAIMED")
                    & (WebhookDeliveryAttempt.claim_expires_at <= now)
                ),
            ),
        )
        .order_by(
            WebhookDeliveryAttempt.available_at,
            WebhookDeliveryAttempt.created_at,
            WebhookDeliveryAttempt.id,
        )
        .with_for_update(skip_locked=True)
        .limit(1)
    )
    if delivery is None:
        return None
    if delivery.status == "CLAIMED":
        previous = delivery.status
        delivery.status = (
            "DEAD_LETTERED" if delivery.attempt_count >= delivery.max_attempts else "RETRY_WAIT"
        )
        delivery.claim_token = None
        delivery.claim_token_digest = None
        delivery.claimed_by = None
        delivery.claim_expires_at = None
        delivery.last_error_code = "CLAIM_EXPIRED"
        delivery.completed_at = now if delivery.status == "DEAD_LETTERED" else None
        delivery.available_at = now
        delivery.version += 1
        delivery.updated_at = now
        await session.flush()
        await _append_transition(
            session,
            delivery=delivery,
            from_status=previous,
            reason_code="CLAIM_EXPIRED",
        )
        if delivery.status == "DEAD_LETTERED":
            destination = await session.scalar(
                select(WebhookDestination)
                .where(WebhookDestination.id == delivery.destination_id)
                .with_for_update()
            )
            if destination is not None and destination.status != "DISABLED":
                destination.consecutive_failure_count = min(
                    destination.failure_threshold,
                    destination.consecutive_failure_count + 1,
                )
                if destination.consecutive_failure_count >= destination.failure_threshold:
                    destination.status = "DISABLED"
                    destination.disabled_reason = "AUTO_FAILURE_THRESHOLD"
                destination.version += 1
                destination.updated_at = now
            return None
    previous, token = delivery.status, secrets.token_hex(32)
    delivery.status, delivery.claim_token, delivery.claimed_by = "CLAIMED", None, worker_id
    delivery.claim_token_digest = _claim_digest(token)
    delivery.claim_expires_at = now + timedelta(seconds=lease_seconds)
    delivery.attempt_count += 1
    delivery.version += 1
    delivery.updated_at = now
    await session.flush()
    await _append_transition(
        session, delivery=delivery, from_status=previous, reason_code="CLAIMED"
    )
    return ClaimedWebhookDelivery(delivery=delivery, claim_token=token)


async def complete_webhook_delivery(
    session: AsyncSession,
    *,
    delivery_id: UUID,
    claim_token: str,
    succeeded: bool,
    http_status: int | None,
    error_code: str | None,
) -> WebhookDeliveryAttempt:
    delivery = await session.scalar(
        select(WebhookDeliveryAttempt)
        .where(WebhookDeliveryAttempt.id == delivery_id)
        .with_for_update()
    )
    now = datetime.now(UTC)
    if (
        delivery is None
        or delivery.status != "CLAIMED"
        or delivery.claim_token_digest != _claim_digest(claim_token)
        or delivery.claim_expires_at is None
        or delivery.claim_expires_at <= now
    ):
        raise ApiError(
            status_code=409,
            code="WEBHOOK_CLAIM_FENCED",
            message="The webhook delivery claim is stale.",
        )
    previous = delivery.status
    destination = await session.scalar(
        select(WebhookDestination)
        .where(WebhookDestination.id == delivery.destination_id)
        .with_for_update()
    )
    if destination is None or destination.status not in {"PENDING_VERIFICATION", "ACTIVE"}:
        raise ApiError(
            status_code=409,
            code="WEBHOOK_CLAIM_FENCED",
            message="The webhook delivery claim is stale.",
        )
    if succeeded:
        delivery.status, reason = "SUCCEEDED", "DELIVERED"
        delivery.completed_at = now
    elif delivery.attempt_count >= delivery.max_attempts:
        delivery.status, reason = "DEAD_LETTERED", "ATTEMPTS_EXHAUSTED"
        delivery.completed_at = now
    else:
        delivery.status, reason = "RETRY_WAIT", "RETRY_SCHEDULED"
        delay = min(3600, 2 ** min(delivery.attempt_count, 10) * 5)
        delivery.available_at = now + timedelta(seconds=delay)
    delivery.last_http_status, delivery.last_error_code = http_status, error_code
    delivery.claim_token = delivery.claimed_by = delivery.claim_expires_at = None
    delivery.claim_token_digest = None
    delivery.version += 1
    delivery.updated_at = now
    await session.flush()
    await _append_transition(
        session,
        delivery=delivery,
        from_status=previous,
        reason_code=reason,
    )
    if succeeded:
        destination.status = "ACTIVE"
        destination.verified_at = destination.verified_at or now
        destination.consecutive_failure_count = 0
        destination.disabled_reason = None
        destination.version += 1
        destination.updated_at = now
    elif delivery.status == "DEAD_LETTERED":
        destination.consecutive_failure_count = min(
            destination.failure_threshold,
            destination.consecutive_failure_count + 1,
        )
        if destination.consecutive_failure_count >= destination.failure_threshold:
            destination.status = "DISABLED"
            destination.disabled_reason = "AUTO_FAILURE_THRESHOLD"
        destination.version += 1
        destination.updated_at = now
    return delivery
