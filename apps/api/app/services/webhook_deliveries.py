from __future__ import annotations

import hashlib
import re
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import set_project_context
from ..core.errors import ApiError
from ..models import (
    Event,
    WebhookDeliveryAttempt,
    WebhookDeliveryTransition,
    WebhookDestination,
)

CLAIMABLE = frozenset({"PENDING", "RETRY_WAIT"})
TERMINAL = frozenset({"SUCCEEDED", "DEAD_LETTERED", "CANCELLED"})


@dataclass(frozen=True)
class ClaimedWebhookDelivery:
    delivery: WebhookDeliveryAttempt
    claim_token: str = field(repr=False)


def _claim_digest(claim_token: str) -> str:
    try:
        encoded = claim_token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Webhook claim token is invalid") from exc
    return hashlib.sha256(encoded).hexdigest()


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
            WebhookDestination.status == "PENDING_VERIFICATION",
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
        created_at=now,
        updated_at=now,
        version=1,
    )
    session.add(delivery)
    await session.flush()
    await _append_transition(session, delivery=delivery, from_status=None, reason_code="ENQUEUED")
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
        .where(
            WebhookDeliveryAttempt.project_id == project_id,
            or_(
                (
                    WebhookDeliveryAttempt.status.in_(CLAIMABLE)
                    & (WebhookDeliveryAttempt.available_at <= now)
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
    return delivery
