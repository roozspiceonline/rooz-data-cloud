# ruff: noqa: E501
from dataclasses import dataclass
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.errors import ApiError
from ..core.pagination import (
    QueueTransitionCursorPosition,
    RequestQueueListCursorPosition,
)
from ..models import (
    Project,
    RequestQueue,
    RequestQueueEnqueueReceipt,
    RequestQueueRequest,
    RequestQueueTransition,
)
from ..request_queue_protocol import ValidatedQueueEnqueue
from ..request_queue_schemas import (
    CreateRequestQueueRequest,
    EnqueueReceiptSummary,
    QueueRequestSummary,
    RequestQueueSummary,
)
from .identity_tenancy import append_audit_event


@dataclass(frozen=True)
class EnqueueOutcome:
    receipt: RequestQueueEnqueueReceipt
    replayed: bool


def queue_summary(record: RequestQueue) -> RequestQueueSummary:
    return RequestQueueSummary.model_validate(record)


def request_summary(record: RequestQueueRequest) -> QueueRequestSummary:
    return QueueRequestSummary.model_validate(record)


def receipt_summary(outcome: EnqueueOutcome) -> EnqueueReceiptSummary:
    receipt = outcome.receipt
    return EnqueueReceiptSummary(id=receipt.id, queue_id=receipt.queue_id, request_id=receipt.request_id, idempotency_key=receipt.idempotency_key, request_digest=receipt.request_digest, replayed=outcome.replayed, created_at=receipt.created_at)


async def list_request_queues(
    session: AsyncSession,
    *,
    project_id: UUID,
    cursor: RequestQueueListCursorPosition | None,
    limit: int,
) -> tuple[list[RequestQueue], bool]:
    statement = select(RequestQueue).where(RequestQueue.project_id == project_id)
    if cursor is not None:
        statement = statement.where(
            or_(
                RequestQueue.created_at < cursor.created_at,
                and_(
                    RequestQueue.created_at == cursor.created_at,
                    RequestQueue.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    RequestQueue.created_at.desc(),
                    RequestQueue.id.desc(),
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def list_queue_transitions(
    session: AsyncSession,
    *,
    queue_id: UUID,
    request_id: UUID | None,
    cursor: QueueTransitionCursorPosition | None,
    limit: int,
) -> tuple[list[RequestQueueTransition], bool]:
    statement = select(RequestQueueTransition).where(
        RequestQueueTransition.queue_id == queue_id
    )
    if request_id is not None:
        statement = statement.where(
            RequestQueueTransition.request_id == request_id
        )
    if cursor is not None:
        statement = statement.where(
            or_(
                RequestQueueTransition.created_at < cursor.created_at,
                and_(
                    RequestQueueTransition.created_at == cursor.created_at,
                    RequestQueueTransition.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    RequestQueueTransition.created_at.desc(),
                    RequestQueueTransition.id.desc(),
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def create_request_queue(session: AsyncSession, *, project: Project, user_id: UUID, actor_type: str, actor_id: str, request_id: str, payload: CreateRequestQueueRequest) -> RequestQueue:
    if await session.scalar(select(RequestQueue).where(RequestQueue.project_id == project.id, RequestQueue.name == payload.name)):
        raise ApiError(status_code=409, code="REQUEST_QUEUE_ALREADY_EXISTS", message="A Request Queue with that name already exists.")
    queue = RequestQueue(organization_id=project.organization_id, project_id=project.id, name=payload.name, created_by_user_id=user_id)
    session.add(queue)
    await session.flush()
    await append_audit_event(session, organization_id=project.organization_id, project_id=project.id, actor_type=actor_type, actor_id=actor_id, action="request_queue.created", resource_type="request_queue", resource_id=str(queue.id), request_id=request_id, details={"name": queue.name})
    return queue


async def enqueue_request(session: AsyncSession, *, queue: RequestQueue, user_id: UUID, actor_type: str, actor_id: str, request_id: str, validated: ValidatedQueueEnqueue) -> EnqueueOutcome:
    # Serialize per queue: the receipt lookup and insert are one idempotent transaction.
    await session.execute(select(RequestQueue.id).where(RequestQueue.id == queue.id).with_for_update())
    existing = await session.scalar(select(RequestQueueEnqueueReceipt).where(RequestQueueEnqueueReceipt.queue_id == queue.id, RequestQueueEnqueueReceipt.idempotency_key == validated.request["idempotency_key"]))
    if existing is not None:
        if existing.request_digest != validated.request_digest:
            raise ApiError(status_code=409, code="IDEMPOTENCY_KEY_REUSED", message="The idempotency key was previously used with a different request.")
        return EnqueueOutcome(receipt=existing, replayed=True)
    duplicate = await session.scalar(select(RequestQueueRequest.id).where(RequestQueueRequest.queue_id == queue.id, RequestQueueRequest.identity_digest == validated.identity_digest))
    if duplicate is not None:
        raise ApiError(status_code=409, code="REQUEST_QUEUE_DUPLICATE", message="An equivalent request is already queued.")
    request = RequestQueueRequest(organization_id=queue.organization_id, project_id=queue.project_id, queue_id=queue.id, request_url=validated.request["url"], unique_key=validated.request["unique_key"], identity_digest=validated.identity_digest, user_data=validated.request["user_data"], created_by_user_id=user_id)
    session.add(request)
    await session.flush()
    receipt = RequestQueueEnqueueReceipt(organization_id=queue.organization_id, project_id=queue.project_id, queue_id=queue.id, request_id=request.id, idempotency_key=validated.request["idempotency_key"], request_digest=validated.request_digest, identity_digest=validated.identity_digest, created_by_user_id=user_id)
    session.add(receipt)
    session.add(RequestQueueTransition(organization_id=queue.organization_id, project_id=queue.project_id, queue_id=queue.id, request_id=request.id, from_status=None, to_status="PENDING", reason="ENQUEUED", attempt_count=0, details={}))
    queue.pending_count += 1
    await session.flush()
    await append_audit_event(
        session,
        organization_id=queue.organization_id,
        project_id=queue.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="request_queue.request_enqueued",
        resource_type="request_queue_request",
        resource_id=str(request.id),
        request_id=request_id,
        details={
            "queue_id": str(queue.id),
            "receipt_id": str(receipt.id),
            "request_digest": validated.request_digest,
            "identity_digest": validated.identity_digest,
        },
    )
    return EnqueueOutcome(receipt=receipt, replayed=False)


async def claim_next_request(session: AsyncSession, *, queue_id: UUID, worker_id: str, request_id: str, lease_seconds: int = 60) -> RequestQueueRequest | None:
    """Worker-only lifecycle primitive; route exposure is deliberately deferred."""
    if not 1 <= lease_seconds <= 300:
        raise ValueError("lease_seconds must be between 1 and 300")
    queue = await session.scalar(select(RequestQueue).where(RequestQueue.id == queue_id).with_for_update())
    if queue is None:
        return None
    row = await session.scalar(select(RequestQueueRequest).where(RequestQueueRequest.queue_id == queue_id, RequestQueueRequest.status == "PENDING", RequestQueueRequest.available_at <= func.now()).order_by(RequestQueueRequest.created_at, RequestQueueRequest.id).with_for_update(skip_locked=True).limit(1))
    if row is None:
        return None
    row.status, row.claimed_by, row.claim_token = "CLAIMED", worker_id, uuid4()
    row.attempt_count += 1
    queue.pending_count -= 1
    queue.claimed_count += 1
    claim_expires_at = await session.scalar(
        select(func.now() + text(f"INTERVAL '{lease_seconds} seconds'"))
    )
    if claim_expires_at is None:
        raise RuntimeError("PostgreSQL did not return a Queue claim expiration")
    row.claim_expires_at = claim_expires_at
    session.add(RequestQueueTransition(organization_id=row.organization_id, project_id=row.project_id, queue_id=row.queue_id, request_id=row.id, from_status="PENDING", to_status="CLAIMED", reason="CLAIMED", attempt_count=row.attempt_count, details={"worker_id": worker_id}))
    await append_audit_event(
        session,
        organization_id=row.organization_id,
        project_id=row.project_id,
        actor_type="worker",
        actor_id=worker_id,
        action="request_queue.request_claimed",
        resource_type="request_queue_request",
        resource_id=str(row.id),
        request_id=request_id,
        details={
            "queue_id": str(row.queue_id),
            "attempt_count": row.attempt_count,
            "claim_expires_at": claim_expires_at.isoformat(),
        },
    )
    return row


async def reclaim_expired_requests(session: AsyncSession, *, queue_id: UUID, worker_id: str, request_id: str) -> int:
    """Lock-safe reclaim primitive; public routes intentionally cannot call it."""
    queue = await session.scalar(select(RequestQueue).where(RequestQueue.id == queue_id).with_for_update())
    if queue is None:
        return 0
    rows = (
        await session.scalars(
            select(RequestQueueRequest)
            .where(
                RequestQueueRequest.queue_id == queue_id,
                RequestQueueRequest.status == "CLAIMED",
                RequestQueueRequest.claim_expires_at < func.now(),
            )
            .with_for_update(skip_locked=True)
        )
    ).all()
    for row in rows:
        expired_worker_id = row.claimed_by
        target = "FAILED" if row.attempt_count >= row.max_attempts else "PENDING"
        row.status = target
        row.claimed_by = None
        row.claim_token = None
        row.claim_expires_at = None
        queue.claimed_count -= 1
        if target == "FAILED":
            queue.failed_count += 1
        else:
            queue.pending_count += 1
        if target == "FAILED":
            row.failure_code = "LEASE_EXPIRED"
            row.failure_summary = "Worker lease expired before completion."
        session.add(RequestQueueTransition(organization_id=row.organization_id, project_id=row.project_id, queue_id=row.queue_id, request_id=row.id, from_status="CLAIMED", to_status=target, reason="LEASE_EXPIRED", attempt_count=row.attempt_count, details={}))
        await append_audit_event(
            session,
            organization_id=row.organization_id,
            project_id=row.project_id,
            actor_type="worker",
            actor_id=worker_id,
            action=(
                "request_queue.request_failed"
                if target == "FAILED"
                else "request_queue.request_reclaimed"
            ),
            resource_type="request_queue_request",
            resource_id=str(row.id),
            request_id=request_id,
            details={
                "queue_id": str(row.queue_id),
                "attempt_count": row.attempt_count,
                "reason": "LEASE_EXPIRED",
                "expired_worker_id": expired_worker_id,
            },
        )
    return len(rows)
