# ruff: noqa: E501
from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.errors import ApiError
from ..models import (
    ExecutionLease,
    RequestQueue,
    RequestQueueRequest,
    RequestQueueTransition,
    WorkerIdentity,
)
from .request_queues import claim_next_request, reclaim_expired_requests

settings = get_settings()


def _enabled(lease: ExecutionLease, worker: WorkerIdentity) -> None:
    manifest = lease.payload_snapshot.get("manifest")
    capabilities = manifest.get("capabilities") if isinstance(manifest, dict) else None
    if not settings.sandbox_execution_enabled or settings.sandbox_activation_mode != "canary" or not settings.sandbox_canary_request_queue_enabled or lease.work_kind != "RUN" or worker.name != settings.sandbox_canary_worker_name.strip() or "REQUEST_QUEUE_ACCESS" not in worker.capabilities or str(lease.payload_snapshot.get("agent_version_id", "")) != settings.sandbox_canary_agent_version_id.strip() or not isinstance(capabilities, dict) or capabilities.get("requestQueue") is not True:
        raise ApiError(status_code=403, code="WORKER_REQUEST_QUEUE_DISABLED", message="Worker Request Queue access is disabled.")


async def claim_worker_queue_request(session: AsyncSession, *, lease: ExecutionLease, worker: WorkerIdentity, payload: object) -> RequestQueueRequest | None:
    _enabled(lease, worker)
    if not isinstance(payload, dict) or set(payload) != {"queue_id"}:
        raise ApiError(status_code=422, code="REQUEST_QUEUE_WORKER_PROTOCOL_INVALID", message="Queue claim payload is invalid.")
    try:
        queue_id = UUID(str(payload["queue_id"]))
    except ValueError as exc:
        raise ApiError(status_code=422, code="REQUEST_QUEUE_WORKER_PROTOCOL_INVALID", message="Queue claim payload is invalid.") from exc
    queue = await session.scalar(select(RequestQueue).where(RequestQueue.id == queue_id, RequestQueue.organization_id == lease.organization_id, RequestQueue.project_id == lease.project_id))
    if queue is None:
        raise ApiError(status_code=404, code="RESOURCE_NOT_FOUND", message="The requested resource was not found.")
    await reclaim_expired_requests(session, queue_id=queue.id)
    return await claim_next_request(session, queue_id=queue.id, worker_id=str(worker.id), lease_seconds=settings.worker_lease_seconds)


async def complete_worker_queue_request(session: AsyncSession, *, lease: ExecutionLease, worker: WorkerIdentity, payload: object) -> RequestQueueRequest:
    _enabled(lease, worker)
    if not isinstance(payload, dict) or set(payload) != {"queue_id", "request_id", "claim_token", "status", "failure_code", "failure_summary"} or payload["status"] not in {"HANDLED", "FAILED"}:
        raise ApiError(status_code=422, code="REQUEST_QUEUE_WORKER_PROTOCOL_INVALID", message="Queue completion payload is invalid.")
    try:
        queue_id, request_id, claim_token = UUID(str(payload["queue_id"])), UUID(str(payload["request_id"])), UUID(str(payload["claim_token"]))
    except ValueError as exc:
        raise ApiError(status_code=422, code="REQUEST_QUEUE_WORKER_PROTOCOL_INVALID", message="Queue completion payload is invalid.") from exc
    queue = await session.scalar(select(RequestQueue).where(RequestQueue.id == queue_id, RequestQueue.organization_id == lease.organization_id, RequestQueue.project_id == lease.project_id).with_for_update())
    if queue is None:
        raise ApiError(status_code=404, code="RESOURCE_NOT_FOUND", message="The requested resource was not found.")
    row = await session.scalar(select(RequestQueueRequest).where(RequestQueueRequest.id == request_id, RequestQueueRequest.queue_id == queue_id, RequestQueueRequest.organization_id == lease.organization_id, RequestQueueRequest.project_id == lease.project_id).with_for_update())
    if row is None:
        raise ApiError(status_code=404, code="RESOURCE_NOT_FOUND", message="The requested resource was not found.")
    if row.status != "CLAIMED" or row.claimed_by != str(worker.id) or row.claim_token != claim_token or row.claim_expires_at is None or row.claim_expires_at <= datetime.now(UTC):
        raise ApiError(status_code=409, code="REQUEST_QUEUE_CLAIM_STALE", message="The Queue request claim is stale or invalid.")
    target = str(payload["status"])
    row.status, row.claimed_by, row.claim_token, row.claim_expires_at = target, None, None, None
    row.handled_at = datetime.now(UTC)
    queue.claimed_count -= 1
    if target == "HANDLED":
        queue.handled_count += 1
    else:
        queue.failed_count += 1
    row.failure_code = str(payload["failure_code"])[:80] if target == "FAILED" and payload["failure_code"] else None
    row.failure_summary = str(payload["failure_summary"])[:2000] if target == "FAILED" and payload["failure_summary"] else None
    session.add(RequestQueueTransition(organization_id=row.organization_id, project_id=row.project_id, queue_id=row.queue_id, request_id=row.id, from_status="CLAIMED", to_status=target, reason="WORKER_COMPLETED", attempt_count=row.attempt_count, details={"worker_id": str(worker.id), "lease_id": str(lease.id)}))
    return row
