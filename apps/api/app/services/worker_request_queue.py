from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.errors import ApiError
from ..core.security import canonical_fingerprint
from ..models import (
    ExecutionLease,
    RequestQueue,
    RequestQueueRequest,
    RequestQueueTransition,
    WorkerIdentity,
)
from .identity_tenancy import append_audit_event
from .request_queues import claim_next_request, reclaim_expired_requests

settings = get_settings()


def request_queue_capability(
    worker: WorkerIdentity,
    payload: dict[str, object],
    *,
    request_queue_enabled: bool,
) -> dict[str, object] | None:
    if (
        not request_queue_enabled
        or not settings.sandbox_canary_request_queue_enabled
        or str(payload.get("work_kind", "")) != "RUN_START"
        or worker.name != settings.sandbox_canary_worker_name.strip()
        or "REQUEST_QUEUE_ACCESS" not in worker.capabilities
        or str(payload.get("agent_version_id", ""))
        != settings.sandbox_canary_agent_version_id.strip()
    ):
        return None

    manifest = payload.get("manifest")
    input_reference = payload.get("input_reference")
    if not isinstance(manifest, dict) or not isinstance(input_reference, dict):
        return None
    capabilities = manifest.get("capabilities")
    binding = input_reference.get("request_queue")
    receipt = input_reference.get("queue_binding_receipt")
    if (
        not isinstance(capabilities, dict)
        or capabilities.get("requestQueue") is not True
        or capabilities.get("network") != "none"
        or capabilities.get("browser") is not False
        or capabilities.get("dataset") is not False
        or capabilities.get("keyValueStore") is not False
        or not isinstance(binding, dict)
        or set(binding) != {"schema_version", "queue_id"}
        or binding.get("schema_version") != "rdc.run-queue/v1"
        or not isinstance(receipt, dict)
    ):
        return None
    try:
        queue_id = UUID(str(binding["queue_id"]))
    except (KeyError, ValueError):
        return None
    normalized_binding = {
        "schema_version": "rdc.run-queue/v1",
        "queue_id": str(queue_id),
    }
    expected_receipt = {
        "schema_version": "rdc.request-queue-binding-receipt/v1",
        "binding_digest": canonical_fingerprint(normalized_binding),
        "queue_id": str(queue_id),
        "agent_version_id": str(payload["agent_version_id"]),
        "direct_database_access": False,
        "direct_object_storage_access": False,
    }
    if receipt != expected_receipt:
        return None
    return {
        "schema_version": "rdc.request-queue-worker-capability/v1",
        "queue_id": str(queue_id),
        "run_id": str(payload.get("run_id", "")),
        "agent_version_id": str(payload["agent_version_id"]),
        "worker_name": worker.name,
        "max_claims_per_run": 1,
        "claim_completion_required": True,
        "direct_database_access": False,
        "direct_object_storage_access": False,
        "enabled": True,
    }


def _enabled(
    lease: ExecutionLease,
    worker: WorkerIdentity,
) -> dict[str, object]:
    snapshot = dict(lease.payload_snapshot)
    activation = snapshot.get("activation")
    enabled = (
        settings.sandbox_execution_enabled
        and settings.sandbox_activation_mode == "canary"
        and isinstance(activation, dict)
        and activation.get("request_queue_enabled") is True
    )
    expected = request_queue_capability(
        worker,
        snapshot,
        request_queue_enabled=enabled,
    )
    if (
        lease.work_kind != "RUN_START"
        or expected is None
        or snapshot.get("request_queue_capability") != expected
    ):
        raise ApiError(
            status_code=403,
            code="WORKER_REQUEST_QUEUE_DISABLED",
            message="Worker Request Queue access is disabled.",
        )
    return expected


async def claim_worker_queue_request(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: object,
    request_id: str,
) -> RequestQueueRequest | None:
    capability = _enabled(lease, worker)
    if not isinstance(payload, dict) or set(payload) != {"queue_id"}:
        raise ApiError(
            status_code=422,
            code="REQUEST_QUEUE_WORKER_PROTOCOL_INVALID",
            message="Queue claim payload is invalid.",
        )
    try:
        queue_id = UUID(str(payload["queue_id"]))
    except ValueError as exc:
        raise ApiError(
            status_code=422,
            code="REQUEST_QUEUE_WORKER_PROTOCOL_INVALID",
            message="Queue claim payload is invalid.",
        ) from exc
    if str(queue_id) != capability["queue_id"]:
        raise ApiError(
            status_code=403,
            code="WORKER_REQUEST_QUEUE_SCOPE_DENIED",
            message="The Queue is outside this lease capability.",
        )
    queue = await session.scalar(
        select(RequestQueue).where(
            RequestQueue.id == queue_id,
            RequestQueue.organization_id == lease.organization_id,
            RequestQueue.project_id == lease.project_id,
        )
    )
    if queue is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    await reclaim_expired_requests(
        session,
        queue_id=queue.id,
        worker_id=str(worker.id),
        request_id=request_id,
    )
    return await claim_next_request(
        session,
        queue_id=queue.id,
        worker_id=str(worker.id),
        request_id=request_id,
        lease_seconds=settings.worker_lease_seconds,
    )


async def complete_worker_queue_request(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: object,
    request_id: str,
) -> RequestQueueRequest:
    capability = _enabled(lease, worker)
    fields = {
        "queue_id",
        "request_id",
        "claim_token",
        "status",
        "failure_code",
        "failure_summary",
    }
    if (
        not isinstance(payload, dict)
        or set(payload) != fields
        or payload["status"] not in {"HANDLED", "FAILED"}
    ):
        raise ApiError(
            status_code=422,
            code="REQUEST_QUEUE_WORKER_PROTOCOL_INVALID",
            message="Queue completion payload is invalid.",
        )
    try:
        queue_id = UUID(str(payload["queue_id"]))
        queue_request_id = UUID(str(payload["request_id"]))
        claim_token = UUID(str(payload["claim_token"]))
    except ValueError as exc:
        raise ApiError(
            status_code=422,
            code="REQUEST_QUEUE_WORKER_PROTOCOL_INVALID",
            message="Queue completion payload is invalid.",
        ) from exc
    if str(queue_id) != capability["queue_id"]:
        raise ApiError(
            status_code=403,
            code="WORKER_REQUEST_QUEUE_SCOPE_DENIED",
            message="The Queue is outside this lease capability.",
        )
    queue = await session.scalar(
        select(RequestQueue)
        .where(
            RequestQueue.id == queue_id,
            RequestQueue.organization_id == lease.organization_id,
            RequestQueue.project_id == lease.project_id,
        )
        .with_for_update()
    )
    if queue is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    row = await session.scalar(
        select(RequestQueueRequest)
        .where(
            RequestQueueRequest.id == queue_request_id,
            RequestQueueRequest.queue_id == queue_id,
            RequestQueueRequest.organization_id == lease.organization_id,
            RequestQueueRequest.project_id == lease.project_id,
        )
        .with_for_update()
    )
    if row is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    if (
        row.status != "CLAIMED"
        or row.claimed_by != str(worker.id)
        or row.claim_token != claim_token
        or row.claim_expires_at is None
        or row.claim_expires_at <= datetime.now(UTC)
    ):
        raise ApiError(
            status_code=409,
            code="REQUEST_QUEUE_CLAIM_STALE",
            message="The Queue request claim is stale or invalid.",
        )
    target = str(payload["status"])
    row.status = target
    row.claimed_by = None
    row.claim_token = None
    row.claim_expires_at = None
    row.handled_at = datetime.now(UTC)
    queue.claimed_count -= 1
    if target == "HANDLED":
        queue.handled_count += 1
    else:
        queue.failed_count += 1
    row.failure_code = (
        str(payload["failure_code"])[:80]
        if target == "FAILED" and payload["failure_code"]
        else None
    )
    row.failure_summary = (
        str(payload["failure_summary"])[:2000]
        if target == "FAILED" and payload["failure_summary"]
        else None
    )
    session.add(
        RequestQueueTransition(
            organization_id=row.organization_id,
            project_id=row.project_id,
            queue_id=row.queue_id,
            request_id=row.id,
            from_status="CLAIMED",
            to_status=target,
            reason="WORKER_COMPLETED",
            attempt_count=row.attempt_count,
            details={"worker_id": str(worker.id), "lease_id": str(lease.id)},
        )
    )
    await append_audit_event(
        session,
        organization_id=row.organization_id,
        project_id=row.project_id,
        actor_type="worker",
        actor_id=str(worker.id),
        action=(
            "request_queue.request_handled"
            if target == "HANDLED"
            else "request_queue.request_failed"
        ),
        resource_type="request_queue_request",
        resource_id=str(row.id),
        request_id=request_id,
        details={
            "queue_id": str(row.queue_id),
            "lease_id": str(lease.id),
            "attempt_count": row.attempt_count,
            "reason": "WORKER_COMPLETED",
            "failure_code": row.failure_code,
        },
    )
    return row
