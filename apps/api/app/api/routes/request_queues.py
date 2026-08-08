# ruff: noqa: E501
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import request_id, success_payload
from ...core.pagination import (
    decode_queue_request_cursor,
    decode_queue_transition_cursor,
    decode_request_queue_list_cursor,
    encode_queue_request_cursor,
    encode_queue_transition_cursor,
    encode_request_queue_list_cursor,
    normalize_limit,
)
from ...request_queue_protocol import RequestQueueProtocolError, validate_queue_enqueue
from ...request_queue_schemas import (
    CreateRequestQueueRequest,
    EnqueueRequest,
    QueueTransitionSummary,
)
from ...services.request_queues import (
    create_request_queue,
    enqueue_request,
    list_queue_transitions,
    list_request_queues,
    queue_summary,
    receipt_summary,
    request_summary,
)
from ..agent_dependencies import (
    ProjectAccess,
    RequestQueueAccess,
    require_project_permission,
    require_request_queue_permission,
)
from ..dependencies import AuthContext, require_csrf

router = APIRouter(tags=["request-queues"])


def actor(context: AuthContext) -> tuple[str, str]:
    if context.principal.auth_type == "api_key":
        if context.principal.api_key_id is None:
            raise RuntimeError("API-key context is missing an API-key ID")
        return "api_key", str(context.principal.api_key_id)
    return "user", str(context.user.id)


@router.post("/projects/{project_id}/request-queues", status_code=status.HTTP_201_CREATED)
async def create_queue(payload: CreateRequestQueueRequest, request: Request, access: Annotated[ProjectAccess, Depends(require_project_permission("queue.create"))], _: Annotated[AuthContext, Depends(require_csrf)], db: Annotated[AsyncSession, Depends(get_db)]) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    queue = await create_request_queue(db, project=access.project, user_id=access.context.user.id, actor_type=actor_type, actor_id=actor_id, request_id=request_id(request), payload=payload)
    return success_payload(request, queue_summary(queue).model_dump(mode="json"))


@router.get("/projects/{project_id}/request-queues")
async def list_queues(request: Request, access: Annotated[ProjectAccess, Depends(require_project_permission("queue.read"))], db: Annotated[AsyncSession, Depends(get_db)], cursor: Annotated[str | None, Query()] = None, limit: Annotated[int, Query()] = 50) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_request_queue_list_cursor(cursor, project_id=access.project.id)
    rows, has_more = await list_request_queues(db, project_id=access.project.id, cursor=position, limit=normalized)
    next_cursor = None
    if has_more and rows:
        final = rows[-1]
        next_cursor = encode_request_queue_list_cursor(project_id=access.project.id, created_at=final.created_at, resource_id=final.id)
    return {"data": [queue_summary(row).model_dump(mode="json") for row in rows], "meta": {"request_id": request_id(request), "page": {"next_cursor": next_cursor, "has_more": next_cursor is not None}}}


@router.get("/request-queues/{queue_id}")
async def get_queue(request: Request, access: Annotated[RequestQueueAccess, Depends(require_request_queue_permission("queue.read"))]) -> dict[str, object]:
    return success_payload(request, queue_summary(access.queue).model_dump(mode="json"))


@router.post("/request-queues/{queue_id}/requests", status_code=status.HTTP_201_CREATED)
async def enqueue(payload: EnqueueRequest, request: Request, access: Annotated[RequestQueueAccess, Depends(require_request_queue_permission("queue.enqueue"))], _: Annotated[AuthContext, Depends(require_csrf)], db: Annotated[AsyncSession, Depends(get_db)]) -> dict[str, object]:
    try:
        validated = validate_queue_enqueue(payload.model_dump())
    except RequestQueueProtocolError as exc:
        from ...core.errors import ApiError
        raise ApiError(status_code=422, code="REQUEST_QUEUE_PROTOCOL_INVALID", message=str(exc)) from exc
    actor_type, actor_id = actor(access.context)
    outcome = await enqueue_request(db, queue=access.queue, user_id=access.context.user.id, actor_type=actor_type, actor_id=actor_id, request_id=request_id(request), validated=validated)
    return success_payload(request, receipt_summary(outcome).model_dump(mode="json"))


@router.get("/request-queues/{queue_id}/requests")
async def list_requests(request: Request, access: Annotated[RequestQueueAccess, Depends(require_request_queue_permission("queue.read"))], db: Annotated[AsyncSession, Depends(get_db)], cursor: Annotated[str | None, Query()] = None, limit: Annotated[int, Query()] = 50, state: Annotated[str | None, Query(pattern="^(PENDING|CLAIMED|HANDLED|FAILED)$")] = None) -> dict[str, object]:
    from ...models import RequestQueueRequest
    position = decode_queue_request_cursor(cursor, queue_id=access.queue.id, status=state)
    statement = select(RequestQueueRequest).where(RequestQueueRequest.queue_id == access.queue.id)
    if state is not None:
        statement = statement.where(RequestQueueRequest.status == state)
    if position is not None:
        statement = statement.where(or_(RequestQueueRequest.created_at < position.created_at, (RequestQueueRequest.created_at == position.created_at) & (RequestQueueRequest.id < position.resource_id)))
    normalized = normalize_limit(limit)
    rows = (await db.scalars(statement.order_by(RequestQueueRequest.created_at.desc(), RequestQueueRequest.id.desc()).limit(normalized + 1))).all()
    page, has_more = rows[:normalized], len(rows) > normalized
    next_cursor = None if not has_more else encode_queue_request_cursor(queue_id=access.queue.id, status=state, created_at=page[-1].created_at, resource_id=page[-1].id)
    return {"data": [request_summary(row).model_dump(mode="json") for row in page], "meta": {"request_id": request_id(request), "page": {"next_cursor": next_cursor, "has_more": has_more}}}


@router.get("/request-queues/{queue_id}/transitions")
async def list_transitions(request: Request, access: Annotated[RequestQueueAccess, Depends(require_request_queue_permission("queue.read"))], db: Annotated[AsyncSession, Depends(get_db)], cursor: Annotated[str | None, Query()] = None, limit: Annotated[int, Query()] = 50, queue_request_id: Annotated[UUID | None, Query(alias="request_id")] = None) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_queue_transition_cursor(cursor, queue_id=access.queue.id, request_id=queue_request_id)
    rows, has_more = await list_queue_transitions(db, queue_id=access.queue.id, request_id=queue_request_id, cursor=position, limit=normalized)
    next_cursor = None
    if has_more and rows:
        final = rows[-1]
        next_cursor = encode_queue_transition_cursor(queue_id=access.queue.id, request_id=queue_request_id, created_at=final.created_at, resource_id=final.id)
    return {"data": [QueueTransitionSummary.model_validate(row).model_dump(mode="json") for row in rows], "meta": {"request_id": request_id(request), "page": {"next_cursor": next_cursor, "has_more": next_cursor is not None}}}
