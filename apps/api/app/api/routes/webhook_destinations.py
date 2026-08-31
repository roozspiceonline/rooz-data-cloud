from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import request_id, success_payload
from ...core.pagination import decode_event_cursor, encode_event_cursor
from ...services.webhook_deliveries import delivery_summary
from ...services.webhook_destinations import (
    create_webhook_destination,
    destination_summary,
    disable_webhook_destination,
    get_webhook_destination,
    list_webhook_destinations,
    rotate_webhook_signing_secret,
    verify_webhook_destination,
)
from ...webhook_destination_schemas import (
    CreateWebhookDestinationRequest,
    DisableWebhookDestinationRequest,
    RotateWebhookSigningSecretRequest,
    VerifyWebhookDestinationRequest,
)
from ..agent_dependencies import ProjectAccess, require_project_permission
from ..dependencies import AuthContext, require_csrf

router = APIRouter(tags=["webhook-destinations"])
_CURSOR_KIND = "webhook-destinations"


def _actor(access: ProjectAccess) -> tuple[str, str]:
    principal = access.context.principal
    if principal.auth_type == "api_key":
        if principal.api_key_id is None:
            raise RuntimeError("API-key context is missing an API-key ID")
        return "api_key", str(principal.api_key_id)
    return "user", str(access.context.user.id)


@router.post("/projects/{project_id}/webhook-destinations", status_code=status.HTTP_201_CREATED)
async def create_destination(
    payload: CreateWebhookDestinationRequest,
    request: Request,
    access: Annotated[ProjectAccess, Depends(require_project_permission("webhook.create"))],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
) -> dict[str, object]:
    actor_type, actor_id = _actor(access)
    result = await create_webhook_destination(
        db,
        project=access.project,
        user_id=access.context.user.id,
        actor_type=actor_type,
        actor_id=actor_id,
        idempotency_key=idempotency_key,
        request_id=request_id(request),
        payload=payload,
    )
    return success_payload(request, result)


@router.post("/projects/{project_id}/webhook-destinations/{destination_id}/verify")
async def verify_destination(
    payload: VerifyWebhookDestinationRequest,
    request: Request,
    destination_id: UUID,
    access: Annotated[ProjectAccess, Depends(require_project_permission("webhook.update"))],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    record = await get_webhook_destination(
        db, project_id=access.project.id, destination_id=destination_id
    )
    actor_type, actor_id = _actor(access)
    delivery = await verify_webhook_destination(
        db,
        record=record,
        expected_version=payload.expected_version,
        event_id=payload.event_id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
    )
    return success_payload(request, delivery_summary(delivery))


@router.get("/projects/{project_id}/webhook-destinations")
async def list_destinations(
    request: Request,
    access: Annotated[ProjectAccess, Depends(require_project_permission("webhook.read"))],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict[str, object]:
    position = decode_event_cursor(cursor, project_id=access.project.id, event_type=_CURSOR_KIND)
    rows, has_more = await list_webhook_destinations(
        db, project_id=access.project.id, cursor=position, limit=limit
    )
    next_cursor = None
    if has_more and rows:
        final = rows[-1]
        next_cursor = encode_event_cursor(
            project_id=access.project.id,
            event_type=_CURSOR_KIND,
            occurred_at=final.created_at,
            resource_id=final.id,
        )
    return {
        "data": [destination_summary(row) for row in rows],
        "meta": {
            "request_id": request_id(request),
            "page": {"next_cursor": next_cursor, "has_more": next_cursor is not None},
        },
    }


@router.get("/projects/{project_id}/webhook-destinations/{destination_id}")
async def get_destination(
    request: Request,
    destination_id: UUID,
    access: Annotated[ProjectAccess, Depends(require_project_permission("webhook.read"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    record = await get_webhook_destination(
        db, project_id=access.project.id, destination_id=destination_id
    )
    return success_payload(request, destination_summary(record))


@router.post("/projects/{project_id}/webhook-destinations/{destination_id}/rotate-signing-secret")
async def rotate_destination_secret(
    payload: RotateWebhookSigningSecretRequest,
    request: Request,
    destination_id: UUID,
    access: Annotated[ProjectAccess, Depends(require_project_permission("webhook.update"))],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    record = await get_webhook_destination(
        db, project_id=access.project.id, destination_id=destination_id
    )
    actor_type, actor_id = _actor(access)
    result = await rotate_webhook_signing_secret(
        db,
        record=record,
        user_id=access.context.user.id,
        expected_version=payload.expected_version,
        signing_secret=payload.signing_secret.get_secret_value(),
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
    )
    return success_payload(request, result)


@router.post("/projects/{project_id}/webhook-destinations/{destination_id}/disable")
async def disable_destination(
    payload: DisableWebhookDestinationRequest,
    request: Request,
    destination_id: UUID,
    access: Annotated[ProjectAccess, Depends(require_project_permission("webhook.update"))],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    record = await get_webhook_destination(
        db, project_id=access.project.id, destination_id=destination_id
    )
    actor_type, actor_id = _actor(access)
    result = await disable_webhook_destination(
        db,
        record=record,
        user_id=access.context.user.id,
        expected_version=payload.expected_version,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
    )
    return success_payload(request, result)
