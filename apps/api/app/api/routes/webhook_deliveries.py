from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import request_id, success_payload
from ...core.pagination import decode_event_cursor, encode_event_cursor
from ...services.webhook_deliveries import (
    delivery_summary,
    get_webhook_delivery,
    list_webhook_deliveries,
    list_webhook_delivery_transitions,
    replay_webhook_delivery,
    transition_summary,
)
from ...webhook_delivery_schemas import ReplayWebhookDeliveryRequest
from ..agent_dependencies import ProjectAccess, require_project_permission
from ..dependencies import AuthContext, require_csrf

router = APIRouter(tags=["webhook-deliveries"])


def _actor(access: ProjectAccess) -> tuple[str, str]:
    principal = access.context.principal
    if principal.auth_type == "api_key":
        if principal.api_key_id is None:
            raise RuntimeError("API-key context is missing an API-key ID")
        return "api_key", str(principal.api_key_id)
    return "user", str(access.context.user.id)


def _cursor_kind(status: str | None, destination_id: UUID | None) -> str:
    return f"webhook-deliveries:{status or '*'}:{destination_id or '*'}"


@router.get("/projects/{project_id}/webhook-deliveries")
async def list_deliveries(
    request: Request,
    access: Annotated[ProjectAccess, Depends(require_project_permission("webhook.read"))],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    delivery_status: Annotated[
        str | None,
        Query(
            alias="status",
            pattern="^(PENDING|CLAIMED|RETRY_WAIT|SUCCEEDED|DEAD_LETTERED|CANCELLED)$",
        ),
    ] = None,
    destination_id: Annotated[UUID | None, Query()] = None,
) -> dict[str, object]:
    kind = _cursor_kind(delivery_status, destination_id)
    position = decode_event_cursor(cursor, project_id=access.project.id, event_type=kind)
    rows, has_more = await list_webhook_deliveries(
        db,
        project_id=access.project.id,
        status=delivery_status,
        destination_id=destination_id,
        cursor=position,
        limit=limit,
    )
    next_cursor = None
    if has_more and rows:
        final = rows[-1]
        next_cursor = encode_event_cursor(
            project_id=access.project.id,
            event_type=kind,
            occurred_at=final.created_at,
            resource_id=final.id,
        )
    return {
        "data": [delivery_summary(row) for row in rows],
        "meta": {
            "request_id": request_id(request),
            "page": {"next_cursor": next_cursor, "has_more": next_cursor is not None},
        },
    }


@router.get("/projects/{project_id}/webhook-deliveries/{delivery_id}")
async def get_delivery(
    request: Request,
    delivery_id: UUID,
    access: Annotated[ProjectAccess, Depends(require_project_permission("webhook.read"))],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    delivery = await get_webhook_delivery(db, project_id=access.project.id, delivery_id=delivery_id)
    transitions = await list_webhook_delivery_transitions(
        db, project_id=access.project.id, delivery_id=delivery_id
    )
    return success_payload(
        request,
        {
            "delivery": delivery_summary(delivery),
            "transitions": [transition_summary(item) for item in transitions],
        },
    )


@router.post("/projects/{project_id}/webhook-deliveries/{delivery_id}/replay")
async def replay_delivery(
    payload: ReplayWebhookDeliveryRequest,
    request: Request,
    delivery_id: UUID,
    access: Annotated[ProjectAccess, Depends(require_project_permission("webhook.update"))],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
) -> dict[str, object]:
    actor_type, actor_id = _actor(access)
    delivery = await replay_webhook_delivery(
        db,
        project_id=access.project.id,
        delivery_id=delivery_id,
        expected_version=payload.expected_version,
        idempotency_key=idempotency_key,
        user_id=access.context.user.id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
    )
    return success_payload(request, delivery_summary(delivery))
