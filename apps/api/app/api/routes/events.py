from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import request_id
from ...core.pagination import decode_event_cursor, encode_event_cursor
from ...services.events import event_summary, list_events
from ..agent_dependencies import ProjectAccess, require_project_permission

router = APIRouter(tags=["events"])


@router.get("/projects/{project_id}/events")
async def list_project_events(
    request: Request,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("event.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
    event_type: Annotated[
        str | None,
        Query(pattern=r"^(build\.created|run\.created)$"),
    ] = None,
) -> dict[str, object]:
    position = decode_event_cursor(
        cursor,
        project_id=access.project.id,
        event_type=event_type,
    )
    events, has_more = await list_events(
        db,
        project_id=access.project.id,
        event_type=event_type,
        cursor=position,
        limit=limit,
    )
    next_cursor = None
    if has_more and events:
        final = events[-1]
        next_cursor = encode_event_cursor(
            project_id=access.project.id,
            event_type=event_type,
            occurred_at=final.occurred_at,
            resource_id=final.id,
        )
    return {
        "data": [event_summary(event) for event in events],
        "meta": {
            "request_id": request_id(request),
            "page": {
                "next_cursor": next_cursor,
                "has_more": next_cursor is not None,
            },
        },
    }
