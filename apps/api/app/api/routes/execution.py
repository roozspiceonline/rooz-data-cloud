from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import request_id
from ...core.pagination import decode_cursor, encode_cursor, normalize_limit
from ...services.execution_plane import (
    artifact_summary,
    lease_summary,
    list_project_artifacts,
    list_project_leases,
)
from ..agent_dependencies import (
    ProjectAccess,
    require_project_permission,
)

router = APIRouter(tags=["execution-plane"])


def collection_payload(
    request: Request,
    data: list[dict[str, object]],
    *,
    next_cursor: str | None,
) -> dict[str, object]:
    return {
        "data": data,
        "meta": {
            "request_id": request_id(request),
            "page": {
                "next_cursor": next_cursor,
                "has_more": next_cursor is not None,
            },
        },
    }


@router.get("/projects/{project_id}/execution-leases")
async def list_execution_leases_route(
    request: Request,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("execution.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_cursor(cursor)
    records, has_more = await list_project_leases(
        db,
        project_id=access.project.id,
        cursor=position,
        limit=normalized,
    )
    next_cursor = None
    if has_more and records:
        final = records[-1]
        next_cursor = encode_cursor(
            created_at=final.created_at,
            resource_id=final.id,
        )
    data = [
        lease_summary(record).model_dump(mode="json")
        for record in records
    ]
    return collection_payload(request, data, next_cursor=next_cursor)


@router.get("/projects/{project_id}/execution-artifacts")
async def list_execution_artifacts_route(
    request: Request,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("execution.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_cursor(cursor)
    records, has_more = await list_project_artifacts(
        db,
        project_id=access.project.id,
        cursor=position,
        limit=normalized,
    )
    next_cursor = None
    if has_more and records:
        final = records[-1]
        next_cursor = encode_cursor(
            created_at=final.created_at,
            resource_id=final.id,
        )
    data = [
        artifact_summary(record).model_dump(mode="json")
        for record in records
    ]
    return collection_payload(request, data, next_cursor=next_cursor)
