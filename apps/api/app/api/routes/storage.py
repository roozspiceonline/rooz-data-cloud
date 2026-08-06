from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import request_id, success_payload
from ...core.pagination import decode_cursor, encode_cursor, normalize_limit
from ...services.storage_delivery import (
    complete_source_upload,
    create_source_upload,
    issue_user_download_grant,
    list_storage_objects,
    storage_object_summary,
)
from ...storage_schemas import CreateSourceUploadRequest
from ..agent_dependencies import (
    AgentAccess,
    ProjectAccess,
    StorageObjectAccess,
    require_agent_permission,
    require_project_permission,
    require_storage_object_permission,
)
from ..dependencies import AuthContext, require_csrf

router = APIRouter(tags=["storage"])


def actor(context: AuthContext) -> tuple[str, str]:
    if context.principal.auth_type == "api_key":
        if context.principal.api_key_id is None:
            raise RuntimeError("API-key context is missing an API-key ID")
        return "api_key", str(context.principal.api_key_id)
    return "user", str(context.user.id)


@router.post(
    "/agents/{agent_id}/source-uploads",
    status_code=status.HTTP_201_CREATED,
)
async def create_source_upload_route(
    payload: CreateSourceUploadRequest,
    request: Request,
    access: Annotated[
        AgentAccess,
        Depends(require_agent_permission("storage.upload")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    result = await create_source_upload(
        db,
        agent=access.agent,
        user_id=access.context.user.id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
        payload=payload,
    )
    return success_payload(request, result.model_dump(mode="json"))


@router.post("/storage-objects/{storage_object_id}/complete")
async def complete_source_upload_route(
    request: Request,
    access: Annotated[
        StorageObjectAccess,
        Depends(require_storage_object_permission("storage.upload")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    record = await complete_source_upload(
        db,
        storage_object=access.storage_object,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
    )
    return success_payload(
        request,
        storage_object_summary(record).model_dump(mode="json"),
    )


@router.get("/projects/{project_id}/storage-objects")
async def list_storage_objects_route(
    request: Request,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("storage.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_cursor(cursor)
    records, has_more = await list_storage_objects(
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
    return {
        "data": [
            storage_object_summary(record).model_dump(mode="json")
            for record in records
        ],
        "meta": {
            "request_id": request_id(request),
            "page": {
                "next_cursor": next_cursor,
                "has_more": next_cursor is not None,
            },
        },
    }


@router.get("/storage-objects/{storage_object_id}")
async def get_storage_object_route(
    request: Request,
    access: Annotated[
        StorageObjectAccess,
        Depends(require_storage_object_permission("storage.read")),
    ],
) -> dict[str, object]:
    return success_payload(
        request,
        storage_object_summary(access.storage_object).model_dump(mode="json"),
    )


@router.post("/storage-objects/{storage_object_id}/download-grant")
async def create_storage_download_grant_route(
    request: Request,
    access: Annotated[
        StorageObjectAccess,
        Depends(require_storage_object_permission("storage.download")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    grant = await issue_user_download_grant(
        db,
        record=access.storage_object,
        user_id=access.context.user.id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
    )
    return success_payload(request, grant.model_dump(mode="json"))
