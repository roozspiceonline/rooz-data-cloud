from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...build_secret_schemas import (
    BuildSummary,
    CreateProjectSecretRequest,
    ProjectSecretSummary,
    ReplaceProjectSecretRequest,
)
from ...core.database import get_db
from ...core.errors import ApiError, request_id, success_payload
from ...core.pagination import decode_cursor, encode_cursor, normalize_limit
from ...services.builds_secrets import (
    build_metadata,
    create_build,
    create_project_secret,
    delete_project_secret,
    list_agent_builds,
    list_project_secrets,
    parse_secret_if_match,
    replace_project_secret,
    secret_metadata,
)
from ..agent_dependencies import (
    AgentAccess,
    AgentVersionAccess,
    BuildAccess,
    ProjectAccess,
    ProjectSecretAccess,
    require_agent_permission,
    require_agent_version_permission,
    require_build_permission,
    require_project_permission,
    require_project_secret_permission,
)
from ..dependencies import AuthContext, require_csrf

router = APIRouter()


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


@router.get("/projects/{project_id}/secrets", tags=["project-secrets"])
async def list_project_secrets_route(
    request: Request,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("secret.read_metadata")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_cursor(cursor)
    records, has_more = await list_project_secrets(
        db,
        project_id=access.project.id,
        cursor=position,
        limit=normalized,
    )
    next_cursor = None
    if has_more and records:
        last = records[-1]
        next_cursor = encode_cursor(
            created_at=last.created_at,
            resource_id=last.id,
        )
    data = [
        ProjectSecretSummary.model_validate(secret_metadata(item)).model_dump(
            mode="json"
        )
        for item in records
    ]
    return collection_payload(request, data, next_cursor=next_cursor)


@router.post(
    "/projects/{project_id}/secrets",
    status_code=status.HTTP_201_CREATED,
    tags=["project-secrets"],
)
async def create_project_secret_route(
    payload: CreateProjectSecretRequest,
    request: Request,
    response: Response,
    context: Annotated[AuthContext, Depends(require_csrf)],
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("secret.create")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    record = await create_project_secret(
        db,
        organization_id=access.project.organization_id,
        project_id=access.project.id,
        user_id=context.user.id,
        payload=payload,
        request_id=request_id(request),
    )
    data = ProjectSecretSummary.model_validate(secret_metadata(record))
    response.headers["ETag"] = data.etag
    return success_payload(request, data.model_dump(mode="json"))


@router.put("/secrets/{secret_id}", tags=["project-secrets"])
async def replace_project_secret_route(
    secret_id: UUID,
    payload: ReplaceProjectSecretRequest,
    request: Request,
    response: Response,
    context: Annotated[AuthContext, Depends(require_csrf)],
    access: Annotated[
        ProjectSecretAccess,
        Depends(require_project_secret_permission("secret.replace")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    idempotency_key: Annotated[
        str | None,
        Header(alias="Idempotency-Key"),
    ] = None,
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> dict[str, object]:
    if idempotency_key is None:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="Idempotency-Key is required.",
        )
    if if_match is None:
        raise ApiError(
            status_code=428,
            code="INVALID_REQUEST",
            message="If-Match is required.",
        )
    expected_version = parse_secret_if_match(if_match, secret_id=secret_id)
    result = await replace_project_secret(
        db,
        record=access.secret,
        user_id=context.user.id,
        expected_version=expected_version,
        idempotency_key=idempotency_key,
        payload=payload,
        request_id=request_id(request),
    )
    data = ProjectSecretSummary.model_validate(result)
    response.headers["ETag"] = data.etag
    return success_payload(request, data.model_dump(mode="json"))


@router.delete(
    "/secrets/{secret_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["project-secrets"],
)
async def delete_project_secret_route(
    context: Annotated[AuthContext, Depends(require_csrf)],
    access: Annotated[
        ProjectSecretAccess,
        Depends(require_project_secret_permission("secret.delete")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    request: Request,
) -> None:
    await delete_project_secret(
        db,
        record=access.secret,
        user_id=context.user.id,
        request_id=request_id(request),
    )


@router.post(
    "/agent-versions/{version_id}/builds",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["builds"],
)
async def create_build_route(
    request: Request,
    context: Annotated[AuthContext, Depends(require_csrf)],
    access: Annotated[
        AgentVersionAccess,
        Depends(require_agent_version_permission("build.create")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    idempotency_key: Annotated[
        str | None,
        Header(alias="Idempotency-Key"),
    ] = None,
) -> dict[str, object]:
    if idempotency_key is None:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="Idempotency-Key is required.",
        )
    result = await create_build(
        db,
        version=access.agent_version,
        user_id=context.user.id,
        idempotency_key=idempotency_key,
        request_id=request_id(request),
    )
    data = BuildSummary.model_validate(result)
    return success_payload(request, data.model_dump(mode="json"))


@router.get("/builds/{build_id}", tags=["builds"])
async def get_build_route(
    request: Request,
    access: Annotated[
        BuildAccess,
        Depends(require_build_permission("build.read")),
    ],
) -> dict[str, object]:
    data = BuildSummary.model_validate(build_metadata(access.build))
    return success_payload(request, data.model_dump(mode="json"))


@router.get("/agents/{agent_id}/builds", tags=["builds"])
async def list_agent_builds_route(
    request: Request,
    access: Annotated[
        AgentAccess,
        Depends(require_agent_permission("build.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_cursor(cursor)
    records, has_more = await list_agent_builds(
        db,
        agent_id=access.agent.id,
        cursor=position,
        limit=normalized,
    )
    next_cursor = None
    if has_more and records:
        last = records[-1]
        next_cursor = encode_cursor(
            created_at=last.created_at,
            resource_id=last.id,
        )
    data = [
        BuildSummary.model_validate(build_metadata(item)).model_dump(mode="json")
        for item in records
    ]
    return collection_payload(request, data, next_cursor=next_cursor)
