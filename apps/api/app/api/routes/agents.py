from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...agent_schemas import (
    AgentSummary,
    AgentVersionDetail,
    AgentVersionSummary,
    CreateAgentRequest,
    CreateAgentVersionRequest,
    UpdateAgentRequest,
)
from ...core.database import get_db
from ...core.errors import ApiError, request_id, success_payload
from ...services.agents import (
    create_agent,
    create_agent_version,
    list_agent_versions,
    list_agents,
    update_agent,
)
from ..agent_dependencies import (
    AgentAccess,
    AgentVersionAccess,
    ProjectAccess,
    require_agent_permission,
    require_agent_version_permission,
    require_project_permission,
)
from ..dependencies import AuthContext, require_csrf

router = APIRouter(tags=["agents"])


def actor(context: AuthContext) -> tuple[str, str]:
    if context.principal.auth_type == "api_key":
        if context.principal.api_key_id is None:
            raise RuntimeError("API-key context is missing an API-key ID")
        return "api_key", str(context.principal.api_key_id)
    return "user", str(context.user.id)


def agent_etag(agent_id: UUID, version: int) -> str:
    return f'"agent-{agent_id}-version-{version}"'


def parse_agent_if_match(value: str | None, *, agent_id: UUID) -> int:
    if value is None:
        raise ApiError(
            status_code=428,
            code="VERSION_REQUIRED",
            message="If-Match is required for Agent updates.",
        )
    normalized = value.strip().strip('"')
    prefix = f"agent-{agent_id}-version-"
    if not normalized.startswith(prefix):
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="If-Match contains an invalid Agent version.",
        )
    try:
        version = int(normalized.removeprefix(prefix))
        if version < 1:
            raise ValueError("Agent versions start at one")
        return version
    except ValueError as exc:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="If-Match contains an invalid Agent version.",
        ) from exc


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


@router.get("/projects/{project_id}/agents")
async def agents_route(
    request: Request,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("agent.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, object]:
    records, next_cursor = await list_agents(
        db,
        organization_id=access.project.organization_id,
        project_id=access.project.id,
        cursor=cursor,
        limit=limit,
    )
    return collection_payload(
        request,
        [
            AgentSummary.model_validate(item).model_dump(mode="json")
            for item in records
        ],
        next_cursor=next_cursor,
    )


@router.post(
    "/projects/{project_id}/agents",
    status_code=status.HTTP_201_CREATED,
)
async def create_agent_route(
    payload: CreateAgentRequest,
    request: Request,
    response: Response,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("agent.create")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    record = await create_agent(
        db,
        project=access.project,
        actor_type=actor_type,
        actor_id=actor_id,
        created_by_user_id=access.context.user.id,
        payload=payload,
        request_id=request_id(request),
    )
    response.headers["ETag"] = agent_etag(record.id, record.version)
    return success_payload(
        request,
        AgentSummary.model_validate(record).model_dump(mode="json"),
    )


@router.get("/agents/{agent_id}")
async def agent_route(
    request: Request,
    response: Response,
    access: Annotated[
        AgentAccess,
        Depends(require_agent_permission("agent.read")),
    ],
) -> dict[str, object]:
    response.headers["ETag"] = agent_etag(
        access.agent.id,
        access.agent.version,
    )
    return success_payload(
        request,
        AgentSummary.model_validate(access.agent).model_dump(mode="json"),
    )


@router.patch("/agents/{agent_id}")
async def update_agent_route(
    payload: UpdateAgentRequest,
    request: Request,
    response: Response,
    access: Annotated[
        AgentAccess,
        Depends(require_agent_permission("agent.update")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
    if_match: Annotated[str | None, Header(alias="If-Match")] = None,
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    record = await update_agent(
        db,
        agent=access.agent,
        actor_type=actor_type,
        actor_id=actor_id,
        payload=payload,
        expected_version=parse_agent_if_match(
            if_match,
            agent_id=access.agent.id,
        ),
        request_id=request_id(request),
    )
    response.headers["ETag"] = agent_etag(record.id, record.version)
    return success_payload(
        request,
        AgentSummary.model_validate(record).model_dump(mode="json"),
    )


@router.get("/agents/{agent_id}/versions")
async def agent_versions_route(
    request: Request,
    access: Annotated[
        AgentAccess,
        Depends(require_agent_permission("agent.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query(max_length=512)] = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
) -> dict[str, object]:
    records, next_cursor = await list_agent_versions(
        db,
        agent=access.agent,
        cursor=cursor,
        limit=limit,
    )
    return collection_payload(
        request,
        [
            AgentVersionSummary.model_validate(item).model_dump(mode="json")
            for item in records
        ],
        next_cursor=next_cursor,
    )


@router.post(
    "/agents/{agent_id}/versions",
    status_code=status.HTTP_201_CREATED,
)
async def create_agent_version_route(
    payload: CreateAgentVersionRequest,
    request: Request,
    access: Annotated[
        AgentAccess,
        Depends(require_agent_permission("agent.version_create")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    record = await create_agent_version(
        db,
        agent=access.agent,
        actor_type=actor_type,
        actor_id=actor_id,
        created_by_user_id=access.context.user.id,
        payload=payload,
        request_id=request_id(request),
    )
    return success_payload(
        request,
        AgentVersionDetail.model_validate(record).model_dump(mode="json"),
    )


@router.get("/agent-versions/{version_id}")
async def agent_version_route(
    request: Request,
    access: Annotated[
        AgentVersionAccess,
        Depends(require_agent_version_permission("agent.read")),
    ],
) -> dict[str, object]:
    return success_payload(
        request,
        AgentVersionDetail.model_validate(
            access.agent_version
        ).model_dump(mode="json"),
    )
