from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import request_id, success_payload
from ...core.pagination import (
    decode_egress_policy_list_cursor,
    decode_egress_policy_revision_cursor,
    encode_egress_policy_list_cursor,
    encode_egress_policy_revision_cursor,
    normalize_limit,
)
from ...egress_policy_schemas import (
    ActivateEgressPolicyRequest,
    CreateEgressPolicyRequest,
    CreateEgressPolicyRevisionRequest,
    DisableEgressPolicyRequest,
)
from ...services.egress_health import (
    summarize_egress_health,
    summarize_egress_health_routes,
)
from ...services.egress_policies import (
    activate_egress_policy,
    create_egress_policy,
    create_egress_policy_revision,
    disable_egress_policy,
    list_egress_policies,
    list_egress_policy_revisions,
    policy_summary,
    revision_summary,
)
from ..agent_dependencies import (
    EgressPolicyAccess,
    ProjectAccess,
    require_egress_policy_permission,
    require_project_permission,
)
from ..dependencies import AuthContext, require_csrf

router = APIRouter(tags=["egress-policies"])


def _actor(context: AuthContext) -> tuple[str, str]:
    if context.principal.auth_type == "api_key":
        if context.principal.api_key_id is None:
            raise RuntimeError("API-key context is missing an API-key ID")
        return "api_key", str(context.principal.api_key_id)
    return "user", str(context.user.id)


@router.get("/projects/{project_id}/egress-health/summary")
async def get_egress_health_summary(
    request: Request,
    access: Annotated[ProjectAccess, Depends(require_project_permission("egress.read"))],
    db: Annotated[AsyncSession, Depends(get_db)],
    window_hours: Annotated[int, Query(ge=1, le=24)] = 1,
) -> dict[str, object]:
    result = await summarize_egress_health(
        db,
        project_id=access.project.id,
        window_hours=window_hours,
    )
    return success_payload(request, result)


@router.get("/projects/{project_id}/egress-health/routes")
async def get_egress_health_routes(
    request: Request,
    access: Annotated[ProjectAccess, Depends(require_project_permission("egress.read"))],
    db: Annotated[AsyncSession, Depends(get_db)],
    window_hours: Annotated[int, Query(ge=1, le=24)] = 1,
) -> dict[str, object]:
    result = await summarize_egress_health_routes(
        db,
        project_id=access.project.id,
        window_hours=window_hours,
    )
    return success_payload(request, result)


@router.post("/projects/{project_id}/egress-policies", status_code=status.HTTP_201_CREATED)
async def create_policy(
    payload: CreateEgressPolicyRequest,
    request: Request,
    access: Annotated[ProjectAccess, Depends(require_project_permission("egress.create"))],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
) -> dict[str, object]:
    actor_type, actor_id = _actor(access.context)
    result = await create_egress_policy(
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


@router.get("/projects/{project_id}/egress-policies")
async def list_policies(
    request: Request,
    access: Annotated[ProjectAccess, Depends(require_project_permission("egress.read"))],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
    policy_status: Annotated[
        str | None, Query(alias="status", pattern="^(DRAFT|ACTIVE|DISABLED)$")
    ] = None,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_egress_policy_list_cursor(
        cursor, project_id=access.project.id, status=policy_status
    )
    rows, has_more = await list_egress_policies(
        db,
        project_id=access.project.id,
        status=policy_status,
        cursor=position,
        limit=normalized,
    )
    next_cursor = None
    if has_more and rows:
        final = rows[-1]
        next_cursor = encode_egress_policy_list_cursor(
            project_id=access.project.id,
            status=policy_status,
            created_at=final.created_at,
            resource_id=final.id,
        )
    return {
        "data": [policy_summary(row) for row in rows],
        "meta": {
            "request_id": request_id(request),
            "page": {"next_cursor": next_cursor, "has_more": next_cursor is not None},
        },
    }


@router.get("/egress-policies/{policy_id}")
async def get_policy(
    request: Request,
    access: Annotated[EgressPolicyAccess, Depends(require_egress_policy_permission("egress.read"))],
) -> dict[str, object]:
    return success_payload(request, policy_summary(access.policy))


@router.get("/egress-policies/{policy_id}/revisions")
async def list_revisions(
    request: Request,
    access: Annotated[EgressPolicyAccess, Depends(require_egress_policy_permission("egress.read"))],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_egress_policy_revision_cursor(cursor, policy_id=access.policy.id)
    rows, has_more = await list_egress_policy_revisions(
        db, policy_id=access.policy.id, cursor=position, limit=normalized
    )
    next_cursor = None
    if has_more and rows:
        next_cursor = encode_egress_policy_revision_cursor(
            policy_id=access.policy.id, revision_number=rows[-1].revision_number
        )
    return {
        "data": [revision_summary(row) for row in rows],
        "meta": {
            "request_id": request_id(request),
            "page": {"next_cursor": next_cursor, "has_more": next_cursor is not None},
        },
    }


@router.post("/egress-policies/{policy_id}/revisions", status_code=status.HTTP_201_CREATED)
async def create_revision(
    payload: CreateEgressPolicyRevisionRequest,
    request: Request,
    access: Annotated[
        EgressPolicyAccess, Depends(require_egress_policy_permission("egress.update"))
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = _actor(access.context)
    revision = await create_egress_policy_revision(
        db,
        policy_id=access.policy.id,
        user_id=access.context.user.id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
        payload=payload,
    )
    return success_payload(request, revision_summary(revision))


@router.post("/egress-policies/{policy_id}/activate")
async def activate_policy(
    payload: ActivateEgressPolicyRequest,
    request: Request,
    access: Annotated[
        EgressPolicyAccess, Depends(require_egress_policy_permission("egress.update"))
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = _actor(access.context)
    policy = await activate_egress_policy(
        db,
        policy_id=access.policy.id,
        revision_id=payload.revision_id,
        expected_version=payload.expected_version,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
    )
    return success_payload(request, policy_summary(policy))


@router.post("/egress-policies/{policy_id}/disable")
async def disable_policy(
    payload: DisableEgressPolicyRequest,
    request: Request,
    access: Annotated[
        EgressPolicyAccess, Depends(require_egress_policy_permission("egress.update"))
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = _actor(access.context)
    policy = await disable_egress_policy(
        db,
        policy_id=access.policy.id,
        expected_version=payload.expected_version,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
    )
    return success_payload(request, policy_summary(policy))
