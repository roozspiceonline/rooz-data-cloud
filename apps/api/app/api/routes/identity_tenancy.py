from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.config import get_settings
from ...core.database import get_db
from ...core.errors import ApiError, request_id, success_payload
from ...core.rate_limit import enforce_auth_rate_limit
from ...core.security import derive_csrf_token
from ...schemas import (
    ApiKeySummary,
    CreateApiKeyRequest,
    CreatedApiKeyResponse,
    CreateOrganizationRequest,
    CreateProjectRequest,
    LoginRequest,
    MembershipSummary,
    OrganizationSummary,
    ProjectSummary,
    RegisterRequest,
    SessionResponse,
    UpdateMembershipRoleRequest,
    UserSummary,
)
from ...services.identity_tenancy import (
    IssuedSession,
    create_api_key,
    create_organization,
    create_project,
    list_api_keys,
    list_memberships,
    list_organizations,
    list_projects,
    load_session_context,
    login,
    register,
    revoke_api_key,
    revoke_session,
    update_membership_role,
)
from ..dependencies import (
    AuthContext,
    Principal,
    require_allowed_origin,
    require_csrf,
    require_organization_permission,
    require_session_auth,
)

router = APIRouter()
settings = get_settings()


def client_ip(request: Request) -> str:
    return request.client.host if request.client is not None else "unknown"


def set_session_cookie(response: Response, issued: IssuedSession) -> None:
    response.set_cookie(
        key=settings.session_cookie_name,
        value=issued.raw_token,
        path="/",
        secure=settings.session_cookie_secure,
        httponly=True,
        samesite="lax",
        max_age=settings.session_absolute_hours * 3600,
    )


def context_for_issued_session(issued: IssuedSession) -> AuthContext:
    return AuthContext(
        principal=Principal(
            auth_type="session",
            user_id=issued.user.id,
            session_id=issued.session.id,
            api_key_id=None,
            organization_id=None,
            scopes=frozenset(),
        ),
        user=issued.user,
        session=issued.session,
        api_key=None,
    )


async def session_payload(
    request: Request,
    db: AsyncSession,
    context: AuthContext,
) -> dict[str, object]:
    memberships, organizations = await load_session_context(
        db,
        user_id=context.user.id,
    )
    csrf_token = (
        derive_csrf_token(
            session_id=context.session.id,
            session_token_digest=context.session.token_digest,
            pepper=settings.csrf_token_pepper,
        )
        if context.session is not None
        else ""
    )
    data = SessionResponse(
        user=UserSummary(
            id=context.user.id,
            email=context.user.email_display,
            display_name=context.user.display_name,
        ),
        memberships=[
            MembershipSummary.model_validate(item)
            for item in memberships
        ],
        organizations=[
            OrganizationSummary.model_validate(item)
            for item in organizations
        ],
        csrf_token=csrf_token,
    )
    return success_payload(request, data.model_dump(mode="json"))


@router.post("/auth/register", status_code=201, tags=["authentication"])
async def register_route(
    payload: RegisterRequest,
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(require_allowed_origin)],
) -> dict[str, object]:
    await enforce_auth_rate_limit("register-ip", client_ip(request))
    await enforce_auth_rate_limit(
        "register-email",
        str(payload.email).casefold(),
    )
    issued = await register(
        db,
        payload=payload,
        request_id=request_id(request),
        user_agent=request.headers.get("user-agent"),
        client_ip=client_ip(request),
    )
    set_session_cookie(response, issued)
    return await session_payload(
        request,
        db,
        context_for_issued_session(issued),
    )


@router.post("/auth/login", tags=["authentication"])
async def login_route(
    payload: LoginRequest,
    request: Request,
    response: Response,
    db: Annotated[AsyncSession, Depends(get_db)],
    _: Annotated[None, Depends(require_allowed_origin)],
) -> dict[str, object]:
    await enforce_auth_rate_limit("login-ip", client_ip(request))
    await enforce_auth_rate_limit(
        "login-email",
        str(payload.email).casefold(),
    )
    issued = await login(
        db,
        payload=payload,
        request_id=request_id(request),
        user_agent=request.headers.get("user-agent"),
        client_ip=client_ip(request),
    )
    set_session_cookie(response, issued)
    return await session_payload(
        request,
        db,
        context_for_issued_session(issued),
    )


@router.get("/auth/session", tags=["authentication"])
async def session_route(
    request: Request,
    context: Annotated[
        AuthContext,
        Depends(require_session_auth),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    return await session_payload(request, db, context)


@router.post(
    "/auth/logout",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["authentication"],
)
async def logout_route(
    request: Request,
    response: Response,
    context: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    if context.session is not None:
        await revoke_session(
            db,
            record=context.session,
            request_id=request_id(request),
        )
    response.delete_cookie(
        key=settings.session_cookie_name,
        path="/",
    )
    response.status_code = status.HTTP_204_NO_CONTENT
    return response


@router.get("/organizations", tags=["organizations"])
async def organizations_route(
    request: Request,
    context: Annotated[
        AuthContext,
        Depends(require_session_auth),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    organizations = await list_organizations(
        db,
        user_id=context.user.id,
    )
    return success_payload(
        request,
        [
            OrganizationSummary.model_validate(item).model_dump(
                mode="json"
            )
            for item in organizations
        ],
    )


@router.post(
    "/organizations",
    status_code=status.HTTP_201_CREATED,
    tags=["organizations"],
)
async def create_organization_route(
    payload: CreateOrganizationRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(require_csrf)],
    _: Annotated[AuthContext, Depends(require_session_auth)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    organization = await create_organization(
        db,
        user_id=context.user.id,
        payload=payload,
        request_id=request_id(request),
    )
    return success_payload(
        request,
        OrganizationSummary.model_validate(
            organization
        ).model_dump(mode="json"),
    )


@router.get(
    "/organizations/{organization_id}/projects",
    tags=["projects"],
)
async def projects_route(
    organization_id: UUID,
    request: Request,
    _: Annotated[
        AuthContext,
        Depends(require_organization_permission("project.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    projects = await list_projects(
        db,
        organization_id=organization_id,
    )
    return success_payload(
        request,
        [
            ProjectSummary.model_validate(item).model_dump(mode="json")
            for item in projects
        ],
    )


@router.post(
    "/organizations/{organization_id}/projects",
    status_code=status.HTTP_201_CREATED,
    tags=["projects"],
)
async def create_project_route(
    organization_id: UUID,
    payload: CreateProjectRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(require_csrf)],
    _: Annotated[
        AuthContext,
        Depends(require_organization_permission("project.create")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    project = await create_project(
        db,
        organization_id=organization_id,
        user_id=context.user.id,
        payload=payload,
        request_id=request_id(request),
    )
    return success_payload(
        request,
        ProjectSummary.model_validate(project).model_dump(mode="json"),
    )


@router.get(
    "/organizations/{organization_id}/memberships",
    tags=["memberships"],
)
async def memberships_route(
    organization_id: UUID,
    request: Request,
    _: Annotated[
        AuthContext,
        Depends(require_organization_permission("membership.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    memberships = await list_memberships(
        db,
        organization_id=organization_id,
    )
    return success_payload(
        request,
        [
            MembershipSummary.model_validate(item).model_dump(
                mode="json"
            )
            for item in memberships
        ],
    )


def parse_if_match(value: str | None) -> int:
    if value is None:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="If-Match is required for membership role changes.",
        )
    normalized = value.strip().strip('"')
    normalized = normalized.removeprefix("membership-version-")
    try:
        return int(normalized)
    except ValueError as exc:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="If-Match contains an invalid membership version.",
        ) from exc


@router.patch(
    "/organizations/{organization_id}/memberships/{membership_id}",
    tags=["memberships"],
)
async def update_membership_route(
    organization_id: UUID,
    membership_id: UUID,
    payload: UpdateMembershipRoleRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(require_csrf)],
    _: Annotated[
        AuthContext,
        Depends(
            require_organization_permission(
                "membership.update_role"
            )
        ),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    if_match: Annotated[
        str | None,
        Header(alias="If-Match"),
    ] = None,
) -> dict[str, object]:
    membership = await update_membership_role(
        db,
        organization_id=organization_id,
        membership_id=membership_id,
        actor_user_id=context.user.id,
        payload=payload,
        expected_version=parse_if_match(if_match),
        request_id=request_id(request),
    )
    return success_payload(
        request,
        MembershipSummary.model_validate(
            membership
        ).model_dump(mode="json"),
    )


@router.get(
    "/organizations/{organization_id}/api-keys",
    tags=["api-keys"],
)
async def api_keys_route(
    organization_id: UUID,
    request: Request,
    _: Annotated[
        AuthContext,
        Depends(
            require_organization_permission(
                "api_key.read_metadata"
            )
        ),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    records = await list_api_keys(
        db,
        organization_id=organization_id,
    )
    return success_payload(
        request,
        [
            ApiKeySummary.model_validate(item).model_dump(mode="json")
            for item in records
        ],
    )


@router.post(
    "/organizations/{organization_id}/api-keys",
    status_code=status.HTTP_201_CREATED,
    tags=["api-keys"],
)
async def create_api_key_route(
    organization_id: UUID,
    payload: CreateApiKeyRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(require_csrf)],
    _: Annotated[
        AuthContext,
        Depends(require_organization_permission("api_key.create")),
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
    record, raw_token = await create_api_key(
        db,
        organization_id=organization_id,
        user_id=context.user.id,
        payload=payload,
        idempotency_key=idempotency_key,
        request_id=request_id(request),
    )
    data = CreatedApiKeyResponse(
        key=ApiKeySummary.model_validate(record),
        token=raw_token,
    )
    return success_payload(request, data.model_dump(mode="json"))


@router.delete(
    "/organizations/{organization_id}/api-keys/{api_key_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    tags=["api-keys"],
)
async def revoke_api_key_route(
    organization_id: UUID,
    api_key_id: UUID,
    request: Request,
    context: Annotated[AuthContext, Depends(require_csrf)],
    _: Annotated[
        AuthContext,
        Depends(require_organization_permission("api_key.revoke")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> None:
    await revoke_api_key(
        db,
        organization_id=organization_id,
        api_key_id=api_key_id,
        actor_user_id=context.user.id,
        request_id=request_id(request),
    )
