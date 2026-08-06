from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Literal
from uuid import UUID

from fastapi import Depends, Header, Path, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.database import (
    get_db,
    set_api_key_lookup_context,
    set_identity_context,
    set_tenant_context,
)
from ..core.errors import ApiError
from ..core.permissions import role_has_permission
from ..core.security import is_expired, secret_digest, verify_csrf_token
from ..models import ApiKey, OrganizationMembership, Session, User

settings = get_settings()


@dataclass(frozen=True)
class Principal:
    auth_type: Literal["session", "api_key"]
    user_id: UUID
    session_id: UUID | None
    api_key_id: UUID | None
    organization_id: UUID | None
    scopes: frozenset[str]


@dataclass(frozen=True)
class AuthContext:
    principal: Principal
    user: User
    session: Session | None
    api_key: ApiKey | None


async def resolve_auth_context(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> AuthContext:
    now = datetime.now(UTC)

    if authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.casefold() != "bearer" or not token:
            raise ApiError(
                status_code=401,
                code="AUTH_REQUIRED",
                message="Authentication is required.",
            )
        token_hash = secret_digest(token, settings.api_key_pepper)
        await set_api_key_lookup_context(db, token_hash.hex())
        api_key = await db.scalar(
            select(ApiKey).where(ApiKey.token_digest == token_hash)
        )
        if (
            api_key is None
            or api_key.revoked_at is not None
            or is_expired(api_key.expires_at, now=now)
        ):
            raise ApiError(
                status_code=401,
                code="CREDENTIAL_INVALID",
                message="The API credential is invalid.",
            )
        user = await db.scalar(
            select(User).where(User.id == api_key.created_by_user_id)
        )
        if user is None or user.status != "ACTIVE":
            raise ApiError(
                status_code=401,
                code="CREDENTIAL_INVALID",
                message="The API credential is invalid.",
            )
        await set_tenant_context(
            db,
            user_id=user.id,
            organization_id=api_key.organization_id,
        )
        api_key.last_used_at = now
        return AuthContext(
            principal=Principal(
                auth_type="api_key",
                user_id=user.id,
                session_id=None,
                api_key_id=api_key.id,
                organization_id=api_key.organization_id,
                scopes=frozenset(api_key.scopes),
            ),
            user=user,
            session=None,
            api_key=api_key,
        )

    raw_session = request.cookies.get(settings.session_cookie_name)
    if not raw_session:
        raise ApiError(
            status_code=401,
            code="AUTH_REQUIRED",
            message="Authentication is required.",
        )

    token_hash = secret_digest(
        raw_session,
        settings.session_token_pepper,
    )
    record = await db.scalar(
        select(Session).where(Session.token_digest == token_hash)
    )
    if record is None or record.revoked_at is not None:
        raise ApiError(
            status_code=401,
            code="AUTH_REQUIRED",
            message="Authentication is required.",
        )
    if record.idle_expires_at <= now or record.absolute_expires_at <= now:
        record.revoked_at = now
        record.revoke_reason = "expired"
        raise ApiError(
            status_code=401,
            code="SESSION_EXPIRED",
            message="The session expired. Sign in again.",
        )

    user = await db.scalar(select(User).where(User.id == record.user_id))
    if user is None or user.status != "ACTIVE":
        raise ApiError(
            status_code=401,
            code="AUTH_REQUIRED",
            message="Authentication is required.",
        )
    await set_identity_context(db, user.id)

    if record.last_seen_at <= now - timedelta(minutes=5):
        record.last_seen_at = now
        record.idle_expires_at = min(
            now + timedelta(minutes=settings.session_idle_minutes),
            record.absolute_expires_at,
        )

    return AuthContext(
        principal=Principal(
            auth_type="session",
            user_id=user.id,
            session_id=record.id,
            api_key_id=None,
            organization_id=None,
            scopes=frozenset(),
        ),
        user=user,
        session=record,
        api_key=None,
    )


async def require_session_auth(
    context: Annotated[AuthContext, Depends(resolve_auth_context)],
) -> AuthContext:
    if context.principal.auth_type != "session":
        raise ApiError(
            status_code=403,
            code="PERMISSION_DENIED",
            message="This operation requires a browser session.",
        )
    return context


async def require_csrf(
    context: Annotated[AuthContext, Depends(resolve_auth_context)],
    csrf_token: Annotated[
        str | None,
        Header(alias="X-RDC-CSRF"),
    ] = None,
) -> AuthContext:
    if context.principal.auth_type == "api_key":
        return context
    if context.session is None or not csrf_token:
        raise ApiError(
            status_code=400,
            code="AUTH_CSRF_INVALID",
            message="The CSRF token is missing or invalid.",
        )
    valid = verify_csrf_token(
        supplied_token=csrf_token,
        session_id=context.session.id,
        session_token_digest=context.session.token_digest,
        expected_digest=context.session.csrf_token_digest,
        pepper=settings.csrf_token_pepper,
    )
    if not valid:
        raise ApiError(
            status_code=400,
            code="AUTH_CSRF_INVALID",
            message="The CSRF token is missing or invalid.",
        )
    return context


def require_organization_permission(
    permission: str,
) -> Callable[[UUID, AuthContext, AsyncSession], Awaitable[AuthContext]]:
    async def dependency(
        organization_id: Annotated[UUID, Path()],
        context: Annotated[
            AuthContext,
            Depends(resolve_auth_context),
        ],
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> AuthContext:
        if context.principal.auth_type == "api_key":
            if (
                context.principal.organization_id != organization_id
                or permission not in context.principal.scopes
            ):
                raise ApiError(
                    status_code=404,
                    code="RESOURCE_NOT_FOUND",
                    message="The requested resource was not found.",
                )
            return context

        membership = await db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id
                == organization_id,
                OrganizationMembership.user_id == context.user.id,
                OrganizationMembership.status == "ACTIVE",
            )
        )
        if membership is None:
            raise ApiError(
                status_code=404,
                code="RESOURCE_NOT_FOUND",
                message="The requested resource was not found.",
            )
        if not role_has_permission(membership.role, permission):
            raise ApiError(
                status_code=403,
                code="PERMISSION_DENIED",
                message="You do not have permission to perform this action.",
            )
        await set_tenant_context(
            db,
            user_id=context.user.id,
            organization_id=organization_id,
        )
        return context

    return dependency


def require_allowed_origin(request: Request) -> None:
    origin = request.headers.get("origin")
    if origin is not None and origin not in settings.allowed_origins:
        raise ApiError(
            status_code=403,
            code="PERMISSION_DENIED",
            message="The request origin is not allowed.",
        )
