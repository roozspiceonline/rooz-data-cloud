from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Path
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import get_db, set_tenant_context
from ..core.errors import ApiError
from ..core.permissions import role_has_permission
from ..models import (
    Agent,
    AgentVersion,
    Build,
    OrganizationMembership,
    Project,
    ProjectSecret,
)
from .dependencies import AuthContext, resolve_auth_context


@dataclass(frozen=True)
class ProjectAccess:
    context: AuthContext
    project: Project


@dataclass(frozen=True)
class AgentAccess:
    context: AuthContext
    agent: Agent


@dataclass(frozen=True)
class AgentVersionAccess:
    context: AuthContext
    agent_version: AgentVersion


@dataclass(frozen=True)
class ProjectSecretAccess:
    context: AuthContext
    secret: ProjectSecret


@dataclass(frozen=True)
class BuildAccess:
    context: AuthContext
    build: Build


async def _resolved_organization_id(
    db: AsyncSession,
    *,
    function_name: str,
    resource_id: UUID,
) -> UUID:
    allowed = {
        "rdc_project_org",
        "rdc_agent_org",
        "rdc_agent_version_org",
        "rdc_project_secret_org",
        "rdc_build_org",
    }
    if function_name not in allowed:
        raise RuntimeError("Unsupported organization resolver")
    value = await db.scalar(
        text(
            f"SELECT security.{function_name}(:resource_id)"
        ),
        {"resource_id": str(resource_id)},
    )
    if value is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    return value if isinstance(value, UUID) else UUID(str(value))


async def _authorize_organization(
    db: AsyncSession,
    *,
    context: AuthContext,
    organization_id: UUID,
    permission: str,
) -> None:
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
        await set_tenant_context(
            db,
            user_id=context.user.id,
            organization_id=organization_id,
        )
        return

    await set_tenant_context(
        db,
        user_id=context.user.id,
        organization_id=organization_id,
    )
    membership = await db.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.organization_id == organization_id,
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


def require_project_permission(
    permission: str,
) -> Callable[..., Awaitable[ProjectAccess]]:
    async def dependency(
        project_id: Annotated[UUID, Path()],
        context: Annotated[AuthContext, Depends(resolve_auth_context)],
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> ProjectAccess:
        organization_id = await _resolved_organization_id(
            db,
            function_name="rdc_project_org",
            resource_id=project_id,
        )
        await _authorize_organization(
            db,
            context=context,
            organization_id=organization_id,
            permission=permission,
        )
        project = await db.scalar(
            select(Project).where(
                Project.id == project_id,
                Project.organization_id == organization_id,
                Project.deleted_at.is_(None),
            )
        )
        if project is None:
            raise ApiError(
                status_code=404,
                code="RESOURCE_NOT_FOUND",
                message="The requested resource was not found.",
            )
        return ProjectAccess(context=context, project=project)

    return dependency


def require_agent_permission(
    permission: str,
) -> Callable[..., Awaitable[AgentAccess]]:
    async def dependency(
        agent_id: Annotated[UUID, Path()],
        context: Annotated[AuthContext, Depends(resolve_auth_context)],
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> AgentAccess:
        organization_id = await _resolved_organization_id(
            db,
            function_name="rdc_agent_org",
            resource_id=agent_id,
        )
        await _authorize_organization(
            db,
            context=context,
            organization_id=organization_id,
            permission=permission,
        )
        agent = await db.scalar(
            select(Agent).where(
                Agent.id == agent_id,
                Agent.organization_id == organization_id,
                Agent.deleted_at.is_(None),
            )
        )
        if agent is None:
            raise ApiError(
                status_code=404,
                code="RESOURCE_NOT_FOUND",
                message="The requested resource was not found.",
            )
        return AgentAccess(context=context, agent=agent)

    return dependency


def require_agent_version_permission(
    permission: str,
) -> Callable[..., Awaitable[AgentVersionAccess]]:
    async def dependency(
        version_id: Annotated[UUID, Path()],
        context: Annotated[AuthContext, Depends(resolve_auth_context)],
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> AgentVersionAccess:
        organization_id = await _resolved_organization_id(
            db,
            function_name="rdc_agent_version_org",
            resource_id=version_id,
        )
        await _authorize_organization(
            db,
            context=context,
            organization_id=organization_id,
            permission=permission,
        )
        record = await db.scalar(
            select(AgentVersion).where(
                AgentVersion.id == version_id,
                AgentVersion.organization_id == organization_id,
            )
        )
        if record is None:
            raise ApiError(
                status_code=404,
                code="RESOURCE_NOT_FOUND",
                message="The requested resource was not found.",
            )
        return AgentVersionAccess(
            context=context,
            agent_version=record,
        )

    return dependency



def require_project_secret_permission(
    permission: str,
) -> Callable[..., Awaitable[ProjectSecretAccess]]:
    async def dependency(
        secret_id: Annotated[UUID, Path()],
        context: Annotated[AuthContext, Depends(resolve_auth_context)],
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> ProjectSecretAccess:
        organization_id = await _resolved_organization_id(
            db,
            function_name="rdc_project_secret_org",
            resource_id=secret_id,
        )
        await _authorize_organization(
            db,
            context=context,
            organization_id=organization_id,
            permission=permission,
        )
        record = await db.scalar(
            select(ProjectSecret).where(
                ProjectSecret.id == secret_id,
                ProjectSecret.organization_id == organization_id,
            )
        )
        if record is None:
            raise ApiError(
                status_code=404,
                code="RESOURCE_NOT_FOUND",
                message="The requested resource was not found.",
            )
        return ProjectSecretAccess(context=context, secret=record)

    return dependency


def require_build_permission(
    permission: str,
) -> Callable[..., Awaitable[BuildAccess]]:
    async def dependency(
        build_id: Annotated[UUID, Path()],
        context: Annotated[AuthContext, Depends(resolve_auth_context)],
        db: Annotated[AsyncSession, Depends(get_db)],
    ) -> BuildAccess:
        organization_id = await _resolved_organization_id(
            db,
            function_name="rdc_build_org",
            resource_id=build_id,
        )
        await _authorize_organization(
            db,
            context=context,
            organization_id=organization_id,
            permission=permission,
        )
        record = await db.scalar(
            select(Build).where(
                Build.id == build_id,
                Build.organization_id == organization_id,
            )
        )
        if record is None:
            raise ApiError(
                status_code=404,
                code="RESOURCE_NOT_FOUND",
                message="The requested resource was not found.",
            )
        return BuildAccess(context=context, build=record)

    return dependency
