import hashlib
import json
from datetime import UTC, datetime
from typing import cast
from uuid import UUID

from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..agent_schemas import (
    CreateAgentRequest,
    CreateAgentVersionRequest,
    UpdateAgentRequest,
)
from ..core.errors import ApiError
from ..core.pagination import decode_cursor, encode_cursor, normalize_limit
from ..models import Agent, AgentVersion, Project
from .identity_tenancy import append_audit_event


def canonical_manifest(payload: CreateAgentVersionRequest) -> dict[str, object]:
    manifest = payload.manifest.model_dump(mode="json", by_alias=True)
    return cast(
        dict[str, object],
        json.loads(
            json.dumps(
                manifest,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        ),
    )


def manifest_digest(manifest: dict[str, object]) -> str:
    serialized = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(serialized).hexdigest()


async def list_agents(
    session: AsyncSession,
    *,
    organization_id: UUID,
    project_id: UUID,
    cursor: str | None,
    limit: int,
) -> tuple[list[Agent], str | None]:
    page_limit = normalize_limit(limit)
    position = decode_cursor(cursor)
    statement = select(Agent).where(
        Agent.organization_id == organization_id,
        Agent.project_id == project_id,
        Agent.deleted_at.is_(None),
    )
    if position is not None:
        statement = statement.where(
            or_(
                Agent.created_at < position.created_at,
                and_(
                    Agent.created_at == position.created_at,
                    Agent.id < position.resource_id,
                ),
            )
        )
    result = await session.scalars(
        statement.order_by(
            Agent.created_at.desc(),
            Agent.id.desc(),
        ).limit(page_limit + 1)
    )
    records = list(result.all())
    has_more = len(records) > page_limit
    visible = records[:page_limit]
    next_cursor = None
    if has_more and visible:
        final = visible[-1]
        next_cursor = encode_cursor(
            created_at=final.created_at,
            resource_id=final.id,
        )
    return visible, next_cursor


async def create_agent(
    session: AsyncSession,
    *,
    project: Project,
    actor_type: str,
    actor_id: str,
    created_by_user_id: UUID,
    payload: CreateAgentRequest,
    request_id: str,
) -> Agent:
    existing = await session.scalar(
        select(Agent).where(
            Agent.organization_id == project.organization_id,
            Agent.project_id == project.id,
            Agent.slug == payload.slug,
            Agent.deleted_at.is_(None),
        )
    )
    if existing is not None:
        raise ApiError(
            status_code=409,
            code="RESOURCE_CONFLICT",
            message="That Agent slug is already used in this project.",
        )

    record = Agent(
        organization_id=project.organization_id,
        project_id=project.id,
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
        status="ACTIVE",
        created_by_user_id=created_by_user_id,
        version=1,
    )
    try:
        async with session.begin_nested():
            session.add(record)
            await session.flush()
    except IntegrityError as exc:
        raise ApiError(
            status_code=409,
            code="RESOURCE_CONFLICT",
            message="That Agent slug is already used in this project.",
        ) from exc
    await append_audit_event(
        session,
        organization_id=project.organization_id,
        project_id=project.id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="agent.created",
        resource_type="agent",
        resource_id=str(record.id),
        request_id=request_id,
        details={"slug": record.slug},
    )
    return record


async def update_agent(
    session: AsyncSession,
    *,
    agent: Agent,
    actor_type: str,
    actor_id: str,
    payload: UpdateAgentRequest,
    expected_version: int,
    request_id: str,
) -> Agent:
    locked = await session.scalar(
        select(Agent)
        .where(
            Agent.id == agent.id,
            Agent.organization_id == agent.organization_id,
            Agent.project_id == agent.project_id,
            Agent.deleted_at.is_(None),
        )
        .with_for_update()
    )
    if locked is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested Agent was not found.",
        )
    if locked.version != expected_version:
        raise ApiError(
            status_code=409,
            code="VERSION_CONFLICT",
            message="The Agent changed before this update.",
        )
    changed: list[str] = []
    supplied = payload.model_fields_set

    if "slug" in supplied and payload.slug is not None and payload.slug != locked.slug:
        conflict = await session.scalar(
            select(Agent).where(
                Agent.organization_id == locked.organization_id,
                Agent.project_id == locked.project_id,
                Agent.slug == payload.slug,
                Agent.id != locked.id,
                Agent.deleted_at.is_(None),
            )
        )
        if conflict is not None:
            raise ApiError(
                status_code=409,
                code="RESOURCE_CONFLICT",
                message="That Agent slug is already used in this project.",
            )
        locked.slug = payload.slug
        changed.append("slug")

    if "name" in supplied and payload.name is not None:
        locked.name = payload.name
        changed.append("name")
    if "description" in supplied:
        locked.description = payload.description
        changed.append("description")
    if "status" in supplied and payload.status is not None:
        locked.status = payload.status
        changed.append("status")

    if not changed:
        return locked
    locked.version += 1
    locked.updated_at = datetime.now(UTC)
    try:
        async with session.begin_nested():
            await session.flush()
    except IntegrityError as exc:
        raise ApiError(
            status_code=409,
            code="RESOURCE_CONFLICT",
            message="That Agent slug is already used in this project.",
        ) from exc
    await append_audit_event(
        session,
        organization_id=locked.organization_id,
        project_id=locked.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="agent.updated",
        resource_type="agent",
        resource_id=str(locked.id),
        request_id=request_id,
        details={"fields": sorted(changed)},
    )
    return locked


async def list_agent_versions(
    session: AsyncSession,
    *,
    agent: Agent,
    cursor: str | None,
    limit: int,
) -> tuple[list[AgentVersion], str | None]:
    page_limit = normalize_limit(limit)
    position = decode_cursor(cursor)
    statement = select(AgentVersion).where(
        AgentVersion.organization_id == agent.organization_id,
        AgentVersion.project_id == agent.project_id,
        AgentVersion.agent_id == agent.id,
    )
    if position is not None:
        statement = statement.where(
            or_(
                AgentVersion.created_at < position.created_at,
                and_(
                    AgentVersion.created_at == position.created_at,
                    AgentVersion.id < position.resource_id,
                ),
            )
        )
    result = await session.scalars(
        statement.order_by(
            AgentVersion.created_at.desc(),
            AgentVersion.id.desc(),
        ).limit(page_limit + 1)
    )
    records = list(result.all())
    has_more = len(records) > page_limit
    visible = records[:page_limit]
    next_cursor = None
    if has_more and visible:
        final = visible[-1]
        next_cursor = encode_cursor(
            created_at=final.created_at,
            resource_id=final.id,
        )
    return visible, next_cursor


async def create_agent_version(
    session: AsyncSession,
    *,
    agent: Agent,
    actor_type: str,
    actor_id: str,
    created_by_user_id: UUID,
    payload: CreateAgentVersionRequest,
    request_id: str,
) -> AgentVersion:
    locked = await session.scalar(
        select(Agent)
        .where(
            Agent.id == agent.id,
            Agent.organization_id == agent.organization_id,
            Agent.project_id == agent.project_id,
            Agent.deleted_at.is_(None),
        )
        .with_for_update()
    )
    if locked is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested Agent was not found.",
        )
    if payload.manifest.name != locked.slug:
        raise ApiError(
            status_code=422,
            code="VALIDATION_FAILED",
            message="The manifest name must match the Agent slug.",
            field_errors=[
                {
                    "field": "manifest.name",
                    "code": "AGENT_SLUG_MISMATCH",
                    "message": "Manifest name must match the Agent slug.",
                }
            ],
        )
    duplicate = await session.scalar(
        select(AgentVersion).where(
            AgentVersion.agent_id == locked.id,
            AgentVersion.semantic_version == payload.manifest.version,
        )
    )
    if duplicate is not None:
        raise ApiError(
            status_code=409,
            code="RESOURCE_CONFLICT",
            message="That semantic version already exists for this Agent.",
        )
    maximum = await session.scalar(
        select(func.max(AgentVersion.version_number)).where(
            AgentVersion.agent_id == locked.id
        )
    )
    manifest = canonical_manifest(payload)
    record = AgentVersion(
        organization_id=locked.organization_id,
        project_id=locked.project_id,
        agent_id=locked.id,
        version_number=int(maximum or 0) + 1,
        protocol=payload.manifest.protocol,
        semantic_version=payload.manifest.version,
        manifest_schema_version=payload.manifest.protocol,
        manifest_digest=manifest_digest(manifest),
        manifest=manifest,
        release_notes=(
            payload.release_notes.strip() if payload.release_notes else None
        ),
        created_by_user_id=created_by_user_id,
    )
    session.add(record)
    await session.flush()
    await append_audit_event(
        session,
        organization_id=locked.organization_id,
        project_id=locked.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="agent.version_created",
        resource_type="agent_version",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "agent_id": str(locked.id),
            "version_number": record.version_number,
            "semantic_version": record.semantic_version,
            "manifest_digest": record.manifest_digest,
        },
    )
    return record
