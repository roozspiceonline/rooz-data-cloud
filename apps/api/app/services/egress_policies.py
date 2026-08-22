from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import and_, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.errors import ApiError
from ..core.pagination import CursorPosition, EgressPolicyRevisionCursorPosition
from ..core.security import canonical_fingerprint
from ..egress_policy_protocol import (
    EgressPolicyProtocolError,
    ValidatedEgressPolicy,
    validate_egress_policy,
)
from ..egress_policy_schemas import (
    CreateEgressPolicyRequest,
    CreateEgressPolicyRevisionRequest,
    EgressPolicyRevisionSummary,
    EgressPolicySummary,
)
from ..models import (
    EgressPolicy,
    EgressPolicyRevision,
    IdempotencyRecord,
    Project,
    ProjectSecret,
)
from .builds_secrets import acquire_idempotency_lock, validate_idempotency_key
from .identity_tenancy import append_audit_event


def policy_summary(record: EgressPolicy) -> dict[str, object]:
    return EgressPolicySummary.model_validate(record, from_attributes=True).model_dump(mode="json")


def revision_summary(record: EgressPolicyRevision) -> dict[str, object]:
    return EgressPolicyRevisionSummary(
        id=record.id,
        policy_id=record.policy_id,
        revision_number=record.revision_number,
        allowed_hosts=list(record.allowed_hosts),
        allowed_methods=list(record.allowed_methods),
        max_requests=record.max_requests,
        max_response_bytes=record.max_response_bytes,
        max_total_bytes=record.max_total_bytes,
        max_redirects=record.max_redirects,
        connect_timeout_seconds=record.connect_timeout_seconds,
        request_timeout_seconds=record.request_timeout_seconds,
        credential_configured=record.credential_secret_id is not None,
        policy_digest=record.policy_digest,
        created_by_user_id=record.created_by_user_id,
        created_at=record.created_at,
    ).model_dump(mode="json")


def _validated(
    payload: CreateEgressPolicyRequest | CreateEgressPolicyRevisionRequest,
) -> ValidatedEgressPolicy:
    try:
        return validate_egress_policy(
            allowed_hosts=payload.spec.allowed_hosts,
            allowed_methods=list(payload.spec.allowed_methods),
            max_requests=payload.spec.max_requests,
            max_response_bytes=payload.spec.max_response_bytes,
            max_total_bytes=payload.spec.max_total_bytes,
            max_redirects=payload.spec.max_redirects,
            connect_timeout_seconds=payload.spec.connect_timeout_seconds,
            request_timeout_seconds=payload.spec.request_timeout_seconds,
        )
    except EgressPolicyProtocolError as exc:
        raise ApiError(
            status_code=422,
            code="EGRESS_POLICY_INVALID",
            message=str(exc),
        ) from exc


async def _validate_credential(
    session: AsyncSession,
    *,
    credential_secret_id: UUID | None,
    organization_id: UUID,
    project_id: UUID,
) -> None:
    if credential_secret_id is None:
        return
    secret = await session.scalar(
        select(ProjectSecret.id).where(
            ProjectSecret.id == credential_secret_id,
            ProjectSecret.organization_id == organization_id,
            ProjectSecret.project_id == project_id,
        )
    )
    if secret is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )


def _new_revision(
    *,
    policy: EgressPolicy,
    revision_number: int,
    user_id: UUID,
    validated: ValidatedEgressPolicy,
    credential_secret_id: UUID | None,
    now: datetime,
) -> EgressPolicyRevision:
    return EgressPolicyRevision(
        id=uuid4(),
        organization_id=policy.organization_id,
        project_id=policy.project_id,
        policy_id=policy.id,
        revision_number=revision_number,
        allowed_hosts=validated.allowed_hosts,
        allowed_methods=validated.allowed_methods,
        max_requests=validated.max_requests,
        max_response_bytes=validated.max_response_bytes,
        max_total_bytes=validated.max_total_bytes,
        max_redirects=validated.max_redirects,
        connect_timeout_seconds=validated.connect_timeout_seconds,
        request_timeout_seconds=validated.request_timeout_seconds,
        credential_secret_id=credential_secret_id,
        policy_digest=validated.policy_digest,
        created_by_user_id=user_id,
        created_at=now,
    )


async def list_egress_policies(
    session: AsyncSession,
    *,
    project_id: UUID,
    status: str | None,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[EgressPolicy], bool]:
    statement = select(EgressPolicy).where(EgressPolicy.project_id == project_id)
    if status is not None:
        statement = statement.where(EgressPolicy.status == status)
    if cursor is not None:
        statement = statement.where(
            or_(
                EgressPolicy.created_at < cursor.created_at,
                and_(
                    EgressPolicy.created_at == cursor.created_at,
                    EgressPolicy.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(EgressPolicy.created_at.desc(), EgressPolicy.id.desc()).limit(
                    limit + 1
                )
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def list_egress_policy_revisions(
    session: AsyncSession,
    *,
    policy_id: UUID,
    cursor: EgressPolicyRevisionCursorPosition | None,
    limit: int,
) -> tuple[list[EgressPolicyRevision], bool]:
    statement = select(EgressPolicyRevision).where(EgressPolicyRevision.policy_id == policy_id)
    if cursor is not None:
        statement = statement.where(EgressPolicyRevision.revision_number < cursor.revision_number)
    rows = list(
        (
            await session.scalars(
                statement.order_by(EgressPolicyRevision.revision_number.desc()).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def create_egress_policy(
    session: AsyncSession,
    *,
    project: Project,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    idempotency_key: str,
    request_id: str,
    payload: CreateEgressPolicyRequest,
) -> dict[str, object]:
    validate_idempotency_key(idempotency_key)
    validated = _validated(payload)
    await _validate_credential(
        session,
        credential_secret_id=payload.spec.credential_secret_id,
        organization_id=project.organization_id,
        project_id=project.id,
    )
    endpoint = "POST:/api/v1/projects/{project_id}/egress-policies"
    key_digest = hashlib.sha256(idempotency_key.encode()).hexdigest()
    fingerprint = canonical_fingerprint(
        {
            "project_id": str(project.id),
            "name": payload.name,
            "policy_digest": validated.policy_digest,
            "credential_secret_id": (
                str(payload.spec.credential_secret_id)
                if payload.spec.credential_secret_id is not None
                else None
            ),
        }
    )
    await acquire_idempotency_lock(
        session,
        organization_id=project.organization_id,
        principal_id=str(user_id),
        endpoint=endpoint,
        key_digest=key_digest,
    )
    existing = await session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.organization_id == project.organization_id,
            IdempotencyRecord.principal_id == str(user_id),
            IdempotencyRecord.endpoint == endpoint,
            IdempotencyRecord.key_digest == key_digest,
        )
    )
    if existing is not None:
        if existing.request_fingerprint != fingerprint:
            raise ApiError(
                status_code=409,
                code="IDEMPOTENCY_CONFLICT",
                message="This idempotency key was used for a different request.",
            )
        if existing.response_snapshot is None:
            raise ApiError(
                status_code=409,
                code="RESOURCE_CONFLICT",
                message="The original idempotent result is unavailable.",
            )
        return {**dict(existing.response_snapshot), "replayed": True}

    await acquire_idempotency_lock(
        session,
        organization_id=project.organization_id,
        principal_id=f"project:{project.id}",
        endpoint="egress-policy-name",
        key_digest=hashlib.sha256(payload.name.encode()).hexdigest(),
    )
    duplicate = await session.scalar(
        select(EgressPolicy.id).where(
            EgressPolicy.project_id == project.id, EgressPolicy.name == payload.name
        )
    )
    if duplicate is not None:
        raise ApiError(
            status_code=409,
            code="EGRESS_POLICY_ALREADY_EXISTS",
            message="An egress policy with that name already exists in the project.",
        )
    now = datetime.now(UTC)
    policy = EgressPolicy(
        id=uuid4(),
        organization_id=project.organization_id,
        project_id=project.id,
        name=payload.name,
        status="DRAFT",
        active_revision_id=None,
        activated_at=None,
        disabled_at=None,
        created_by_user_id=user_id,
        created_at=now,
        updated_at=now,
        version=1,
    )
    session.add(policy)
    await session.flush()
    revision = _new_revision(
        policy=policy,
        revision_number=1,
        user_id=user_id,
        validated=validated,
        credential_secret_id=payload.spec.credential_secret_id,
        now=now,
    )
    session.add(revision)
    await session.flush()
    snapshot = {
        "policy": policy_summary(policy),
        "revision": revision_summary(revision),
        "replayed": False,
    }
    session.add(
        IdempotencyRecord(
            organization_id=policy.organization_id,
            principal_id=str(user_id),
            endpoint=endpoint,
            key_digest=key_digest,
            request_fingerprint=fingerprint,
            resource_type="egress_policy",
            resource_id=str(policy.id),
            response_status=201,
            response_snapshot={**snapshot, "replayed": False},
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
    )
    await append_audit_event(
        session,
        organization_id=policy.organization_id,
        project_id=policy.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="egress_policy.created",
        resource_type="egress_policy",
        resource_id=str(policy.id),
        request_id=request_id,
        details={
            "policy_digest": revision.policy_digest,
            "credential_configured": revision.credential_secret_id is not None,
        },
    )
    return snapshot


async def create_egress_policy_revision(
    session: AsyncSession,
    *,
    policy_id: UUID,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    request_id: str,
    payload: CreateEgressPolicyRevisionRequest,
) -> EgressPolicyRevision:
    validated = _validated(payload)
    policy = await session.scalar(
        select(EgressPolicy).where(EgressPolicy.id == policy_id).with_for_update()
    )
    if policy is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    if policy.version != payload.expected_version:
        raise ApiError(
            status_code=409,
            code="VERSION_CONFLICT",
            message="The egress policy changed. Reload it and try again.",
        )
    await _validate_credential(
        session,
        credential_secret_id=payload.spec.credential_secret_id,
        organization_id=policy.organization_id,
        project_id=policy.project_id,
    )
    latest = await session.scalar(
        select(func.max(EgressPolicyRevision.revision_number)).where(
            EgressPolicyRevision.policy_id == policy.id
        )
    )
    now = datetime.now(UTC)
    revision = _new_revision(
        policy=policy,
        revision_number=int(latest or 0) + 1,
        user_id=user_id,
        validated=validated,
        credential_secret_id=payload.spec.credential_secret_id,
        now=now,
    )
    session.add(revision)
    policy.version += 1
    policy.updated_at = now
    await session.flush()
    await append_audit_event(
        session,
        organization_id=policy.organization_id,
        project_id=policy.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="egress_policy.revision_created",
        resource_type="egress_policy_revision",
        resource_id=str(revision.id),
        request_id=request_id,
        details={
            "policy_id": str(policy.id),
            "revision_number": revision.revision_number,
            "policy_digest": revision.policy_digest,
            "credential_configured": revision.credential_secret_id is not None,
        },
    )
    return revision


async def activate_egress_policy(
    session: AsyncSession,
    *,
    policy_id: UUID,
    revision_id: UUID,
    expected_version: int,
    actor_type: str,
    actor_id: str,
    request_id: str,
) -> EgressPolicy:
    policy = await session.scalar(
        select(EgressPolicy).where(EgressPolicy.id == policy_id).with_for_update()
    )
    if policy is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    if policy.version != expected_version:
        raise ApiError(
            status_code=409,
            code="VERSION_CONFLICT",
            message="The egress policy changed. Reload it and try again.",
        )
    revision = await session.scalar(
        select(EgressPolicyRevision).where(
            EgressPolicyRevision.id == revision_id,
            EgressPolicyRevision.policy_id == policy.id,
            EgressPolicyRevision.organization_id == policy.organization_id,
            EgressPolicyRevision.project_id == policy.project_id,
        )
    )
    if revision is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    now = datetime.now(UTC)
    policy.active_revision_id = revision.id
    policy.status = "ACTIVE"
    policy.activated_at = now
    policy.disabled_at = None
    policy.version += 1
    policy.updated_at = now
    await session.flush()
    await append_audit_event(
        session,
        organization_id=policy.organization_id,
        project_id=policy.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="egress_policy.activated",
        resource_type="egress_policy",
        resource_id=str(policy.id),
        request_id=request_id,
        details={"revision_id": str(revision.id), "policy_digest": revision.policy_digest},
    )
    return policy


async def disable_egress_policy(
    session: AsyncSession,
    *,
    policy_id: UUID,
    expected_version: int,
    actor_type: str,
    actor_id: str,
    request_id: str,
) -> EgressPolicy:
    policy = await session.scalar(
        select(EgressPolicy).where(EgressPolicy.id == policy_id).with_for_update()
    )
    if policy is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    if policy.version != expected_version:
        raise ApiError(
            status_code=409,
            code="VERSION_CONFLICT",
            message="The egress policy changed. Reload it and try again.",
        )
    now = datetime.now(UTC)
    policy.status = "DISABLED"
    policy.disabled_at = now
    policy.version += 1
    policy.updated_at = now
    await session.flush()
    await append_audit_event(
        session,
        organization_id=policy.organization_id,
        project_id=policy.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="egress_policy.disabled",
        resource_type="egress_policy",
        resource_id=str(policy.id),
        request_id=request_id,
        details={
            "active_revision_id": str(policy.active_revision_id)
            if policy.active_revision_id
            else None
        },
    )
    return policy
