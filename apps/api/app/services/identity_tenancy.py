import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.database import set_identity_context, set_tenant_context
from ..core.errors import ApiError
from ..core.permissions import validate_scopes
from ..core.security import (
    canonical_fingerprint,
    derive_api_key,
    derive_csrf_token,
    hash_password,
    needs_password_rehash,
    new_session_token,
    secret_digest,
    verify_password,
)
from ..models import (
    ApiKey,
    AuditEvent,
    IdempotencyRecord,
    Organization,
    OrganizationMembership,
    Project,
    Session,
    User,
)
from ..schemas import (
    CreateApiKeyRequest,
    CreateOrganizationRequest,
    CreateProjectRequest,
    LoginRequest,
    RegisterRequest,
    UpdateMembershipRoleRequest,
)

settings = get_settings()


@dataclass(frozen=True)
class IssuedSession:
    raw_token: str
    csrf_token: str
    session: Session
    user: User


def normalize_email(value: str) -> str:
    return value.strip().casefold()


def privacy_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


async def append_audit_event(
    session: AsyncSession,
    *,
    organization_id: UUID | None,
    project_id: UUID | None,
    actor_type: str,
    actor_id: str,
    action: str,
    resource_type: str,
    resource_id: str | None,
    request_id: str,
    details: dict[str, object] | None = None,
) -> None:
    session.add(
        AuditEvent(
            organization_id=organization_id,
            project_id=project_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            request_id=request_id,
            details=details or {},
            created_at=datetime.now(UTC),
        )
    )


async def issue_session(
    session: AsyncSession,
    *,
    user: User,
    user_agent: str | None,
    client_ip: str | None,
) -> IssuedSession:
    now = datetime.now(UTC)
    raw_token = new_session_token()
    token_digest = secret_digest(raw_token, settings.session_token_pepper)

    record = Session(
        user_id=user.id,
        token_digest=token_digest,
        csrf_token_digest=b"",
        created_at=now,
        last_seen_at=now,
        idle_expires_at=now
        + timedelta(minutes=settings.session_idle_minutes),
        absolute_expires_at=now
        + timedelta(hours=settings.session_absolute_hours),
        user_agent_hash=privacy_hash(user_agent) if user_agent else None,
        ip_prefix_hash=privacy_hash(client_ip) if client_ip else None,
        version=1,
    )
    session.add(record)
    await session.flush()

    csrf_token = derive_csrf_token(
        session_id=record.id,
        session_token_digest=token_digest,
        pepper=settings.csrf_token_pepper,
    )
    record.csrf_token_digest = secret_digest(
        csrf_token,
        settings.csrf_token_pepper,
    )
    return IssuedSession(
        raw_token=raw_token,
        csrf_token=csrf_token,
        session=record,
        user=user,
    )


async def register(
    session: AsyncSession,
    *,
    payload: RegisterRequest,
    request_id: str,
    user_agent: str | None,
    client_ip: str | None,
) -> IssuedSession:
    normalized_email = normalize_email(str(payload.email))
    existing = await session.scalar(
        select(User).where(User.email_normalized == normalized_email)
    )
    if existing is not None:
        raise ApiError(
            status_code=409,
            code="RESOURCE_CONFLICT",
            message="An account cannot be created with those details.",
        )

    existing_org = await session.scalar(
        select(Organization).where(
            Organization.slug == payload.organization_slug
        )
    )
    if existing_org is not None:
        raise ApiError(
            status_code=409,
            code="RESOURCE_CONFLICT",
            message="That organization slug is unavailable.",
        )

    now = datetime.now(UTC)
    user = User(
        email_normalized=normalized_email,
        email_display=str(payload.email),
        password_hash=hash_password(payload.password),
        password_algorithm="argon2id",
        display_name=payload.display_name.strip(),
        status="ACTIVE",
        failed_login_count=0,
        version=1,
    )
    session.add(user)
    await session.flush()
    await set_identity_context(session, user.id)

    organization = Organization(
        name=payload.organization_name.strip(),
        slug=payload.organization_slug,
        status="ACTIVE",
        created_by_user_id=user.id,
        version=1,
    )
    session.add(organization)
    await session.flush()
    await set_tenant_context(
        session,
        user_id=user.id,
        organization_id=organization.id,
    )

    session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=user.id,
            role="owner",
            status="ACTIVE",
            joined_at=now,
            created_by_user_id=user.id,
            updated_at=now,
            version=1,
        )
    )
    await append_audit_event(
        session,
        organization_id=organization.id,
        project_id=None,
        actor_type="user",
        actor_id=str(user.id),
        action="organization.created",
        resource_type="organization",
        resource_id=str(organization.id),
        request_id=request_id,
        details={"initial_owner": True},
    )
    return await issue_session(
        session,
        user=user,
        user_agent=user_agent,
        client_ip=client_ip,
    )


async def login(
    session: AsyncSession,
    *,
    payload: LoginRequest,
    request_id: str,
    user_agent: str | None,
    client_ip: str | None,
) -> IssuedSession:
    now = datetime.now(UTC)
    normalized_email = normalize_email(str(payload.email))
    user = await session.scalar(
        select(User).where(User.email_normalized == normalized_email)
    )
    if user is None:
        raise ApiError(
            status_code=401,
            code="CREDENTIAL_INVALID",
            message="The email or password is invalid.",
        )

    valid = (
        user.status == "ACTIVE"
        and (user.locked_until is None or user.locked_until <= now)
        and verify_password(user.password_hash, payload.password)
    )

    if not valid:
        user.failed_login_count += 1
        if user.failed_login_count >= 10:
            user.locked_until = now + timedelta(minutes=15)
        await session.commit()
        raise ApiError(
            status_code=401,
            code="CREDENTIAL_INVALID",
            message="The email or password is invalid.",
        )

    if needs_password_rehash(user.password_hash):
        user.password_hash = hash_password(payload.password)
    user.failed_login_count = 0
    user.locked_until = None
    await set_identity_context(session, user.id)

    issued = await issue_session(
        session,
        user=user,
        user_agent=user_agent,
        client_ip=client_ip,
    )
    await append_audit_event(
        session,
        organization_id=None,
        project_id=None,
        actor_type="user",
        actor_id=str(user.id),
        action="auth.login_succeeded",
        resource_type="session",
        resource_id=str(issued.session.id),
        request_id=request_id,
    )
    return issued


async def revoke_session(
    session: AsyncSession,
    *,
    record: Session,
    request_id: str,
) -> None:
    record.revoked_at = datetime.now(UTC)
    record.revoke_reason = "logout"
    await append_audit_event(
        session,
        organization_id=None,
        project_id=None,
        actor_type="user",
        actor_id=str(record.user_id),
        action="auth.logout",
        resource_type="session",
        resource_id=str(record.id),
        request_id=request_id,
    )


async def load_session_context(
    session: AsyncSession,
    *,
    user_id: UUID,
) -> tuple[list[OrganizationMembership], list[Organization]]:
    memberships = list(
        (
            await session.scalars(
                select(OrganizationMembership)
                .where(
                    OrganizationMembership.user_id == user_id,
                    OrganizationMembership.status == "ACTIVE",
                )
                .order_by(OrganizationMembership.joined_at.asc())
            )
        ).all()
    )
    organization_ids = [item.organization_id for item in memberships]
    organizations = (
        list(
            (
                await session.scalars(
                    select(Organization)
                    .where(
                        Organization.id.in_(organization_ids),
                        Organization.status == "ACTIVE",
                    )
                    .order_by(Organization.name.asc())
                )
            ).all()
        )
        if organization_ids
        else []
    )
    return memberships, organizations


async def list_organizations(
    session: AsyncSession,
    *,
    user_id: UUID,
) -> list[Organization]:
    await set_identity_context(session, user_id)
    result = await session.scalars(
        select(Organization)
        .join(
            OrganizationMembership,
            OrganizationMembership.organization_id == Organization.id,
        )
        .where(
            OrganizationMembership.user_id == user_id,
            OrganizationMembership.status == "ACTIVE",
            Organization.status == "ACTIVE",
        )
        .order_by(Organization.name.asc())
    )
    return list(result.all())


async def create_organization(
    session: AsyncSession,
    *,
    user_id: UUID,
    payload: CreateOrganizationRequest,
    request_id: str,
) -> Organization:
    existing = await session.scalar(
        select(Organization).where(Organization.slug == payload.slug)
    )
    if existing is not None:
        raise ApiError(
            status_code=409,
            code="RESOURCE_CONFLICT",
            message="That organization slug is unavailable.",
        )

    now = datetime.now(UTC)
    await set_identity_context(session, user_id)
    organization = Organization(
        name=payload.name.strip(),
        slug=payload.slug,
        status="ACTIVE",
        created_by_user_id=user_id,
        version=1,
    )
    session.add(organization)
    await session.flush()
    await set_tenant_context(
        session,
        user_id=user_id,
        organization_id=organization.id,
    )
    session.add(
        OrganizationMembership(
            organization_id=organization.id,
            user_id=user_id,
            role="owner",
            status="ACTIVE",
            joined_at=now,
            created_by_user_id=user_id,
            updated_at=now,
            version=1,
        )
    )
    await append_audit_event(
        session,
        organization_id=organization.id,
        project_id=None,
        actor_type="user",
        actor_id=str(user_id),
        action="organization.created",
        resource_type="organization",
        resource_id=str(organization.id),
        request_id=request_id,
    )
    return organization


async def list_projects(
    session: AsyncSession,
    *,
    organization_id: UUID,
) -> list[Project]:
    result = await session.scalars(
        select(Project)
        .where(
            Project.organization_id == organization_id,
            Project.deleted_at.is_(None),
        )
        .order_by(Project.name.asc())
    )
    return list(result.all())


async def create_project(
    session: AsyncSession,
    *,
    organization_id: UUID,
    user_id: UUID,
    payload: CreateProjectRequest,
    request_id: str,
) -> Project:
    existing = await session.scalar(
        select(Project).where(
            Project.organization_id == organization_id,
            Project.slug == payload.slug,
            Project.deleted_at.is_(None),
        )
    )
    if existing is not None:
        raise ApiError(
            status_code=409,
            code="RESOURCE_CONFLICT",
            message="That project slug is unavailable in this organization.",
        )

    project = Project(
        organization_id=organization_id,
        name=payload.name.strip(),
        slug=payload.slug,
        description=payload.description,
        status="ACTIVE",
        created_by_user_id=user_id,
        version=1,
    )
    session.add(project)
    await session.flush()
    await append_audit_event(
        session,
        organization_id=organization_id,
        project_id=project.id,
        actor_type="user",
        actor_id=str(user_id),
        action="project.created",
        resource_type="project",
        resource_id=str(project.id),
        request_id=request_id,
    )
    return project


async def list_memberships(
    session: AsyncSession,
    *,
    organization_id: UUID,
) -> list[OrganizationMembership]:
    result = await session.scalars(
        select(OrganizationMembership)
        .where(
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.status == "ACTIVE",
        )
        .order_by(OrganizationMembership.joined_at.asc())
    )
    return list(result.all())


async def update_membership_role(
    session: AsyncSession,
    *,
    organization_id: UUID,
    membership_id: UUID,
    actor_user_id: UUID,
    payload: UpdateMembershipRoleRequest,
    expected_version: int,
    request_id: str,
) -> OrganizationMembership:
    membership = await session.scalar(
        select(OrganizationMembership).where(
            OrganizationMembership.id == membership_id,
            OrganizationMembership.organization_id == organization_id,
            OrganizationMembership.status == "ACTIVE",
        )
    )
    if membership is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="Membership was not found.",
        )
    if membership.version != expected_version:
        raise ApiError(
            status_code=409,
            code="VERSION_CONFLICT",
            message="The membership changed before this update.",
        )

    if membership.role == "owner" and payload.role != "owner":
        owner_count = await session.scalar(
            select(func.count())
            .select_from(OrganizationMembership)
            .where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.status == "ACTIVE",
                OrganizationMembership.role == "owner",
            )
        )
        if int(owner_count or 0) <= 1:
            raise ApiError(
                status_code=409,
                code="RESOURCE_CONFLICT",
                message="The final organization owner cannot be demoted.",
            )

    previous_role = membership.role
    membership.role = payload.role
    membership.version += 1
    membership.updated_at = datetime.now(UTC)
    await append_audit_event(
        session,
        organization_id=organization_id,
        project_id=None,
        actor_type="user",
        actor_id=str(actor_user_id),
        action="membership.role_updated",
        resource_type="organization_membership",
        resource_id=str(membership.id),
        request_id=request_id,
        details={"previous_role": previous_role, "new_role": payload.role},
    )
    return membership


async def list_api_keys(
    session: AsyncSession,
    *,
    organization_id: UUID,
) -> list[ApiKey]:
    result = await session.scalars(
        select(ApiKey)
        .where(ApiKey.organization_id == organization_id)
        .order_by(ApiKey.created_at.desc())
    )
    return list(result.all())


async def create_api_key(
    session: AsyncSession,
    *,
    organization_id: UUID,
    user_id: UUID,
    payload: CreateApiKeyRequest,
    idempotency_key: str,
    request_id: str,
) -> tuple[ApiKey, str]:
    if not 8 <= len(idempotency_key) <= 200:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="Idempotency-Key must contain between 8 and 200 characters.",
        )
    try:
        scopes = validate_scopes(payload.scopes)
    except ValueError as exc:
        raise ApiError(
            status_code=422,
            code="VALIDATION_FAILED",
            message="One or more API-key scopes are invalid.",
            details={"reason": str(exc)},
        ) from exc

    fingerprint = canonical_fingerprint(
        {
            "name": payload.name,
            "scopes": scopes,
            "expires_at": (
                payload.expires_at.isoformat()
                if payload.expires_at
                else None
            ),
            "environment": payload.environment,
        }
    )
    key_digest = hashlib.sha256(
        idempotency_key.encode("utf-8")
    ).hexdigest()
    endpoint = "POST:/api/v1/organizations/{organization_id}/api-keys"

    existing_record = await session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.organization_id == organization_id,
            IdempotencyRecord.principal_id == str(user_id),
            IdempotencyRecord.endpoint == endpoint,
            IdempotencyRecord.key_digest == key_digest,
        )
    )
    issued = derive_api_key(
        environment=payload.environment,
        organization_id=organization_id,
        principal_id=user_id,
        idempotency_key=idempotency_key,
        issuance_secret=settings.api_key_issuance_secret,
    )

    if existing_record is not None:
        if existing_record.request_fingerprint != fingerprint:
            raise ApiError(
                status_code=409,
                code="IDEMPOTENCY_CONFLICT",
                message="This idempotency key was used for a different request.",
            )
        existing_key = await session.scalar(
            select(ApiKey).where(
                ApiKey.id == UUID(existing_record.resource_id),
                ApiKey.organization_id == organization_id,
            )
        )
        if existing_key is None:
            raise ApiError(
                status_code=409,
                code="RESOURCE_CONFLICT",
                message="The original idempotent result is unavailable.",
            )
        return existing_key, issued.raw_token

    now = datetime.now(UTC)
    record = ApiKey(
        organization_id=organization_id,
        name=payload.name.strip(),
        public_prefix=issued.public_prefix,
        last_four=issued.last_four,
        token_digest=secret_digest(
            issued.raw_token,
            settings.api_key_pepper,
        ),
        scopes=scopes,
        environment=payload.environment,
        created_by_user_id=user_id,
        created_at=now,
        expires_at=payload.expires_at,
    )
    session.add(record)
    await session.flush()
    session.add(
        IdempotencyRecord(
            organization_id=organization_id,
            principal_id=str(user_id),
            endpoint=endpoint,
            key_digest=key_digest,
            request_fingerprint=fingerprint,
            resource_type="api_key",
            resource_id=str(record.id),
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
    )
    await append_audit_event(
        session,
        organization_id=organization_id,
        project_id=None,
        actor_type="user",
        actor_id=str(user_id),
        action="api_key.created",
        resource_type="api_key",
        resource_id=str(record.id),
        request_id=request_id,
        details={"scopes": scopes, "environment": payload.environment},
    )
    return record, issued.raw_token


async def revoke_api_key(
    session: AsyncSession,
    *,
    organization_id: UUID,
    api_key_id: UUID,
    actor_user_id: UUID,
    request_id: str,
) -> None:
    record = await session.scalar(
        select(ApiKey).where(
            ApiKey.id == api_key_id,
            ApiKey.organization_id == organization_id,
        )
    )
    if record is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="API key was not found.",
        )
    if record.revoked_at is None:
        record.revoked_at = datetime.now(UTC)
        record.revoke_reason = "user_revoked"
        await append_audit_event(
            session,
            organization_id=organization_id,
            project_id=None,
            actor_type="user",
            actor_id=str(actor_user_id),
            action="api_key.revoked",
            resource_type="api_key",
            resource_id=str(record.id),
            request_id=request_id,
        )
