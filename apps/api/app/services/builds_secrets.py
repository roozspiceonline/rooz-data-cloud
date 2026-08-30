import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import and_, delete, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..build_secret_schemas import (
    CreateProjectSecretRequest,
    ReplaceProjectSecretRequest,
)
from ..core.config import get_settings
from ..core.envelope_encryption import encrypt_project_secret
from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..core.security import canonical_fingerprint, secret_digest
from ..models import (
    Agent,
    AgentVersion,
    Build,
    BuildDispatchOutbox,
    IdempotencyRecord,
    ProjectSecret,
    SecretInjectionGrant,
    StorageObject,
)
from .egress_credential_canaries import enqueue_credential_rotation_canaries
from .events import emit_event
from .identity_tenancy import append_audit_event

settings = get_settings()


def validate_idempotency_key(value: str) -> None:
    if not 8 <= len(value) <= 200:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="Idempotency-Key must contain between 8 and 200 characters.",
        )


async def acquire_idempotency_lock(
    session: AsyncSession,
    *,
    organization_id: UUID,
    principal_id: str,
    endpoint: str,
    key_digest: str,
) -> None:
    material = (
        f"{organization_id}:{principal_id}:{endpoint}:{key_digest}"
    ).encode()
    lock_key = int.from_bytes(
        hashlib.sha256(material).digest()[:8],
        byteorder="big",
        signed=True,
    )
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": lock_key},
    )


def secret_etag(secret_id: UUID, version: int) -> str:
    return f'"secret-{secret_id}-v{version}"'


def parse_secret_if_match(value: str, *, secret_id: UUID) -> int:
    prefix = f'"secret-{secret_id}-v'
    if not value.startswith(prefix) or not value.endswith('"'):
        raise ApiError(
            status_code=409,
            code="VERSION_CONFLICT",
            message="The project secret changed. Reload it and try again.",
        )
    try:
        return int(value[len(prefix) : -1])
    except ValueError as exc:
        raise ApiError(
            status_code=409,
            code="VERSION_CONFLICT",
            message="The project secret changed. Reload it and try again.",
        ) from exc


def secret_metadata(record: ProjectSecret) -> dict[str, object]:
    return {
        "id": record.id,
        "project_id": record.project_id,
        "name": record.name,
        "description": record.description,
        "environment": record.environment,
        "has_value": True,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "last_used_at": record.last_used_at,
        "version": record.version,
        "etag": secret_etag(record.id, record.version),
    }


def build_metadata(record: Build) -> dict[str, object]:
    return {
        "id": record.id,
        "organization_id": record.organization_id,
        "project_id": record.project_id,
        "agent_id": record.agent_id,
        "agent_version_id": record.agent_version_id,
        "manifest_digest": record.manifest_digest,
        "source_object_id": record.source_object_id,
        "status": record.status,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "started_at": record.started_at,
        "completed_at": record.completed_at,
        "artifact_digest": record.artifact_digest,
        "error_code": record.error_code,
        "error_message": record.error_message,
        "status_url": f"/api/v1/builds/{record.id}",
    }


async def list_project_secrets(
    session: AsyncSession,
    *,
    project_id: UUID,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[ProjectSecret], bool]:
    statement = select(ProjectSecret).where(ProjectSecret.project_id == project_id)
    if cursor is not None:
        statement = statement.where(
            or_(
                ProjectSecret.created_at < cursor.created_at,
                and_(
                    ProjectSecret.created_at == cursor.created_at,
                    ProjectSecret.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    ProjectSecret.created_at.desc(),
                    ProjectSecret.id.desc(),
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def create_project_secret(
    session: AsyncSession,
    *,
    organization_id: UUID,
    project_id: UUID,
    user_id: UUID,
    payload: CreateProjectSecretRequest,
    request_id: str,
) -> ProjectSecret:
    secret_id = uuid4()
    encrypted = encrypt_project_secret(
        payload.value,
        organization_id=organization_id,
        project_id=project_id,
        secret_id=secret_id,
        name=payload.name,
        version=1,
    )
    record = ProjectSecret(
        id=secret_id,
        organization_id=organization_id,
        project_id=project_id,
        name=payload.name,
        description=payload.description,
        environment=payload.environment,
        encrypted_value=encrypted.ciphertext,
        value_nonce=encrypted.value_nonce,
        wrapped_data_key=encrypted.wrapped_data_key,
        key_nonce=encrypted.key_nonce,
        encryption_algorithm=encrypted.algorithm,
        master_key_version=encrypted.master_key_version,
        created_by_user_id=user_id,
        updated_by_user_id=user_id,
        version=1,
    )
    session.add(record)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise ApiError(
            status_code=409,
            code="RESOURCE_CONFLICT",
            message="A project secret with this name already exists.",
        ) from exc
    await append_audit_event(
        session,
        organization_id=organization_id,
        project_id=project_id,
        actor_type="user",
        actor_id=str(user_id),
        action="project.secret.created",
        resource_type="project_secret",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "secret_name": record.name,
            "environment": record.environment,
        },
    )
    return record


async def replace_project_secret(
    session: AsyncSession,
    *,
    record: ProjectSecret,
    user_id: UUID,
    expected_version: int,
    idempotency_key: str,
    payload: ReplaceProjectSecretRequest,
    request_id: str,
) -> dict[str, object]:
    validate_idempotency_key(idempotency_key)
    fingerprint = canonical_fingerprint(
        {
            "secret_id": str(record.id),
            "value_digest": secret_digest(
                "project-secret-idempotency:v1:" + payload.value,
                settings.rate_limit_key,
            ).hex(),
            "description": payload.description,
            "environment": payload.environment,
            "expected_version": expected_version,
        }
    )
    key_digest = hashlib.sha256(idempotency_key.encode()).hexdigest()
    endpoint = "PUT:/api/v1/secrets/{secret_id}"
    await acquire_idempotency_lock(
        session,
        organization_id=record.organization_id,
        principal_id=str(user_id),
        endpoint=endpoint,
        key_digest=key_digest,
    )
    existing = await session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.organization_id == record.organization_id,
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
        return dict(existing.response_snapshot)

    locked = await session.scalar(
        select(ProjectSecret)
        .where(
            ProjectSecret.id == record.id,
            ProjectSecret.organization_id == record.organization_id,
            ProjectSecret.project_id == record.project_id,
        )
        .execution_options(populate_existing=True)
        .with_for_update()
    )
    if locked is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    record = locked

    if record.version != expected_version:
        raise ApiError(
            status_code=409,
            code="VERSION_CONFLICT",
            message="The project secret changed. Reload it and try again.",
        )
    next_version = record.version + 1
    encrypted = encrypt_project_secret(
        payload.value,
        organization_id=record.organization_id,
        project_id=record.project_id,
        secret_id=record.id,
        name=record.name,
        version=next_version,
    )
    record.encrypted_value = encrypted.ciphertext
    record.value_nonce = encrypted.value_nonce
    record.wrapped_data_key = encrypted.wrapped_data_key
    record.key_nonce = encrypted.key_nonce
    record.encryption_algorithm = encrypted.algorithm
    record.master_key_version = encrypted.master_key_version
    record.description = payload.description
    if payload.environment is not None:
        record.environment = payload.environment
    record.updated_by_user_id = user_id
    record.version = next_version
    now = datetime.now(UTC)
    record.updated_at = now
    grants = list(
        (
            await session.scalars(
                select(SecretInjectionGrant)
                .where(
                    SecretInjectionGrant.project_id == record.project_id,
                    SecretInjectionGrant.status == "ISSUED",
                )
                .with_for_update()
            )
        ).all()
    )
    for grant in grants:
        if record.name in grant.secret_names:
            grant.status = "REVOKED"
    await session.flush()
    await enqueue_credential_rotation_canaries(
        session,
        secret=record,
        request_id=request_id,
    )
    snapshot = secret_metadata(record)
    json_snapshot = {
        **snapshot,
        "id": str(record.id),
        "project_id": str(record.project_id),
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "last_used_at": (
            record.last_used_at.isoformat() if record.last_used_at else None
        ),
    }
    session.add(
        IdempotencyRecord(
            organization_id=record.organization_id,
            principal_id=str(user_id),
            endpoint=endpoint,
            key_digest=key_digest,
            request_fingerprint=fingerprint,
            resource_type="project_secret",
            resource_id=str(record.id),
            response_status=200,
            response_snapshot=json_snapshot,
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
    )
    await append_audit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        actor_type="user",
        actor_id=str(user_id),
        action="project.secret.replaced",
        resource_type="project_secret",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "secret_name": record.name,
            "environment": record.environment,
            "version": record.version,
        },
    )
    await session.flush()
    return snapshot


async def delete_project_secret(
    session: AsyncSession,
    *,
    record: ProjectSecret,
    user_id: UUID,
    request_id: str,
) -> None:
    await append_audit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        actor_type="user",
        actor_id=str(user_id),
        action="project.secret.deleted",
        resource_type="project_secret",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "secret_name": record.name,
            "environment": record.environment,
        },
    )
    await session.execute(
        delete(ProjectSecret).where(
            ProjectSecret.id == record.id,
            ProjectSecret.organization_id == record.organization_id,
        )
    )


async def create_build(
    session: AsyncSession,
    *,
    version: AgentVersion,
    user_id: UUID,
    idempotency_key: str,
    request_id: str,
) -> dict[str, object]:
    validate_idempotency_key(idempotency_key)
    if version.source_object_id is None:
        raise ApiError(
            status_code=409,
            code="SOURCE_OBJECT_NOT_AVAILABLE",
            message="This legacy Agent version has no verified source archive.",
        )
    fingerprint = canonical_fingerprint(
        {
            "agent_version_id": str(version.id),
            "manifest_digest": version.manifest_digest,
            "source_object_id": str(version.source_object_id),
        }
    )
    key_digest = hashlib.sha256(idempotency_key.encode()).hexdigest()
    endpoint = "POST:/api/v1/agent-versions/{version_id}/builds"
    await acquire_idempotency_lock(
        session,
        organization_id=version.organization_id,
        principal_id=str(user_id),
        endpoint=endpoint,
        key_digest=key_digest,
    )
    existing = await session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.organization_id == version.organization_id,
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
        return dict(existing.response_snapshot)

    agent = await session.scalar(
        select(Agent).where(
            Agent.id == version.agent_id,
            Agent.organization_id == version.organization_id,
            Agent.project_id == version.project_id,
            Agent.deleted_at.is_(None),
        )
    )
    if agent is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    source_object = await session.scalar(
        select(StorageObject).where(
            StorageObject.id == version.source_object_id,
            StorageObject.organization_id == version.organization_id,
            StorageObject.project_id == version.project_id,
            StorageObject.agent_id == version.agent_id,
            StorageObject.kind == "AGENT_SOURCE",
            StorageObject.status == "AVAILABLE",
            StorageObject.scan_status == "PASSED",
            StorageObject.deleted_at.is_(None),
        )
    )
    if source_object is None:
        raise ApiError(
            status_code=409,
            code="SOURCE_OBJECT_NOT_AVAILABLE",
            message="The immutable Agent source archive is unavailable.",
        )
    now = datetime.now(UTC)
    record = Build(
        organization_id=version.organization_id,
        project_id=version.project_id,
        agent_id=version.agent_id,
        agent_version_id=version.id,
        manifest_digest=version.manifest_digest,
        source_object_id=source_object.id,
        status="QUEUED",
        requested_by_user_id=user_id,
        version=1,
    )
    session.add(record)
    await session.flush()
    await emit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        event_type="build.created",
        subject_type="build",
        subject_id=record.id,
        payload={
            "agent_id": str(record.agent_id),
            "agent_version_id": str(record.agent_version_id),
            "status": record.status,
        },
        request_id=request_id,
        idempotent=False,
    )
    snapshot = build_metadata(record)
    json_snapshot = {
        **snapshot,
        "id": str(record.id),
        "organization_id": str(record.organization_id),
        "project_id": str(record.project_id),
        "agent_id": str(record.agent_id),
        "agent_version_id": str(record.agent_version_id),
        "created_at": record.created_at.isoformat(),
        "updated_at": record.updated_at.isoformat(),
        "started_at": record.started_at.isoformat() if record.started_at else None,
        "completed_at": (
            record.completed_at.isoformat() if record.completed_at else None
        ),
    }
    manifest_resources = version.manifest.get("resources")
    build_timeout_seconds = settings.sandbox_max_build_seconds
    if isinstance(manifest_resources, dict):
        manifest_timeout = manifest_resources.get("timeoutSeconds")
        if isinstance(manifest_timeout, int) and not isinstance(
            manifest_timeout, bool
        ):
            build_timeout_seconds = min(
                manifest_timeout,
                settings.sandbox_max_build_seconds,
            )
    session.add(
        BuildDispatchOutbox(
            organization_id=record.organization_id,
            project_id=record.project_id,
            build_id=record.id,
            topic="rdc.build.requested.v1",
            payload={
                "schema_version": "1",
                "build_id": str(record.id),
                "organization_id": str(record.organization_id),
                "project_id": str(record.project_id),
                "agent_id": str(record.agent_id),
                "agent_version_id": str(record.agent_version_id),
                "manifest_digest": record.manifest_digest,
                "timeout_seconds": build_timeout_seconds,
                "source_object_id": str(record.source_object_id),
                "source_sha256_digest": source_object.sha256_digest,
                "source_size_bytes": source_object.size_bytes,
            },
            status="PENDING",
            attempts=0,
            available_at=now,
        )
    )
    session.add(
        IdempotencyRecord(
            organization_id=record.organization_id,
            principal_id=str(user_id),
            endpoint=endpoint,
            key_digest=key_digest,
            request_fingerprint=fingerprint,
            resource_type="build",
            resource_id=str(record.id),
            response_status=202,
            response_snapshot=json_snapshot,
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
    )
    await append_audit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        actor_type="user",
        actor_id=str(user_id),
        action="build.queued",
        resource_type="build",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "agent_id": str(record.agent_id),
            "agent_version_id": str(record.agent_version_id),
            "manifest_digest": record.manifest_digest,
            "source_object_id": str(record.source_object_id),
        },
    )
    return snapshot


async def list_agent_builds(
    session: AsyncSession,
    *,
    agent_id: UUID,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[Build], bool]:
    statement = select(Build).where(Build.agent_id == agent_id)
    if cursor is not None:
        statement = statement.where(
            or_(
                Build.created_at < cursor.created_at,
                and_(
                    Build.created_at == cursor.created_at,
                    Build.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    Build.created_at.desc(),
                    Build.id.desc(),
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit
