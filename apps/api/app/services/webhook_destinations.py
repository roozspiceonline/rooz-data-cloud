from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import set_project_context
from ..core.envelope_encryption import encrypt_project_secret
from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..core.security import canonical_fingerprint
from ..models import IdempotencyRecord, Project, ProjectSecret, WebhookDestination
from ..webhook_destination_protocol import (
    ValidatedWebhookDestination,
    WebhookDestinationProtocolError,
    validate_webhook_destination,
)
from ..webhook_destination_schemas import (
    CreateWebhookDestinationRequest,
    WebhookDestinationSummary,
)
from .builds_secrets import acquire_idempotency_lock, validate_idempotency_key
from .identity_tenancy import append_audit_event


def destination_summary(record: WebhookDestination) -> dict[str, object]:
    return WebhookDestinationSummary(
        id=record.id,
        organization_id=record.organization_id,
        project_id=record.project_id,
        name=record.name,
        endpoint_url=record.endpoint_url,
        endpoint_origin=record.endpoint_origin,
        event_types=list(record.event_types),
        status=record.status,
        signing_secret_configured=True,
        signing_secret_version=record.signing_secret_version,
        created_by_user_id=record.created_by_user_id,
        updated_by_user_id=record.updated_by_user_id,
        created_at=record.created_at,
        updated_at=record.updated_at,
        version=record.version,
    ).model_dump(mode="json")


def _validated(payload: CreateWebhookDestinationRequest) -> ValidatedWebhookDestination:
    try:
        return validate_webhook_destination(
            endpoint_url=payload.endpoint_url, event_types=payload.event_types
        )
    except WebhookDestinationProtocolError as exc:
        raise ApiError(
            status_code=422, code="WEBHOOK_DESTINATION_INVALID", message=str(exc)
        ) from exc


async def create_webhook_destination(
    session: AsyncSession,
    *,
    project: Project,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    idempotency_key: str,
    request_id: str,
    payload: CreateWebhookDestinationRequest,
) -> dict[str, object]:
    validate_idempotency_key(idempotency_key)
    validated = _validated(payload)
    endpoint = "POST:/api/v1/projects/{project_id}/webhook-destinations"
    key_digest = hashlib.sha256(idempotency_key.encode()).hexdigest()
    fingerprint = canonical_fingerprint(
        {
            "project_id": str(project.id),
            "name": payload.name,
            "endpoint_url": validated.endpoint_url,
            "event_types": validated.event_types,
            "signing_secret_digest": hashlib.sha256(
                payload.signing_secret.get_secret_value().encode()
            ).hexdigest(),
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
    await set_project_context(session, project.id)
    duplicate = await session.scalar(
        select(WebhookDestination.id).where(
            WebhookDestination.project_id == project.id, WebhookDestination.name == payload.name
        )
    )
    if duplicate is not None:
        raise ApiError(
            status_code=409,
            code="WEBHOOK_DESTINATION_ALREADY_EXISTS",
            message="A webhook destination with that name already exists.",
        )
    now, destination_id, secret_id = datetime.now(UTC), uuid4(), uuid4()
    secret_name = f"WEBHOOK_{destination_id.hex}"
    encrypted = encrypt_project_secret(
        payload.signing_secret.get_secret_value(),
        organization_id=project.organization_id,
        project_id=project.id,
        secret_id=secret_id,
        name=secret_name,
        version=1,
    )
    session.add(
        ProjectSecret(
            id=secret_id,
            organization_id=project.organization_id,
            project_id=project.id,
            name=secret_name,
            description="Managed webhook signing secret",
            environment="webhook",
            encrypted_value=encrypted.ciphertext,
            value_nonce=encrypted.value_nonce,
            wrapped_data_key=encrypted.wrapped_data_key,
            key_nonce=encrypted.key_nonce,
            encryption_algorithm=encrypted.algorithm,
            master_key_version=encrypted.master_key_version,
            created_by_user_id=user_id,
            updated_by_user_id=user_id,
            version=1,
            created_at=now,
            updated_at=now,
        )
    )
    record = WebhookDestination(
        id=destination_id,
        organization_id=project.organization_id,
        project_id=project.id,
        name=payload.name,
        endpoint_url=validated.endpoint_url,
        endpoint_origin=validated.endpoint_origin,
        event_types=validated.event_types,
        status="PENDING_VERIFICATION",
        signing_secret_id=secret_id,
        signing_secret_version=1,
        created_by_user_id=user_id,
        updated_by_user_id=user_id,
        created_at=now,
        updated_at=now,
        version=1,
    )
    session.add(record)
    await session.flush()
    snapshot = {"destination": destination_summary(record), "replayed": False}
    session.add(
        IdempotencyRecord(
            organization_id=project.organization_id,
            principal_id=str(user_id),
            endpoint=endpoint,
            key_digest=key_digest,
            request_fingerprint=fingerprint,
            resource_type="webhook_destination",
            resource_id=str(record.id),
            response_status=201,
            response_snapshot=snapshot,
            created_at=now,
            expires_at=now + timedelta(hours=24),
        )
    )
    await append_audit_event(
        session,
        organization_id=project.organization_id,
        project_id=project.id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="webhook_destination.created",
        resource_type="webhook_destination",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "endpoint_origin": record.endpoint_origin,
            "event_types": record.event_types,
            "status": record.status,
        },
    )
    return snapshot


async def list_webhook_destinations(
    session: AsyncSession, *, project_id: UUID, cursor: CursorPosition | None, limit: int
) -> tuple[list[WebhookDestination], bool]:
    await set_project_context(session, project_id)
    statement = select(WebhookDestination).where(WebhookDestination.project_id == project_id)
    if cursor is not None:
        statement = statement.where(
            or_(
                WebhookDestination.created_at < cursor.created_at,
                and_(
                    WebhookDestination.created_at == cursor.created_at,
                    WebhookDestination.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    WebhookDestination.created_at.desc(), WebhookDestination.id.desc()
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def get_webhook_destination(
    session: AsyncSession, *, project_id: UUID, destination_id: UUID
) -> WebhookDestination:
    await set_project_context(session, project_id)
    record = await session.scalar(
        select(WebhookDestination).where(
            WebhookDestination.id == destination_id, WebhookDestination.project_id == project_id
        )
    )
    if record is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    return record


async def rotate_webhook_signing_secret(
    session: AsyncSession,
    *,
    record: WebhookDestination,
    user_id: UUID,
    expected_version: int,
    signing_secret: str,
    actor_type: str,
    actor_id: str,
    request_id: str,
) -> dict[str, object]:
    locked = await session.scalar(
        select(WebhookDestination)
        .where(
            WebhookDestination.id == record.id, WebhookDestination.project_id == record.project_id
        )
        .with_for_update()
    )
    if locked is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    if locked.version != expected_version:
        raise ApiError(
            status_code=409,
            code="VERSION_CONFLICT",
            message="The webhook destination changed. Reload it and try again.",
        )
    secret = await session.scalar(
        select(ProjectSecret)
        .where(
            ProjectSecret.id == locked.signing_secret_id,
            ProjectSecret.project_id == locked.project_id,
        )
        .with_for_update()
    )
    if secret is None:
        raise RuntimeError("Webhook signing secret is unavailable")
    next_secret_version = secret.version + 1
    encrypted = encrypt_project_secret(
        signing_secret,
        organization_id=secret.organization_id,
        project_id=secret.project_id,
        secret_id=secret.id,
        name=secret.name,
        version=next_secret_version,
    )
    secret.encrypted_value, secret.value_nonce = encrypted.ciphertext, encrypted.value_nonce
    secret.wrapped_data_key, secret.key_nonce = encrypted.wrapped_data_key, encrypted.key_nonce
    secret.encryption_algorithm, secret.master_key_version = (
        encrypted.algorithm,
        encrypted.master_key_version,
    )
    secret.version, secret.updated_by_user_id, secret.updated_at = (
        next_secret_version,
        user_id,
        datetime.now(UTC),
    )
    locked.signing_secret_version, locked.version = next_secret_version, locked.version + 1
    locked.updated_by_user_id, locked.updated_at = user_id, datetime.now(UTC)
    await session.flush()
    await append_audit_event(
        session,
        organization_id=locked.organization_id,
        project_id=locked.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="webhook_destination.signing_secret_rotated",
        resource_type="webhook_destination",
        resource_id=str(locked.id),
        request_id=request_id,
        details={"signing_secret_version": next_secret_version},
    )
    return destination_summary(locked)


async def disable_webhook_destination(
    session: AsyncSession,
    *,
    record: WebhookDestination,
    user_id: UUID,
    expected_version: int,
    actor_type: str,
    actor_id: str,
    request_id: str,
) -> dict[str, object]:
    locked = await session.scalar(
        select(WebhookDestination)
        .where(
            WebhookDestination.id == record.id, WebhookDestination.project_id == record.project_id
        )
        .with_for_update()
    )
    if locked is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )
    if locked.version != expected_version:
        raise ApiError(
            status_code=409,
            code="VERSION_CONFLICT",
            message="The webhook destination changed. Reload it and try again.",
        )
    locked.status, locked.version = "DISABLED", locked.version + 1
    locked.updated_by_user_id, locked.updated_at = user_id, datetime.now(UTC)
    await session.flush()
    await append_audit_event(
        session,
        organization_id=locked.organization_id,
        project_id=locked.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="webhook_destination.disabled",
        resource_type="webhook_destination",
        resource_id=str(locked.id),
        request_id=request_id,
        details={"status": locked.status},
    )
    return destination_summary(locked)
