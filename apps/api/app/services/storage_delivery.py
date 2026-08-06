import hashlib
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import and_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..core.s3_storage import (
    StorageBackendError,
    capability_digest,
    object_storage,
    public_upload_payload,
)
from ..core.source_archive import SourceArchiveError, inspect_source_archive
from ..models import Agent, Build, ExecutionLease, StorageGrant, StorageObject
from ..storage_schemas import (
    CreateSourceUploadRequest,
    PresignedUpload,
    SourceUploadIntent,
    StorageDownloadGrant,
    StorageObjectSummary,
)
from .identity_tenancy import append_audit_event

settings = get_settings()


def storage_object_summary(record: StorageObject) -> StorageObjectSummary:
    return StorageObjectSummary.model_validate(record)


def _storage_error(exc: StorageBackendError) -> ApiError:
    status = 409 if exc.code == "STORAGE_OBJECT_NOT_UPLOADED" else 503
    return ApiError(status_code=status, code=exc.code, message=exc.message)


async def create_source_upload(
    session: AsyncSession,
    *,
    agent: Agent,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    request_id: str,
    payload: CreateSourceUploadRequest,
) -> SourceUploadIntent:
    if payload.size_bytes > settings.source_archive_max_bytes:
        raise ApiError(
            status_code=413,
            code="SOURCE_ARCHIVE_TOO_LARGE",
            message="The source archive exceeds the configured compressed limit.",
        )

    object_id = uuid4()
    safe_name = payload.file_name.replace('"', "")
    object_key = (
        f"organizations/{agent.organization_id}/projects/{agent.project_id}/"
        f"agents/{agent.id}/sources/{object_id}/{safe_name}"
    )
    expires_at = datetime.now(UTC) + timedelta(
        seconds=settings.storage_upload_grant_seconds
    )
    record = StorageObject(
        id=object_id,
        organization_id=agent.organization_id,
        project_id=agent.project_id,
        agent_id=agent.id,
        kind="AGENT_SOURCE",
        provider="S3",
        bucket=settings.s3_bucket,
        object_key=object_key,
        file_name=safe_name,
        media_type=payload.media_type,
        expected_size_bytes=payload.size_bytes,
        expected_sha256_digest=payload.sha256_digest,
        status="PENDING_UPLOAD",
        scan_status="PENDING",
        metadata_json={},
        created_by_user_id=user_id,
    )
    session.add(record)
    await session.flush()

    try:
        raw_upload = await object_storage.create_presigned_upload(
            object_key=record.object_key,
            object_id=str(record.id),
            content_type=record.media_type,
            sha256_digest=record.expected_sha256_digest,
            size_bytes=record.expected_size_bytes,
            expires_seconds=settings.storage_upload_grant_seconds,
        )
    except StorageBackendError as exc:
        raise _storage_error(exc) from exc

    url, fields = public_upload_payload(raw_upload)
    grant = StorageGrant(
        organization_id=record.organization_id,
        project_id=record.project_id,
        storage_object_id=record.id,
        issued_to_user_id=user_id,
        operation="UPLOAD",
        provider="S3_PRESIGNED",
        capability_digest=capability_digest(
            {
                "url": url,
                "fields": fields,
                "object_id": str(record.id),
                "expires_at": expires_at.isoformat(),
            }
        ),
        expires_at=expires_at,
    )
    session.add(grant)
    await append_audit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="storage.source_upload_created",
        resource_type="storage_object",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "agent_id": str(agent.id),
            "size_bytes": record.expected_size_bytes,
            "sha256_digest": record.expected_sha256_digest,
        },
    )
    return SourceUploadIntent(
        object=storage_object_summary(record),
        upload=PresignedUpload(
            url=url,
            fields=fields,
            expires_at=expires_at,
        ),
    )


async def complete_source_upload(
    session: AsyncSession,
    *,
    storage_object: StorageObject,
    actor_type: str,
    actor_id: str,
    request_id: str,
) -> StorageObject:
    record = await session.scalar(
        select(StorageObject)
        .where(StorageObject.id == storage_object.id)
        .with_for_update()
    )
    if record is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested storage object was not found.",
        )
    if record.status == "AVAILABLE":
        return record
    if record.status in {"REJECTED", "DELETED"}:
        raise ApiError(
            status_code=409,
            code="STORAGE_OBJECT_STATE_CONFLICT",
            message="The source object cannot be completed in its current state.",
        )

    try:
        head = await object_storage.head_object(object_key=record.object_key)
        if head.size_bytes != record.expected_size_bytes:
            raise SourceArchiveError(
                "STORAGE_SIZE_MISMATCH",
                "The uploaded object size does not match the upload intent.",
            )
        if head.content_type != record.media_type:
            raise SourceArchiveError(
                "STORAGE_MEDIA_TYPE_MISMATCH",
                "The uploaded object media type does not match the upload intent.",
            )
        if head.metadata.get("rdc-object-id") != str(record.id):
            raise SourceArchiveError(
                "STORAGE_METADATA_MISMATCH",
                "The uploaded object identity metadata is invalid.",
            )
        if head.metadata.get("sha256") != record.expected_sha256_digest:
            raise SourceArchiveError(
                "STORAGE_METADATA_MISMATCH",
                "The uploaded object digest metadata is invalid.",
            )
        content = await object_storage.read_object(
            object_key=record.object_key,
            max_bytes=settings.source_archive_max_bytes,
        )
        actual_digest = hashlib.sha256(content).hexdigest()
        if actual_digest != record.expected_sha256_digest:
            raise SourceArchiveError(
                "STORAGE_DIGEST_MISMATCH",
                "The uploaded source archive digest does not match the upload intent.",
            )
        agent = await session.scalar(
            select(Agent).where(
                Agent.id == record.agent_id,
                Agent.organization_id == record.organization_id,
                Agent.project_id == record.project_id,
                Agent.deleted_at.is_(None),
            )
        )
        if agent is None:
            raise SourceArchiveError(
                "SOURCE_AGENT_UNAVAILABLE",
                "The target Agent is unavailable.",
            )
        inspection = inspect_source_archive(
            content,
            expected_agent_slug=agent.slug,
            max_archive_bytes=settings.source_archive_max_bytes,
            max_expanded_bytes=settings.source_archive_max_expanded_bytes,
            max_files=settings.source_archive_max_files,
            max_single_file_bytes=settings.source_archive_max_single_file_bytes,
            max_compression_ratio=settings.source_archive_max_compression_ratio,
        )
    except StorageBackendError as exc:
        raise _storage_error(exc) from exc
    except SourceArchiveError as exc:
        now = datetime.now(UTC)
        record.status = "REJECTED"
        record.scan_status = "FAILED"
        record.rejection_code = exc.code
        record.rejected_at = now
        record.metadata_json = {"rejection_message": exc.message}
        try:
            await object_storage.delete_object(object_key=record.object_key)
        except StorageBackendError:
            pass
        await append_audit_event(
            session,
            organization_id=record.organization_id,
            project_id=record.project_id,
            actor_type=actor_type,
            actor_id=actor_id,
            action="storage.source_rejected",
            resource_type="storage_object",
            resource_id=str(record.id),
            request_id=request_id,
            details={"code": exc.code},
        )
        raise ApiError(
            status_code=422,
            code=exc.code,
            message=exc.message,
        ) from exc

    now = datetime.now(UTC)
    record.size_bytes = len(content)
    record.sha256_digest = actual_digest
    record.status = "AVAILABLE"
    record.scan_status = "PASSED"
    record.uploaded_at = now
    record.available_at = now
    record.rejection_code = None
    record.metadata_json = {
        "manifest": inspection.manifest,
        "manifest_digest": inspection.manifest_digest,
        "file_count": inspection.file_count,
        "expanded_size_bytes": inspection.expanded_size_bytes,
        "compressed_size_bytes": inspection.compressed_size_bytes,
        "paths": list(inspection.paths[:1000]),
        "paths_truncated": len(inspection.paths) > 1000,
    }
    grants = await session.scalars(
        select(StorageGrant).where(
            StorageGrant.storage_object_id == record.id,
            StorageGrant.operation == "UPLOAD",
            StorageGrant.completed_at.is_(None),
        )
    )
    for grant in grants.all():
        grant.completed_at = now
    await append_audit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="storage.source_available",
        resource_type="storage_object",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "sha256_digest": actual_digest,
            "manifest_digest": inspection.manifest_digest,
            "file_count": inspection.file_count,
        },
    )
    return record


async def list_storage_objects(
    session: AsyncSession,
    *,
    project_id: UUID,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[StorageObject], bool]:
    statement = select(StorageObject).where(
        StorageObject.project_id == project_id,
        StorageObject.deleted_at.is_(None),
    )
    if cursor is not None:
        statement = statement.where(
            or_(
                StorageObject.created_at < cursor.created_at,
                and_(
                    StorageObject.created_at == cursor.created_at,
                    StorageObject.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    StorageObject.created_at.desc(),
                    StorageObject.id.desc(),
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def _issue_download_grant(
    session: AsyncSession,
    *,
    record: StorageObject,
    lease_id: UUID | None,
    worker_id: UUID | None,
    user_id: UUID | None,
) -> StorageDownloadGrant:
    if record.status != "AVAILABLE" or record.scan_status != "PASSED":
        raise ApiError(
            status_code=409,
            code="STORAGE_OBJECT_NOT_AVAILABLE",
            message="The requested object is not available for download.",
        )
    expires_at = datetime.now(UTC) + timedelta(
        seconds=settings.storage_download_grant_seconds
    )
    try:
        url = await object_storage.create_presigned_download(
            object_key=record.object_key,
            file_name=record.file_name,
            expires_seconds=settings.storage_download_grant_seconds,
        )
    except StorageBackendError as exc:
        raise _storage_error(exc) from exc
    grant = StorageGrant(
        organization_id=record.organization_id,
        project_id=record.project_id,
        storage_object_id=record.id,
        lease_id=lease_id,
        worker_id=worker_id,
        issued_to_user_id=user_id,
        operation="DOWNLOAD",
        provider="S3_PRESIGNED",
        capability_digest=capability_digest(
            {
                "url": url,
                "object_id": str(record.id),
                "expires_at": expires_at.isoformat(),
                "lease_id": str(lease_id) if lease_id else None,
            }
        ),
        expires_at=expires_at,
    )
    session.add(grant)
    await session.flush()
    return StorageDownloadGrant(
        grant_id=grant.id,
        object_id=record.id,
        url=url,
        expires_at=expires_at,
    )


async def issue_user_download_grant(
    session: AsyncSession,
    *,
    record: StorageObject,
    user_id: UUID,
    actor_type: str,
    actor_id: str,
    request_id: str,
) -> StorageDownloadGrant:
    grant = await _issue_download_grant(
        session,
        record=record,
        lease_id=None,
        worker_id=None,
        user_id=user_id,
    )
    await append_audit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        actor_type=actor_type,
        actor_id=actor_id,
        action="storage.download_granted",
        resource_type="storage_object",
        resource_id=str(record.id),
        request_id=request_id,
        details={"grant_id": str(grant.grant_id)},
    )
    return grant


async def issue_build_source_download_grant(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker_id: UUID,
    request_id: str,
) -> StorageDownloadGrant:
    if lease.work_kind != "BUILD" or lease.build_id is None:
        raise ApiError(
            status_code=409,
            code="LEASE_WORK_KIND_CONFLICT",
            message="Only active Build leases can request source delivery.",
        )
    build = await session.scalar(
        select(Build).where(Build.id == lease.build_id)
    )
    if build is None:
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_STATE_CONFLICT",
            message="The Build source is unavailable.",
        )
    if build.source_object_id is None:
        raise ApiError(
            status_code=409,
            code="SOURCE_OBJECT_UNAVAILABLE",
            message="This legacy Build has no verified source archive.",
        )
    record = await session.scalar(
        select(StorageObject).where(
            StorageObject.id == build.source_object_id,
            StorageObject.organization_id == lease.organization_id,
            StorageObject.project_id == lease.project_id,
        )
    )
    if record is None:
        raise ApiError(
            status_code=409,
            code="SOURCE_OBJECT_UNAVAILABLE",
            message="The immutable Build source object is unavailable.",
        )
    grant = await _issue_download_grant(
        session,
        record=record,
        lease_id=lease.id,
        worker_id=worker_id,
        user_id=None,
    )
    await append_audit_event(
        session,
        organization_id=record.organization_id,
        project_id=record.project_id,
        actor_type="worker",
        actor_id=str(worker_id),
        action="storage.worker_source_granted",
        resource_type="storage_object",
        resource_id=str(record.id),
        request_id=request_id,
        details={"lease_id": str(lease.id), "grant_id": str(grant.grant_id)},
    )
    return grant
