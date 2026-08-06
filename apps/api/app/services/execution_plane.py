import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.envelope_encryption import decrypt_project_secret
from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..core.security import (
    canonical_fingerprint,
    issue_lease_token,
    issue_worker_token,
    secret_digest,
)
from ..core.worker_crypto import (
    decode_worker_public_key,
    encrypt_secret_payload_for_worker,
    worker_secret_aad,
)
from ..execution_schemas import (
    AppendWorkerEventsRequest,
    ArtifactRegistration,
    ClaimWorkRequest,
    CompleteLeaseRequest,
    ExecutionArtifactSummary,
    ExecutionLeaseSummary,
    LeaseClaim,
    LeaseStatusUpdateRequest,
    RegisteredWorkerResponse,
    RegisterWorkerRequest,
    RenewLeaseRequest,
    SecretEnvelopeRequest,
    SecretEnvelopeResponse,
    WorkerHeartbeatRequest,
    WorkerSummary,
)
from ..models import (
    AgentVersion,
    Build,
    BuildDispatchOutbox,
    ExecutionArtifact,
    ExecutionLease,
    ProjectSecret,
    Run,
    RunCommandOutbox,
    SecretInjectionGrant,
    WorkerIdentity,
)
from .identity_tenancy import append_audit_event
from .runs import append_run_event, sanitize_event_payload

settings = get_settings()


def worker_summary(record: WorkerIdentity) -> WorkerSummary:
    return WorkerSummary(
        id=record.id,
        name=record.name,
        public_prefix=record.public_prefix,
        last_four=record.last_four,
        capabilities=list(record.capabilities),
        max_concurrency=record.max_concurrency,
        status=record.status,
        protocol_version=record.protocol_version,
        software_version=record.software_version,
        metadata=dict(record.metadata_json),
        registered_at=record.registered_at,
        last_seen_at=record.last_seen_at,
        expires_at=record.expires_at,
    )


def lease_summary(record: ExecutionLease) -> ExecutionLeaseSummary:
    return ExecutionLeaseSummary(
        id=record.id,
        worker_id=record.worker_id,
        organization_id=record.organization_id,
        project_id=record.project_id,
        work_kind=record.work_kind,  # type: ignore[arg-type]
        build_id=record.build_id,
        run_id=record.run_id,
        status=record.status,  # type: ignore[arg-type]
        attempt=record.attempt,
        claimed_at=record.claimed_at,
        expires_at=record.expires_at,
        completed_at=record.completed_at,
        failure_code=record.failure_code,
        failure_summary=record.failure_summary,
    )


def artifact_summary(record: ExecutionArtifact) -> ExecutionArtifactSummary:
    return ExecutionArtifactSummary(
        id=record.id,
        organization_id=record.organization_id,
        project_id=record.project_id,
        build_id=record.build_id,
        run_id=record.run_id,
        lease_id=record.lease_id,
        kind=record.kind,  # type: ignore[arg-type]
        digest_algorithm=record.digest_algorithm,
        digest=record.digest,
        object_key=record.object_key,
        media_type=record.media_type,
        size_bytes=record.size_bytes,
        status=record.status,  # type: ignore[arg-type]
        scan_status=record.scan_status,  # type: ignore[arg-type]
        provenance=dict(record.provenance),
        created_at=record.created_at,
    )


async def register_worker(
    session: AsyncSession,
    *,
    payload: RegisterWorkerRequest,
    request_id: str,
) -> RegisteredWorkerResponse:
    existing = await session.scalar(
        select(WorkerIdentity).where(WorkerIdentity.name == payload.name)
    )
    if existing is not None:
        raise ApiError(
            status_code=409,
            code="WORKER_NAME_CONFLICT",
            message="A worker with this name is already registered.",
        )
    issued = issue_worker_token()
    now = datetime.now(UTC)
    record = WorkerIdentity(
        name=payload.name,
        public_prefix=issued.public_prefix,
        last_four=issued.last_four,
        token_digest=secret_digest(
            issued.raw_token,
            settings.worker_token_pepper,
        ),
        capabilities=sorted(payload.capabilities),
        max_concurrency=payload.max_concurrency,
        status="ACTIVE",
        protocol_version=payload.protocol_version,
        software_version=payload.software_version,
        metadata_json=payload.metadata,
        registered_at=now,
        last_seen_at=now,
    )
    session.add(record)
    await session.flush()
    await append_audit_event(
        session,
        organization_id=None,
        project_id=None,
        actor_type="system",
        actor_id="worker-bootstrap",
        action="worker.registered",
        resource_type="worker",
        resource_id=str(record.id),
        request_id=request_id,
        details={
            "name": record.name,
            "capabilities": list(record.capabilities),
            "protocol_version": record.protocol_version,
        },
    )
    return RegisteredWorkerResponse(
        worker=worker_summary(record),
        token=issued.raw_token,
    )


async def heartbeat_worker(
    session: AsyncSession,
    *,
    worker: WorkerIdentity,
    payload: WorkerHeartbeatRequest,
    request_id: str,
) -> WorkerSummary:
    if worker.status == "REVOKED" or worker.revoked_at is not None:
        raise ApiError(
            status_code=401,
            code="INTERNAL_CREDENTIAL_INVALID",
            message="The internal credential is invalid.",
        )
    now = datetime.now(UTC)
    worker.status = payload.status
    worker.software_version = payload.software_version
    worker.last_seen_at = now
    worker.metadata_json = {
        **payload.metadata,
        "active_lease_count": payload.active_lease_count,
    }
    await reap_expired_leases(session, now=now, request_id=request_id)
    return worker_summary(worker)


async def _reset_expired_source(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    now: datetime,
) -> None:
    retry = lease.attempt < settings.worker_max_attempts
    if lease.work_kind == "BUILD":
        source = await session.scalar(
            select(BuildDispatchOutbox).where(
                BuildDispatchOutbox.id == lease.source_outbox_id
            )
        )
        build = await session.scalar(
            select(Build).where(Build.id == lease.build_id)
        )
        if source is not None:
            source.status = "PENDING" if retry else "FAILED"
            source.available_at = now + timedelta(seconds=min(300, 2**lease.attempt))
            source.last_error_code = "LEASE_EXPIRED"
            source.updated_at = now
        if build is not None:
            build.status = "QUEUED" if retry else "FAILED"
            build.error_code = None if retry else "LEASE_EXPIRED"
            build.error_message = None if retry else "The execution lease expired."
            build.completed_at = None if retry else now
            build.updated_at = now
            build.version += 1
        return

    source = await session.scalar(
        select(RunCommandOutbox).where(
            RunCommandOutbox.id == lease.source_outbox_id
        )
    )
    run = await session.scalar(select(Run).where(Run.id == lease.run_id))
    if source is not None:
        source.status = "PENDING" if retry else "FAILED"
        source.available_at = now + timedelta(seconds=min(300, 2**lease.attempt))
        source.last_error_code = "LEASE_EXPIRED"
        source.updated_at = now
    if run is None:
        return
    previous = run.status
    if lease.work_kind == "RUN_START":
        run.status = "QUEUED" if retry else "FAILED"
        run.failure_code = None if retry else "LEASE_EXPIRED"
        run.failure_summary = None if retry else "The execution lease expired."
        run.finished_at = None if retry else now
    elif not retry:
        run.status = "FAILED"
        run.failure_code = "CANCEL_LEASE_EXPIRED"
        run.failure_summary = "The cancellation lease expired."
        run.finished_at = now
    run.updated_at = now
    run.version += 1
    if run.status != previous:
        await append_run_event(
            session,
            run=run,
            event_type="run.status",
            payload={"previous_status": previous, "status": run.status},
        )


async def reap_expired_leases(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    request_id: str,
) -> int:
    current = now or datetime.now(UTC)
    records = list(
        (
            await session.scalars(
                select(ExecutionLease)
                .where(
                    ExecutionLease.status == "ACTIVE",
                    ExecutionLease.expires_at <= current,
                )
                .order_by(ExecutionLease.expires_at.asc())
                .with_for_update(skip_locked=True)
                .limit(100)
            )
        ).all()
    )
    for lease in records:
        await _reset_expired_source(session, lease=lease, now=current)
        grants = list(
            (
                await session.scalars(
                    select(SecretInjectionGrant).where(
                        SecretInjectionGrant.lease_id == lease.id,
                        SecretInjectionGrant.status == "ISSUED",
                    )
                )
            ).all()
        )
        for grant in grants:
            grant.status = "EXPIRED"
        lease.status = "EXPIRED"
        lease.completed_at = current
        lease.failure_code = "LEASE_EXPIRED"
        lease.failure_summary = "The worker did not renew the lease."
        lease.updated_at = current
        await append_audit_event(
            session,
            organization_id=lease.organization_id,
            project_id=lease.project_id,
            actor_type="system",
            actor_id="lease-reaper",
            action="execution.lease.expired",
            resource_type="execution_lease",
            resource_id=str(lease.id),
            request_id=request_id,
            details={
                "work_kind": lease.work_kind,
                "attempt": lease.attempt,
                "worker_id": str(lease.worker_id),
            },
        )
    return len(records)


async def _build_claim_payload(
    session: AsyncSession,
    *,
    source: BuildDispatchOutbox,
) -> tuple[dict[str, object], Build]:
    build = await session.scalar(
        select(Build).where(Build.id == source.build_id)
    )
    if build is None or build.status != "QUEUED":
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_STATE_CONFLICT",
            message="The Build work item is no longer claimable.",
        )
    version = await session.scalar(
        select(AgentVersion).where(AgentVersion.id == build.agent_version_id)
    )
    if version is None:
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_STATE_CONFLICT",
            message="The immutable Agent version is unavailable.",
        )
    payload: dict[str, object] = {
        "schema_version": "1",
        "work_kind": "BUILD",
        "build_id": str(build.id),
        "organization_id": str(build.organization_id),
        "project_id": str(build.project_id),
        "agent_id": str(build.agent_id),
        "agent_version_id": str(build.agent_version_id),
        "manifest_digest": build.manifest_digest,
        "manifest": dict(version.manifest),
        "source": {"kind": "deferred", "available": False},
        "execution_enabled": False,
    }
    return payload, build


async def _run_claim_payload(
    session: AsyncSession,
    *,
    source: RunCommandOutbox,
    work_kind: str,
) -> tuple[dict[str, object], Run]:
    run = await session.scalar(select(Run).where(Run.id == source.run_id))
    if run is None:
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_STATE_CONFLICT",
            message="The Run work item is unavailable.",
        )
    version = await session.scalar(
        select(AgentVersion).where(AgentVersion.id == run.agent_version_id)
    )
    if version is None:
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_STATE_CONFLICT",
            message="The immutable Agent version is unavailable.",
        )
    artifact = await session.scalar(
        select(ExecutionArtifact).where(
            ExecutionArtifact.build_id == run.build_id,
            ExecutionArtifact.kind == "CONTAINER_IMAGE",
            ExecutionArtifact.status == "AVAILABLE",
            ExecutionArtifact.scan_status == "PASSED",
        )
    )
    payload: dict[str, object] = {
        "schema_version": "1",
        "work_kind": work_kind,
        "run_id": str(run.id),
        "organization_id": str(run.organization_id),
        "project_id": str(run.project_id),
        "agent_id": str(run.agent_id),
        "agent_version_id": str(run.agent_version_id),
        "build_id": str(run.build_id),
        "manifest": dict(version.manifest),
        "input_reference": dict(run.input_reference),
        "runtime": dict(run.runtime_configuration),
        "artifact": (
            {
                "id": str(artifact.id),
                "digest": f"{artifact.digest_algorithm}:{artifact.digest}",
                "object_key": artifact.object_key,
                "media_type": artifact.media_type,
            }
            if artifact is not None
            else None
        ),
        "execution_enabled": False,
    }
    return payload, run


async def _select_source(
    session: AsyncSession,
    *,
    kind: str,
    now: datetime,
) -> BuildDispatchOutbox | RunCommandOutbox | None:
    if kind == "BUILD":
        return await session.scalar(
            select(BuildDispatchOutbox)
            .where(
                BuildDispatchOutbox.status == "PENDING",
                BuildDispatchOutbox.available_at <= now,
            )
            .order_by(
                BuildDispatchOutbox.available_at.asc(),
                BuildDispatchOutbox.id.asc(),
            )
            .with_for_update(skip_locked=True)
            .limit(1)
        )
    command = "START" if kind == "RUN_START" else "CANCEL"
    return await session.scalar(
        select(RunCommandOutbox)
        .where(
            RunCommandOutbox.status == "PENDING",
            RunCommandOutbox.command == command,
            RunCommandOutbox.available_at <= now,
        )
        .order_by(
            RunCommandOutbox.available_at.asc(),
            RunCommandOutbox.id.asc(),
        )
        .with_for_update(skip_locked=True)
        .limit(1)
    )


async def _lock_worker_claims(
    session: AsyncSession,
    *,
    worker_id: UUID,
) -> None:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
        {"scope": f"rdc:worker-claim:{worker_id}"},
    )


async def claim_work(
    session: AsyncSession,
    *,
    worker: WorkerIdentity,
    payload: ClaimWorkRequest,
    request_id: str,
) -> LeaseClaim | None:
    now = datetime.now(UTC)
    await reap_expired_leases(session, now=now, request_id=request_id)
    await _lock_worker_claims(session, worker_id=worker.id)
    if worker.status != "ACTIVE":
        raise ApiError(
            status_code=409,
            code="WORKER_DRAINING",
            message="A draining worker cannot claim new work.",
        )
    requested = list(payload.kinds)
    unsupported = [kind for kind in requested if kind not in worker.capabilities]
    if unsupported:
        raise ApiError(
            status_code=403,
            code="WORKER_CAPABILITY_DENIED",
            message="The worker is not allowed to claim this work kind.",
            details={"unsupported": unsupported},
        )
    active_count = await session.scalar(
        select(func.count())
        .select_from(ExecutionLease)
        .where(
            ExecutionLease.worker_id == worker.id,
            ExecutionLease.status == "ACTIVE",
            ExecutionLease.expires_at > now,
        )
    )
    if int(active_count or 0) >= worker.max_concurrency:
        raise ApiError(
            status_code=409,
            code="WORKER_CONCURRENCY_LIMIT",
            message="The worker has reached its active lease limit.",
        )

    for kind in requested:
        source = await _select_source(session, kind=kind, now=now)
        if source is None:
            continue

        if isinstance(source, BuildDispatchOutbox):
            organization_id = source.organization_id
            project_id = source.project_id
            build_id: UUID | None = source.build_id
            run_id: UUID | None = None
        else:
            organization_id = source.organization_id
            project_id = source.project_id
            build_id = None
            run_id = source.run_id

        source.status = "CLAIMED"
        source.attempts += 1
        source.claimed_at = now
        source.updated_at = now
        issued = issue_lease_token(pepper=settings.lease_token_pepper)
        expires_at = now + timedelta(seconds=settings.worker_lease_seconds)
        lease = ExecutionLease(
            worker_id=worker.id,
            organization_id=organization_id,
            project_id=project_id,
            work_kind=kind,
            source_outbox_id=source.id,
            source_topic=source.topic,
            build_id=build_id,
            run_id=run_id,
            lease_token_digest=issued.digest,
            payload_digest=canonical_fingerprint({}),
            payload_snapshot={},
            status="ACTIVE",
            attempt=source.attempts,
            claimed_at=now,
            expires_at=expires_at,
        )
        session.add(lease)
        await session.flush()

        if isinstance(source, BuildDispatchOutbox):
            claim_payload, build = await _build_claim_payload(
                session,
                source=source,
            )
            build.status = "STARTING"
            build.started_at = build.started_at or now
            build.updated_at = now
            build.version += 1
        else:
            claim_payload, run = await _run_claim_payload(
                session,
                source=source,
                work_kind=kind,
            )
            if kind == "RUN_START":
                previous = run.status
                if previous != "QUEUED":
                    raise ApiError(
                        status_code=409,
                        code="WORK_ITEM_STATE_CONFLICT",
                        message="The Run is no longer queued.",
                    )
                run.status = "STARTING"
                run.started_at = run.started_at or now
                run.updated_at = now
                run.version += 1
                await append_run_event(
                    session,
                    run=run,
                    event_type="run.status",
                    payload={
                        "previous_status": previous,
                        "status": "STARTING",
                    },
                )
            elif run.status != "ABORTING":
                raise ApiError(
                    status_code=409,
                    code="WORK_ITEM_STATE_CONFLICT",
                    message="The Run is no longer awaiting cancellation.",
                )

        lease.payload_digest = canonical_fingerprint(claim_payload)
        lease.payload_snapshot = claim_payload
        await append_audit_event(
            session,
            organization_id=organization_id,
            project_id=project_id,
            actor_type="worker",
            actor_id=str(worker.id),
            action="execution.lease.claimed",
            resource_type="execution_lease",
            resource_id=str(lease.id),
            request_id=request_id,
            details={
                "work_kind": kind,
                "attempt": lease.attempt,
                "source_topic": lease.source_topic,
            },
        )
        return LeaseClaim(
            id=lease.id,
            work_kind=kind,  # type: ignore[arg-type]
            organization_id=organization_id,
            project_id=project_id,
            build_id=build_id,
            run_id=run_id,
            attempt=lease.attempt,
            claimed_at=now,
            expires_at=expires_at,
            lease_token=issued.raw_token,
            payload=claim_payload,
        )
    return None


async def renew_lease(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: RenewLeaseRequest,
    request_id: str,
) -> ExecutionLeaseSummary:
    now = datetime.now(UTC)
    hard_limit = lease.claimed_at + timedelta(
        seconds=settings.worker_lease_max_seconds
    )
    requested = max(now, lease.expires_at) + timedelta(
        seconds=payload.extend_seconds
    )
    extended_until = min(requested, hard_limit)
    if extended_until <= now:
        raise ApiError(
            status_code=409,
            code="LEASE_MAXIMUM_REACHED",
            message="The lease reached its maximum lifetime.",
        )
    lease.expires_at = extended_until
    lease.last_renewed_at = now
    lease.updated_at = now
    await append_audit_event(
        session,
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        actor_type="worker",
        actor_id=str(worker.id),
        action="execution.lease.renewed",
        resource_type="execution_lease",
        resource_id=str(lease.id),
        request_id=request_id,
        details={"expires_at": lease.expires_at.isoformat()},
    )
    return lease_summary(lease)


async def update_lease_status(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: LeaseStatusUpdateRequest,
    request_id: str,
) -> ExecutionLeaseSummary:
    now = datetime.now(UTC)
    if lease.work_kind == "BUILD":
        if payload.status not in {"STARTING", "RUNNING"}:
            raise ApiError(
                status_code=409,
                code="WORK_ITEM_STATE_CONFLICT",
                message="That status is invalid for a Build lease.",
            )
        build = await session.scalar(select(Build).where(Build.id == lease.build_id))
        if build is None:
            raise ApiError(
                status_code=404,
                code="RESOURCE_NOT_FOUND",
                message="The Build was not found.",
            )
        build.status = payload.status
        build.started_at = build.started_at or now
        build.updated_at = now
        build.version += 1
    else:
        run = await session.scalar(select(Run).where(Run.id == lease.run_id))
        if run is None:
            raise ApiError(
                status_code=404,
                code="RESOURCE_NOT_FOUND",
                message="The Run was not found.",
            )
        allowed = (
            {"STARTING", "RUNNING"}
            if lease.work_kind == "RUN_START"
            else {"ABORTING"}
        )
        if payload.status not in allowed:
            raise ApiError(
                status_code=409,
                code="WORK_ITEM_STATE_CONFLICT",
                message="That status is invalid for this Run lease.",
            )
        previous = run.status
        run.status = payload.status
        run.started_at = run.started_at or now
        run.updated_at = now
        run.version += 1
        if previous != run.status:
            await append_run_event(
                session,
                run=run,
                event_type="run.status",
                payload={
                    "previous_status": previous,
                    "status": run.status,
                    "message": payload.message,
                },
            )
    lease.last_renewed_at = now
    await append_audit_event(
        session,
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        actor_type="worker",
        actor_id=str(worker.id),
        action="execution.work.status_updated",
        resource_type="execution_lease",
        resource_id=str(lease.id),
        request_id=request_id,
        details={"status": payload.status},
    )
    return lease_summary(lease)


async def append_worker_events(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: AppendWorkerEventsRequest,
    request_id: str,
) -> int:
    if lease.work_kind != "RUN_START" or lease.run_id is None:
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_STATE_CONFLICT",
            message="Only Run execution leases can append Run events.",
        )
    if "EVENT_INGEST" not in worker.capabilities:
        raise ApiError(
            status_code=403,
            code="WORKER_CAPABILITY_DENIED",
            message="The worker cannot ingest Run events.",
        )
    run = await session.scalar(select(Run).where(Run.id == lease.run_id))
    if run is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The Run was not found.",
        )
    for event in payload.events:
        await append_run_event(
            session,
            run=run,
            event_type=event.event_type,
            payload=sanitize_event_payload(event.payload),
        )
    await append_audit_event(
        session,
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        actor_type="worker",
        actor_id=str(worker.id),
        action="execution.run_events.appended",
        resource_type="run",
        resource_id=str(run.id),
        request_id=request_id,
        details={
            "count": len(payload.events),
            "event_types": sorted({event.event_type for event in payload.events}),
        },
    )
    return len(payload.events)


async def _register_artifact(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: ArtifactRegistration,
) -> ExecutionArtifact:
    existing = await session.scalar(
        select(ExecutionArtifact).where(
            ExecutionArtifact.organization_id == lease.organization_id,
            ExecutionArtifact.digest_algorithm == payload.digest_algorithm,
            ExecutionArtifact.digest == payload.digest,
            ExecutionArtifact.kind == payload.kind,
        )
    )
    if existing is not None:
        if (
            existing.object_key != payload.object_key
            or existing.size_bytes != payload.size_bytes
            or existing.media_type != payload.media_type
        ):
            raise ApiError(
                status_code=409,
                code="ARTIFACT_DIGEST_CONFLICT",
                message="The artifact digest is already registered with different metadata.",
            )
        return existing
    record = ExecutionArtifact(
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        build_id=lease.build_id,
        run_id=lease.run_id,
        lease_id=lease.id,
        created_by_worker_id=worker.id,
        kind=payload.kind,
        digest_algorithm=payload.digest_algorithm,
        digest=payload.digest,
        object_key=payload.object_key,
        media_type=payload.media_type,
        size_bytes=payload.size_bytes,
        status=payload.status,
        scan_status=payload.scan_status,
        provenance=payload.provenance,
        created_at=datetime.now(UTC),
    )
    session.add(record)
    try:
        await session.flush()
    except IntegrityError as exc:
        raise ApiError(
            status_code=409,
            code="ARTIFACT_DIGEST_CONFLICT",
            message="The artifact digest could not be registered.",
        ) from exc
    return record


async def _source_for_lease(
    session: AsyncSession,
    lease: ExecutionLease,
) -> BuildDispatchOutbox | RunCommandOutbox | None:
    if lease.work_kind == "BUILD":
        return await session.scalar(
            select(BuildDispatchOutbox).where(
                BuildDispatchOutbox.id == lease.source_outbox_id
            )
        )
    return await session.scalar(
        select(RunCommandOutbox).where(
            RunCommandOutbox.id == lease.source_outbox_id
        )
    )


async def complete_lease(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: CompleteLeaseRequest,
    request_id: str,
) -> ExecutionLeaseSummary:
    now = datetime.now(UTC)
    source = await _source_for_lease(session, lease)
    retry = (
        payload.retryable
        and payload.outcome in {"FAILED", "TIMED_OUT"}
        and lease.attempt < settings.worker_max_attempts
    )
    artifact: ExecutionArtifact | None = None
    if payload.artifact is not None:
        artifact = await _register_artifact(
            session,
            lease=lease,
            worker=worker,
            payload=payload.artifact,
        )

    if retry:
        lease.status = "FAILED"
        lease.completed_at = now
        lease.failure_code = payload.error_code or "WORKER_RETRYABLE_FAILURE"
        lease.failure_summary = payload.error_summary
        if source is not None:
            source.status = "PENDING"
            source.available_at = now + timedelta(seconds=min(300, 2**lease.attempt))
            source.last_error_code = lease.failure_code
            source.updated_at = now
        await _reset_retry_target(
            session,
            lease=lease,
            now=now,
        )
    elif lease.work_kind == "BUILD":
        build = await session.scalar(select(Build).where(Build.id == lease.build_id))
        if build is None:
            raise ApiError(
                status_code=404,
                code="RESOURCE_NOT_FOUND",
                message="The Build was not found.",
            )
        if payload.outcome == "SUCCEEDED":
            if (
                artifact is None
                or artifact.kind != "CONTAINER_IMAGE"
                or artifact.status != "AVAILABLE"
                or artifact.scan_status != "PASSED"
            ):
                raise ApiError(
                    status_code=422,
                    code="ARTIFACT_REQUIRED",
                    message="A passed, available container image artifact is required.",
                )
            build.status = "SUCCEEDED"
            build.artifact_digest = (
                f"{artifact.digest_algorithm}:{artifact.digest}"
            )
            build.error_code = None
            build.error_message = None
        elif payload.outcome == "TIMED_OUT":
            build.status = "TIMED_OUT"
            build.error_code = payload.error_code or "BUILD_TIMED_OUT"
            build.error_message = payload.error_summary
        elif payload.outcome in {"ABORTED", "CANCELLED"}:
            build.status = "CANCELLED"
            build.error_code = payload.error_code
            build.error_message = payload.error_summary
        else:
            build.status = "FAILED"
            build.error_code = payload.error_code or "BUILD_FAILED"
            build.error_message = payload.error_summary
        build.completed_at = now
        build.updated_at = now
        build.version += 1
        lease.status = "COMPLETED" if payload.outcome == "SUCCEEDED" else "FAILED"
        lease.completed_at = now
        lease.failure_code = build.error_code
        lease.failure_summary = build.error_message
        if source is not None:
            source.status = "DELIVERED" if payload.outcome == "SUCCEEDED" else "FAILED"
            source.delivered_at = now
            source.last_error_code = build.error_code
            source.updated_at = now
    else:
        run = await session.scalar(select(Run).where(Run.id == lease.run_id))
        if run is None:
            raise ApiError(
                status_code=404,
                code="RESOURCE_NOT_FOUND",
                message="The Run was not found.",
            )
        previous = run.status
        if lease.work_kind == "RUN_CANCEL":
            if payload.outcome not in {"ABORTED", "SUCCEEDED"}:
                run.status = "FAILED"
                run.failure_code = payload.error_code or "CANCEL_FAILED"
                run.failure_summary = payload.error_summary
            else:
                run.status = "ABORTED"
                run.failure_code = None
                run.failure_summary = None
        elif payload.outcome == "SUCCEEDED":
            run.status = "SUCCEEDED"
            run.failure_code = None
            run.failure_summary = None
        elif payload.outcome == "TIMED_OUT":
            run.status = "TIMED_OUT"
            run.failure_code = payload.error_code or "RUN_TIMED_OUT"
            run.failure_summary = payload.error_summary
        elif payload.outcome in {"ABORTED", "CANCELLED"}:
            run.status = "ABORTED"
            run.failure_code = payload.error_code
            run.failure_summary = payload.error_summary
        else:
            run.status = "FAILED"
            run.failure_code = payload.error_code or "RUN_FAILED"
            run.failure_summary = payload.error_summary
        run.finished_at = now
        run.updated_at = now
        run.version += 1
        await append_run_event(
            session,
            run=run,
            event_type="run.status",
            payload={"previous_status": previous, "status": run.status},
        )
        terminal_type = (
            "run.completed"
            if run.status in {"SUCCEEDED", "ABORTED"}
            else "run.failed"
        )
        await append_run_event(
            session,
            run=run,
            event_type=terminal_type,
            payload={
                "status": run.status,
                "failure_code": run.failure_code,
                "failure_summary": run.failure_summary,
            },
        )
        lease.status = (
            "COMPLETED"
            if run.status in {"SUCCEEDED", "ABORTED"}
            else "FAILED"
        )
        lease.completed_at = now
        lease.failure_code = run.failure_code
        lease.failure_summary = run.failure_summary
        if source is not None:
            source.status = (
                "DELIVERED"
                if lease.status == "COMPLETED"
                else "FAILED"
            )
            source.delivered_at = now
            source.last_error_code = run.failure_code
            source.updated_at = now

    lease.updated_at = now
    grants = list(
        (
            await session.scalars(
                select(SecretInjectionGrant).where(
                    SecretInjectionGrant.lease_id == lease.id,
                    SecretInjectionGrant.status == "ISSUED",
                )
            )
        ).all()
    )
    for grant in grants:
        grant.status = "REVOKED"

    await append_audit_event(
        session,
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        actor_type="worker",
        actor_id=str(worker.id),
        action="execution.lease.completed",
        resource_type="execution_lease",
        resource_id=str(lease.id),
        request_id=request_id,
        details={
            "work_kind": lease.work_kind,
            "outcome": payload.outcome,
            "retryable": retry,
            "artifact_id": str(artifact.id) if artifact is not None else None,
        },
    )
    return lease_summary(lease)


async def _reset_retry_target(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    now: datetime,
) -> None:
    if lease.work_kind == "BUILD":
        build = await session.scalar(select(Build).where(Build.id == lease.build_id))
        if build is not None:
            build.status = "QUEUED"
            build.error_code = None
            build.error_message = None
            build.completed_at = None
            build.updated_at = now
            build.version += 1
        return
    run = await session.scalar(select(Run).where(Run.id == lease.run_id))
    if run is None:
        return
    if lease.work_kind == "RUN_START":
        previous = run.status
        run.status = "QUEUED"
        run.failure_code = None
        run.failure_summary = None
        run.finished_at = None
        run.updated_at = now
        run.version += 1
        await append_run_event(
            session,
            run=run,
            event_type="run.status",
            payload={"previous_status": previous, "status": "QUEUED"},
        )


async def issue_secret_envelope(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: SecretEnvelopeRequest,
    request_id: str,
) -> SecretEnvelopeResponse:
    if lease.work_kind != "RUN_START" or lease.run_id is None:
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_STATE_CONFLICT",
            message="Secret envelopes are available only for Run execution leases.",
        )
    if "SECRET_ENVELOPE" not in worker.capabilities:
        raise ApiError(
            status_code=403,
            code="WORKER_CAPABILITY_DENIED",
            message="The worker cannot request secret envelopes.",
        )
    run = await session.scalar(select(Run).where(Run.id == lease.run_id))
    if run is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The Run was not found.",
        )
    version = await session.scalar(
        select(AgentVersion).where(AgentVersion.id == run.agent_version_id)
    )
    if version is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The immutable Agent version was not found.",
        )
    declared_raw = version.manifest.get("secrets", [])
    declared = {
        str(name)
        for name in declared_raw
        if isinstance(name, str)
    } if isinstance(declared_raw, list) else set()
    requested = set(payload.names)
    if not requested.issubset(declared):
        raise ApiError(
            status_code=403,
            code="SECRET_NOT_DECLARED",
            message="The Agent version did not declare every requested secret.",
        )
    try:
        worker_public_key = decode_worker_public_key(
            payload.worker_public_key_b64
        )
    except ValueError as exc:
        raise ApiError(
            status_code=422,
            code="VALIDATION_FAILED",
            message=str(exc),
        ) from exc
    public_key_digest = hashlib.sha256(worker_public_key).hexdigest()
    fingerprint = canonical_fingerprint(
        {
            "lease_id": str(lease.id),
            "names": payload.names,
            "environment": payload.environment,
            "worker_public_key_digest": public_key_digest,
        }
    )
    now = datetime.now(UTC)
    existing = await session.scalar(
        select(SecretInjectionGrant).where(
            SecretInjectionGrant.lease_id == lease.id,
            SecretInjectionGrant.request_fingerprint == fingerprint,
        )
    )
    if existing is not None:
        if existing.expires_at <= now or existing.status != "ISSUED":
            raise ApiError(
                status_code=409,
                code="SECRET_GRANT_EXPIRED",
                message="The secret grant expired. Claim a new execution lease.",
            )
        return SecretEnvelopeResponse(
            grant_id=existing.id,
            algorithm=existing.algorithm,
            ephemeral_public_key_b64=base64.b64encode(
                existing.ephemeral_public_key
            ).decode("ascii"),
            nonce_b64=base64.b64encode(existing.nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(existing.ciphertext).decode("ascii"),
            expires_at=existing.expires_at,
            secret_names=list(existing.secret_names),
            environment=payload.environment,
        )
    records = list(
        (
            await session.scalars(
                select(ProjectSecret).where(
                    ProjectSecret.organization_id == lease.organization_id,
                    ProjectSecret.project_id == lease.project_id,
                    ProjectSecret.environment == payload.environment,
                    ProjectSecret.name.in_(payload.names),
                )
            )
        ).all()
    )
    by_name = {record.name: record for record in records}
    missing = [name for name in payload.names if name not in by_name]
    if missing:
        raise ApiError(
            status_code=409,
            code="SECRET_NOT_CONFIGURED",
            message="One or more declared project secrets are not configured.",
            details={"names": missing, "environment": payload.environment},
        )
    values: dict[str, str] = {}
    for name in payload.names:
        record = by_name[name]
        if record.master_key_version != settings.project_secret_master_key_version:
            raise ApiError(
                status_code=503,
                code="SECRET_KEY_VERSION_UNAVAILABLE",
                message="A required secret key version is unavailable.",
            )
        raw = decrypt_project_secret(
            ciphertext=record.encrypted_value,
            value_nonce=record.value_nonce,
            wrapped_data_key=record.wrapped_data_key,
            key_nonce=record.key_nonce,
            organization_id=record.organization_id,
            project_id=record.project_id,
            secret_id=record.id,
            name=record.name,
            version=record.version,
        )
        values[name] = raw.decode("utf-8")
        record.last_used_at = now
    plaintext = bytearray(
        json.dumps(
            {
                "schema_version": "1",
                "lease_id": str(lease.id),
                "run_id": str(run.id),
                "environment": payload.environment,
                "secrets": values,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    aad = worker_secret_aad(
        lease_id=str(lease.id),
        worker_id=str(worker.id),
        run_id=str(run.id),
    )
    try:
        envelope = encrypt_secret_payload_for_worker(
            bytes(plaintext),
            worker_public_key=worker_public_key,
            aad=aad,
        )
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0
        values.clear()
    expires_at = min(
        lease.expires_at,
        now + timedelta(seconds=settings.worker_secret_envelope_seconds),
    )
    grant = SecretInjectionGrant(
        worker_id=worker.id,
        lease_id=lease.id,
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        run_id=run.id,
        request_fingerprint=fingerprint,
        secret_names=payload.names,
        environment=payload.environment,
        algorithm=envelope.algorithm,
        ephemeral_public_key=envelope.ephemeral_public_key,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        worker_public_key_digest=envelope.worker_public_key_digest,
        status="ISSUED",
        issued_at=now,
        expires_at=expires_at,
    )
    session.add(grant)
    await session.flush()
    await append_audit_event(
        session,
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        actor_type="worker",
        actor_id=str(worker.id),
        action="execution.secret_envelope.issued",
        resource_type="secret_injection_grant",
        resource_id=str(grant.id),
        request_id=request_id,
        details={
            "run_id": str(run.id),
            "secret_names": payload.names,
            "environment": payload.environment,
            "expires_at": expires_at.isoformat(),
        },
    )
    return SecretEnvelopeResponse(
        grant_id=grant.id,
        algorithm=grant.algorithm,
        ephemeral_public_key_b64=base64.b64encode(
            grant.ephemeral_public_key
        ).decode("ascii"),
        nonce_b64=base64.b64encode(grant.nonce).decode("ascii"),
        ciphertext_b64=base64.b64encode(grant.ciphertext).decode("ascii"),
        expires_at=grant.expires_at,
        secret_names=list(grant.secret_names),
        environment=payload.environment,
    )


async def list_project_leases(
    session: AsyncSession,
    *,
    project_id: UUID,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[ExecutionLease], bool]:
    statement = select(ExecutionLease).where(
        ExecutionLease.project_id == project_id
    )
    if cursor is not None:
        statement = statement.where(
            or_(
                ExecutionLease.created_at < cursor.created_at,
                and_(
                    ExecutionLease.created_at == cursor.created_at,
                    ExecutionLease.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    ExecutionLease.created_at.desc(),
                    ExecutionLease.id.desc(),
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit


async def list_project_artifacts(
    session: AsyncSession,
    *,
    project_id: UUID,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[ExecutionArtifact], bool]:
    statement = select(ExecutionArtifact).where(
        ExecutionArtifact.project_id == project_id
    )
    if cursor is not None:
        statement = statement.where(
            or_(
                ExecutionArtifact.created_at < cursor.created_at,
                and_(
                    ExecutionArtifact.created_at == cursor.created_at,
                    ExecutionArtifact.id < cursor.resource_id,
                ),
            )
        )
    rows = list(
        (
            await session.scalars(
                statement.order_by(
                    ExecutionArtifact.created_at.desc(),
                    ExecutionArtifact.id.desc(),
                ).limit(limit + 1)
            )
        ).all()
    )
    return rows[:limit], len(rows) > limit
