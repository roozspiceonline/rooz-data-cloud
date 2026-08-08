import base64
import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import cast
from uuid import UUID

from sqlalchemy import and_, func, or_, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.envelope_encryption import decrypt_project_secret
from ..core.errors import ApiError
from ..core.pagination import CursorPosition
from ..core.s3_storage import StorageBackendError, object_storage
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
    ArtifactDownloadGrant,
    ArtifactRegistration,
    ArtifactUploadIntent,
    ArtifactUploadRequest,
    ClaimWorkRequest,
    CompleteLeaseRequest,
    ExecutionArtifactSummary,
    ExecutionLeaseSummary,
    LeaseClaim,
    LeaseStatusUpdateRequest,
    RegisteredWorkerResponse,
    RegisterWorkerRequest,
    RenewLeaseRequest,
    SandboxActivation,
    SandboxAttestation,
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
    StorageObject,
    WorkerIdentity,
)
from .identity_tenancy import append_audit_event
from .runs import (
    _browser_egress_policy_payload,
    _browser_policy_payload,
    append_run_event,
    sanitize_event_payload,
)

settings = get_settings()


def _sandbox_digest(attestation: SandboxAttestation) -> str:
    return canonical_fingerprint(attestation.model_dump(mode="json"))


def _sandbox_attestation_allowed(attestation: SandboxAttestation) -> bool:
    return (
        attestation.schema_version == settings.sandbox_required_profile
        and attestation.max_memory_mb <= settings.sandbox_max_memory_mb
        and attestation.max_cpu_millis <= settings.sandbox_max_cpu_millis
        and attestation.max_pids <= settings.sandbox_max_pids
        and attestation.max_ephemeral_disk_mb
        <= settings.sandbox_max_ephemeral_disk_mb
        and attestation.max_build_seconds <= settings.sandbox_max_build_seconds
        and attestation.max_run_seconds <= settings.sandbox_max_run_seconds
    )


def _egress_policy_payload() -> dict[str, object]:
    return {
        "schema_version": "rdc.egress/v1",
        "mode": "brokered",
        "allowed_schemes": ["https"],
        "allowed_methods": ["GET", "HEAD"],
        "allowed_hosts": list(
            settings.sandbox_canary_web_egress_allowed_hosts
        ),
        "deny_ip_literals": True,
        "require_global_dns": True,
        "revalidate_redirects": True,
        "container_network": "none",
        "max_requests": settings.sandbox_canary_web_egress_max_requests,
        "max_response_bytes": (
            settings.sandbox_canary_web_egress_max_response_bytes
        ),
        "max_total_bytes": settings.sandbox_canary_web_egress_max_total_bytes,
        "max_redirects": settings.sandbox_canary_web_egress_max_redirects,
        "connect_timeout_seconds": (
            settings.sandbox_canary_web_egress_connect_timeout_seconds
        ),
        "request_timeout_seconds": (
            settings.sandbox_canary_web_egress_request_timeout_seconds
        ),
    }


def _browser_navigation_canary_receipt_allowed(
    input_reference: dict[str, object],
) -> bool:
    if not settings.sandbox_canary_browser_live_navigation_enabled:
        return False
    navigation = input_reference.get("browser_navigation")
    receipt = input_reference.get("browser_navigation_receipt")
    stored_browser_policy = input_reference.get("browser_policy")
    stored_browser_digest = input_reference.get("browser_policy_digest")
    stored_egress_policy = input_reference.get("browser_egress_policy")
    stored_egress_digest = input_reference.get("browser_egress_policy_digest")
    if (
        not isinstance(navigation, dict)
        or not isinstance(receipt, dict)
        or not isinstance(stored_browser_policy, dict)
        or not isinstance(stored_browser_digest, str)
        or not isinstance(stored_egress_policy, dict)
        or not isinstance(stored_egress_digest, str)
    ):
        return False
    current_browser_policy = _browser_policy_payload()
    current_browser_digest = canonical_fingerprint(current_browser_policy)
    current_egress_policy = _browser_egress_policy_payload()
    current_egress_digest = canonical_fingerprint(current_egress_policy)
    if (
        stored_browser_policy != current_browser_policy
        or stored_browser_digest != current_browser_digest
        or stored_egress_policy != current_egress_policy
        or stored_egress_digest != current_egress_digest
    ):
        return False
    expected_receipt = {
        "schema_version": "rdc.browser-navigation-receipt/v1",
        "request_schema_version": "rdc.browser/v2",
        "request_digest": canonical_fingerprint(navigation),
        "browser_policy_digest": current_browser_digest,
        "browser_egress_policy_digest": current_egress_digest,
        "execution_enabled": True,
        "dispatch_enabled": True,
        "browser_network": "none",
        "browser_egress_gateway_required": True,
    }
    return receipt == expected_receipt


def _canary_constraints(
    *,
    network: str,
    browser: bool = False,
) -> dict[str, object]:
    return {
        "memory_mb": settings.sandbox_canary_max_memory_mb,
        "cpu_millis": settings.sandbox_canary_max_cpu_millis,
        "pids": settings.sandbox_canary_max_pids,
        "ephemeral_disk_mb": settings.sandbox_canary_max_ephemeral_disk_mb,
        "build_timeout_seconds": settings.sandbox_canary_max_build_seconds,
        "run_timeout_seconds": settings.sandbox_canary_max_run_seconds,
        "network": (
            "brokered-web-egress"
            if network == "web-egress"
            else "none"
        ),
        "browser": browser,
        "dataset": False,
        "key_value_store": False,
        "request_queue": False,
        "secrets": False,
        "max_concurrency": 1,
    }


def _canary_activation(
    worker: WorkerIdentity,
    payload: dict[str, object],
    sandbox_policy: dict[str, object] | None,
) -> SandboxActivation | None:
    if (
        sandbox_policy is None
        or not settings.sandbox_execution_enabled
        or settings.sandbox_activation_mode != "canary"
    ):
        return None

    configured_version_id = settings.sandbox_canary_agent_version_id.strip()
    configured_worker = settings.sandbox_canary_worker_name.strip()
    if not configured_version_id or not configured_worker:
        return None
    if worker.name != configured_worker or worker.max_concurrency != 1:
        return None
    if str(payload.get("agent_version_id", "")) != configured_version_id:
        return None
    if str(payload.get("work_kind", "")) not in {
        "BUILD",
        "RUN_START",
        "RUN_CANCEL",
    }:
        return None

    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        return None

    secrets = manifest.get("secrets", [])
    if not isinstance(secrets, list) or secrets:
        return None

    capabilities = manifest.get("capabilities")
    resources = manifest.get("resources")
    if not isinstance(capabilities, dict) or not isinstance(resources, dict):
        return None

    network = str(capabilities.get("network", ""))
    if network not in {"none", "web-egress"}:
        return None
    if (
        network == "web-egress"
        and not settings.sandbox_canary_web_egress_enabled
    ):
        return None
    browser = capabilities.get("browser")
    if not isinstance(browser, bool):
        return None
    if (
        capabilities.get("dataset") is not False
        or capabilities.get("keyValueStore") is not False
        or capabilities.get("requestQueue") is not False
    ):
        return None

    browser_policy_digest: str | None = None
    if browser:
        if (
            str(payload.get("work_kind", "")) != "RUN_START"
            or network != "web-egress"
            or not settings.sandbox_canary_browser_enabled
        ):
            return None
        input_reference = payload.get("input_reference")
        if not isinstance(input_reference, dict):
            return None
        if "browser_navigation" in input_reference:
            if not _browser_navigation_canary_receipt_allowed(input_reference):
                return None
            browser_policy_digest = canonical_fingerprint(_browser_policy_payload())
        else:
            browser_plan = input_reference.get("browser")
            stored_policy = input_reference.get("browser_policy")
            stored_digest = input_reference.get("browser_policy_digest")
            if (
                not isinstance(browser_plan, dict)
                or not isinstance(stored_policy, dict)
                or not isinstance(stored_digest, str)
            ):
                return None
            current_policy = _browser_policy_payload()
            current_digest = canonical_fingerprint(current_policy)
            if (
                canonical_fingerprint(stored_policy) != current_digest
                or stored_digest != current_digest
            ):
                return None
            browser_policy_digest = current_digest

    try:
        memory_mb = int(resources["memoryMb"])
        cpu_millis = int(resources["cpuUnits"])
        pids = int(resources["maxProcesses"])
        disk_mb = int(resources["ephemeralDiskMb"])
        timeout_seconds = int(resources["timeoutSeconds"])
    except (KeyError, TypeError, ValueError):
        return None

    work_kind = str(payload.get("work_kind"))
    timeout_ceiling = (
        settings.sandbox_canary_max_build_seconds
        if work_kind == "BUILD"
        else settings.sandbox_canary_max_run_seconds
    )
    if (
        memory_mb > settings.sandbox_canary_max_memory_mb
        or cpu_millis > settings.sandbox_canary_max_cpu_millis
        or pids > settings.sandbox_canary_max_pids
        or disk_mb > settings.sandbox_canary_max_ephemeral_disk_mb
        or timeout_seconds > timeout_ceiling
    ):
        return None

    constraints = _canary_constraints(
        network=network,
        browser=browser,
    )
    if browser:
        capability_profile = "controlled-browser"
    else:
        capability_profile = (
            "brokered-web-egress"
            if network == "web-egress"
            else "offline-minimal"
        )
    egress_policy_digest = (
        canonical_fingerprint(_egress_policy_payload())
        if network == "web-egress"
        else None
    )

    return SandboxActivation(
        agent_version_id=UUID(configured_version_id),
        worker_name=configured_worker,
        attestation_digest=str(sandbox_policy["attestation_digest"]),
        sandbox_policy_digest=canonical_fingerprint(sandbox_policy),
        constraints_digest=canonical_fingerprint(constraints),
        capability_profile=capability_profile,
        egress_policy_digest=egress_policy_digest,
        browser_policy_digest=browser_policy_digest,
    )


def _activation_payload(
    activation: SandboxActivation | None,
) -> dict[str, object] | None:
    if activation is None:
        return None
    return activation.model_dump(mode="json")


def _apply_sandbox_attestation(
    worker: WorkerIdentity,
    attestation: SandboxAttestation | None,
    *,
    now: datetime,
) -> None:
    if attestation is None:
        return
    digest = _sandbox_digest(attestation)
    worker.sandbox_profile = attestation.schema_version
    worker.sandbox_attestation_digest = digest
    worker.sandbox_attested_at = now
    worker.sandbox_execution_enabled = (
        settings.sandbox_execution_enabled
        and settings.sandbox_activation_mode == "canary"
        and worker.name == settings.sandbox_canary_worker_name.strip()
        and worker.max_concurrency == 1
        and _sandbox_attestation_allowed(attestation)
    )
    worker.metadata_json = {
        **dict(worker.metadata_json),
        "sandbox": attestation.model_dump(mode="json"),
    }


def _sandbox_claim_policy(
    worker: WorkerIdentity,
    payload: dict[str, object],
) -> dict[str, object] | None:
    if (
        not settings.sandbox_execution_enabled
        or not worker.sandbox_execution_enabled
        or worker.sandbox_attestation_digest is None
    ):
        return None

    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        return None
    capabilities = manifest.get("capabilities")
    resources = manifest.get("resources")
    if not isinstance(capabilities, dict) or not isinstance(resources, dict):
        return None

    network = str(capabilities.get("network", ""))
    if network not in {"none", "web-egress"}:
        return None
    if (
        network == "web-egress"
        and not settings.sandbox_canary_web_egress_enabled
    ):
        return None
    browser = capabilities.get("browser")
    if not isinstance(browser, bool):
        return None
    if browser:
        if (
            str(payload.get("work_kind", "")) != "RUN_START"
            or network != "web-egress"
            or not settings.sandbox_canary_browser_enabled
        ):
            return None
        input_reference = payload.get("input_reference")
        if not isinstance(input_reference, dict):
            return None
        if "browser_navigation" in input_reference:
            if not _browser_navigation_canary_receipt_allowed(input_reference):
                return None
        elif (
            not isinstance(input_reference.get("browser"), dict)
            or not isinstance(input_reference.get("browser_policy"), dict)
            or not isinstance(input_reference.get("browser_policy_digest"), str)
        ):
            return None

    memory_mb = int(
        resources.get("memoryMb", settings.sandbox_max_memory_mb)
    )
    cpu_millis = int(
        resources.get("cpuUnits", settings.sandbox_max_cpu_millis)
    )
    pids = int(resources.get("maxProcesses", settings.sandbox_max_pids))
    disk_mb = int(
        resources.get(
            "ephemeralDiskMb",
            settings.sandbox_max_ephemeral_disk_mb,
        )
    )
    timeout = int(
        resources.get(
            "timeoutSeconds",
            settings.sandbox_max_run_seconds,
        )
    )
    if (
        memory_mb > settings.sandbox_max_memory_mb
        or cpu_millis > settings.sandbox_max_cpu_millis
        or pids > settings.sandbox_max_pids
        or disk_mb > settings.sandbox_max_ephemeral_disk_mb
    ):
        return None

    work_kind = str(payload.get("work_kind", ""))
    if work_kind == "RUN_START" and payload.get("artifact") is None:
        return None
    if work_kind == "BUILD":
        timeout = min(timeout, settings.sandbox_max_build_seconds)
    else:
        timeout = min(timeout, settings.sandbox_max_run_seconds)

    return {
        "schema_version": settings.sandbox_required_profile,
        "attestation_digest": worker.sandbox_attestation_digest,
        "runtime": "containerd-rootless",
        "builder": "buildkit-rootless",
        "network_policy": "deny-all",
        "brokered_web_egress": network == "web-egress",
        "rootless": True,
        "no_host_docker_socket": True,
        "no_new_privileges": True,
        "read_only_rootfs": True,
        "drop_all_capabilities": True,
        "seccomp_profile": "rdc-default",
        "memory_mb": memory_mb,
        "cpu_millis": cpu_millis,
        "pids": pids,
        "ephemeral_disk_mb": disk_mb,
        "timeout_seconds": timeout,
        "max_output_bytes": settings.sandbox_max_output_bytes,
    }


def _artifact_object_key(
    lease: ExecutionLease,
    *,
    kind: str,
    digest: str,
) -> str:
    safe_kind = kind.casefold().replace("_", "-")
    return (
        "artifacts/"
        + str(lease.organization_id)
        + "/"
        + str(lease.project_id)
        + "/"
        + str(lease.id)
        + "/"
        + safe_kind
        + "/"
        + digest
    )


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
        sandbox_profile=record.sandbox_profile,
        sandbox_attestation_digest=record.sandbox_attestation_digest,
        sandbox_execution_enabled=record.sandbox_execution_enabled,
        sandbox_attested_at=record.sandbox_attested_at,
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
        work_kind=record.work_kind,
        build_id=record.build_id,
        run_id=record.run_id,
        status=record.status,
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
        kind=record.kind,
        digest_algorithm=record.digest_algorithm,
        digest=record.digest,
        object_key=record.object_key,
        media_type=record.media_type,
        size_bytes=record.size_bytes,
        status=record.status,
        scan_status=record.scan_status,
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
        sandbox_execution_enabled=False,
        registered_at=now,
        last_seen_at=now,
    )
    _apply_sandbox_attestation(record, payload.sandbox, now=now)
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
        **dict(worker.metadata_json),
        **payload.metadata,
        "active_lease_count": payload.active_lease_count,
    }
    _apply_sandbox_attestation(worker, payload.sandbox, now=now)
    if not settings.sandbox_execution_enabled:
        worker.sandbox_execution_enabled = False
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
    if build.source_object_id is None:
        raise ApiError(
            status_code=409,
            code="SOURCE_OBJECT_UNAVAILABLE",
            message="This legacy Build has no verified source archive.",
        )
    source_object = await session.scalar(
        select(StorageObject).where(
            StorageObject.id == build.source_object_id,
            StorageObject.organization_id == build.organization_id,
            StorageObject.project_id == build.project_id,
            StorageObject.status == "AVAILABLE",
            StorageObject.scan_status == "PASSED",
            StorageObject.deleted_at.is_(None),
        )
    )
    if source_object is None:
        raise ApiError(
            status_code=409,
            code="SOURCE_OBJECT_UNAVAILABLE",
            message="The verified Build source archive is unavailable.",
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
        "source": {
            "kind": "object_storage",
            "object_id": str(source_object.id),
            "sha256_digest": source_object.sha256_digest,
            "size_bytes": source_object.size_bytes,
            "media_type": source_object.media_type,
            "download_grant_path": (
                "/internal/v1/leases/{lease_id}/source-download"
            ),
            "available": True,
        },
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
                "size_bytes": artifact.size_bytes,
                "provenance": dict(artifact.provenance),
                "download_grant_path": (
                    "/internal/v1/leases/{lease_id}/artifact-download"
                ),
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
        source = await session.scalar(
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
        return source
    command = "START" if kind == "RUN_START" else "CANCEL"
    source = await session.scalar(
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
    return cast(RunCommandOutbox | None, source)


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

        sandbox_policy = _sandbox_claim_policy(worker, claim_payload)
        activation = _canary_activation(
            worker,
            claim_payload,
            sandbox_policy,
        )
        execution_enabled = sandbox_policy is not None and activation is not None
        claim_payload["execution_enabled"] = execution_enabled
        claim_payload["sandbox"] = sandbox_policy if execution_enabled else None
        claim_payload["activation"] = _activation_payload(activation)
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
                "execution_enabled": execution_enabled,
                "sandbox_attestation_digest": worker.sandbox_attestation_digest,
                "activation_mode": (
                    activation.mode if activation is not None else "disabled"
                ),
                "activation_agent_version_id": (
                    str(activation.agent_version_id)
                    if activation is not None
                    else None
                ),
            },
        )
        return LeaseClaim(
            id=lease.id,
            work_kind=kind,
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


async def issue_artifact_upload_grant(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: ArtifactUploadRequest,
    request_id: str,
) -> ArtifactUploadIntent:
    if not settings.sandbox_execution_enabled or not worker.sandbox_execution_enabled:
        raise ApiError(
            status_code=403,
            code="SANDBOX_EXECUTION_DISABLED",
            message="This worker is not eligible for sandbox execution.",
        )
    if payload.size_bytes > settings.sandbox_artifact_max_bytes:
        raise ApiError(
            status_code=413,
            code="ARTIFACT_TOO_LARGE",
            message="The artifact exceeds the configured sandbox limit.",
        )
    if lease.work_kind == "BUILD" and payload.kind not in {
        "CONTAINER_IMAGE",
        "SBOM",
        "PROVENANCE",
        "LOG_BUNDLE",
    }:
        raise ApiError(
            status_code=422,
            code="ARTIFACT_KIND_INVALID",
            message="That artifact kind is not valid for a Build lease.",
        )
    if lease.work_kind != "BUILD" and payload.kind not in {
        "RUN_OUTPUT",
        "LOG_BUNDLE",
    }:
        raise ApiError(
            status_code=422,
            code="ARTIFACT_KIND_INVALID",
            message="That artifact kind is not valid for a Run lease.",
        )
    object_key = _artifact_object_key(
        lease,
        kind=payload.kind,
        digest=payload.digest,
    )
    try:
        upload = await object_storage.create_presigned_artifact_upload(
            object_key=object_key,
            lease_id=str(lease.id),
            artifact_kind=payload.kind,
            content_type=payload.media_type,
            sha256_digest=payload.digest,
            expires_seconds=settings.storage_upload_grant_seconds,
        )
    except StorageBackendError as exc:
        raise ApiError(
            status_code=503,
            code=exc.code,
            message=exc.message,
        ) from exc
    expires_at = datetime.now(UTC) + timedelta(
        seconds=settings.storage_upload_grant_seconds
    )
    await append_audit_event(
        session,
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        actor_type="worker",
        actor_id=str(worker.id),
        action="execution.artifact_upload_granted",
        resource_type="execution_lease",
        resource_id=str(lease.id),
        request_id=request_id,
        details={
            "kind": payload.kind,
            "digest": payload.digest,
            "size_bytes": payload.size_bytes,
            "expires_at": expires_at.isoformat(),
        },
    )
    upload_url = cast(str, upload["url"])
    upload_headers = cast(dict[str, str], upload["headers"])
    return ArtifactUploadIntent(
        object_key=object_key,
        url=upload_url,
        headers=dict(upload_headers),
        expires_at=expires_at,
    )


async def issue_run_artifact_download_grant(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    request_id: str,
) -> ArtifactDownloadGrant:
    if lease.work_kind != "RUN_START" or lease.run_id is None:
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_STATE_CONFLICT",
            message="Only Run-start leases can download container artifacts.",
        )
    run = await session.scalar(select(Run).where(Run.id == lease.run_id))
    if run is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The Run was not found.",
        )
    artifact = await session.scalar(
        select(ExecutionArtifact).where(
            ExecutionArtifact.build_id == run.build_id,
            ExecutionArtifact.kind == "CONTAINER_IMAGE",
            ExecutionArtifact.status == "AVAILABLE",
            ExecutionArtifact.scan_status == "PASSED",
        )
    )
    if artifact is None:
        raise ApiError(
            status_code=409,
            code="ARTIFACT_NOT_AVAILABLE",
            message="The verified container artifact is unavailable.",
        )
    try:
        url = await object_storage.create_presigned_download(
            object_key=artifact.object_key,
            file_name="rdc-agent-" + str(run.build_id) + ".oci.tar",
            expires_seconds=settings.storage_download_grant_seconds,
        )
    except StorageBackendError as exc:
        raise ApiError(
            status_code=503,
            code=exc.code,
            message=exc.message,
        ) from exc
    expires_at = datetime.now(UTC) + timedelta(
        seconds=settings.storage_download_grant_seconds
    )
    await append_audit_event(
        session,
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        actor_type="worker",
        actor_id=str(worker.id),
        action="execution.artifact_download_granted",
        resource_type="execution_artifact",
        resource_id=str(artifact.id),
        request_id=request_id,
        details={"lease_id": str(lease.id), "expires_at": expires_at.isoformat()},
    )
    return ArtifactDownloadGrant(
        artifact_id=artifact.id,
        url=url,
        expires_at=expires_at,
        digest_algorithm=artifact.digest_algorithm,
        digest=artifact.digest,
        media_type=artifact.media_type,
        size_bytes=artifact.size_bytes,
        provenance=dict(artifact.provenance),
    )


def _validate_activation_provenance(
    lease: ExecutionLease,
    payload: ArtifactRegistration,
) -> None:
    snapshot = dict(lease.payload_snapshot)
    activation = snapshot.get("activation")
    if not isinstance(activation, dict):
        return

    provenance = dict(payload.provenance)
    if provenance.get("activation") != activation:
        raise ApiError(
            status_code=422,
            code="ARTIFACT_ACTIVATION_MISMATCH",
            message="Artifact provenance does not match the lease activation.",
        )

    if lease.work_kind == "BUILD":
        source = snapshot.get("source")
        if not isinstance(source, dict):
            raise ApiError(
                status_code=422,
                code="ARTIFACT_LINEAGE_INVALID",
                message="Build lease source lineage is unavailable.",
            )
        if (
            provenance.get("source_sha256") != source.get("sha256_digest")
            or provenance.get("agent_version_id")
            != snapshot.get("agent_version_id")
        ):
            raise ApiError(
                status_code=422,
                code="ARTIFACT_LINEAGE_INVALID",
                message="Build artifact provenance does not match source lineage.",
            )
        return

    if lease.work_kind == "RUN_START":
        artifact = snapshot.get("artifact")
        if not isinstance(artifact, dict):
            raise ApiError(
                status_code=422,
                code="ARTIFACT_LINEAGE_INVALID",
                message="Run lease image lineage is unavailable.",
            )
        if (
            provenance.get("image_digest") != artifact.get("digest")
            or provenance.get("run_id") != snapshot.get("run_id")
        ):
            raise ApiError(
                status_code=422,
                code="ARTIFACT_LINEAGE_INVALID",
                message="Run artifact provenance does not match image lineage.",
            )


async def _register_artifact(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: ArtifactRegistration,
) -> ExecutionArtifact:
    _validate_activation_provenance(lease, payload)
    expected_key = _artifact_object_key(
        lease,
        kind=payload.kind,
        digest=payload.digest,
    )
    if payload.object_key != expected_key:
        raise ApiError(
            status_code=422,
            code="ARTIFACT_OBJECT_KEY_INVALID",
            message="The artifact object key does not match the lease grant.",
        )
    if payload.size_bytes > settings.sandbox_artifact_max_bytes:
        raise ApiError(
            status_code=413,
            code="ARTIFACT_TOO_LARGE",
            message="The artifact exceeds the configured sandbox limit.",
        )
    try:
        head = await object_storage.head_object(object_key=payload.object_key)
        digest, verified_size = await object_storage.sha256_object(
            object_key=payload.object_key,
            max_bytes=settings.sandbox_artifact_max_bytes,
        )
    except StorageBackendError as exc:
        raise ApiError(
            status_code=409 if exc.code == "STORAGE_OBJECT_NOT_UPLOADED" else 503,
            code=exc.code,
            message=exc.message,
        ) from exc
    metadata = {key.casefold(): value for key, value in head.metadata.items()}
    if (
        verified_size != payload.size_bytes
        or head.size_bytes != payload.size_bytes
        or head.content_type != payload.media_type
        or digest != payload.digest
        or metadata.get("sha256") != payload.digest
        or metadata.get("rdc-lease-id") != str(lease.id)
        or metadata.get("rdc-artifact-kind") != payload.kind
    ):
        raise ApiError(
            status_code=422,
            code="ARTIFACT_VERIFICATION_FAILED",
            message="The uploaded artifact did not match its signed metadata.",
        )

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
            or (
                isinstance(lease.payload_snapshot.get("activation"), dict)
                and dict(existing.provenance) != dict(payload.provenance)
            )
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
        source = await session.scalar(
            select(BuildDispatchOutbox).where(
                BuildDispatchOutbox.id == lease.source_outbox_id
            )
        )
        return source
    source = await session.scalar(
        select(RunCommandOutbox).where(
            RunCommandOutbox.id == lease.source_outbox_id
        )
    )
    return cast(RunCommandOutbox | None, source)


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
    registrations = (
        [payload.artifact]
        if payload.artifact is not None
        else list(payload.artifacts)
    )
    registered: list[ExecutionArtifact] = []
    for registration in registrations:
        if registration is None:
            continue
        registered.append(
            await _register_artifact(
                session,
                lease=lease,
                worker=worker,
                payload=registration,
            )
        )
    artifact = next(
        (item for item in registered if item.kind == "CONTAINER_IMAGE"),
        None,
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
