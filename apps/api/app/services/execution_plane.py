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
    worker_egress_credential_aad,
    worker_secret_aad,
)
from ..dataset_schemas import CreateDatasetRequest
from ..egress_policy_protocol import (
    EgressPolicyProtocolError,
    validate_egress_policy,
)
from ..execution_recovery import (
    clamp_lease_expiry,
    execution_deadline_at,
    execution_retry_allowed,
    retry_available_at,
)
from ..execution_schemas import (
    AppendWorkerEventsRequest,
    ArtifactDownloadGrant,
    ArtifactRegistration,
    ArtifactUploadIntent,
    ArtifactUploadRequest,
    ClaimWorkRequest,
    CompleteLeaseRequest,
    EgressCredentialEnvelopeRequest,
    EgressCredentialEnvelopeResponse,
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
    Dataset,
    EgressPolicy,
    EgressPolicyRevision,
    ExecutionArtifact,
    ExecutionLease,
    Project,
    ProjectSecret,
    Run,
    RunCommandOutbox,
    SecretInjectionGrant,
    StorageObject,
    WorkerIdentity,
)
from .datasets import (
    DatasetAppendOutcome,
    append_dataset_items,
    create_dataset,
)
from .identity_tenancy import append_audit_event
from .runs import (
    _browser_egress_policy_payload,
    _browser_policy_payload,
    append_run_event,
    sanitize_event_payload,
)
from .worker_key_value_store import key_value_store_capability
from .worker_request_queue import request_queue_capability

settings = get_settings()
PROJECT_EXECUTION_SLOT_KINDS = {"BUILD", "RUN_START"}


def _sandbox_digest(attestation: SandboxAttestation) -> str:
    return canonical_fingerprint(attestation.model_dump(mode="json"))


def _sandbox_attestation_allowed(attestation: SandboxAttestation) -> bool:
    return (
        attestation.schema_version == settings.sandbox_required_profile
        and attestation.max_memory_mb <= settings.sandbox_max_memory_mb
        and attestation.max_cpu_millis <= settings.sandbox_max_cpu_millis
        and attestation.max_pids <= settings.sandbox_max_pids
        and attestation.max_ephemeral_disk_mb <= settings.sandbox_max_ephemeral_disk_mb
        and attestation.max_build_seconds <= settings.sandbox_max_build_seconds
        and attestation.max_run_seconds <= settings.sandbox_max_run_seconds
    )


def _egress_policy_payload() -> dict[str, object]:
    return {
        "schema_version": "rdc.egress/v1",
        "mode": "brokered",
        "allowed_schemes": ["https"],
        "allowed_methods": ["GET", "HEAD"],
        "allowed_hosts": list(settings.sandbox_canary_web_egress_allowed_hosts),
        "deny_ip_literals": True,
        "require_global_dns": True,
        "revalidate_redirects": True,
        "container_network": "none",
        "max_requests": settings.sandbox_canary_web_egress_max_requests,
        "max_response_bytes": (settings.sandbox_canary_web_egress_max_response_bytes),
        "max_total_bytes": settings.sandbox_canary_web_egress_max_total_bytes,
        "max_redirects": settings.sandbox_canary_web_egress_max_redirects,
        "connect_timeout_seconds": (
            settings.sandbox_canary_web_egress_connect_timeout_seconds
        ),
        "request_timeout_seconds": (
            settings.sandbox_canary_web_egress_request_timeout_seconds
        ),
    }


def _bound_egress_policy(
    input_reference: dict[str, object],
) -> tuple[dict[str, object], str] | None:
    stored = input_reference.get("project_egress_policy")
    receipt = input_reference.get("project_egress_policy_receipt")
    if stored is None and receipt is None:
        return None
    if not isinstance(stored, dict) or not isinstance(receipt, dict):
        raise ValueError("Incomplete Project egress-policy binding.")
    if set(receipt) != {
        "schema_version",
        "policy_id",
        "revision_id",
        "revision_number",
        "policy_digest",
        "runtime_policy_digest",
        "credential_configured",
        "binding_digest",
    }:
        raise ValueError("Unexpected Project egress-policy receipt fields.")
    if (
        receipt.get("schema_version") != "rdc.run-egress-policy-receipt/v1"
        or type(receipt.get("credential_configured")) is not bool
        or type(receipt.get("revision_number")) is not int
        or int(receipt["revision_number"]) < 1
    ):
        raise ValueError("Invalid Project egress-policy receipt.")
    try:
        UUID(str(receipt["policy_id"]))
        UUID(str(receipt["revision_id"]))
    except (KeyError, ValueError) as exc:
        raise ValueError("Invalid Project egress-policy identifiers.") from exc
    receipt_without_digest = {
        key: value for key, value in receipt.items() if key != "binding_digest"
    }
    if receipt.get("binding_digest") != canonical_fingerprint(receipt_without_digest):
        raise ValueError("Project egress-policy binding digest mismatch.")
    required_runtime = {
        "schema_version": "rdc.egress/v1",
        "mode": "brokered",
        "allowed_schemes": ["https"],
        "deny_ip_literals": True,
        "require_global_dns": True,
        "revalidate_redirects": True,
        "container_network": "none",
    }
    if any(stored.get(key) != value for key, value in required_runtime.items()):
        raise ValueError("Unsafe Project egress-policy runtime envelope.")
    hosts = stored.get("allowed_hosts")
    methods = stored.get("allowed_methods")
    if (
        not isinstance(hosts, list)
        or not hosts
        or not all(isinstance(host, str) for host in hosts)
        or hosts != sorted(set(hosts))
        or not isinstance(methods, list)
        or not methods
        or not all(isinstance(method, str) for method in methods)
        or methods != sorted(set(methods))
        or not set(methods) <= {"GET", "HEAD"}
    ):
        raise ValueError("Invalid Project egress-policy hosts or methods.")
    ceiling = _egress_policy_payload()
    if not set(hosts) <= set(cast(list[str], ceiling["allowed_hosts"])):
        raise ValueError("Project egress policy exceeds the host ceiling.")
    numeric_minimums = {
        "max_requests": 1,
        "max_response_bytes": 65_536,
        "max_total_bytes": 65_536,
        "max_redirects": 0,
        "connect_timeout_seconds": 1,
        "request_timeout_seconds": 1,
    }
    if any(
        type(stored.get(key)) is not int
        or int(stored[key]) < minimum
        or int(stored[key]) > cast(int, ceiling[key])
        for key, minimum in numeric_minimums.items()
    ):
        raise ValueError("Project egress policy exceeds a numeric ceiling.")
    runtime_digest = canonical_fingerprint(stored)
    if receipt.get("runtime_policy_digest") != runtime_digest:
        raise ValueError("Project runtime-policy digest mismatch.")
    try:
        validated = validate_egress_policy(
            allowed_hosts=hosts,
            allowed_methods=methods,
            max_requests=cast(int, stored["max_requests"]),
            max_response_bytes=cast(int, stored["max_response_bytes"]),
            max_total_bytes=cast(int, stored["max_total_bytes"]),
            max_redirects=cast(int, stored["max_redirects"]),
            connect_timeout_seconds=cast(
                int, stored["connect_timeout_seconds"]
            ),
            request_timeout_seconds=cast(
                int, stored["request_timeout_seconds"]
            ),
        )
    except EgressPolicyProtocolError as exc:
        raise ValueError(
            "Project policy revision failed protocol validation."
        ) from exc
    if (
        validated.allowed_hosts != hosts
        or validated.allowed_methods != methods
        or receipt.get("policy_digest") != validated.policy_digest
    ):
        raise ValueError("Project policy-revision digest mismatch.")
    return stored, str(receipt["binding_digest"])


def _browser_navigation_canary_receipt_allowed(
    input_reference: dict[str, object],
    *,
    runtime_egress_policy: dict[str, object] | None = None,
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
    current_egress_policy = _browser_egress_policy_payload(runtime_egress_policy)
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
    dataset: bool = False,
    key_value_store: bool = False,
    request_queue: bool = False,
    request_queue_http: bool = False,
    request_queue_browser: bool = False,
    request_queue_dataset: bool = False,
    request_queue_key_value_store: bool = False,
) -> dict[str, object]:
    return {
        "memory_mb": settings.sandbox_canary_max_memory_mb,
        "cpu_millis": settings.sandbox_canary_max_cpu_millis,
        "pids": settings.sandbox_canary_max_pids,
        "ephemeral_disk_mb": settings.sandbox_canary_max_ephemeral_disk_mb,
        "build_timeout_seconds": settings.sandbox_canary_max_build_seconds,
        "run_timeout_seconds": settings.sandbox_canary_max_run_seconds,
        "network": ("brokered-web-egress" if network == "web-egress" else "none"),
        "browser": browser,
        "dataset": dataset,
        "key_value_store": key_value_store,
        "request_queue": request_queue,
        "request_queue_http": request_queue_http,
        "request_queue_browser": request_queue_browser,
        "request_queue_dataset": request_queue_dataset,
        "request_queue_key_value_store": request_queue_key_value_store,
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
    if network == "web-egress" and not settings.sandbox_canary_web_egress_enabled:
        return None
    browser = capabilities.get("browser")
    if not isinstance(browser, bool):
        return None
    dataset = capabilities.get("dataset")
    if not isinstance(dataset, bool):
        return None
    key_value_store = capabilities.get("keyValueStore")
    if not isinstance(key_value_store, bool):
        return None
    request_queue = capabilities.get("requestQueue")
    if not isinstance(request_queue, bool):
        return None
    work_kind = str(payload.get("work_kind", ""))
    kv_runtime_enabled = key_value_store and work_kind == "RUN_START"
    queue_runtime_enabled = request_queue and work_kind == "RUN_START"
    queue_dataset_runtime_enabled = queue_runtime_enabled and dataset
    queue_kv_runtime_enabled = queue_runtime_enabled and kv_runtime_enabled
    queue_browser_runtime_enabled = (
        queue_runtime_enabled and network == "web-egress" and browser
    )
    queue_http_runtime_enabled = (
        queue_runtime_enabled and network == "web-egress" and not browser
    )
    input_reference = payload.get("input_reference")
    if not isinstance(input_reference, dict):
        input_reference = {}
    try:
        bound_egress = _bound_egress_policy(input_reference)
    except ValueError:
        return None
    if bound_egress is not None and network != "web-egress":
        return None
    effective_egress_policy = (
        bound_egress[0] if bound_egress is not None else _egress_policy_payload()
    )
    egress_policy_digest = (
        canonical_fingerprint(effective_egress_policy)
        if network == "web-egress"
        else None
    )
    project_egress_policy_binding_digest = (
        bound_egress[1] if bound_egress is not None else None
    )
    if work_kind == "RUN_START" and dataset and kv_runtime_enabled:
        return None
    if (
        work_kind == "RUN_START"
        and browser
        and kv_runtime_enabled
        and not queue_kv_runtime_enabled
    ):
        return None
    current_browser_policy_digest = (
        canonical_fingerprint(_browser_policy_payload()) if browser else None
    )
    current_browser_egress_digest = (
        canonical_fingerprint(_browser_egress_policy_payload(effective_egress_policy))
        if queue_browser_runtime_enabled
        else None
    )
    if queue_runtime_enabled and (
        not settings.sandbox_canary_request_queue_enabled
        or (
            queue_kv_runtime_enabled
            and (
                not settings.sandbox_canary_key_value_store_enabled
                or not settings.sandbox_canary_request_queue_key_value_store_enabled
            )
        )
        or (
            queue_dataset_runtime_enabled
            and (
                not settings.sandbox_canary_dataset_writes_enabled
                or not settings.sandbox_canary_request_queue_dataset_enabled
            )
        )
        or (
            queue_http_runtime_enabled
            and not settings.sandbox_canary_request_queue_http_enabled
        )
        or (
            queue_browser_runtime_enabled
            and not settings.sandbox_canary_request_queue_browser_enabled
        )
        or request_queue_capability(
            worker,
            payload,
            request_queue_enabled=True,
            request_queue_http_enabled=queue_http_runtime_enabled,
            egress_policy_digest=(
                egress_policy_digest if queue_http_runtime_enabled else None
            ),
            request_queue_browser_enabled=queue_browser_runtime_enabled,
            browser_policy_digest=current_browser_policy_digest,
            browser_egress_policy_digest=current_browser_egress_digest,
            request_queue_dataset_enabled=queue_dataset_runtime_enabled,
            request_queue_key_value_store_enabled=queue_kv_runtime_enabled,
            project_egress_policy_binding_digest=(project_egress_policy_binding_digest),
        )
        is None
    ):
        return None
    if dataset and (
        work_kind != "RUN_START"
        or (browser and not queue_dataset_runtime_enabled)
        or not settings.sandbox_canary_dataset_writes_enabled
        or "DATASET_APPEND" not in worker.capabilities
    ):
        return None
    if (
        kv_runtime_enabled
        and key_value_store_capability(
            worker,
            payload,
            key_value_store_enabled=True,
            request_queue_key_value_store_enabled=queue_kv_runtime_enabled,
        )
        is None
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
        if queue_browser_runtime_enabled:
            browser_policy_digest = current_browser_policy_digest
        elif "browser_navigation" in input_reference:
            if not _browser_navigation_canary_receipt_allowed(
                input_reference,
                runtime_egress_policy=effective_egress_policy,
            ):
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
        dataset=dataset,
        key_value_store=kv_runtime_enabled,
        request_queue=queue_runtime_enabled,
        request_queue_http=queue_http_runtime_enabled,
        request_queue_browser=queue_browser_runtime_enabled,
        request_queue_dataset=queue_dataset_runtime_enabled,
        request_queue_key_value_store=queue_kv_runtime_enabled,
    )
    if browser:
        capability_profile = "controlled-browser"
    else:
        capability_profile = (
            "brokered-web-egress" if network == "web-egress" else "offline-minimal"
        )
    return SandboxActivation(
        agent_version_id=UUID(configured_version_id),
        worker_name=configured_worker,
        attestation_digest=str(sandbox_policy["attestation_digest"]),
        sandbox_policy_digest=canonical_fingerprint(sandbox_policy),
        constraints_digest=canonical_fingerprint(constraints),
        capability_profile=capability_profile,
        egress_policy_digest=egress_policy_digest,
        project_egress_policy_binding_digest=(project_egress_policy_binding_digest),
        browser_policy_digest=browser_policy_digest,
        dataset_write_enabled=dataset,
        key_value_store_enabled=kv_runtime_enabled,
        request_queue_enabled=queue_runtime_enabled,
        request_queue_http_enabled=queue_http_runtime_enabled,
        request_queue_browser_enabled=queue_browser_runtime_enabled,
        request_queue_dataset_enabled=queue_dataset_runtime_enabled,
        request_queue_key_value_store_enabled=queue_kv_runtime_enabled,
    )


def _dataset_append_capability(
    worker: WorkerIdentity,
    payload: dict[str, object],
    *,
    dataset_write_enabled: bool,
    request_queue_dataset_enabled: bool = False,
) -> dict[str, object] | None:
    if (
        not dataset_write_enabled
        or not settings.sandbox_canary_dataset_writes_enabled
        or str(payload.get("work_kind", "")) != "RUN_START"
        or worker.name != settings.sandbox_canary_worker_name.strip()
        or "DATASET_APPEND" not in worker.capabilities
        or str(payload.get("agent_version_id", ""))
        != settings.sandbox_canary_agent_version_id.strip()
    ):
        return None

    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        return None
    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, dict):
        return None
    request_queue = capabilities.get("requestQueue")
    if (
        capabilities.get("dataset") is not True
        or capabilities.get("keyValueStore") is not False
        or not isinstance(request_queue, bool)
        or request_queue is not request_queue_dataset_enabled
        or (
            capabilities.get("browser") is not False
            and not request_queue_dataset_enabled
        )
        or (
            request_queue_dataset_enabled
            and not settings.sandbox_canary_request_queue_dataset_enabled
        )
    ):
        return None

    run_id = payload.get("run_id")
    if not isinstance(run_id, str) or not run_id:
        return None

    capability: dict[str, object] = {
        "schema_version": (
            "rdc.dataset-worker-capability/v2"
            if request_queue_dataset_enabled
            else "rdc.dataset-worker-capability/v1"
        ),
        "append_schema_version": "rdc.dataset-append/v1",
        "run_id": run_id,
        "agent_version_id": str(payload["agent_version_id"]),
        "worker_name": worker.name,
        "dataset_name": "default",
        "max_items_per_append": 100,
        "max_item_bytes": 65_536,
        "max_batch_bytes": 262_144,
        "max_dataset_items": 100_000,
        "max_dataset_bytes": 268_435_456,
        "enabled": True,
    }
    if request_queue_dataset_enabled:
        input_reference = payload.get("input_reference")
        binding = (
            input_reference.get("request_queue")
            if isinstance(input_reference, dict)
            else None
        )
        if (
            not isinstance(binding, dict)
            or binding.get("schema_version") != "rdc.run-queue/v1"
            or not isinstance(binding.get("queue_id"), str)
        ):
            return None
        capability.update(
            {
                "queue_id": binding["queue_id"],
                "completion_order": "dataset-before-queue-handled",
            }
        )
    return capability


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
    if network == "web-egress" and not settings.sandbox_canary_web_egress_enabled:
        return None
    browser = capabilities.get("browser")
    if not isinstance(browser, bool):
        return None
    dataset = capabilities.get("dataset")
    if not isinstance(dataset, bool):
        return None
    key_value_store = capabilities.get("keyValueStore")
    if not isinstance(key_value_store, bool):
        return None
    request_queue = capabilities.get("requestQueue")
    if not isinstance(request_queue, bool):
        return None
    work_kind = str(payload.get("work_kind", ""))
    kv_runtime_enabled = key_value_store and work_kind == "RUN_START"
    queue_runtime_enabled = request_queue and work_kind == "RUN_START"
    queue_dataset_runtime_enabled = queue_runtime_enabled and dataset
    queue_kv_runtime_enabled = queue_runtime_enabled and kv_runtime_enabled
    queue_browser_runtime_enabled = (
        queue_runtime_enabled and network == "web-egress" and browser
    )
    queue_http_runtime_enabled = (
        queue_runtime_enabled and network == "web-egress" and not browser
    )
    input_reference = payload.get("input_reference")
    if not isinstance(input_reference, dict):
        input_reference = {}
    try:
        bound_egress = _bound_egress_policy(input_reference)
    except ValueError:
        return None
    if bound_egress is not None and network != "web-egress":
        return None
    effective_egress_policy = (
        bound_egress[0] if bound_egress is not None else _egress_policy_payload()
    )
    egress_policy_digest = (
        canonical_fingerprint(effective_egress_policy)
        if network == "web-egress"
        else None
    )
    project_egress_policy_binding_digest = (
        bound_egress[1] if bound_egress is not None else None
    )
    if work_kind == "RUN_START" and dataset and kv_runtime_enabled:
        return None
    if (
        work_kind == "RUN_START"
        and browser
        and kv_runtime_enabled
        and not queue_kv_runtime_enabled
    ):
        return None
    current_browser_policy_digest = (
        canonical_fingerprint(_browser_policy_payload()) if browser else None
    )
    current_browser_egress_digest = (
        canonical_fingerprint(_browser_egress_policy_payload(effective_egress_policy))
        if queue_browser_runtime_enabled
        else None
    )
    if queue_runtime_enabled and (
        not settings.sandbox_canary_request_queue_enabled
        or (
            queue_kv_runtime_enabled
            and (
                not settings.sandbox_canary_key_value_store_enabled
                or not settings.sandbox_canary_request_queue_key_value_store_enabled
            )
        )
        or (
            queue_dataset_runtime_enabled
            and (
                not settings.sandbox_canary_dataset_writes_enabled
                or not settings.sandbox_canary_request_queue_dataset_enabled
            )
        )
        or (
            queue_http_runtime_enabled
            and not settings.sandbox_canary_request_queue_http_enabled
        )
        or (
            queue_browser_runtime_enabled
            and not settings.sandbox_canary_request_queue_browser_enabled
        )
        or request_queue_capability(
            worker,
            payload,
            request_queue_enabled=True,
            request_queue_http_enabled=queue_http_runtime_enabled,
            egress_policy_digest=(
                egress_policy_digest if queue_http_runtime_enabled else None
            ),
            request_queue_browser_enabled=queue_browser_runtime_enabled,
            browser_policy_digest=current_browser_policy_digest,
            browser_egress_policy_digest=current_browser_egress_digest,
            request_queue_dataset_enabled=queue_dataset_runtime_enabled,
            request_queue_key_value_store_enabled=queue_kv_runtime_enabled,
            project_egress_policy_binding_digest=(project_egress_policy_binding_digest),
        )
        is None
    ):
        return None
    if dataset and (
        work_kind != "RUN_START"
        or (browser and not queue_dataset_runtime_enabled)
        or not settings.sandbox_canary_dataset_writes_enabled
        or "DATASET_APPEND" not in worker.capabilities
    ):
        return None
    if (
        kv_runtime_enabled
        and key_value_store_capability(
            worker,
            payload,
            key_value_store_enabled=True,
            request_queue_key_value_store_enabled=queue_kv_runtime_enabled,
        )
        is None
    ):
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
        if (
            not queue_browser_runtime_enabled
            and "browser_navigation" in input_reference
        ):
            if not _browser_navigation_canary_receipt_allowed(
                input_reference,
                runtime_egress_policy=effective_egress_policy,
            ):
                return None
        elif not queue_browser_runtime_enabled and (
            not isinstance(input_reference.get("browser"), dict)
            or not isinstance(input_reference.get("browser_policy"), dict)
            or not isinstance(input_reference.get("browser_policy_digest"), str)
        ):
            return None

    memory_mb = int(resources.get("memoryMb", settings.sandbox_max_memory_mb))
    cpu_millis = int(resources.get("cpuUnits", settings.sandbox_max_cpu_millis))
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
        last_lost_at=record.last_lost_at,
        last_recovered_at=record.last_recovered_at,
        last_cleanup_at=record.last_cleanup_at,
        cleanup_generation=record.cleanup_generation,
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
        deadline_at=record.deadline_at,
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
        max_concurrency=min(
            payload.max_concurrency,
            settings.worker_registration_max_concurrency,
        ),
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
            "requested_max_concurrency": payload.max_concurrency,
            "effective_max_concurrency": record.max_concurrency,
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
    locked_worker = await session.scalar(
        select(WorkerIdentity)
        .where(WorkerIdentity.id == worker.id)
        .execution_options(populate_existing=True)
        .with_for_update()
    )
    if locked_worker is None:
        raise ApiError(
            status_code=401,
            code="INTERNAL_CREDENTIAL_INVALID",
            message="The internal credential is invalid.",
        )
    worker = locked_worker
    if worker.status == "REVOKED" or worker.revoked_at is not None:
        raise ApiError(
            status_code=401,
            code="INTERNAL_CREDENTIAL_INVALID",
            message="The internal credential is invalid.",
        )
    now = datetime.now(UTC)
    recovery_pending = worker.last_lost_at is not None and (
        worker.last_recovered_at is None
        or worker.last_recovered_at < worker.last_lost_at
    )
    if recovery_pending and payload.recovery is None:
        raise ApiError(
            status_code=409,
            code="WORKER_RECOVERY_REQUIRED",
            message=(
                "The worker must complete managed-runtime cleanup before it can recover."
            ),
        )
    previous_startup_id = worker.metadata_json.get("recovery_startup_id")
    worker.status = payload.status
    worker.software_version = payload.software_version
    worker.last_seen_at = now
    worker.metadata_json = {
        **dict(worker.metadata_json),
        **payload.metadata,
        "active_lease_count": payload.active_lease_count,
    }
    _apply_sandbox_attestation(worker, payload.sandbox, now=now)
    recovery_startup_id = (
        str(payload.recovery.startup_id) if payload.recovery is not None else None
    )
    if (
        recovery_pending
        and recovery_startup_id is not None
        and recovery_startup_id == previous_startup_id
    ):
        raise ApiError(
            status_code=409,
            code="WORKER_RECOVERY_REPORT_REPLAYED",
            message="The worker recovery report was already accepted.",
        )
    if payload.recovery is not None and recovery_startup_id != previous_startup_id:
        worker.last_cleanup_at = now
        worker.cleanup_generation += 1
        worker.metadata_json = {
            **dict(worker.metadata_json),
            "recovery_startup_id": recovery_startup_id,
            "managed_containers_removed": (payload.recovery.managed_containers_removed),
            "workspace_directories_removed": (
                payload.recovery.workspace_directories_removed
            ),
        }
        if recovery_pending:
            worker.last_recovered_at = now
            await append_audit_event(
                session,
                organization_id=None,
                project_id=None,
                actor_type="worker",
                actor_id=str(worker.id),
                action="worker.recovered",
                resource_type="worker",
                resource_id=str(worker.id),
                request_id=request_id,
                details={
                    "cleanup_generation": worker.cleanup_generation,
                    "managed_containers_removed": (
                        payload.recovery.managed_containers_removed
                    ),
                    "workspace_directories_removed": (
                        payload.recovery.workspace_directories_removed
                    ),
                },
            )
    if not settings.sandbox_execution_enabled:
        worker.sandbox_execution_enabled = False
    await reap_expired_leases(session, now=now, request_id=request_id)
    return worker_summary(worker)


async def _fence_cancelled_run_leases(
    session: AsyncSession,
    *,
    run_id: UUID,
    now: datetime,
    preserve_lease_id: UUID | None = None,
    preserve_source_id: UUID | None = None,
) -> int:
    leases = list(
        (
            await session.scalars(
                select(ExecutionLease)
                .where(
                    ExecutionLease.run_id == run_id,
                    ExecutionLease.status == "ACTIVE",
                )
                .order_by(ExecutionLease.id.asc())
                .with_for_update(skip_locked=True)
            )
        ).all()
    )
    cancelled_ids: list[UUID] = []
    for active_lease in leases:
        if active_lease.id == preserve_lease_id:
            continue
        active_lease.status = "CANCELLED"
        active_lease.completed_at = now
        active_lease.failure_code = "RUN_CANCELLED"
        active_lease.failure_summary = "The Run cancellation was converged."
        active_lease.updated_at = now
        cancelled_ids.append(active_lease.id)
    if cancelled_ids:
        grants = list(
            (
                await session.scalars(
                    select(SecretInjectionGrant).where(
                        SecretInjectionGrant.lease_id.in_(cancelled_ids),
                        SecretInjectionGrant.status == "ISSUED",
                    )
                )
            ).all()
        )
        for grant in grants:
            grant.status = "REVOKED"
    commands = list(
        (
            await session.scalars(
                select(RunCommandOutbox)
                .where(
                    RunCommandOutbox.run_id == run_id,
                    RunCommandOutbox.status.in_({"PENDING", "CLAIMED"}),
                )
                .order_by(RunCommandOutbox.id.asc())
                .with_for_update()
            )
        ).all()
    )
    for command in commands:
        if command.id == preserve_source_id:
            continue
        command.status = "CANCELLED"
        command.last_error_code = "RUN_CANCELLATION_CONVERGED"
        command.updated_at = now
    return len(cancelled_ids)


async def _converge_cancelled_run(
    session: AsyncSession,
    *,
    run_id: UUID,
    now: datetime,
    request_id: str,
    reason: str,
) -> bool:
    fenced_lease_count = await _fence_cancelled_run_leases(
        session,
        run_id=run_id,
        now=now,
    )
    run = await session.scalar(
        select(Run)
        .where(Run.id == run_id)
        .execution_options(populate_existing=True)
        .with_for_update()
    )
    if run is None or run.cancel_requested_at is None:
        return False
    if run.status == "ABORTED":
        return True
    if run.status != "ABORTING":
        return False
    previous = run.status
    run.status = "ABORTED"
    run.finished_at = run.finished_at or now
    run.failure_code = None
    run.failure_summary = None
    run.updated_at = now
    if previous != "ABORTED":
        run.version += 1
        await append_run_event(
            session,
            run=run,
            event_type="run.status",
            payload={"previous_status": previous, "status": "ABORTED"},
        )
        await append_run_event(
            session,
            run=run,
            event_type="run.completed",
            payload={"status": "ABORTED", "reason": reason},
        )
        await append_audit_event(
            session,
            organization_id=run.organization_id,
            project_id=run.project_id,
            actor_type="system",
            actor_id="cancellation-reaper",
            action="run.cancellation_converged",
            resource_type="run",
            resource_id=str(run.id),
            request_id=request_id,
            details={
                "previous_status": previous,
                "reason": reason,
                "fenced_lease_count": fenced_lease_count,
                "cancel_deadline_at": (
                    run.cancel_deadline_at.isoformat()
                    if run.cancel_deadline_at is not None
                    else None
                ),
            },
        )
    return True


async def reap_overdue_cancellations(
    session: AsyncSession,
    *,
    now: datetime,
    request_id: str,
    batch_size: int = 100,
) -> int:
    if not 1 <= batch_size <= 500:
        raise ValueError("Cancellation recovery batch size must be between 1 and 500.")
    run_ids = list(
        (
            await session.scalars(
                select(Run.id)
                .where(
                    Run.status == "ABORTING",
                    Run.cancel_requested_at.is_not(None),
                    Run.cancel_deadline_at <= now,
                )
                .order_by(Run.cancel_deadline_at.asc(), Run.id.asc())
                .with_for_update(skip_locked=True)
                .limit(batch_size)
            )
        ).all()
    )
    converged = 0
    for run_id in run_ids:
        if await _converge_cancelled_run(
            session,
            run_id=run_id,
            now=now,
            request_id=request_id,
            reason="CANCEL_DEADLINE_EXCEEDED",
        ):
            converged += 1
    return converged


async def _reset_expired_source(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    now: datetime,
    deadline_exceeded: bool,
    failure_code: str,
    request_id: str,
) -> tuple[datetime | None, bool]:
    if lease.work_kind == "BUILD":
        source = await session.scalar(
            select(BuildDispatchOutbox).where(
                BuildDispatchOutbox.id == lease.source_outbox_id
            )
        )
        build = await session.scalar(select(Build).where(Build.id == lease.build_id))
        retry = execution_retry_allowed(
            requested=not deadline_exceeded,
            outcome="FAILED",
            attempt=lease.attempt,
            max_attempts=settings.worker_max_attempts,
            source_available=source is not None,
        )
        next_attempt_at = (
            retry_available_at(
                now=now,
                attempt=lease.attempt,
                base_seconds=settings.worker_retry_base_seconds,
                max_seconds=settings.worker_retry_max_seconds,
            )
            if retry
            else None
        )
        if source is not None:
            source.status = "PENDING" if retry else "FAILED"
            source.available_at = next_attempt_at or now
            source.last_error_code = failure_code
            source.updated_at = now
        if build is not None:
            build.status = (
                "QUEUED" if retry else "TIMED_OUT" if deadline_exceeded else "FAILED"
            )
            build.error_code = None if retry else failure_code
            build.error_message = (
                None
                if retry
                else (
                    "The Build execution deadline was exceeded."
                    if deadline_exceeded
                    else (
                        "The execution worker was lost."
                        if failure_code == "WORKER_LOST"
                        else "The execution lease expired."
                    )
                )
            )
            build.completed_at = None if retry else now
            build.updated_at = now
            build.version += 1
        return next_attempt_at, False

    source = await session.scalar(
        select(RunCommandOutbox).where(RunCommandOutbox.id == lease.source_outbox_id)
    )
    run = await session.scalar(select(Run).where(Run.id == lease.run_id))
    if (
        run is not None
        and run.cancel_requested_at is not None
        and lease.work_kind in {"RUN_START", "RUN_CANCEL"}
        and await _converge_cancelled_run(
            session,
            run_id=run.id,
            now=now,
            request_id=request_id,
            reason=(
                "RUN_START_LEASE_LOST"
                if lease.work_kind == "RUN_START"
                else "RUN_CANCEL_LEASE_LOST"
            ),
        )
    ):
        return None, True
    retry = execution_retry_allowed(
        requested=not deadline_exceeded,
        outcome="FAILED",
        attempt=lease.attempt,
        max_attempts=settings.worker_max_attempts,
        source_available=source is not None,
    )
    next_attempt_at = (
        retry_available_at(
            now=now,
            attempt=lease.attempt,
            base_seconds=settings.worker_retry_base_seconds,
            max_seconds=settings.worker_retry_max_seconds,
        )
        if retry
        else None
    )
    if source is not None:
        source.status = "PENDING" if retry else "FAILED"
        source.available_at = next_attempt_at or now
        source.last_error_code = failure_code
        source.updated_at = now
    if run is None:
        return next_attempt_at, False
    previous = run.status
    if lease.work_kind == "RUN_START":
        run.status = (
            "QUEUED" if retry else "TIMED_OUT" if deadline_exceeded else "FAILED"
        )
        run.failure_code = None if retry else failure_code
        run.failure_summary = (
            None
            if retry
            else (
                "The Run execution deadline was exceeded."
                if deadline_exceeded
                else (
                    "The execution worker was lost."
                    if failure_code == "WORKER_LOST"
                    else "The execution lease expired."
                )
            )
        )
        run.finished_at = None if retry else now
    elif not retry:
        run.status = "FAILED"
        run.failure_code = (
            "CANCEL_DEADLINE_EXCEEDED" if deadline_exceeded else "CANCEL_LEASE_EXPIRED"
        )
        run.failure_summary = (
            "The cancellation deadline was exceeded."
            if deadline_exceeded
            else "The cancellation lease expired."
        )
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
    return next_attempt_at, False


async def reap_expired_leases(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    request_id: str,
    batch_size: int = 100,
    reap_cancellations: bool = True,
) -> int:
    if not 1 <= batch_size <= 500:
        raise ValueError("Lease recovery batch size must be between 1 and 500.")
    current = now or datetime.now(UTC)
    records = list(
        (
            await session.scalars(
                select(ExecutionLease)
                .where(
                    ExecutionLease.status == "ACTIVE",
                    or_(
                        ExecutionLease.expires_at <= current,
                        ExecutionLease.deadline_at <= current,
                    ),
                )
                .order_by(ExecutionLease.expires_at.asc())
                .with_for_update(skip_locked=True)
                .limit(batch_size)
            )
        ).all()
    )
    for lease in records:
        deadline_exceeded = lease.deadline_at <= current
        failure_code = (
            "WORKLOAD_DEADLINE_EXCEEDED"
            if deadline_exceeded
            else (
                "WORKER_LOST"
                if lease.failure_code == "WORKER_LOST"
                else "LEASE_EXPIRED"
            )
        )
        next_attempt_at, cancellation_converged = await _reset_expired_source(
            session,
            lease=lease,
            now=current,
            deadline_exceeded=deadline_exceeded,
            failure_code=failure_code,
            request_id=request_id,
        )
        if cancellation_converged:
            await append_audit_event(
                session,
                organization_id=lease.organization_id,
                project_id=lease.project_id,
                actor_type="system",
                actor_id="cancellation-reaper",
                action="execution.lease.cancellation_converged",
                resource_type="execution_lease",
                resource_id=str(lease.id),
                request_id=request_id,
                details={
                    "work_kind": lease.work_kind,
                    "attempt": lease.attempt,
                    "worker_id": str(lease.worker_id),
                    "retry_scheduled": False,
                },
            )
            continue
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
        lease.status = "FAILED" if deadline_exceeded else "EXPIRED"
        lease.completed_at = current
        lease.failure_code = failure_code
        lease.failure_summary = (
            "The workload execution deadline was exceeded."
            if deadline_exceeded
            else (
                "The execution worker heartbeat was lost."
                if failure_code == "WORKER_LOST"
                else "The worker did not renew the lease."
            )
        )
        lease.updated_at = current
        await append_audit_event(
            session,
            organization_id=lease.organization_id,
            project_id=lease.project_id,
            actor_type="system",
            actor_id=(
                "worker-loss-reaper"
                if failure_code == "WORKER_LOST"
                else "lease-reaper"
            ),
            action=(
                "execution.lease.deadline_exceeded"
                if deadline_exceeded
                else (
                    "execution.lease.worker_lost"
                    if failure_code == "WORKER_LOST"
                    else "execution.lease.expired"
                )
            ),
            resource_type="execution_lease",
            resource_id=str(lease.id),
            request_id=request_id,
            details={
                "work_kind": lease.work_kind,
                "attempt": lease.attempt,
                "worker_id": str(lease.worker_id),
                "deadline_at": lease.deadline_at.isoformat(),
                "deadline_exceeded": deadline_exceeded,
                "worker_lost": failure_code == "WORKER_LOST",
                "retry_scheduled": next_attempt_at is not None,
                "next_attempt_at": (
                    next_attempt_at.isoformat() if next_attempt_at is not None else None
                ),
            },
        )
    if reap_cancellations:
        await reap_overdue_cancellations(
            session,
            now=current,
            request_id=request_id,
            batch_size=batch_size,
        )
    return len(records)


async def _build_claim_payload(
    session: AsyncSession,
    *,
    source: BuildDispatchOutbox,
) -> tuple[dict[str, object], Build]:
    build = await session.scalar(select(Build).where(Build.id == source.build_id))
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
            "download_grant_path": ("/internal/v1/leases/{lease_id}/source-download"),
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
        "cancel_requested_at": (
            run.cancel_requested_at.isoformat()
            if run.cancel_requested_at is not None
            else None
        ),
        "cancel_deadline_at": (
            run.cancel_deadline_at.isoformat()
            if run.cancel_deadline_at is not None
            else None
        ),
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


async def _bound_run_egress_policy_is_current(
    session: AsyncSession,
    *,
    source: RunCommandOutbox,
    now: datetime,
    request_id: str,
) -> bool:
    run = await session.scalar(
        select(Run).where(Run.id == source.run_id).with_for_update()
    )
    if run is None:
        return True
    input_reference = dict(run.input_reference)
    stored_policy = input_reference.get("project_egress_policy")
    receipt = input_reference.get("project_egress_policy_receipt")
    if receipt is None and stored_policy is None:
        return True
    receipt_dict = receipt if isinstance(receipt, dict) else {}
    binding_valid = True
    try:
        _bound_egress_policy(input_reference)
        if not isinstance(receipt, dict):
            raise ValueError
        policy_id = UUID(str(receipt["policy_id"]))
        revision_id = UUID(str(receipt["revision_id"]))
    except (KeyError, TypeError, ValueError):
        binding_valid = False
        policy_id = UUID(int=0)
        revision_id = UUID(int=0)
    policy = await session.scalar(
        select(EgressPolicy)
        .where(
            EgressPolicy.id == policy_id,
            EgressPolicy.organization_id == run.organization_id,
            EgressPolicy.project_id == run.project_id,
        )
        .with_for_update()
    )
    revision = await session.scalar(
        select(EgressPolicyRevision).where(
            EgressPolicyRevision.id == revision_id,
            EgressPolicyRevision.policy_id == policy_id,
            EgressPolicyRevision.organization_id == run.organization_id,
            EgressPolicyRevision.project_id == run.project_id,
        )
    )
    current = (
        binding_valid
        and policy is not None
        and revision is not None
        and policy.status == "ACTIVE"
        and policy.active_revision_id == revision_id
        and receipt_dict.get("revision_number") == revision.revision_number
        and receipt_dict.get("policy_digest") == revision.policy_digest
        and receipt_dict.get("credential_configured")
        == (revision.credential_secret_id is not None)
    )
    if current:
        return True

    previous_status = run.status
    source.status = "FAILED"
    source.attempts += 1
    source.claimed_at = now
    source.last_error_code = "EGRESS_POLICY_BINDING_REVOKED"
    source.updated_at = now
    run.status = "FAILED"
    run.failure_code = "EGRESS_POLICY_BINDING_REVOKED"
    run.failure_summary = (
        "The bound egress policy is no longer active at execution admission."
    )
    run.finished_at = now
    run.updated_at = now
    run.version += 1
    await append_run_event(
        session,
        run=run,
        event_type="run.status",
        payload={"previous_status": previous_status, "status": "FAILED"},
    )
    await append_run_event(
        session,
        run=run,
        event_type="run.failed",
        payload={
            "failure_code": "EGRESS_POLICY_BINDING_REVOKED",
            "retryable": False,
        },
    )
    await append_audit_event(
        session,
        organization_id=run.organization_id,
        project_id=run.project_id,
        actor_type="system",
        actor_id="execution-admission",
        action="run.egress_policy_binding_revoked",
        resource_type="run",
        resource_id=str(run.id),
        request_id=request_id,
        details={
            "policy_id": str(policy_id) if policy_id.int != 0 else None,
            "revision_id": str(revision_id) if revision_id.int != 0 else None,
            "binding_integrity_valid": binding_valid,
            "policy_active": policy is not None and policy.status == "ACTIVE",
            "same_revision_selected": (
                policy is not None and policy.active_revision_id == revision_id
            ),
        },
    )
    return False


async def _select_source(
    session: AsyncSession,
    *,
    kind: str,
    now: datetime,
) -> BuildDispatchOutbox | RunCommandOutbox | None:
    if kind == "BUILD":
        active_project_leases = (
            select(func.count(ExecutionLease.id))
            .where(
                ExecutionLease.project_id == BuildDispatchOutbox.project_id,
                ExecutionLease.status == "ACTIVE",
                ExecutionLease.work_kind.in_(PROJECT_EXECUTION_SLOT_KINDS),
                ExecutionLease.expires_at > now,
                ExecutionLease.deadline_at > now,
            )
            .correlate(BuildDispatchOutbox)
            .scalar_subquery()
        )
        project_limit = (
            select(Project.max_active_leases)
            .where(
                Project.id == BuildDispatchOutbox.project_id,
                Project.status == "ACTIVE",
                Project.deleted_at.is_(None),
            )
            .correlate(BuildDispatchOutbox)
            .scalar_subquery()
        )
        source = await session.scalar(
            select(BuildDispatchOutbox)
            .where(
                BuildDispatchOutbox.status == "PENDING",
                BuildDispatchOutbox.available_at <= now,
                active_project_leases < project_limit,
            )
            .order_by(
                BuildDispatchOutbox.available_at.asc(),
                BuildDispatchOutbox.id.asc(),
            )
            .with_for_update(of=BuildDispatchOutbox, skip_locked=True)
            .limit(1)
        )
        return source
    command = "START" if kind == "RUN_START" else "CANCEL"
    query = select(RunCommandOutbox).where(
        RunCommandOutbox.status == "PENDING",
        RunCommandOutbox.command == command,
        RunCommandOutbox.available_at <= now,
    )
    if kind == "RUN_START":
        active_project_leases = (
            select(func.count(ExecutionLease.id))
            .where(
                ExecutionLease.project_id == RunCommandOutbox.project_id,
                ExecutionLease.status == "ACTIVE",
                ExecutionLease.work_kind.in_(PROJECT_EXECUTION_SLOT_KINDS),
                ExecutionLease.expires_at > now,
                ExecutionLease.deadline_at > now,
            )
            .correlate(RunCommandOutbox)
            .scalar_subquery()
        )
        project_limit = (
            select(Project.max_active_leases)
            .where(
                Project.id == RunCommandOutbox.project_id,
                Project.status == "ACTIVE",
                Project.deleted_at.is_(None),
            )
            .correlate(RunCommandOutbox)
            .scalar_subquery()
        )
        query = query.where(active_project_leases < project_limit)
    source = await session.scalar(
        query.order_by(
            RunCommandOutbox.available_at.asc(),
            RunCommandOutbox.id.asc(),
        )
        .with_for_update(of=RunCommandOutbox, skip_locked=True)
        .limit(1)
    )
    return cast(RunCommandOutbox | None, source)


def _execution_timeout_seconds(
    source: BuildDispatchOutbox | RunCommandOutbox,
    *,
    work_kind: str,
) -> int:
    if work_kind == "BUILD":
        raw_timeout = source.payload.get(
            "timeout_seconds",
            settings.sandbox_max_build_seconds,
        )
        ceiling = settings.sandbox_max_build_seconds
    elif work_kind == "RUN_START":
        runtime = source.payload.get("runtime")
        raw_timeout = (
            runtime.get("timeout_seconds") if isinstance(runtime, dict) else None
        )
        ceiling = settings.sandbox_max_run_seconds
    else:
        raw_timeout = settings.worker_lease_max_seconds
        ceiling = settings.worker_lease_max_seconds
    if (
        isinstance(raw_timeout, bool)
        or not isinstance(raw_timeout, int)
        or raw_timeout < 1
    ):
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_DEADLINE_INVALID",
            message="The persisted work item has an invalid execution timeout.",
        )
    return min(raw_timeout, ceiling)


def _cancellation_deadline_from_source(source: RunCommandOutbox) -> datetime:
    raw_deadline = source.payload.get("cancel_deadline_at")
    if not isinstance(raw_deadline, str):
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_DEADLINE_INVALID",
            message="The persisted cancellation has no convergence deadline.",
        )
    try:
        deadline = datetime.fromisoformat(raw_deadline)
    except ValueError as exc:
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_DEADLINE_INVALID",
            message="The persisted cancellation deadline is invalid.",
        ) from exc
    if deadline.tzinfo is None:
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_DEADLINE_INVALID",
            message="The persisted cancellation deadline is invalid.",
        )
    return deadline


async def _lock_worker_claims(
    session: AsyncSession,
    *,
    worker_id: UUID,
) -> None:
    await session.execute(
        text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
        {"scope": f"rdc:worker-claim:{worker_id}"},
    )


async def _active_worker_lease_count(
    session: AsyncSession,
    *,
    worker_id: UUID,
    now: datetime,
) -> int:
    value = await session.scalar(
        select(func.count())
        .select_from(ExecutionLease)
        .where(
            ExecutionLease.worker_id == worker_id,
            ExecutionLease.status == "ACTIVE",
            ExecutionLease.expires_at > now,
            ExecutionLease.deadline_at > now,
        )
    )
    return int(value or 0)


async def _lock_project_admission(
    session: AsyncSession,
    *,
    project_id: UUID,
    work_kind: str,
    now: datetime,
) -> tuple[Project, int]:
    project = await session.scalar(
        select(Project)
        .where(Project.id == project_id)
        .execution_options(populate_existing=True)
        .with_for_update()
    )
    if project is None or project.status != "ACTIVE" or project.deleted_at is not None:
        raise ApiError(
            status_code=409,
            code="PROJECT_EXECUTION_DISABLED",
            message="The work item's project is not active.",
        )
    value = await session.scalar(
        select(func.count())
        .select_from(ExecutionLease)
        .where(
            ExecutionLease.project_id == project.id,
            ExecutionLease.status == "ACTIVE",
            ExecutionLease.work_kind.in_(PROJECT_EXECUTION_SLOT_KINDS),
            ExecutionLease.expires_at > now,
            ExecutionLease.deadline_at > now,
        )
    )
    active_count = int(value or 0)
    if (
        work_kind in PROJECT_EXECUTION_SLOT_KINDS
        and active_count >= project.max_active_leases
    ):
        raise ApiError(
            status_code=409,
            code="PROJECT_CONCURRENCY_LIMIT",
            message="The project has reached its active execution lease limit.",
            details={"max_active_leases": project.max_active_leases},
        )
    return project, active_count


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
    locked_worker = await session.scalar(
        select(WorkerIdentity)
        .where(WorkerIdentity.id == worker.id)
        .execution_options(populate_existing=True)
        .with_for_update()
    )
    if locked_worker is None:
        raise ApiError(
            status_code=401,
            code="INTERNAL_CREDENTIAL_INVALID",
            message="The internal credential is invalid.",
        )
    worker = locked_worker
    recovery_pending = worker.last_lost_at is not None and (
        worker.last_recovered_at is None
        or worker.last_recovered_at < worker.last_lost_at
    )
    if recovery_pending:
        raise ApiError(
            status_code=409,
            code="WORKER_RECOVERY_REQUIRED",
            message="The worker must complete managed-runtime cleanup.",
        )
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
    active_worker_count = await _active_worker_lease_count(
        session,
        worker_id=worker.id,
        now=now,
    )
    if active_worker_count >= worker.max_concurrency:
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

        if (
            kind == "RUN_START"
            and isinstance(source, RunCommandOutbox)
            and not await _bound_run_egress_policy_is_current(
                session,
                source=source,
                now=now,
                request_id=request_id,
            )
        ):
            return None

        project, active_project_count = await _lock_project_admission(
            session,
            project_id=project_id,
            work_kind=kind,
            now=now,
        )

        source.status = "CLAIMED"
        source.attempts += 1
        source.claimed_at = now
        source.updated_at = now
        issued = issue_lease_token(pepper=settings.lease_token_pepper)
        timeout_seconds = _execution_timeout_seconds(source, work_kind=kind)
        deadline_at = execution_deadline_at(
            claimed_at=now,
            timeout_seconds=timeout_seconds,
        )
        if kind == "RUN_CANCEL" and isinstance(source, RunCommandOutbox):
            deadline_at = min(
                deadline_at,
                _cancellation_deadline_from_source(source),
            )
        if deadline_at <= now:
            raise ApiError(
                status_code=409,
                code="WORK_ITEM_DEADLINE_EXPIRED",
                message="The persisted work item deadline has expired.",
            )
        expires_at = clamp_lease_expiry(
            proposed=now + timedelta(seconds=settings.worker_lease_seconds),
            claimed_at=now,
            max_lifetime_seconds=settings.worker_lease_max_seconds,
            deadline_at=deadline_at,
        )
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
            deadline_at=deadline_at,
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
        claim_payload["deadline_at"] = deadline_at.isoformat()
        claim_payload["admission"] = {
            "worker_active_before_claim": active_worker_count,
            "worker_max_concurrency": worker.max_concurrency,
            "project_active_before_claim": active_project_count,
            "project_max_active_leases": project.max_active_leases,
            "project_slot_consumed": kind in PROJECT_EXECUTION_SLOT_KINDS,
        }
        claim_payload["dataset_append_capability"] = _dataset_append_capability(
            worker,
            claim_payload,
            dataset_write_enabled=(
                activation is not None and activation.dataset_write_enabled
            ),
            request_queue_dataset_enabled=(
                activation is not None and activation.request_queue_dataset_enabled
            ),
        )
        claim_payload["key_value_store_capability"] = key_value_store_capability(
            worker,
            claim_payload,
            key_value_store_enabled=(
                activation is not None and activation.key_value_store_enabled
            ),
            request_queue_key_value_store_enabled=(
                activation is not None
                and activation.request_queue_key_value_store_enabled
            ),
        )
        claim_payload["request_queue_capability"] = request_queue_capability(
            worker,
            claim_payload,
            request_queue_enabled=(
                activation is not None and activation.request_queue_enabled
            ),
            request_queue_http_enabled=(
                activation is not None and activation.request_queue_http_enabled
            ),
            egress_policy_digest=(
                activation.egress_policy_digest
                if activation is not None and activation.request_queue_http_enabled
                else None
            ),
            request_queue_browser_enabled=(
                activation is not None and activation.request_queue_browser_enabled
            ),
            browser_policy_digest=(
                activation.browser_policy_digest
                if activation is not None and activation.request_queue_browser_enabled
                else None
            ),
            browser_egress_policy_digest=(
                str(
                    cast(dict[str, object], claim_payload["input_reference"])[
                        "request_queue_browser_egress_policy_digest"
                    ]
                )
                if activation is not None
                and activation.request_queue_browser_enabled
                and isinstance(claim_payload.get("input_reference"), dict)
                and isinstance(
                    cast(dict[str, object], claim_payload["input_reference"]).get(
                        "request_queue_browser_egress_policy_digest"
                    ),
                    str,
                )
                else None
            ),
            request_queue_dataset_enabled=(
                activation is not None and activation.request_queue_dataset_enabled
            ),
            request_queue_key_value_store_enabled=(
                activation is not None
                and activation.request_queue_key_value_store_enabled
            ),
            project_egress_policy_binding_digest=(
                activation.project_egress_policy_binding_digest
                if activation is not None
                else None
            ),
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
                "deadline_at": deadline_at.isoformat(),
                "worker_active_before_claim": active_worker_count,
                "worker_max_concurrency": worker.max_concurrency,
                "project_active_before_claim": active_project_count,
                "project_max_active_leases": project.max_active_leases,
                "project_slot_consumed": (kind in PROJECT_EXECUTION_SLOT_KINDS),
                "execution_enabled": execution_enabled,
                "sandbox_attestation_digest": worker.sandbox_attestation_digest,
                "activation_mode": (
                    activation.mode if activation is not None else "disabled"
                ),
                "activation_agent_version_id": (
                    str(activation.agent_version_id) if activation is not None else None
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
            deadline_at=deadline_at,
            lease_token=issued.raw_token,
            payload=claim_payload,
        )
    return None


async def append_worker_dataset_items(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: object,
    request_id: str,
) -> DatasetAppendOutcome:
    if not settings.sandbox_canary_dataset_writes_enabled:
        raise ApiError(
            status_code=403,
            code="DATASET_WORKER_APPEND_DISABLED",
            message="Worker Dataset append is disabled.",
        )
    if lease.work_kind != "RUN_START" or lease.run_id is None:
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_STATE_CONFLICT",
            message="Only active Run execution leases can append Dataset items.",
        )
    if "DATASET_APPEND" not in worker.capabilities:
        raise ApiError(
            status_code=403,
            code="WORKER_CAPABILITY_DENIED",
            message="The worker cannot append Dataset items.",
        )

    snapshot = dict(lease.payload_snapshot)
    activation = snapshot.get("activation")
    dataset_write_enabled = (
        isinstance(activation, dict) and activation.get("dataset_write_enabled") is True
    )
    expected_capability = _dataset_append_capability(
        worker,
        snapshot,
        dataset_write_enabled=dataset_write_enabled,
        request_queue_dataset_enabled=(
            isinstance(activation, dict)
            and activation.get("request_queue_dataset_enabled") is True
        ),
    )
    if (
        expected_capability is None
        or snapshot.get("dataset_append_capability") != expected_capability
        or str(snapshot.get("run_id", "")) != str(lease.run_id)
    ):
        raise ApiError(
            status_code=403,
            code="DATASET_WORKER_CAPABILITY_INVALID",
            message="The worker Dataset capability receipt is invalid.",
        )

    run = await session.scalar(
        select(Run).where(
            Run.id == lease.run_id,
            Run.organization_id == lease.organization_id,
            Run.project_id == lease.project_id,
        )
    )
    if (
        run is None
        or str(run.agent_version_id) != settings.sandbox_canary_agent_version_id.strip()
        or str(snapshot.get("agent_version_id", "")) != str(run.agent_version_id)
    ):
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The requested resource was not found.",
        )

    dataset = await session.scalar(
        select(Dataset).where(
            Dataset.organization_id == run.organization_id,
            Dataset.project_id == run.project_id,
            Dataset.run_id == run.id,
            Dataset.name == "default",
        )
    )
    if dataset is None:
        dataset = await create_dataset(
            session,
            run=run,
            user_id=run.requested_by_user_id,
            actor_type="worker",
            actor_id=str(worker.id),
            request_id=request_id,
            payload=CreateDatasetRequest(name="default"),
        )

    return await append_dataset_items(
        session,
        dataset=dataset,
        user_id=run.requested_by_user_id,
        actor_type="worker",
        actor_id=str(worker.id),
        request_id=request_id,
        payload=payload,
    )


async def renew_lease(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: RenewLeaseRequest,
    request_id: str,
) -> ExecutionLeaseSummary:
    now = datetime.now(UTC)
    requested = max(now, lease.expires_at) + timedelta(seconds=payload.extend_seconds)
    extended_until = clamp_lease_expiry(
        proposed=requested,
        claimed_at=lease.claimed_at,
        max_lifetime_seconds=settings.worker_lease_max_seconds,
        deadline_at=lease.deadline_at,
    )
    if extended_until <= now:
        raise ApiError(
            status_code=409,
            code=(
                "WORKLOAD_DEADLINE_EXCEEDED"
                if lease.deadline_at <= now
                else "LEASE_MAXIMUM_REACHED"
            ),
            message=(
                "The workload execution deadline was exceeded."
                if lease.deadline_at <= now
                else "The lease reached its maximum lifetime."
            ),
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
        details={
            "expires_at": lease.expires_at.isoformat(),
            "deadline_at": lease.deadline_at.isoformat(),
        },
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
        if lease.work_kind == "RUN_START" and run.cancel_requested_at is not None:
            raise ApiError(
                status_code=409,
                code="RUN_CANCELLATION_PENDING",
                message="The Run is awaiting cancellation convergence.",
            )
        allowed = (
            {"STARTING", "RUNNING"} if lease.work_kind == "RUN_START" else {"ABORTING"}
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
        if provenance.get("source_sha256") != source.get(
            "sha256_digest"
        ) or provenance.get("agent_version_id") != snapshot.get("agent_version_id"):
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
        if provenance.get("image_digest") != artifact.get("digest") or provenance.get(
            "run_id"
        ) != snapshot.get("run_id"):
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
        select(RunCommandOutbox).where(RunCommandOutbox.id == lease.source_outbox_id)
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
    if lease.work_kind == "RUN_START" and lease.run_id is not None:
        cancelling_run = await session.scalar(select(Run).where(Run.id == lease.run_id))
        if (
            cancelling_run is not None
            and cancelling_run.cancel_requested_at is not None
            and await _converge_cancelled_run(
                session,
                run_id=cancelling_run.id,
                now=now,
                request_id=request_id,
                reason="LATE_RUN_START_COMPLETION",
            )
        ):
            await append_audit_event(
                session,
                organization_id=lease.organization_id,
                project_id=lease.project_id,
                actor_type="worker",
                actor_id=str(worker.id),
                action="execution.lease.cancellation_converged",
                resource_type="execution_lease",
                resource_id=str(lease.id),
                request_id=request_id,
                details={
                    "work_kind": lease.work_kind,
                    "attempt": lease.attempt,
                    "reported_outcome": payload.outcome,
                    "retry_scheduled": False,
                },
            )
            return lease_summary(lease)
    source = await _source_for_lease(session, lease)
    retry = execution_retry_allowed(
        requested=payload.retryable,
        outcome=payload.outcome,
        attempt=lease.attempt,
        max_attempts=settings.worker_max_attempts,
        source_available=source is not None,
    )
    next_attempt_at: datetime | None = None
    registrations = (
        [payload.artifact] if payload.artifact is not None else list(payload.artifacts)
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
        next_attempt_at = retry_available_at(
            now=now,
            attempt=lease.attempt,
            base_seconds=settings.worker_retry_base_seconds,
            max_seconds=settings.worker_retry_max_seconds,
        )
        lease.status = "FAILED"
        lease.completed_at = now
        lease.failure_code = payload.error_code or "WORKER_RETRYABLE_FAILURE"
        lease.failure_summary = payload.error_summary
        if source is not None:
            source.status = "PENDING"
            source.available_at = next_attempt_at
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
            build.artifact_digest = f"{artifact.digest_algorithm}:{artifact.digest}"
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
                fenced_lease_count = await _fence_cancelled_run_leases(
                    session,
                    run_id=run.id,
                    now=now,
                    preserve_lease_id=lease.id,
                    preserve_source_id=(source.id if source is not None else None),
                )
                run.status = "ABORTED"
                run.failure_code = None
                run.failure_summary = None
                await append_audit_event(
                    session,
                    organization_id=run.organization_id,
                    project_id=run.project_id,
                    actor_type="worker",
                    actor_id=str(worker.id),
                    action="run.cancellation_converged",
                    resource_type="run",
                    resource_id=str(run.id),
                    request_id=request_id,
                    details={
                        "previous_status": previous,
                        "reason": "WORKER_CONFIRMED",
                        "fenced_lease_count": fenced_lease_count,
                        "cancel_deadline_at": (
                            run.cancel_deadline_at.isoformat()
                            if run.cancel_deadline_at is not None
                            else None
                        ),
                    },
                )
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
            "run.completed" if run.status in {"SUCCEEDED", "ABORTED"} else "run.failed"
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
            "COMPLETED" if run.status in {"SUCCEEDED", "ABORTED"} else "FAILED"
        )
        lease.completed_at = now
        lease.failure_code = run.failure_code
        lease.failure_summary = run.failure_summary
        if source is not None:
            source.status = "DELIVERED" if lease.status == "COMPLETED" else "FAILED"
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
            "next_attempt_at": (
                next_attempt_at.isoformat() if next_attempt_at is not None else None
            ),
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
    declared = (
        {str(name) for name in declared_raw if isinstance(name, str)}
        if isinstance(declared_raw, list)
        else set()
    )
    requested = set(payload.names)
    if not requested.issubset(declared):
        raise ApiError(
            status_code=403,
            code="SECRET_NOT_DECLARED",
            message="The Agent version did not declare every requested secret.",
        )
    try:
        worker_public_key = decode_worker_public_key(payload.worker_public_key_b64)
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
        ephemeral_public_key_b64=base64.b64encode(grant.ephemeral_public_key).decode(
            "ascii"
        ),
        nonce_b64=base64.b64encode(grant.nonce).decode("ascii"),
        ciphertext_b64=base64.b64encode(grant.ciphertext).decode("ascii"),
        expires_at=grant.expires_at,
        secret_names=list(grant.secret_names),
        environment=payload.environment,
    )


async def issue_egress_credential_envelope(
    session: AsyncSession,
    *,
    lease: ExecutionLease,
    worker: WorkerIdentity,
    payload: EgressCredentialEnvelopeRequest,
    request_id: str,
) -> EgressCredentialEnvelopeResponse:
    if lease.work_kind != "RUN_START" or lease.run_id is None:
        raise ApiError(
            status_code=409,
            code="WORK_ITEM_STATE_CONFLICT",
            message="Egress credentials require an active Run execution lease.",
        )
    if "SECRET_ENVELOPE" not in worker.capabilities:
        raise ApiError(
            status_code=403,
            code="WORKER_CAPABILITY_DENIED",
            message="The worker cannot request credential envelopes.",
        )
    run = await session.scalar(
        select(Run).where(Run.id == lease.run_id).with_for_update()
    )
    if run is None:
        raise ApiError(
            status_code=404,
            code="RESOURCE_NOT_FOUND",
            message="The Run was not found.",
        )
    input_reference = dict(run.input_reference)
    receipt = input_reference.get("project_egress_policy_receipt")
    try:
        binding = _bound_egress_policy(input_reference)
        if binding is None or not isinstance(receipt, dict):
            raise ValueError
        policy_id = UUID(str(receipt["policy_id"]))
        revision_id = UUID(str(receipt["revision_id"]))
        if (
            receipt.get("credential_configured") is not True
            or receipt.get("binding_digest") != payload.policy_binding_digest
        ):
            raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise ApiError(
            status_code=409,
            code="EGRESS_CREDENTIAL_BINDING_INVALID",
            message="The Run egress credential binding is invalid.",
        ) from exc
    policy = await session.scalar(
        select(EgressPolicy)
        .where(
            EgressPolicy.id == policy_id,
            EgressPolicy.organization_id == lease.organization_id,
            EgressPolicy.project_id == lease.project_id,
        )
        .with_for_update()
    )
    revision = await session.scalar(
        select(EgressPolicyRevision).where(
            EgressPolicyRevision.id == revision_id,
            EgressPolicyRevision.policy_id == policy_id,
            EgressPolicyRevision.organization_id == lease.organization_id,
            EgressPolicyRevision.project_id == lease.project_id,
        )
    )
    if (
        policy is None
        or revision is None
        or policy.status != "ACTIVE"
        or policy.active_revision_id != revision.id
        or revision.revision_number != receipt.get("revision_number")
        or revision.policy_digest != receipt.get("policy_digest")
        or revision.credential_secret_id is None
    ):
        raise ApiError(
            status_code=409,
            code="EGRESS_CREDENTIAL_BINDING_REVOKED",
            message="The bound egress credential is no longer eligible.",
        )
    secret = await session.scalar(
        select(ProjectSecret)
        .where(
            ProjectSecret.id == revision.credential_secret_id,
            ProjectSecret.organization_id == lease.organization_id,
            ProjectSecret.project_id == lease.project_id,
        )
        .with_for_update()
    )
    if secret is None:
        raise ApiError(
            status_code=409,
            code="EGRESS_CREDENTIAL_UNAVAILABLE",
            message="The bound egress credential is unavailable.",
        )
    try:
        worker_public_key = decode_worker_public_key(payload.worker_public_key_b64)
    except ValueError as exc:
        raise ApiError(
            status_code=422,
            code="VALIDATION_FAILED",
            message=str(exc),
        ) from exc
    public_key_digest = hashlib.sha256(worker_public_key).hexdigest()
    fingerprint = canonical_fingerprint(
        {
            "purpose": "egress-authorization/v1",
            "lease_id": str(lease.id),
            "policy_binding_digest": payload.policy_binding_digest,
            "secret_version": secret.version,
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
                code="EGRESS_CREDENTIAL_GRANT_EXPIRED",
                message="The credential grant expired. Claim a new execution lease.",
            )
        return EgressCredentialEnvelopeResponse(
            grant_id=existing.id,
            algorithm=existing.algorithm,
            ephemeral_public_key_b64=base64.b64encode(
                existing.ephemeral_public_key
            ).decode("ascii"),
            nonce_b64=base64.b64encode(existing.nonce).decode("ascii"),
            ciphertext_b64=base64.b64encode(existing.ciphertext).decode("ascii"),
            expires_at=existing.expires_at,
            policy_binding_digest=payload.policy_binding_digest,
        )
    if secret.master_key_version != settings.project_secret_master_key_version:
        raise ApiError(
            status_code=503,
            code="SECRET_KEY_VERSION_UNAVAILABLE",
            message="The egress credential key version is unavailable.",
        )
    raw = decrypt_project_secret(
        ciphertext=secret.encrypted_value,
        value_nonce=secret.value_nonce,
        wrapped_data_key=secret.wrapped_data_key,
        key_nonce=secret.key_nonce,
        organization_id=secret.organization_id,
        project_id=secret.project_id,
        secret_id=secret.id,
        name=secret.name,
        version=secret.version,
    )
    try:
        authorization = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ApiError(
            status_code=409,
            code="EGRESS_CREDENTIAL_INVALID",
            message="The egress credential is not valid UTF-8.",
        ) from exc
    if (
        not authorization
        or len(authorization) > 8192
        or "\r" in authorization
        or "\n" in authorization
    ):
        raise ApiError(
            status_code=409,
            code="EGRESS_CREDENTIAL_INVALID",
            message="The egress credential is not a safe Authorization value.",
        )
    expires_at = min(
        lease.expires_at,
        now + timedelta(seconds=settings.worker_secret_envelope_seconds),
    )
    plaintext = bytearray(
        json.dumps(
            {
                "schema_version": "rdc.egress-credential/v1",
                "lease_id": str(lease.id),
                "run_id": str(run.id),
                "policy_binding_digest": payload.policy_binding_digest,
                "expires_at": expires_at.isoformat(),
                "authorization": authorization,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    aad = worker_egress_credential_aad(
        lease_id=str(lease.id),
        worker_id=str(worker.id),
        run_id=str(run.id),
        policy_binding_digest=payload.policy_binding_digest,
    )
    try:
        envelope = encrypt_secret_payload_for_worker(
            bytes(plaintext), worker_public_key=worker_public_key, aad=aad
        )
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0
        authorization = ""
    grant = SecretInjectionGrant(
        worker_id=worker.id,
        lease_id=lease.id,
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        run_id=run.id,
        request_fingerprint=fingerprint,
        secret_names=[secret.name],
        environment=secret.environment,
        algorithm=envelope.algorithm,
        ephemeral_public_key=envelope.ephemeral_public_key,
        nonce=envelope.nonce,
        ciphertext=envelope.ciphertext,
        worker_public_key_digest=envelope.worker_public_key_digest,
        status="ISSUED",
        issued_at=now,
        expires_at=expires_at,
    )
    secret.last_used_at = now
    session.add(grant)
    await session.flush()
    await append_audit_event(
        session,
        organization_id=lease.organization_id,
        project_id=lease.project_id,
        actor_type="worker",
        actor_id=str(worker.id),
        action="execution.egress_credential_envelope.issued",
        resource_type="secret_injection_grant",
        resource_id=str(grant.id),
        request_id=request_id,
        details={
            "run_id": str(run.id),
            "policy_binding_digest": payload.policy_binding_digest,
            "expires_at": expires_at.isoformat(),
        },
    )
    return EgressCredentialEnvelopeResponse(
        grant_id=grant.id,
        algorithm=grant.algorithm,
        ephemeral_public_key_b64=base64.b64encode(grant.ephemeral_public_key).decode(
            "ascii"
        ),
        nonce_b64=base64.b64encode(grant.nonce).decode("ascii"),
        ciphertext_b64=base64.b64encode(grant.ciphertext).decode("ascii"),
        expires_at=grant.expires_at,
        policy_binding_digest=payload.policy_binding_digest,
    )


async def list_project_leases(
    session: AsyncSession,
    *,
    project_id: UUID,
    cursor: CursorPosition | None,
    limit: int,
) -> tuple[list[ExecutionLease], bool]:
    statement = select(ExecutionLease).where(ExecutionLease.project_id == project_id)
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
