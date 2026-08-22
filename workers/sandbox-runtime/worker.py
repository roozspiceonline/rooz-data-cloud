from __future__ import annotations

import hashlib
import json
import signal
import time
import zipfile
from pathlib import Path
from typing import Any

from browser_egress_policy import BrowserEgressPolicy
from browser_executor import (
    BrowserRuntimeError,
    run_browser_live_navigation,
    run_browser_self_test,
)
from browser_navigation_contract import (
    BrowserNavigationContractError,
    validate_browser_navigation_plan,
)
from browser_policy import (
    BrowserPolicy,
    BrowserPolicyError,
    validate_browser_plan,
)
from build_executor import LocalArtifact, build_agent
from config import SandboxWorkerConfig
from dataset_protocol import DatasetProtocolError, validate_dataset_append
from egress_broker import broker_web_requests
from egress_policy import EgressPolicy, EgressPolicyError
from io_utils import (
    cleanup_tree,
    download_file,
    private_temp_dir,
    sha256_file,
    upload_file,
)
from kv_worker_protocol import (
    KVWorkerBoundaryError,
    validate_kv_read_request,
    validate_kv_read_result,
    validate_kv_worker_output,
)
from policy import SandboxPolicyError, verify_host
from queue_worker_protocol import (
    QueueWorkerBoundaryError,
    queue_browser_agent_result,
    queue_browser_navigation_plan,
    queue_completion_payload,
    queue_dataset_idempotency_key,
    queue_http_agent_result,
    queue_http_fetch_envelope,
    queue_kv_idempotency_key,
    validate_queue_claim_result,
)
from rdc_worker_client import (
    RdcWorkerClient,
    WorkerProtocolError,
    decrypt_secret_envelope,
    generate_worker_key_pair,
)
from run_executor import cancel_run, load_image, run_agent
from web_fetch_contract import (
    WebFetchContractError,
    phase1j_broker_adapter,
    phase1j_broker_result_adapter,
)
from worker_recovery import (
    LeaseWatchdog,
    force_startup_cleanup,
)


class WorkerShutdown(BaseException):
    """Unwind active work immediately when the supervisor requests stop."""


def _data(response: dict[str, Any]) -> dict[str, Any]:
    value = response.get("data")
    if not isinstance(value, dict):
        raise SandboxPolicyError("Worker protocol response is missing data.")
    return value


def _extract_zip(archive: Path, destination: Path) -> None:
    with zipfile.ZipFile(archive) as package:
        for info in package.infolist():
            name = info.filename.replace("\\", "/")
            parts = [part for part in name.split("/") if part not in {"", "."}]
            if name.startswith("/") or ".." in parts:
                raise SandboxPolicyError("Source archive contains an unsafe path.")
        package.extractall(destination)


def _canonical_digest(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _worker_egress_policy(
    config: SandboxWorkerConfig,
) -> EgressPolicy | None:
    if not config.web_egress_enabled:
        return None
    return EgressPolicy.create(
        config.web_egress_allowed_hosts,
        max_requests=config.web_egress_max_requests,
        max_response_bytes=config.web_egress_max_response_bytes,
        max_total_bytes=config.web_egress_max_total_bytes,
        max_redirects=config.web_egress_max_redirects,
        connect_timeout_seconds=config.web_egress_connect_timeout_seconds,
        request_timeout_seconds=config.web_egress_request_timeout_seconds,
    )


def _worker_browser_policy(
    config: SandboxWorkerConfig,
) -> BrowserPolicy | None:
    if not config.browser_enabled:
        return None
    return BrowserPolicy.create(
        enabled=True,
        allowed_hosts=config.web_egress_allowed_hosts,
        max_pages=config.browser_max_pages,
        max_actions=config.browser_max_actions,
        navigation_timeout_seconds=(
            config.browser_navigation_timeout_seconds
        ),
        max_dom_bytes=config.browser_max_dom_bytes,
        max_screenshot_bytes=config.browser_max_screenshot_bytes,
    )


def _require_live_browser_navigation_receipt(
    input_reference: dict[str, object],
    *,
    egress_policy: EgressPolicy,
    browser_policy: BrowserPolicy,
    live_navigation_enabled: bool,
) -> None:
    if not live_navigation_enabled:
        raise SandboxPolicyError("Worker live browser navigation gate is disabled.")
    navigation = input_reference.get("browser_navigation")
    receipt = input_reference.get("browser_navigation_receipt")
    stored_policy = input_reference.get("browser_policy")
    stored_policy_digest = input_reference.get("browser_policy_digest")
    stored_egress_policy = input_reference.get("browser_egress_policy")
    stored_egress_digest = input_reference.get(
        "browser_egress_policy_digest"
    )
    if (
        not isinstance(navigation, dict)
        or not isinstance(receipt, dict)
        or not isinstance(stored_policy, dict)
        or not isinstance(stored_policy_digest, str)
        or not isinstance(stored_egress_policy, dict)
        or not isinstance(stored_egress_digest, str)
    ):
        raise SandboxPolicyError(
            "Phase 1M browser navigation claim lacks immutable receipts."
        )
    if _canonical_digest(stored_policy) != browser_policy.digest:
        raise SandboxPolicyError(
            "Phase 1M stored browser policy does not match worker policy."
        )
    if stored_policy_digest != browser_policy.digest:
        raise SandboxPolicyError(
            "Phase 1M browser policy digest does not match worker policy."
        )
    browser_egress_policy = BrowserEgressPolicy.create(
        egress_policy
    )
    if stored_egress_policy != browser_egress_policy.as_dict():
        raise SandboxPolicyError(
            "Phase 1M stored browser egress policy does not match worker policy."
        )
    if stored_egress_digest != browser_egress_policy.digest:
        raise SandboxPolicyError(
            "Phase 1M browser egress policy digest does not match worker policy."
        )

    try:
        normalized = validate_browser_navigation_plan(
            navigation,
            policy=browser_policy,
        )
    except BrowserNavigationContractError as exc:
        raise SandboxPolicyError(
            "Phase 1M navigation failed independent worker validation."
        ) from exc

    expected_receipt = {
        "schema_version": "rdc.browser-navigation-receipt/v1",
        "request_schema_version": "rdc.browser/v2",
        "request_digest": normalized["request_digest"],
        "browser_policy_digest": browser_policy.digest,
        "browser_egress_policy_digest": browser_egress_policy.digest,
        "execution_enabled": True,
        "dispatch_enabled": True,
        "browser_network": "none",
        "browser_egress_gateway_required": True,
    }
    if receipt != expected_receipt:
        raise SandboxPolicyError(
            "Phase 1M browser navigation receipt does not match the Run intent."
        )
    return None



def _require_canary_activation(
    payload: dict[str, Any],
    *,
    worker_name: str,
    egress_policy: EgressPolicy | None,
    browser_policy: BrowserPolicy | None,
    browser_live_navigation_enabled: bool,
    dataset_writes_enabled: bool,
    key_value_store_enabled: bool,
    request_queue_enabled: bool,
    request_queue_http_enabled: bool,
    request_queue_browser_enabled: bool,
    request_queue_dataset_enabled: bool = False,
    request_queue_key_value_store_enabled: bool = False,
) -> dict[str, object]:
    activation = payload.get("activation")
    sandbox = payload.get("sandbox")
    if not isinstance(activation, dict) or not isinstance(sandbox, dict):
        raise SandboxPolicyError(
            "The control plane did not provide a canary activation receipt."
        )
    if activation.get("mode") != "canary":
        raise SandboxPolicyError("Only canary activation is accepted.")
    if activation.get("worker_name") != worker_name:
        raise SandboxPolicyError(
            "Canary activation is bound to a different worker identity."
        )
    if activation.get("agent_version_id") != payload.get("agent_version_id"):
        raise SandboxPolicyError(
            "Canary activation does not match the immutable Agent version."
        )
    if activation.get("max_concurrency") != 1:
        raise SandboxPolicyError(
            "Canary activation requires single-concurrency execution."
        )
    if activation.get("no_secrets") is not True:
        raise SandboxPolicyError(
            "Canary execution cannot inject project secrets."
        )
    if activation.get("attestation_digest") != sandbox.get(
        "attestation_digest"
    ):
        raise SandboxPolicyError(
            "Canary activation does not match the sandbox attestation."
        )
    if activation.get("sandbox_policy_digest") != _canonical_digest(sandbox):
        raise SandboxPolicyError(
            "Canary activation does not match the sandbox policy digest."
        )

    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        raise SandboxPolicyError("Canary claim is missing the Agent manifest.")
    if manifest.get("secrets"):
        raise SandboxPolicyError(
            "Canary Agent manifests cannot declare secrets."
        )

    capabilities = manifest.get("capabilities")
    if not isinstance(capabilities, dict):
        raise SandboxPolicyError("Canary Agent capabilities are missing.")
    browser = capabilities.get("browser")
    if not isinstance(browser, bool):
        raise SandboxPolicyError(
            "Canary Agent browser capability is invalid."
        )
    dataset = capabilities.get("dataset")
    if not isinstance(dataset, bool):
        raise SandboxPolicyError(
            "Canary Agent Dataset capability is invalid."
        )
    key_value_store = capabilities.get("keyValueStore")
    if not isinstance(key_value_store, bool):
        raise SandboxPolicyError(
            "Canary Agent Key-Value Store capability is invalid."
        )
    request_queue = capabilities.get("requestQueue")
    if not isinstance(request_queue, bool):
        raise SandboxPolicyError(
            "Canary Agent Request Queue capability is invalid."
        )
    kv_runtime_enabled = (
        key_value_store and payload.get("work_kind") == "RUN_START"
    )
    queue_runtime_enabled = (
        request_queue and payload.get("work_kind") == "RUN_START"
    )
    queue_dataset_runtime_enabled = queue_runtime_enabled and dataset
    queue_kv_runtime_enabled = queue_runtime_enabled and kv_runtime_enabled
    network = capabilities.get("network")
    queue_browser_runtime_enabled = (
        queue_runtime_enabled and network == "web-egress" and browser
    )
    queue_http_runtime_enabled = (
        queue_runtime_enabled
        and network == "web-egress"
        and not browser
    )
    if dataset and kv_runtime_enabled:
        raise SandboxPolicyError(
            "Canary Dataset and Key-Value Store cannot be combined."
        )
    if browser and kv_runtime_enabled and not queue_kv_runtime_enabled:
        raise SandboxPolicyError(
            "Canary browser and Key-Value Store cannot be combined."
        )
    if queue_kv_runtime_enabled and not request_queue_key_value_store_enabled:
        raise SandboxPolicyError(
            "Worker Queue Key-Value Store composition gate is disabled."
        )
    if (
        activation.get("request_queue_key_value_store_enabled")
        is not queue_kv_runtime_enabled
    ):
        raise SandboxPolicyError(
            "Queue Key-Value Store activation does not match the manifest."
        )
    if queue_dataset_runtime_enabled and not request_queue_dataset_enabled:
        raise SandboxPolicyError(
            "Worker Queue Dataset composition gate is disabled."
        )
    if (
        activation.get("request_queue_dataset_enabled")
        is not queue_dataset_runtime_enabled
    ):
        raise SandboxPolicyError(
            "Queue Dataset activation does not match the manifest."
        )
    if activation.get("dataset_write_enabled") is not dataset:
        raise SandboxPolicyError(
            "Canary Dataset activation receipt does not match manifest."
        )
    if dataset:
        if (
            payload.get("work_kind") != "RUN_START"
            or (browser and not queue_dataset_runtime_enabled)
            or not dataset_writes_enabled
        ):
            raise SandboxPolicyError(
                "Canary Dataset writes are not enabled for this Run."
            )
        expected_dataset_capability = {
            "schema_version": (
                "rdc.dataset-worker-capability/v2"
                if queue_dataset_runtime_enabled
                else "rdc.dataset-worker-capability/v1"
            ),
            "append_schema_version": "rdc.dataset-append/v1",
            "run_id": str(payload.get("run_id", "")),
            "agent_version_id": str(payload.get("agent_version_id", "")),
            "worker_name": worker_name,
            "dataset_name": "default",
            "max_items_per_append": 100,
            "max_item_bytes": 65_536,
            "max_batch_bytes": 262_144,
            "max_dataset_items": 100_000,
            "max_dataset_bytes": 268_435_456,
            "enabled": True,
        }
        if queue_dataset_runtime_enabled:
            input_reference = payload.get("input_reference")
            binding = (
                input_reference.get("request_queue")
                if isinstance(input_reference, dict)
                else None
            )
            if not isinstance(binding, dict) or not isinstance(
                binding.get("queue_id"), str
            ):
                raise SandboxPolicyError(
                    "Queue Dataset binding is invalid."
                )
            expected_dataset_capability.update(
                {
                    "queue_id": binding["queue_id"],
                    "completion_order": "dataset-before-queue-handled",
                }
            )
        if payload.get("dataset_append_capability") != (
            expected_dataset_capability
        ):
            raise SandboxPolicyError(
                "Canary Dataset capability receipt is invalid."
            )
    elif payload.get("dataset_append_capability") is not None:
        raise SandboxPolicyError(
            "Dataset-disabled Run cannot carry a Dataset capability."
        )

    if activation.get("key_value_store_enabled") is not kv_runtime_enabled:
        raise SandboxPolicyError(
            "Canary Key-Value Store activation does not match manifest."
        )
    if kv_runtime_enabled:
        if not key_value_store_enabled:
            raise SandboxPolicyError(
                "Worker Key-Value Store gate is disabled."
            )
        input_reference = payload.get("input_reference")
        if not isinstance(input_reference, dict):
            raise SandboxPolicyError("KV Run lacks input reference.")
        input_value = input_reference.get("value")
        if not isinstance(input_value, dict) or "_rdc_kv" in input_value:
            raise SandboxPolicyError("KV Run input is invalid.")
        read_request = input_value.get("_rdc_kv_read")
        read_digest = None
        if read_request is not None:
            try:
                read_value = validate_kv_read_request(read_request)
                read_digest = str(read_value["request_digest"])
            except KVWorkerBoundaryError as exc:
                raise SandboxPolicyError(
                    "KV read request is invalid."
                ) from exc
        expected_kv_capability = {
            "schema_version": (
                "rdc.kv-worker-capability/v2"
                if queue_kv_runtime_enabled
                else "rdc.kv-worker-capability/v1"
            ),
            "write_schema_version": "rdc.kv-write/v1",
            "read_schema_version": "rdc.kv-worker-read/v1",
            "output_schema_version": "rdc.kv-worker-output/v1",
            "run_id": str(payload.get("run_id", "")),
            "agent_version_id": str(payload.get("agent_version_id", "")),
            "worker_name": worker_name,
            "store_name": "default",
            "read_request_digest": read_digest,
            "max_read_keys": 16,
            "max_read_total_bytes": 262_144,
            "max_mutations": 4,
            "max_value_bytes": 1_048_576,
            "post_run_mutations_only": True,
            "direct_database_access": False,
            "direct_object_storage_access": False,
            "enabled": True,
        }
        if queue_kv_runtime_enabled:
            binding = input_reference.get("request_queue")
            if not isinstance(binding, dict) or not isinstance(
                binding.get("queue_id"), str
            ):
                raise SandboxPolicyError("Queue KV binding is invalid.")
            expected_kv_capability.update(
                {
                    "queue_id": binding["queue_id"],
                    "mutation_idempotency_scope": "queue-request-index",
                    "completion_order": "kv-before-queue-handled",
                }
            )
        if payload.get("key_value_store_capability") != expected_kv_capability:
            raise SandboxPolicyError(
                "Canary Key-Value Store capability receipt is invalid."
            )
    elif payload.get("key_value_store_capability") is not None:
        raise SandboxPolicyError(
            "KV-disabled work cannot carry a Key-Value Store capability."
        )

    if activation.get("request_queue_enabled") is not queue_runtime_enabled:
        raise SandboxPolicyError(
            "Canary Request Queue activation does not match manifest."
        )
    if (
        activation.get("request_queue_http_enabled")
        is not queue_http_runtime_enabled
    ):
        raise SandboxPolicyError(
            "Queue HTTP activation does not match the manifest."
        )
    if (
        activation.get("request_queue_browser_enabled")
        is not queue_browser_runtime_enabled
    ):
        raise SandboxPolicyError(
            "Queue browser activation does not match the manifest."
        )
    if queue_runtime_enabled:
        if not request_queue_enabled:
            raise SandboxPolicyError("Worker Request Queue gate is disabled.")
        if queue_http_runtime_enabled and not request_queue_http_enabled:
            raise SandboxPolicyError(
                "Worker Queue HTTP acquisition gate is disabled."
            )
        if queue_browser_runtime_enabled and not request_queue_browser_enabled:
            raise SandboxPolicyError(
                "Worker Queue browser acquisition gate is disabled."
            )
        input_reference = payload.get("input_reference")
        if not isinstance(input_reference, dict):
            raise SandboxPolicyError("Queue-bound Run lacks input reference.")
        binding = input_reference.get("request_queue")
        receipt = input_reference.get("queue_binding_receipt")
        if (
            not isinstance(binding, dict)
            or set(binding) != {"schema_version", "queue_id"}
            or binding.get("schema_version") != "rdc.run-queue/v1"
            or not isinstance(binding.get("queue_id"), str)
        ):
            raise SandboxPolicyError("Queue-bound Run binding is invalid.")
        normalized_binding = {
            "schema_version": "rdc.run-queue/v1",
            "queue_id": binding["queue_id"],
        }
        if queue_browser_runtime_enabled:
            if egress_policy is None or browser_policy is None:
                raise SandboxPolicyError(
                    "Queue browser policy is unavailable."
                )
            browser_egress_policy = BrowserEgressPolicy.create(egress_policy)
            stored_browser_policy = input_reference.get(
                "request_queue_browser_policy"
            )
            stored_browser_digest = input_reference.get(
                "request_queue_browser_policy_digest"
            )
            stored_browser_egress_policy = input_reference.get(
                "request_queue_browser_egress_policy"
            )
            stored_browser_egress_digest = input_reference.get(
                "request_queue_browser_egress_policy_digest"
            )
            if (
                stored_browser_policy != browser_policy.as_dict()
                or stored_browser_digest != browser_policy.digest
                or stored_browser_egress_policy
                != browser_egress_policy.as_dict()
                or stored_browser_egress_digest
                != browser_egress_policy.digest
            ):
                raise SandboxPolicyError(
                    "Queue browser receipt does not match worker policy."
                )
            expected_receipt = {
                "schema_version": "rdc.request-queue-binding-receipt/v3",
                "binding_digest": _canonical_digest(normalized_binding),
                "queue_id": binding["queue_id"],
                "agent_version_id": str(payload.get("agent_version_id", "")),
                "acquisition_mode": "controlled-browser",
                "browser_policy_digest": browser_policy.digest,
                "browser_egress_policy_digest": browser_egress_policy.digest,
                "dispatch_enabled": True,
                "agent_container_network": "none",
                "direct_database_access": False,
                "direct_object_storage_access": False,
            }
        elif queue_http_runtime_enabled:
            stored_egress_policy = input_reference.get(
                "request_queue_egress_policy"
            )
            stored_egress_digest = input_reference.get(
                "request_queue_egress_policy_digest"
            )
            if (
                egress_policy is None
                or not isinstance(stored_egress_policy, dict)
                or stored_egress_policy != egress_policy.as_dict()
                or stored_egress_digest != egress_policy.digest
            ):
                raise SandboxPolicyError(
                    "Queue HTTP egress receipt does not match worker policy."
                )
            expected_receipt = {
                "schema_version": "rdc.request-queue-binding-receipt/v2",
                "binding_digest": _canonical_digest(normalized_binding),
                "queue_id": binding["queue_id"],
                "agent_version_id": str(payload.get("agent_version_id", "")),
                "acquisition_mode": "brokered-http",
                "egress_policy_digest": egress_policy.digest,
                "dispatch_enabled": True,
                "agent_container_network": "none",
                "direct_database_access": False,
                "direct_object_storage_access": False,
            }
        else:
            expected_receipt = {
                "schema_version": "rdc.request-queue-binding-receipt/v1",
                "binding_digest": _canonical_digest(normalized_binding),
                "queue_id": binding["queue_id"],
                "agent_version_id": str(payload.get("agent_version_id", "")),
                "direct_database_access": False,
                "direct_object_storage_access": False,
            }
        if receipt != expected_receipt:
            raise SandboxPolicyError(
                "Queue-bound Run binding receipt is invalid."
            )
        if queue_dataset_runtime_enabled:
            expected_composition_receipt = {
                "schema_version": "rdc.request-queue-dataset-receipt/v1",
                "queue_id": binding["queue_id"],
                "agent_version_id": str(payload.get("agent_version_id", "")),
                "queue_binding_receipt_digest": _canonical_digest(receipt),
                "dataset_name": "default",
                "dispatch_enabled": True,
                "completion_order": "dataset-before-queue-handled",
                "agent_container_network": "none",
                "direct_database_access": False,
                "direct_object_storage_access": False,
            }
            if (
                input_reference.get("request_queue_dataset_receipt")
                != expected_composition_receipt
            ):
                raise SandboxPolicyError(
                    "Queue Dataset composition receipt is invalid."
                )
        elif input_reference.get("request_queue_dataset_receipt") is not None:
            raise SandboxPolicyError(
                "Dataset-disabled Queue work cannot carry a composition receipt."
            )
        if queue_kv_runtime_enabled:
            input_value = input_reference.get("value")
            read_request = (
                input_value.get("_rdc_kv_read")
                if isinstance(input_value, dict)
                else None
            )
            read_digest = None
            if read_request is not None:
                try:
                    read_digest = str(
                        validate_kv_read_request(read_request)[
                            "request_digest"
                        ]
                    )
                except KVWorkerBoundaryError as exc:
                    raise SandboxPolicyError(
                        "Queue KV read request is invalid."
                    ) from exc
            expected_composition_receipt = {
                "schema_version": (
                    "rdc.request-queue-key-value-store-receipt/v1"
                ),
                "queue_id": binding["queue_id"],
                "agent_version_id": str(payload.get("agent_version_id", "")),
                "queue_binding_receipt_digest": _canonical_digest(receipt),
                "store_name": "default",
                "read_request_digest": read_digest,
                "mutation_idempotency_scope": "queue-request-index",
                "dispatch_enabled": True,
                "completion_order": "kv-before-queue-handled",
                "agent_container_network": "none",
                "direct_database_access": False,
                "direct_object_storage_access": False,
            }
            if (
                input_reference.get(
                    "request_queue_key_value_store_receipt"
                )
                != expected_composition_receipt
            ):
                raise SandboxPolicyError(
                    "Queue Key-Value Store composition receipt is invalid."
                )
        elif input_reference.get(
            "request_queue_key_value_store_receipt"
        ) is not None:
            raise SandboxPolicyError(
                "KV-disabled Queue work cannot carry a composition receipt."
            )
        expected_queue_capability = {
            "schema_version": (
                "rdc.request-queue-worker-capability/v5"
                if queue_kv_runtime_enabled
                else (
                    "rdc.request-queue-worker-capability/v4"
                    if queue_dataset_runtime_enabled
                    else (
                        "rdc.request-queue-worker-capability/v3"
                        if queue_browser_runtime_enabled
                        else (
                            "rdc.request-queue-worker-capability/v2"
                            if queue_http_runtime_enabled
                            else "rdc.request-queue-worker-capability/v1"
                        )
                    )
                )
            ),
            "queue_id": binding["queue_id"],
            "run_id": str(payload.get("run_id", "")),
            "agent_version_id": str(payload.get("agent_version_id", "")),
            "worker_name": worker_name,
            "max_claims_per_run": 1,
            "claim_completion_required": True,
            "direct_database_access": False,
            "direct_object_storage_access": False,
            "enabled": True,
        }
        if queue_browser_runtime_enabled:
            expected_queue_capability.update(
                {
                    "acquisition_mode": "controlled-browser",
                    "browser_policy_digest": browser_policy.digest,
                    "browser_egress_policy_digest": (
                        browser_egress_policy.digest
                    ),
                    "agent_container_network": "none",
                }
            )
        elif queue_http_runtime_enabled:
            expected_queue_capability.update(
                {
                    "acquisition_mode": "brokered-http",
                    "egress_policy_digest": egress_policy.digest,
                    "agent_container_network": "none",
                }
            )
        if queue_dataset_runtime_enabled:
            expected_queue_capability.update(
                {
                    "dataset_write_enabled": True,
                    "dataset_name": "default",
                    "completion_order": "dataset-before-queue-handled",
                }
            )
        if queue_kv_runtime_enabled:
            expected_queue_capability.update(
                {
                    "key_value_store_enabled": True,
                    "store_name": "default",
                    "mutation_idempotency_scope": "queue-request-index",
                    "completion_order": "kv-before-queue-handled",
                }
            )
        if payload.get("request_queue_capability") != expected_queue_capability:
            raise SandboxPolicyError(
                "Canary Request Queue capability receipt is invalid."
            )
    elif payload.get("request_queue_capability") is not None:
        raise SandboxPolicyError(
            "Queue-disabled work cannot carry a Request Queue capability."
        )

    profile = activation.get("capability_profile")
    egress_digest = activation.get("egress_policy_digest")
    browser_digest = activation.get("browser_policy_digest")

    if profile == "offline-minimal":
        if network != "none":
            raise SandboxPolicyError(
                "Offline-minimal activation requires network=none."
            )
        if egress_digest is not None:
            raise SandboxPolicyError(
                "Offline-minimal activation cannot carry an egress digest."
            )
        if queue_http_runtime_enabled:
            raise SandboxPolicyError(
                "Queue HTTP acquisition cannot use the offline profile."
            )
    elif profile == "brokered-web-egress":
        if browser is not False:
            raise SandboxPolicyError(
                "Brokered web-egress activation cannot enable browser."
            )
        if network != "web-egress":
            raise SandboxPolicyError(
                "Brokered web-egress activation requires network=web-egress."
            )
        if egress_policy is None:
            raise SandboxPolicyError(
                "Worker web-egress policy is disabled or unavailable."
            )
        if egress_digest != egress_policy.digest:
            raise SandboxPolicyError(
                "Canary activation egress-policy digest does not match "
                "the worker policy."
            )
        if browser_digest is not None:
            raise SandboxPolicyError(
                "Brokered web-egress activation cannot carry browser policy."
            )
        if queue_runtime_enabled and not queue_http_runtime_enabled:
            raise SandboxPolicyError(
                "Brokered Queue Runs require Queue HTTP acquisition."
            )
    elif profile == "controlled-browser":
        if payload.get("work_kind") != "RUN_START":
            raise SandboxPolicyError(
                "Controlled-browser activation is valid only for RUN_START."
            )
        if browser is not True or network != "web-egress":
            raise SandboxPolicyError(
                "Controlled browser requires browser=true and web-egress."
            )
        if egress_policy is None or browser_policy is None:
            raise SandboxPolicyError(
                "Worker browser or web-egress policy is unavailable."
            )
        if egress_digest != egress_policy.digest:
            raise SandboxPolicyError(
                "Controlled-browser egress-policy digest mismatch."
            )
        if browser_digest != browser_policy.digest:
            raise SandboxPolicyError(
                "Controlled-browser policy digest mismatch."
            )

        input_reference = payload.get("input_reference")
        if not isinstance(input_reference, dict):
            raise SandboxPolicyError(
                "Controlled-browser claim lacks an input reference."
            )
        if (
            not queue_browser_runtime_enabled
            and "browser_navigation" in input_reference
        ):
            _require_live_browser_navigation_receipt(
                input_reference,
                egress_policy=egress_policy,
                browser_policy=browser_policy,
                live_navigation_enabled=browser_live_navigation_enabled,
            )
        elif not queue_browser_runtime_enabled:
            browser_plan = input_reference.get("browser")
            stored_policy = input_reference.get("browser_policy")
            stored_digest = input_reference.get("browser_policy_digest")
            if not isinstance(stored_policy, dict):
                raise SandboxPolicyError(
                    "Controlled-browser claim lacks a policy receipt."
                )
            if _canonical_digest(stored_policy) != browser_policy.digest:
                raise SandboxPolicyError(
                    "Stored browser policy receipt does not match worker policy."
                )
            if stored_digest != browser_policy.digest:
                raise SandboxPolicyError(
                    "Stored browser policy digest does not match worker policy."
                )
            try:
                validate_browser_plan(browser_plan, policy=browser_policy)
            except BrowserPolicyError as exc:
                raise SandboxPolicyError(
                    "Browser plan failed independent worker validation."
                ) from exc
    else:
        raise SandboxPolicyError(
            "Canary activation capability profile is unsupported."
        )

    return {str(key): value for key, value in activation.items()}


def _queue_browser_acquire(
    *,
    config: SandboxWorkerConfig,
    payload: dict[str, Any],
    workspace: Path,
    queue_claim: dict[str, object],
    egress_policy: EgressPolicy,
    browser_policy: BrowserPolicy,
) -> tuple[dict[str, object], dict[str, object]]:
    navigation_plan = queue_browser_navigation_plan(
        queue_claim,
        max_dom_bytes=browser_policy.max_dom_bytes,
    )
    normalized_navigation = validate_browser_navigation_plan(
        navigation_plan,
        policy=browser_policy,
    )
    request_digest = normalized_navigation.get("request_digest")
    if not isinstance(request_digest, str):
        raise QueueWorkerBoundaryError(
            "Queue browser request digest is invalid."
        )
    browser_egress_policy = BrowserEgressPolicy.create(egress_policy)
    browser_output, _browser_log = run_browser_live_navigation(
        config=config,
        run_id=str(payload["run_id"]),
        workspace=workspace,
        navigation_plan=navigation_plan,
        browser_policy_digest=browser_policy.digest,
        browser_egress_policy=browser_egress_policy,
        request_digest=request_digest,
        max_screenshot_bytes=browser_policy.max_screenshot_bytes,
        navigation_timeout_seconds=(
            browser_policy.navigation_timeout_seconds
        ),
        runtime_timeout_seconds=int(
            payload["sandbox"]["timeout_seconds"]
        ),
    )
    if (
        not browser_output.is_file()
        or browser_output.stat().st_size > 16_777_216
    ):
        raise QueueWorkerBoundaryError(
            "Queue browser result is outside the worker limit."
        )
    decoded_browser = json.loads(browser_output.read_text(encoding="utf-8"))
    agent_result = queue_browser_agent_result(
        queue_claim,
        navigation_plan,
        decoded_browser,
    )
    provenance = {
        "acquisition_mode": "controlled-browser",
        "request_digest": request_digest,
        "browser_policy_digest": browser_policy.digest,
        "browser_egress_policy_digest": browser_egress_policy.digest,
        "browser_network": "none",
        "gateway_transport": "unix",
        "agent_container_network": "none",
    }
    return agent_result, provenance


def _upload_artifacts(
    client: RdcWorkerClient,
    *,
    lease_id: str,
    lease_token: str,
    artifacts: list[LocalArtifact],
) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for artifact in artifacts:
        grant = _data(
            client.artifact_upload(
                lease_id,
                lease_token,
                {
                    "kind": artifact.kind,
                    "digest_algorithm": "sha256",
                    "digest": artifact.digest,
                    "media_type": artifact.media_type,
                    "size_bytes": artifact.size_bytes,
                },
            )
        )
        upload_file(str(grant["url"]), dict(grant["headers"]), artifact.path)
        result.append(
            {
                "kind": artifact.kind,
                "digest_algorithm": "sha256",
                "digest": artifact.digest,
                "object_key": grant["object_key"],
                "media_type": artifact.media_type,
                "size_bytes": artifact.size_bytes,
                "status": "AVAILABLE",
                "scan_status": artifact.scan_status,
                "provenance": artifact.provenance,
            }
        )
    return result


def _build(
    client: RdcWorkerClient,
    config: SandboxWorkerConfig,
    claim: dict[str, Any],
    *,
    worker_name: str,
) -> None:
    lease = _data(claim)
    payload = dict(lease["payload"])
    lease_id = str(lease["id"])
    token = str(lease["lease_token"])
    if (
        payload.get("execution_enabled") is not True
        or not isinstance(payload.get("sandbox"), dict)
    ):
        client.complete(
            lease_id,
            token,
            {
                "outcome": "FAILED",
                "retryable": False,
                "error_code": "SANDBOX_POLICY_DENIED",
                "error_summary": "The control plane did not authorize sandbox execution.",
            },
        )
        return
    workspace = private_temp_dir(config.workspace_root, "build-")
    try:
        egress_policy = _worker_egress_policy(config)
        browser_policy = _worker_browser_policy(config)
        activation = _require_canary_activation(
            payload,
            worker_name=worker_name,
            egress_policy=egress_policy,
            browser_policy=browser_policy,
            browser_live_navigation_enabled=(
                config.browser_live_navigation_enabled
            ),
            dataset_writes_enabled=config.dataset_writes_enabled,
            key_value_store_enabled=config.key_value_store_enabled,
            request_queue_enabled=config.request_queue_enabled,
            request_queue_http_enabled=config.request_queue_http_enabled,
            request_queue_browser_enabled=(
                config.request_queue_browser_enabled
            ),
            request_queue_dataset_enabled=(
                config.request_queue_dataset_enabled
            ),
            request_queue_key_value_store_enabled=(
                config.request_queue_key_value_store_enabled
            ),
        )
        source_zip = workspace / "source.zip"
        source_dir = workspace / "source"
        source_dir.mkdir(mode=0o700)
        grant = _data(client.source_download(lease_id, token))
        source_meta = dict(payload["source"])
        download_file(str(grant["url"]), source_zip, max_bytes=int(source_meta["size_bytes"]))
        digest, size = sha256_file(source_zip)
        if digest != source_meta["sha256_digest"] or size != int(source_meta["size_bytes"]):
            raise SandboxPolicyError("Downloaded source digest or size does not match the claim.")
        _extract_zip(source_zip, source_dir)
        client.status(lease_id, token, status="RUNNING")
        artifacts = build_agent(
            config=config,
            source_dir=source_dir,
            workspace=workspace,
            build_id=str(payload["build_id"]),
            agent_version_id=str(payload["agent_version_id"]),
            source_sha256=str(source_meta["sha256_digest"]),
            activation=activation,
            timeout_seconds=int(payload["sandbox"]["timeout_seconds"]),
        )
        registrations = _upload_artifacts(
            client,
            lease_id=lease_id,
            lease_token=token,
            artifacts=artifacts,
        )
        client.complete(
            lease_id,
            token,
            {"outcome": "SUCCEEDED", "retryable": False, "artifacts": registrations},
        )
    except Exception as exc:
        client.complete(
            lease_id,
            token,
            {
                "outcome": "FAILED",
                "retryable": False,
                "error_code": "SANDBOX_BUILD_FAILED",
                "error_summary": str(exc)[:2000],
            },
        )
    finally:
        cleanup_tree(workspace)


def _run(
    client: RdcWorkerClient,
    config: SandboxWorkerConfig,
    claim: dict[str, Any],
    *,
    worker_name: str,
) -> None:
    lease = _data(claim)
    payload = dict(lease["payload"])
    lease_id = str(lease["id"])
    token = str(lease["lease_token"])
    if payload.get("work_kind") == "RUN_CANCEL":
        cancel_run(config=config, run_id=str(payload["run_id"]))
        client.complete(lease_id, token, {"outcome": "ABORTED", "retryable": False})
        return
    if (
        payload.get("execution_enabled") is not True
        or not isinstance(payload.get("sandbox"), dict)
    ):
        client.complete(
            lease_id,
            token,
            {
                "outcome": "FAILED",
                "retryable": False,
                "error_code": "SANDBOX_POLICY_DENIED",
                "error_summary": (
                    "The control plane did not authorize sandbox execution."
                ),
            },
        )
        return
    workspace = private_temp_dir(config.workspace_root, "run-")
    try:
        egress_policy = _worker_egress_policy(config)
        browser_policy = _worker_browser_policy(config)
        activation = _require_canary_activation(
            payload,
            worker_name=worker_name,
            egress_policy=egress_policy,
            browser_policy=browser_policy,
            browser_live_navigation_enabled=(
                config.browser_live_navigation_enabled
            ),
            dataset_writes_enabled=config.dataset_writes_enabled,
            key_value_store_enabled=config.key_value_store_enabled,
            request_queue_enabled=config.request_queue_enabled,
            request_queue_http_enabled=config.request_queue_http_enabled,
            request_queue_browser_enabled=(
                config.request_queue_browser_enabled
            ),
            request_queue_dataset_enabled=(
                config.request_queue_dataset_enabled
            ),
            request_queue_key_value_store_enabled=(
                config.request_queue_key_value_store_enabled
            ),
        )
        if (
            activation.get("capability_profile") == "controlled-browser"
            and activation.get("request_queue_browser_enabled") is not True
        ):
            input_reference = payload.get("input_reference")
            if not isinstance(input_reference, dict):
                raise SandboxPolicyError("Controlled-browser Run lacks input reference.")
            browser_navigation = input_reference.get("browser_navigation")
            try:
                client.status(lease_id, token, status="RUNNING")
                if browser_navigation is not None:
                    if (
                        not isinstance(browser_navigation, dict)
                        or egress_policy is None
                        or browser_policy is None
                    ):
                        raise SandboxPolicyError("Live browser Run lacks validated policy.")
                    browser_egress_policy = BrowserEgressPolicy.create(egress_policy)
                    receipt = input_reference.get("browser_navigation_receipt")
                    if not isinstance(receipt, dict):
                        raise SandboxPolicyError("Live browser Run lacks receipt.")
                    request_digest = receipt.get("request_digest")
                    if not isinstance(request_digest, str):
                        raise SandboxPolicyError("Live browser Run request digest is invalid.")
                    browser_output, browser_log = run_browser_live_navigation(
                        config=config,
                        run_id=str(payload["run_id"]),
                        workspace=workspace,
                        navigation_plan=browser_navigation,
                        browser_policy_digest=browser_policy.digest,
                        browser_egress_policy=browser_egress_policy,
                        request_digest=request_digest,
                        max_screenshot_bytes=browser_policy.max_screenshot_bytes,
                        navigation_timeout_seconds=browser_policy.navigation_timeout_seconds,
                        runtime_timeout_seconds=int(payload["sandbox"]["timeout_seconds"]),
                    )
                    browser_provenance = {
                        "activation": activation,
                        "run_id": str(payload["run_id"]),
                        "browser_runtime_mode": "bounded-unix-gateway-navigation",
                        "browser_runtime_image_ref": config.browser_runtime_image_ref,
                        "request_digest": request_digest,
                        "browser_policy_digest": browser_policy.digest,
                        "browser_egress_policy_digest": browser_egress_policy.digest,
                        "browser_network": "none",
                        "gateway_transport": "unix",
                        "direct_browser_internet": False,
                        "external_navigation": True,
                    }
                else:
                    browser_output, browser_log = run_browser_self_test(
                        config=config,
                        run_id=str(payload["run_id"]),
                        workspace=workspace,
                    )
                    browser_provenance = {
                        "activation": activation,
                        "run_id": str(payload["run_id"]),
                        "browser_runtime_mode": "about-blank-self-test",
                        "browser_runtime_image_ref": config.browser_runtime_image_ref,
                        "browser_network": "none",
                        "direct_browser_internet": False,
                        "external_navigation": False,
                    }
            except (BrowserRuntimeError, SandboxPolicyError):
                client.complete(
                    lease_id,
                    token,
                    {
                        "outcome": "FAILED",
                        "retryable": False,
                        "error_code": "BROWSER_RUNTIME_FAILED",
                        "error_summary": "Controlled browser execution failed closed.",
                    },
                )
                return

            browser_artifacts: list[LocalArtifact] = []
            for kind, path, media_type in [
                ("RUN_OUTPUT", browser_output, "application/json"),
                ("LOG_BUNDLE", browser_log, "text/plain"),
            ]:
                digest, size = sha256_file(path)
                browser_artifacts.append(
                    LocalArtifact(
                        kind,
                        path,
                        media_type,
                        digest,
                        size,
                        "NOT_REQUIRED",
                        dict(browser_provenance),
                    )
                )
            registrations = _upload_artifacts(
                client,
                lease_id=lease_id,
                lease_token=token,
                artifacts=browser_artifacts,
            )
            client.complete(
                lease_id,
                token,
                {
                    "outcome": "SUCCEEDED",
                    "retryable": False,
                    "artifacts": registrations,
                },
            )
            return

        artifact_grant = _data(client.artifact_download(lease_id, token))
        image_path = workspace / "image.oci.tar"
        download_file(
            str(artifact_grant["url"]),
            image_path,
            max_bytes=int(artifact_grant["size_bytes"]),
        )
        digest, size = sha256_file(image_path)
        if digest != artifact_grant["digest"] or size != int(artifact_grant["size_bytes"]):
            raise SandboxPolicyError("Downloaded image artifact failed digest verification.")
        load_image(config, image_path)
        provenance = dict(artifact_grant.get("provenance") or {})
        image_ref = str(provenance.get("image_ref", ""))
        if not image_ref.startswith("rdc.local/agent:"):
            raise SandboxPolicyError("Container artifact provenance lacks a safe image reference.")
        manifest = dict(payload["manifest"])
        runtime = dict(manifest["runtime"])
        entrypoint = [str(value) for value in runtime["entrypoint"]]
        input_ref = dict(payload["input_reference"])
        input_value = dict(input_ref.get("value") or {})
        web_fetch = input_ref.get("web_fetch")
        profile = activation.get("capability_profile")
        kv_enabled = activation.get("key_value_store_enabled") is True
        queue_enabled = activation.get("request_queue_enabled") is True
        queue_http_enabled = (
            activation.get("request_queue_http_enabled") is True
        )
        queue_browser_enabled = (
            activation.get("request_queue_browser_enabled") is True
        )
        queue_claim: dict[str, object] | None = None
        queue_browser_provenance: dict[str, object] | None = None

        if (queue_http_enabled or queue_browser_enabled) and not queue_enabled:
            raise SandboxPolicyError(
                "Queue acquisition requires Queue access."
            )

        if queue_enabled:
            capability = payload.get("request_queue_capability")
            if not isinstance(capability, dict):
                raise SandboxPolicyError(
                    "Queue-bound Run lacks a capability receipt."
                )
            queue_id = capability.get("queue_id")
            if not isinstance(queue_id, str):
                raise SandboxPolicyError(
                    "Queue-bound Run capability is invalid."
                )
            try:
                claimed = client.queue_claim(
                    lease_id,
                    token,
                    queue_id=queue_id,
                )
                if claimed is None:
                    client.complete(
                        lease_id,
                        token,
                        {
                            "outcome": "SUCCEEDED",
                            "retryable": False,
                            "artifacts": [],
                        },
                    )
                    return
                queue_claim = validate_queue_claim_result(
                    _data(claimed),
                    expected_queue_id=queue_id,
                )
                if (
                    "_rdc_queue" in input_value
                    or "_rdc_queue_http" in input_value
                    or "_rdc_queue_browser" in input_value
                ):
                    raise QueueWorkerBoundaryError(
                        "Run input cannot populate Queue runtime keys."
                    )
                input_value["_rdc_queue"] = {
                    key: value
                    for key, value in queue_claim.items()
                    if key != "claim_token"
                }
            except (QueueWorkerBoundaryError, WorkerProtocolError):
                client.complete(
                    lease_id,
                    token,
                    {
                        "outcome": "FAILED",
                        "retryable": False,
                        "error_code": "REQUEST_QUEUE_CLAIM_FAILED",
                        "error_summary": (
                            "Controlled Request Queue claim failed closed."
                        ),
                    },
                )
                return

        if queue_claim is not None and queue_browser_enabled:
            if egress_policy is None or browser_policy is None:
                raise SandboxPolicyError(
                    "Queue browser acquisition lacks worker policy."
                )
            try:
                (
                    input_value["_rdc_queue_browser"],
                    queue_browser_provenance,
                ) = _queue_browser_acquire(
                    config=config,
                    payload=payload,
                    workspace=workspace,
                    queue_claim=queue_claim,
                    egress_policy=egress_policy,
                    browser_policy=browser_policy,
                )
            except (
                BrowserNavigationContractError,
                BrowserRuntimeError,
                QueueWorkerBoundaryError,
                json.JSONDecodeError,
                OSError,
                UnicodeError,
            ):
                try:
                    client.queue_complete(
                        lease_id,
                        token,
                        queue_completion_payload(
                            queue_claim,
                            handled=False,
                            failure_code="QUEUE_BROWSER_NAVIGATION_FAILED",
                            failure_summary=(
                                "Controlled Queue browser acquisition failed."
                            ),
                        ),
                    )
                except WorkerProtocolError:
                    client.complete(
                        lease_id,
                        token,
                        {
                            "outcome": "FAILED",
                            "retryable": False,
                            "error_code": (
                                "REQUEST_QUEUE_COMPLETION_FAILED"
                            ),
                            "error_summary": (
                                "Queue browser failure completion failed closed."
                            ),
                        },
                    )
                    return
                client.complete(
                    lease_id,
                    token,
                    {
                        "outcome": "FAILED",
                        "retryable": False,
                        "error_code": "QUEUE_BROWSER_NAVIGATION_FAILED",
                        "error_summary": (
                            "Controlled Queue browser acquisition failed closed."
                        ),
                    },
                )
                return

        if queue_claim is not None and queue_http_enabled:
            if egress_policy is None:
                raise SandboxPolicyError(
                    "Queue HTTP acquisition lacks worker egress policy."
                )
            try:
                queue_fetch = queue_http_fetch_envelope(queue_claim)
                broker_input = phase1j_broker_adapter(queue_fetch)
                broker_output = broker_web_requests(
                    broker_input,
                    policy=egress_policy,
                )
                fetch_result = phase1j_broker_result_adapter(
                    queue_fetch,
                    broker_output,
                )
                input_value["_rdc_queue_http"] = queue_http_agent_result(
                    queue_claim,
                    fetch_result,
                )
            except (
                QueueWorkerBoundaryError,
                WebFetchContractError,
                EgressPolicyError,
            ):
                try:
                    client.queue_complete(
                        lease_id,
                        token,
                        queue_completion_payload(
                            queue_claim,
                            handled=False,
                            failure_code="QUEUE_HTTP_FETCH_FAILED",
                            failure_summary=(
                                "Brokered Queue HTTP acquisition failed."
                            ),
                        ),
                    )
                except WorkerProtocolError:
                    client.complete(
                        lease_id,
                        token,
                        {
                            "outcome": "FAILED",
                            "retryable": False,
                            "error_code": "REQUEST_QUEUE_COMPLETION_FAILED",
                            "error_summary": (
                                "Queue HTTP failure completion failed closed."
                            ),
                        },
                    )
                    return
                client.complete(
                    lease_id,
                    token,
                    {
                        "outcome": "FAILED",
                        "retryable": False,
                        "error_code": "QUEUE_HTTP_FETCH_FAILED",
                        "error_summary": (
                            "Brokered Queue HTTP acquisition failed closed."
                        ),
                    },
                )
                return

        if kv_enabled:
            try:
                if "_rdc_kv" in input_value:
                    raise KVWorkerBoundaryError(
                        "Run input cannot populate reserved _rdc_kv."
                    )
                read_request = input_value.pop("_rdc_kv_read", None)
                if read_request is not None:
                    validated_read = validate_kv_read_request(read_request)
                    request_value = validated_read["request"]
                    expected_keys = validated_read["keys"]
                    if not isinstance(request_value, dict):
                        raise KVWorkerBoundaryError("KV read request is invalid.")
                    if not isinstance(expected_keys, tuple):
                        raise KVWorkerBoundaryError("KV read keys are invalid.")
                    read_response = _data(
                        client.kv_read(lease_id, token, request_value)
                    )
                    input_value["_rdc_kv"] = validate_kv_read_result(
                        read_response,
                        expected_keys=expected_keys,
                    )
            except (KVWorkerBoundaryError, WorkerProtocolError):
                if queue_claim is not None:
                    try:
                        client.queue_complete(
                            lease_id,
                            token,
                            queue_completion_payload(
                                queue_claim,
                                handled=False,
                                failure_code="KV_READ_FAILED",
                                failure_summary=(
                                    "Queue-bound Key-Value Store read failed."
                                ),
                            ),
                        )
                    except WorkerProtocolError:
                        client.complete(
                            lease_id,
                            token,
                            {
                                "outcome": "FAILED",
                                "retryable": False,
                                "error_code": "REQUEST_QUEUE_COMPLETION_FAILED",
                                "error_summary": (
                                    "Queue KV read failure completion failed closed."
                                ),
                            },
                        )
                        return
                client.complete(
                    lease_id,
                    token,
                    {
                        "outcome": "FAILED",
                        "retryable": False,
                        "error_code": "KV_READ_FAILED",
                        "error_summary": (
                            "Controlled Key-Value Store read failed closed."
                        ),
                    },
                )
                return

        if web_fetch is not None and profile != "brokered-web-egress":
            raise SandboxPolicyError(
                "Web-fetch intent requires brokered-web-egress activation."
            )

        if profile == "brokered-web-egress":
            if egress_policy is None:
                raise SandboxPolicyError(
                    "Brokered web-egress activation lacks worker policy."
                )
            if queue_http_enabled:
                if web_fetch is not None or "_rdc_web_requests" in input_value:
                    raise SandboxPolicyError(
                        "Queue HTTP acquisition cannot carry another web intent."
                    )
            elif web_fetch is not None:
                if "_rdc_web_requests" in input_value:
                    raise SandboxPolicyError(
                        "Versioned web fetch cannot be mixed with the "
                        "legacy Phase 1J request key."
                    )
                try:
                    broker_input = phase1j_broker_adapter(web_fetch)
                    broker_output = broker_web_requests(
                        broker_input,
                        policy=egress_policy,
                    )
                    web_fetch_result = phase1j_broker_result_adapter(
                        web_fetch,
                        broker_output,
                    )
                except WebFetchContractError:
                    client.complete(
                        lease_id,
                        token,
                        {
                            "outcome": "FAILED",
                            "retryable": False,
                            "error_code": "WEB_FETCH_CONTRACT_INVALID",
                            "error_summary": (
                                "The versioned web-fetch contract was invalid."
                            ),
                        },
                    )
                    return
                except EgressPolicyError:
                    client.complete(
                        lease_id,
                        token,
                        {
                            "outcome": "FAILED",
                            "retryable": False,
                            "error_code": "WEB_FETCH_POLICY_DENIED",
                            "error_summary": (
                                "Brokered web fetch was denied or failed "
                                "within the operator policy."
                            ),
                        },
                    )
                    return
                input_value["_rdc_web_fetch_result"] = web_fetch_result
            else:
                input_value = broker_web_requests(
                    input_value,
                    policy=egress_policy,
                )
        secrets: dict[str, object] = {}
        names = [str(value) for value in manifest.get("secrets", [])]
        if names:
            key_pair = generate_worker_key_pair()
            envelope = client.request_secret_envelope(
                lease_id,
                token,
                names=names,
                environment="production",
                key_pair=key_pair,
            )
            worker = _data(client.worker())
            secrets = decrypt_secret_envelope(
                envelope,
                key_pair=key_pair,
                lease_id=lease_id,
                worker_id=str(worker["id"]),
                run_id=str(payload["run_id"]),
            )
        client.status(lease_id, token, status="RUNNING")
        code, output_path, log_path = run_agent(
            config=config,
            run_id=str(payload["run_id"]),
            image_ref=image_ref,
            entrypoint=entrypoint,
            input_value=input_value,
            secrets=secrets,
            workspace=workspace,
            policy=dict(payload["sandbox"]),
        )

        if kv_enabled and code == 0:
            try:
                if not output_path.is_file():
                    raise KVWorkerBoundaryError(
                        "KV-enabled Run did not produce output."
                    )
                if output_path.stat().st_size > 1_572_864:
                    raise KVWorkerBoundaryError(
                        "KV worker output exceeds the read limit."
                    )
                decoded_kv = json.loads(
                    output_path.read_text(encoding="utf-8")
                )
                normalized_kv = validate_kv_worker_output(decoded_kv)
                mutations = normalized_kv["mutations"]
                if not isinstance(mutations, list):
                    raise KVWorkerBoundaryError("KV mutations are invalid.")
                for mutation_index, mutation in enumerate(mutations):
                    if not isinstance(mutation, dict):
                        raise KVWorkerBoundaryError("KV mutation is invalid.")
                    persisted_mutation = dict(mutation)
                    if queue_claim is not None:
                        persisted_mutation["idempotency_key"] = (
                            queue_kv_idempotency_key(
                                queue_claim, mutation_index
                            )
                        )
                    client.kv_mutate(lease_id, token, persisted_mutation)
                result_bytes = json.dumps(
                    normalized_kv["result"],
                    ensure_ascii=False,
                    allow_nan=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                output_path.write_bytes(result_bytes)
            except (
                KVWorkerBoundaryError,
                WorkerProtocolError,
                json.JSONDecodeError,
                OSError,
                UnicodeError,
                TypeError,
                ValueError,
            ):
                if queue_claim is not None:
                    try:
                        client.queue_complete(
                            lease_id,
                            token,
                            queue_completion_payload(
                                queue_claim,
                                handled=False,
                                failure_code="KV_MUTATION_FAILED",
                                failure_summary=(
                                    "Queue-bound Key-Value Store mutation failed."
                                ),
                            ),
                        )
                    except WorkerProtocolError:
                        client.complete(
                            lease_id,
                            token,
                            {
                                "outcome": "FAILED",
                                "retryable": False,
                                "error_code": "REQUEST_QUEUE_COMPLETION_FAILED",
                                "error_summary": (
                                    "Queue KV mutation failure completion failed closed."
                                ),
                            },
                        )
                        return
                client.complete(
                    lease_id,
                    token,
                    {
                        "outcome": "FAILED",
                        "retryable": False,
                        "error_code": "KV_MUTATION_FAILED",
                        "error_summary": (
                            "Controlled Key-Value Store mutation failed closed."
                        ),
                    },
                )
                return

        dataset_enabled = (
            isinstance(manifest.get("capabilities"), dict)
            and manifest["capabilities"].get("dataset") is True
        )
        if dataset_enabled and code == 0:
            try:
                if not output_path.is_file():
                    raise DatasetProtocolError(
                        "Dataset-enabled Run did not produce an output envelope."
                    )
                if output_path.stat().st_size > 262_144:
                    raise DatasetProtocolError(
                        "Dataset output envelope exceeds the worker read limit."
                    )
                decoded = json.loads(output_path.read_text(encoding="utf-8"))
                if not isinstance(decoded, dict):
                    raise DatasetProtocolError(
                        "Dataset output envelope must be an object."
                    )
                dataset_payload = {
                    str(key): value for key, value in decoded.items()
                }
                if queue_claim is not None:
                    dataset_payload["idempotency_key"] = (
                        queue_dataset_idempotency_key(queue_claim)
                    )
                validate_dataset_append(dataset_payload)
                client.dataset_append(
                    lease_id,
                    token,
                    dataset_payload,
                )
            except (
                DatasetProtocolError,
                WorkerProtocolError,
                json.JSONDecodeError,
                OSError,
                UnicodeError,
            ):
                if queue_claim is not None:
                    try:
                        client.queue_complete(
                            lease_id,
                            token,
                            queue_completion_payload(
                                queue_claim,
                                handled=False,
                                failure_code="DATASET_APPEND_FAILED",
                                failure_summary=(
                                    "Queue-bound Dataset persistence failed."
                                ),
                            ),
                        )
                    except WorkerProtocolError:
                        client.complete(
                            lease_id,
                            token,
                            {
                                "outcome": "FAILED",
                                "retryable": False,
                                "error_code": (
                                    "REQUEST_QUEUE_COMPLETION_FAILED"
                                ),
                                "error_summary": (
                                    "Queue Dataset failure completion failed closed."
                                ),
                            },
                        )
                        return
                client.complete(
                    lease_id,
                    token,
                    {
                        "outcome": "FAILED",
                        "retryable": False,
                        "error_code": "DATASET_APPEND_FAILED",
                        "error_summary": (
                            "Controlled Dataset append failed closed."
                        ),
                    },
                )
                return

        if queue_claim is not None:
            try:
                client.queue_complete(
                    lease_id,
                    token,
                    queue_completion_payload(
                        queue_claim,
                        handled=code == 0,
                    ),
                )
            except WorkerProtocolError:
                client.complete(
                    lease_id,
                    token,
                    {
                        "outcome": "FAILED",
                        "retryable": False,
                        "error_code": "REQUEST_QUEUE_COMPLETION_FAILED",
                        "error_summary": (
                            "Controlled Request Queue completion failed closed."
                        ),
                    },
                )
                return

        image_digest = (
            str(artifact_grant["digest_algorithm"])
            + ":"
            + str(artifact_grant["digest"])
        )
        run_provenance = {
            "activation": activation,
            "run_id": str(payload["run_id"]),
            "image_digest": image_digest,
        }
        if queue_browser_provenance is not None:
            run_provenance["queue_browser"] = queue_browser_provenance
        artifacts: list[LocalArtifact] = []
        if output_path.is_file():
            digest, size = sha256_file(output_path)
            artifacts.append(
                LocalArtifact(
                    "RUN_OUTPUT",
                    output_path,
                    "application/json",
                    digest,
                    size,
                    "NOT_REQUIRED",
                    dict(run_provenance),
                )
            )
        if log_path.is_file():
            digest, size = sha256_file(log_path)
            artifacts.append(
                LocalArtifact(
                    "LOG_BUNDLE",
                    log_path,
                    "text/plain",
                    digest,
                    size,
                    "NOT_REQUIRED",
                    dict(run_provenance),
                )
            )
        registrations = _upload_artifacts(
            client,
            lease_id=lease_id,
            lease_token=token,
            artifacts=artifacts,
        )
        client.complete(
            lease_id,
            token,
            {
                "outcome": "SUCCEEDED" if code == 0 else "FAILED",
                "retryable": False,
                "error_code": None if code == 0 else "AGENT_EXIT_NONZERO",
                "error_summary": None if code == 0 else f"Agent exited with status {code}.",
                "artifacts": registrations,
            },
        )
    except Exception as exc:
        client.complete(
            lease_id,
            token,
            {
                "outcome": "FAILED",
                "retryable": False,
                "error_code": "SANDBOX_RUN_FAILED",
                "error_summary": str(exc)[:2000],
            },
        )
    finally:
        cleanup_tree(workspace)


def main() -> None:
    config = SandboxWorkerConfig.from_env()
    probe = verify_host(config)
    cleanup_report = force_startup_cleanup(config)
    client = RdcWorkerClient(
        base_url=config.api_base_url,
        worker_token=config.worker_token,
    )
    client.heartbeat(
        software_version=config.software_version,
        active_lease_count=0,
        sandbox=probe.attestation,
        recovery=cleanup_report.as_protocol(),
    )
    worker = _data(client.worker())
    worker_name = str(worker["name"])
    if int(worker["max_concurrency"]) != 1:
        raise SandboxPolicyError(
            "Phase 1J canary worker must have max_concurrency=1."
        )
    stop_requested = False

    def request_stop(_signum: int, _frame: object) -> None:
        nonlocal stop_requested
        stop_requested = True
        raise WorkerShutdown

    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, request_stop)

    try:
        while not stop_requested:
            claim = client.claim(["RUN_CANCEL", "BUILD", "RUN_START"])
            if claim is None:
                time.sleep(config.poll_seconds)
                client.heartbeat(
                    software_version=config.software_version,
                    active_lease_count=0,
                    sandbox=probe.attestation,
                )
                continue
            data = _data(claim)
            with LeaseWatchdog(
                client=client,
                config=config,
                lease_id=str(data["id"]),
                lease_token=str(data["lease_token"]),
                sandbox=probe.attestation,
            ) as watchdog:
                if data["work_kind"] == "BUILD":
                    _build(
                        client,
                        config,
                        claim,
                        worker_name=worker_name,
                    )
                else:
                    _run(
                        client,
                        config,
                        claim,
                        worker_name=worker_name,
                    )
                watchdog.mark_completed()
    except WorkerShutdown:
        pass
    finally:
        final_cleanup = force_startup_cleanup(config)
        client.heartbeat(
            software_version=config.software_version,
            active_lease_count=0,
            draining=True,
            sandbox=probe.attestation,
            recovery=final_cleanup.as_protocol(),
        )


if __name__ == "__main__":
    main()
