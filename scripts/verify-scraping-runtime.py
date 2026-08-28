#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def need(path: str, *markers: str) -> None:
    source = (ROOT / path).read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise SystemExit(f"{path} missing: {', '.join(missing)}")


need(
    "apps/api/app/run_schemas.py",
    'Literal["rdc.run-queue/v1"]',
    "request_queue: RequestQueueBindingInput | None",
    "reserved _rdc_queue",
    '"_rdc_queue_http"',
    '"_rdc_queue_browser"',
    '"_rdc_web_requests"',
)
need(
    "apps/api/app/services/runs.py",
    "RequestQueue.organization_id == version.organization_id",
    "RequestQueue.project_id == version.project_id",
    '"rdc.request-queue-binding-receipt/v1"',
    '"rdc.request-queue-binding-receipt/v2"',
    '"rdc.request-queue-binding-receipt/v3"',
    '"acquisition_mode": "brokered-http"',
    '"acquisition_mode": "controlled-browser"',
    '"agent_container_network": "none"',
    "_request_queue_http_canary_enabled",
    "_request_queue_browser_canary_enabled",
    "_request_queue_dataset_canary_enabled",
    "_request_queue_key_value_store_canary_enabled",
    '"rdc.request-queue-dataset-receipt/v1"',
    '"rdc.request-queue-key-value-store-receipt/v1"',
    '"direct_database_access": False',
)
need(
    "apps/api/app/services/worker_request_queue.py",
    "request_queue_capability(",
    'snapshot.get("request_queue_capability") != expected',
    'str(queue_id) != capability["queue_id"]',
    "RequestQueue.organization_id == lease.organization_id",
    "row.claim_token != claim_token",
    "with_for_update()",
    '"rdc.request-queue-worker-capability/v2"',
    '"rdc.request-queue-worker-capability/v3"',
    '"rdc.request-queue-worker-capability/v4"',
    '"rdc.request-queue-worker-capability/v5"',
    '"rdc.request-queue-worker-capability/v6"',
    "request_queue_http_enabled",
    "request_queue_browser_enabled",
    "request_queue_dataset_enabled",
    "request_queue_key_value_store_enabled",
    "egress_policy_digest",
)
need(
    "apps/api/app/services/execution_plane.py",
    "request_queue_capability(",
    "activation.request_queue_enabled",
    "activation.request_queue_browser_enabled",
    "activation.request_queue_dataset_enabled",
    "activation.request_queue_key_value_store_enabled",
    '"rdc.dataset-worker-capability/v2"',
)
need(
    "workers/sandbox-runtime/worker.py",
    "validate_queue_claim_result(",
    "client.queue_claim(",
    "client.queue_complete(",
    'if key != "claim_token"',
    "REQUEST_QUEUE_COMPLETION_FAILED",
    "queue_http_fetch_envelope(",
    "queue_http_agent_result(",
    '"QUEUE_HTTP_FETCH_FAILED"',
    "_queue_browser_acquire(",
    '"QUEUE_BROWSER_NAVIGATION_FAILED"',
    'failure_code="DATASET_APPEND_FAILED"',
    '"dataset-before-queue-handled"',
    '"kv-before-queue-handled"',
)
need(
    "workers/sandbox-runtime/queue_worker_protocol.py",
    "MAX_USER_DATA_BYTES = 65_536",
    "IP literal",
    "expected_queue_id",
    "queue_completion_payload(",
    "queue_dataset_idempotency_key(",
    "queue_kv_idempotency_key(",
    "queue_http_fetch_envelope(",
    "queue_http_agent_result(",
    "queue_browser_navigation_plan(",
    "queue_browser_agent_result(",
    '"rdc.queue-http-result/v1"',
    '"rdc.queue-browser-result/v1"',
)
need(
    "apps/api/tests/test_scraping_runtime_queue_foundation.py",
    "test_create_run_derives_queue_tenancy_and_persists_receipt",
    "test_create_run_hides_cross_tenant_queue",
    "test_queue_worker_protocol_rejects_scope_and_ip_literals",
    "test_queue_http_protocol_is_claim_derived_and_token_free",
    "test_queue_http_gates_are_independent_and_fail_closed",
    "test_queue_http_capability_binds_egress_policy",
    "test_create_run_persists_brokered_queue_http_receipt",
    "test_create_run_persists_gated_queue_browser_receipt",
    "test_queue_browser_control_plane_activation_is_exact_and_fail_closed",
    "test_queue_browser_worker_independently_validates_v3_receipts",
    "test_queue_browser_live_acquisition_is_claim_derived_and_token_free",
    "test_queue_dataset_capabilities_are_exact_and_fail_closed",
    "test_queue_dataset_idempotency_is_server_derived_and_token_free",
    "test_queue_dataset_persists_before_handled_completion",
    "test_create_run_persists_gated_queue_dataset_composition",
    "test_queue_kv_capabilities_are_exact_and_fail_closed",
    "test_queue_kv_composition_preserves_web_acquisition_mode",
    "test_queue_kv_idempotency_is_server_derived_and_token_free",
    "test_queue_kv_persists_before_handled_completion",
    "test_create_run_persists_gated_queue_kv_composition",
)
need(
    ".env.example",
    "RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED=false",
    "RDC_SANDBOX_CANARY_REQUEST_QUEUE_HTTP_ENABLED=false",
    "RDC_SANDBOX_CANARY_REQUEST_QUEUE_BROWSER_ENABLED=false",
    "RDC_SANDBOX_CANARY_REQUEST_QUEUE_DATASET_ENABLED=false",
    "RDC_SANDBOX_CANARY_REQUEST_QUEUE_KEY_VALUE_STORE_ENABLED=false",
)
for path in (
    "infrastructure/environments/staging/api.env.example",
    "infrastructure/environments/staging/worker.env.example",
    "infrastructure/environments/production/api.env.example",
    "infrastructure/environments/production/worker.env.example",
):
    need(
        path,
        "RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED=false",
        "RDC_SANDBOX_CANARY_REQUEST_QUEUE_HTTP_ENABLED=false",
        "RDC_SANDBOX_CANARY_REQUEST_QUEUE_BROWSER_ENABLED=false",
        "RDC_SANDBOX_CANARY_REQUEST_QUEUE_DATASET_ENABLED=false",
        "RDC_SANDBOX_CANARY_REQUEST_QUEUE_KEY_VALUE_STORE_ENABLED=false",
    )
for path in (
    "docs/scraping-runtime/README.md",
    "docs/scraping-runtime/RUNBOOK.md",
    "docs/scraping-runtime/THREAT_MODEL.md",
):
    need(path, "Scraping Runtime")

print("Scraping Runtime verification passed")
