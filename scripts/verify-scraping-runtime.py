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
)
need(
    "apps/api/app/services/runs.py",
    "RequestQueue.organization_id == version.organization_id",
    "RequestQueue.project_id == version.project_id",
    '"rdc.request-queue-binding-receipt/v1"',
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
)
need(
    "apps/api/app/services/execution_plane.py",
    "request_queue_capability(",
    "activation.request_queue_enabled",
)
need(
    "workers/sandbox-runtime/worker.py",
    "validate_queue_claim_result(",
    "client.queue_claim(",
    "client.queue_complete(",
    'if key != "claim_token"',
    "REQUEST_QUEUE_COMPLETION_FAILED",
)
need(
    "workers/sandbox-runtime/queue_worker_protocol.py",
    "MAX_USER_DATA_BYTES = 65_536",
    "IP literal",
    "expected_queue_id",
    "queue_completion_payload(",
)
need(
    "apps/api/tests/test_scraping_runtime_queue_foundation.py",
    "test_create_run_derives_queue_tenancy_and_persists_receipt",
    "test_create_run_hides_cross_tenant_queue",
    "test_queue_worker_protocol_rejects_scope_and_ip_literals",
)
need(
    ".env.example",
    "RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED=false",
)
for path in (
    "infrastructure/environments/staging/api.env.example",
    "infrastructure/environments/staging/worker.env.example",
    "infrastructure/environments/production/api.env.example",
    "infrastructure/environments/production/worker.env.example",
):
    need(path, "RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED=false")
for path in (
    "docs/scraping-runtime/README.md",
    "docs/scraping-runtime/RUNBOOK.md",
    "docs/scraping-runtime/THREAT_MODEL.md",
):
    need(path, "Scraping Runtime")

print("Scraping Runtime verification passed")
