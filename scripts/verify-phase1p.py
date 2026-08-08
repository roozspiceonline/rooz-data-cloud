#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def need(path: str, *markers: str) -> None:
    text = (ROOT / path).read_text()
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise SystemExit(f"{path} missing: {', '.join(missing)}")


need("apps/api/migrations/versions/20260809_0015_request_queues.py", "ENABLE ROW LEVEL SECURITY", "rdc_request_queue_org", "request_queue_transition_immutable")
need("apps/api/app/services/request_queues.py", "with_for_update()", "skip_locked=True", "reclaim_expired_requests", "IDEMPOTENCY_KEY_REUSED", "RequestQueueTransition")
need("apps/api/app/core/pagination.py", "encode_queue_request_cursor", "decode_queue_request_cursor", '"queue-requests"')
need("apps/api/app/core/config.py", "sandbox_canary_request_queue_enabled: bool = False")
need("apps/api/app/services/worker_request_queue.py", "WORKER_REQUEST_QUEUE_DISABLED", "lease.organization_id", "lease.project_id", "REQUEST_QUEUE_CLAIM_STALE")
need("apps/api/tests/test_phase1p_postgres_integration.py", "simultaneous_claim", "tenancy_trigger", "pending_count,claimed_count")
need("docs/phase1p/THREAT_MODEL.md", "RLS", "Idempotency")
need("docs/phase1p/RUNBOOK.md", "20260809_0015", "RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED")
print("Phase 1P verification passed")
