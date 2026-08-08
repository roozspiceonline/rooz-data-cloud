#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def need(path: str, *markers: str) -> None:
    text = (ROOT / path).read_text()
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise SystemExit(f"{path} missing: {', '.join(missing)}")


need("apps/api/migrations/versions/20260809_0015_request_queues.py", "ENABLE ROW LEVEL SECURITY", "rdc_request_queue_org", "request_queue_transition_immutable", "enforce_audit_event_tenancy", "audit_event_immutable")
need("apps/api/app/services/request_queues.py", "with_for_update()", "skip_locked=True", "reclaim_expired_requests", "IDEMPOTENCY_KEY_REUSED", "RequestQueueTransition", "request_queue.request_enqueued", "request_queue.request_claimed", "request_queue.request_reclaimed")
need("apps/api/app/core/pagination.py", "encode_queue_request_cursor", "decode_queue_request_cursor", '"queue-requests"')
need("apps/api/app/core/config.py", "sandbox_canary_request_queue_enabled: bool = False")
need("apps/api/app/services/worker_request_queue.py", "WORKER_REQUEST_QUEUE_DISABLED", "lease.organization_id", "lease.project_id", "REQUEST_QUEUE_CLAIM_STALE", "REQUEST_QUEUE_ACCESS", "claim_expires_at", "request_queue.request_handled", "request_queue.request_failed")
need("apps/api/tests/test_phase1p_postgres_integration.py", "simultaneous_claim", "idempotent_enqueue_emits_one_tenant_bound_audit_event", "tenancy_trigger", "expired_claim_requeues", "retry_exhaustion", "audit_events_reject_cross_tenant_projects_and_mutation", "worker_completion_emits_tenant_bound_audit_event", "cross_tenant_resolver", "stale_claim_token")
need("docs/phase1p/THREAT_MODEL.md", "RLS", "Idempotency", "immutable audit")
need("docs/phase1p/RUNBOOK.md", "20260809_0015", "RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED", "request_queue.request_enqueued", "request_queue.request_claimed", "request_queue.request_reclaimed", "request_queue.request_handled", "request_queue.request_failed")
print("Phase 1P verification passed")
