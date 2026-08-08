#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def need(path: str, *markers: str) -> None:
    text = (ROOT / path).read_text()
    missing = [marker for marker in markers if marker not in text]
    if missing:
        raise SystemExit(f"{path} missing: {', '.join(missing)}")


need("apps/api/migrations/versions/20260809_0015_request_queues.py", "ENABLE ROW LEVEL SECURITY", "rdc_request_queue_org", "request_queue_transition_immutable", "request_queue_enqueue_receipt_immutable", "Request Queue request identity is immutable", "enforce_request_queue_request_immutable", "enforce_request_queue_request_reference", "request_queues_tenant_update", "request_queues_execution_worker_update", "request_queue_requests_execution_worker_update", "request_queue_transitions_execution_worker_insert", "lease.work_kind = 'RUN_START'", "enforce_audit_event_tenancy", "audit_event_immutable")
need("apps/api/app/services/request_queues.py", "with_for_update()", "skip_locked=True", "reclaim_expired_requests", "IDEMPOTENCY_KEY_REUSED", "RequestQueueTransition", "request_queue.request_enqueued", "request_queue.request_claimed", "request_queue.request_reclaimed", "list_request_queues", "list_queue_transitions", ".limit(limit + 1)")
need("apps/api/app/core/pagination.py", "encode_queue_request_cursor", "decode_queue_request_cursor", '"queue-requests"', "encode_request_queue_list_cursor", "decode_request_queue_list_cursor", '"request-queue-list"', "encode_queue_transition_cursor", "decode_queue_transition_cursor", '"queue-transitions"')
need("apps/api/app/core/config.py", "sandbox_canary_request_queue_enabled: bool = False")
need("apps/api/app/services/worker_request_queue.py", "WORKER_REQUEST_QUEUE_DISABLED", "lease.organization_id", "lease.project_id", "REQUEST_QUEUE_CLAIM_STALE", "REQUEST_QUEUE_ACCESS", "claim_expires_at", "request_queue.request_handled", "request_queue.request_failed")
need("apps/api/tests/test_phase1p_queue_pagination.py", "signed_and_project_bound", "queue_and_request_filter_bound", "rejects_tampering_and_filter_replay", "cannot_cross_collection_boundaries")
need("apps/api/tests/test_phase1p_postgres_integration.py", "simultaneous_claim", "idempotent_enqueue_emits_one_tenant_bound_audit_event", "tenancy_trigger", "transition_rejects_request_from_another_queue", "request_identity_and_enqueue_receipts_are_immutable", "expired_claim_requeues", "retry_exhaustion", "audit_events_reject_cross_tenant_projects_and_mutation", "queue_pagination_is_stable_at_equal_timestamps", "queue_and_transition_rls_hide_other_tenant", "worker_completion_emits_tenant_bound_audit_event", "cross_tenant_resolver", "stale_claim_token")
need("docs/phase1p/THREAT_MODEL.md", "RLS", "Idempotency", "immutable audit", "filter-bound signed cursors")
need("docs/phase1p/RUNBOOK.md", "20260809_0015", "RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED", "request_queue.request_enqueued", "request_queue.request_claimed", "request_queue.request_reclaimed", "request_queue.request_handled", "request_queue.request_failed", "INVALID_CURSOR")
print("Phase 1P verification passed")
