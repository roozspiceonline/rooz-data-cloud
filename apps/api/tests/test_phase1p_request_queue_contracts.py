# ruff: noqa: E501
from pathlib import Path

API_ROOT = Path(__file__).parents[1]
REPO_ROOT = API_ROOT.parents[1]


def test_phase1p_migration_has_rls_tenancy_and_immutable_history() -> None:
    source = (API_ROOT / "migrations/versions/20260809_0015_request_queues.py").read_text()
    for marker in ("request_queues", "request_queue_requests", "request_queue_transitions", "ENABLE ROW LEVEL SECURITY", "rdc_request_queue_org", "request_queue_transition_immutable", "request_queue_enqueue_receipt_immutable", "Request Queue request identity is immutable", "enforce_request_queue_tenancy", "enforce_request_queue_request_reference", "enforce_audit_event_tenancy", "audit_event_immutable"):
        assert marker in source


def test_phase1p_rls_separates_tenant_commands_and_scopes_workers_to_run_leases() -> None:
    source = (API_ROOT / "migrations/versions/20260809_0015_request_queues.py").read_text()
    assert "request_queue_requests_tenant_update" not in source
    assert "request_queue_transitions_tenant_update" not in source
    assert "request_queue_enqueue_receipts_tenant_update" not in source
    assert "request_queues_tenant_update" in source
    for marker in (
        "request_queues_execution_worker_select",
        "request_queues_execution_worker_update",
        "request_queue_requests_execution_worker_select",
        "request_queue_requests_execution_worker_update",
        "request_queue_transitions_execution_worker_insert",
        "lease.work_kind = 'RUN_START'",
        "lease.organization_id",
        "lease.project_id",
    ):
        assert marker in source


def test_phase1p_service_serializes_idempotency_before_persistence() -> None:
    source = (API_ROOT / "app/services/request_queues.py").read_text()
    assert "with_for_update()" in source
    assert "IDEMPOTENCY_KEY_REUSED" in source
    assert "RequestQueueTransition" in source
    for action in (
        "request_queue.request_enqueued",
        "request_queue.request_claimed",
        "request_queue.request_reclaimed",
        "request_queue.request_failed",
    ):
        assert action in source


def test_phase1p_worker_completion_audits_terminal_transitions() -> None:
    source = (API_ROOT / "app/services/worker_request_queue.py").read_text()
    assert "request_queue.request_handled" in source
    assert "request_queue.request_failed" in source
    assert '"failure_summary"' not in source.split("details={", 1)[-1]


def test_phase1p_routes_use_server_derived_queue_ownership() -> None:
    source = (API_ROOT / "app/api/routes/request_queues.py").read_text()
    assert 'require_request_queue_permission("queue.enqueue")' in source
    assert "organization_id=" not in source
    assert "decode_request_queue_list_cursor" in source
    assert "decode_queue_transition_cursor" in source
    assert "list_request_queues" in source
    assert "list_queue_transitions" in source


def test_phase1p_migration_upgrade_and_downgrade_cover_all_queue_tables() -> None:
    source = (API_ROOT / "migrations/versions/20260809_0015_request_queues.py").read_text()
    assert 'down_revision: str | None = "20260808_0014"' in source
    assert 'server_default="PENDING"' in source
    assert "ck_request_queues_nonnegative_counts" in source
    downgrade = source.split("def downgrade() -> None:", 1)[1]
    for table in ("request_queue_enqueue_receipts", "request_queue_transitions", "request_queue_requests", "request_queues"):
        assert f'op.drop_table("{table}", schema="control")' in downgrade
    assert downgrade.index('op.drop_table("request_queue_enqueue_receipts"') < downgrade.index('op.drop_table("request_queues"')
