# ruff: noqa: E501
from pathlib import Path

API_ROOT = Path(__file__).parents[1]
REPO_ROOT = API_ROOT.parents[1]


def test_phase1p_migration_has_rls_tenancy_and_immutable_history() -> None:
    source = (API_ROOT / "migrations/versions/20260809_0015_request_queues.py").read_text()
    for marker in ("request_queues", "request_queue_requests", "request_queue_transitions", "ENABLE ROW LEVEL SECURITY", "rdc_request_queue_org", "request_queue_transition_immutable", "enforce_request_queue_tenancy", "enforce_audit_event_tenancy", "audit_event_immutable"):
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


def test_phase1p_migration_upgrade_and_downgrade_cover_all_queue_tables() -> None:
    source = (API_ROOT / "migrations/versions/20260809_0015_request_queues.py").read_text()
    assert 'down_revision: str | None = "20260808_0014"' in source
    assert 'server_default="PENDING"' in source
    assert "ck_request_queues_nonnegative_counts" in source
    downgrade = source.split("def downgrade() -> None:", 1)[1]
    for table in ("request_queue_enqueue_receipts", "request_queue_transitions", "request_queue_requests", "request_queues"):
        assert f'op.drop_table("{table}", schema="control")' in downgrade
    assert downgrade.index('op.drop_table("request_queue_enqueue_receipts"') < downgrade.index('op.drop_table("request_queues"')
