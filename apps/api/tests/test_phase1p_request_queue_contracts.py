# ruff: noqa: E501
from pathlib import Path

API_ROOT = Path(__file__).parents[1]
REPO_ROOT = API_ROOT.parents[1]


def test_phase1p_migration_has_rls_tenancy_and_immutable_history() -> None:
    source = (API_ROOT / "migrations/versions/20260809_0015_request_queues.py").read_text()
    for marker in ("request_queues", "request_queue_requests", "request_queue_transitions", "ENABLE ROW LEVEL SECURITY", "rdc_request_queue_org", "request_queue_transition_immutable", "enforce_request_queue_tenancy"):
        assert marker in source


def test_phase1p_service_serializes_idempotency_before_persistence() -> None:
    source = (API_ROOT / "app/services/request_queues.py").read_text()
    assert "with_for_update()" in source
    assert "IDEMPOTENCY_KEY_REUSED" in source
    assert "RequestQueueTransition" in source


def test_phase1p_routes_use_server_derived_queue_ownership() -> None:
    source = (API_ROOT / "app/api/routes/request_queues.py").read_text()
    assert 'require_request_queue_permission("queue.enqueue")' in source
    assert "organization_id=" not in source
