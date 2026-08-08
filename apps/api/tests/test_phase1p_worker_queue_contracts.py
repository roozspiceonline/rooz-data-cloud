# ruff: noqa: E501
from pathlib import Path

API_ROOT = Path(__file__).parents[1]


def test_worker_queue_gate_defaults_off_and_requires_canary_run_lease() -> None:
    config = (API_ROOT / "app/core/config.py").read_text()
    service = (API_ROOT / "app/services/worker_request_queue.py").read_text()
    assert "sandbox_canary_request_queue_enabled: bool = False" in config
    assert 'settings.sandbox_activation_mode != "canary"' in service
    assert 'lease.work_kind != "RUN"' in service


def test_worker_queue_is_lease_tenant_scoped_and_claim_token_bound() -> None:
    service = (API_ROOT / "app/services/worker_request_queue.py").read_text()
    for marker in ("RequestQueue.organization_id == lease.organization_id", "RequestQueue.project_id == lease.project_id", "RequestQueueRequest.organization_id == lease.organization_id", "row.claimed_by != str(worker.id)", "row.claim_token != claim_token", "with_for_update()"):
        assert marker in service
