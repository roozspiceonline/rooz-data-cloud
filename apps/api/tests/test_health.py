from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_liveness() -> None:
    response = client.get("/health/live")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_foundation_contract() -> None:
    response = client.get("/api/v1/system/foundation")
    assert response.status_code == 200
    payload = response.json()
    assert payload["arbitrary_code_in_api"] is False
    assert payload["tenant_rls_required"] is True
    assert payload["write_only_secrets_required"] is True
    assert payload["execution_recovery_scheduler_enabled"] is True
    assert payload["execution_recovery_sweep_batch_size"] == 100
    assert (
        payload["execution_recovery_singleton_lock"]
        == "postgresql-advisory-xact"
    )
    assert payload["worker_loss_detection"] is True
    assert payload["worker_lost_after_seconds"] == 45
    assert payload["worker_restart_cleanup_required"] is True
    assert payload["production_environment_identity_guard"] is True
    assert payload["production_supervisor_contract"] == "systemd-control-group"
    assert payload["database_restore_rollback_drill"] is True
    assert payload["object_version_recovery_drill"] is True
    assert payload["execution_recovery_slo_metrics"] is True
