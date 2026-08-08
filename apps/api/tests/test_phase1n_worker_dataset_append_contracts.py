from pathlib import Path


def test_phase1n_increment4_worker_gate_defaults_off() -> None:
    api_config = Path("app/core/config.py").read_text(encoding="utf-8")
    worker_config = Path(
        "../../workers/sandbox-runtime/config.py"
    ).read_text(encoding="utf-8")
    env = Path("../../.env.example").read_text(encoding="utf-8")

    assert "sandbox_canary_dataset_writes_enabled: bool = False" in api_config
    assert "dataset_writes_enabled: bool" in worker_config
    assert "RDC_SANDBOX_CANARY_DATASET_WRITES_ENABLED=false" in env


def test_phase1n_increment4_worker_capability_is_explicit() -> None:
    schemas = Path("app/execution_schemas.py").read_text(encoding="utf-8")
    assert '"DATASET_APPEND"' in schemas
    assert "dataset_write_enabled: bool = False" in schemas


def test_phase1n_increment4_internal_route_is_lease_scoped_and_hidden() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/internal/v1/leases/{lease_id}/dataset-append" not in paths

    source = Path(
        "app/api/routes/internal_execution.py"
    ).read_text(encoding="utf-8")
    assert '"/leases/{lease_id}/dataset-append"' in source
    assert "Depends(require_lease_access)" in source
    assert "append_worker_dataset_items" in source


def test_phase1n_increment4_worker_rls_is_active_lease_scoped() -> None:
    migration = Path(
        "migrations/versions/20260808_0011_dataset_worker_rls.py"
    ).read_text(encoding="utf-8")

    for marker in [
        'revision: str = "20260808_0011"',
        'down_revision: str | None = "20260808_0010"',
        "datasets_execution_worker_select",
        "datasets_execution_worker_insert",
        "datasets_execution_worker_update",
        "dataset_items_execution_worker_insert",
        "dataset_append_receipts_execution_worker_select",
        "dataset_append_receipts_execution_worker_insert",
        "security.rdc_current_worker_id()",
        "security.rdc_worker_is_active()",
        "lease.status = 'ACTIVE'",
        "lease.expires_at > now()",
        "lease.work_kind = 'RUN_START'",
    ]:
        assert marker in migration

    assert "FOR DELETE" not in migration


def test_phase1n_increment4_control_plane_reuses_increment3_transaction() -> None:
    service = Path(
        "app/services/execution_plane.py"
    ).read_text(encoding="utf-8")

    for marker in [
        "async def append_worker_dataset_items(",
        '"DATASET_APPEND" not in worker.capabilities',
        "lease.payload_snapshot",
        "dataset_append_capability",
        'Dataset.name == "default"',
        "create_dataset(",
        "append_dataset_items(",
        "run.requested_by_user_id",
    ]:
        assert marker in service

    for forbidden in [
        "psycopg",
        "asyncpg.connect",
        "docker.sock",
        "subprocess",
    ]:
        assert forbidden not in service.casefold()


def test_phase1n_increment4_worker_validates_before_forwarding() -> None:
    worker = Path(
        "../../workers/sandbox-runtime/worker.py"
    ).read_text(encoding="utf-8")
    client = Path(
        "../../workers/sandbox-runtime/rdc_worker_client.py"
    ).read_text(encoding="utf-8")

    for marker in [
        "validate_dataset_append(dataset_payload)",
        "client.dataset_append(",
        "DATASET_APPEND_FAILED",
        "dataset_append_capability",
        "config.dataset_writes_enabled",
    ]:
        assert marker in worker

    assert 'f"/internal/v1/leases/{lease_id}/dataset-append"' in client

    run_call = worker.split("code, output_path, log_path = run_agent(", 1)[1]
    run_call = run_call.split(")", 1)[0]
    assert "lease_token" not in run_call
    assert "worker_token" not in run_call
    assert "database" not in run_call.casefold()


def test_phase1n_increment4_no_direct_agent_database_path() -> None:
    worker = Path(
        "../../workers/sandbox-runtime/worker.py"
    ).read_text(encoding="utf-8").casefold()

    for forbidden in [
        "postgresql://",
        "postgresql+asyncpg://",
        "psycopg",
        "asyncpg.connect",
        "rdc_database_url",
    ]:
        assert forbidden not in worker
