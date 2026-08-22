from pathlib import Path

import pytest

from app.kv_worker_protocol import (
    KVWorkerProtocolError,
    validate_kv_read_request,
)


def test_phase1o_increment4_worker_gate_defaults_off() -> None:
    api_config = Path("app/core/config.py").read_text(encoding="utf-8")
    worker_config = Path(
        "../../workers/sandbox-runtime/config.py"
    ).read_text(encoding="utf-8")
    env = Path("../../.env.example").read_text(encoding="utf-8")
    compose = Path("../../docker-compose.yml").read_text(encoding="utf-8")

    assert "sandbox_canary_key_value_store_enabled: bool = False" in api_config
    assert "key_value_store_enabled: bool" in worker_config
    assert "RDC_SANDBOX_CANARY_KEY_VALUE_STORE_ENABLED=false" in env
    assert "RDC_SANDBOX_CANARY_KEY_VALUE_STORE_ENABLED" in compose


def test_phase1o_increment4_read_contract_is_bounded() -> None:
    value = validate_kv_read_request(
        {
            "schema_version": "rdc.kv-worker-read/v1",
            "keys": ["crawler.state", "cursor.next"],
        }
    )
    assert value.keys == ("crawler.state", "cursor.next")
    assert len(value.request_digest) == 64

    with pytest.raises(KVWorkerProtocolError):
        validate_kv_read_request(
            {
                "schema_version": "rdc.kv-worker-read/v1",
                "keys": ["../secret"],
            }
        )
    with pytest.raises(KVWorkerProtocolError):
        validate_kv_read_request(
            {
                "schema_version": "rdc.kv-worker-read/v1",
                "keys": ["same", "same"],
            }
        )


def test_phase1o_increment4_worker_capability_is_explicit() -> None:
    schemas = Path("app/execution_schemas.py").read_text(encoding="utf-8")
    assert '"KV_ACCESS"' in schemas
    assert "key_value_store_enabled: bool = False" in schemas
    assert "max_length=8" in schemas


def test_phase1o_increment4_internal_routes_are_hidden() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/internal/v1/leases/{lease_id}/kv-read" not in paths
    assert "/internal/v1/leases/{lease_id}/kv-mutate" not in paths

    source = Path(
        "app/api/routes/internal_execution.py"
    ).read_text(encoding="utf-8")
    for marker in [
        '"/leases/{lease_id}/kv-read"',
        '"/leases/{lease_id}/kv-mutate"',
        "Depends(require_lease_access)",
        "read_worker_key_value_records",
        "mutate_worker_key_value_record",
    ]:
        assert marker in source


def test_phase1o_increment4_rls_is_active_run_lease_scoped() -> None:
    migration = Path(
        "migrations/versions/20260808_0014_kv_worker_rls.py"
    ).read_text(encoding="utf-8")

    for marker in [
        'revision: str = "20260808_0014"',
        'down_revision: str | None = "20260808_0013"',
        "key_value_stores_execution_worker_select",
        "key_value_records_execution_worker_update",
        "key_value_record_versions_execution_worker_insert",
        "key_value_mutation_receipts_execution_worker_insert",
        "security.rdc_current_worker_id()",
        "security.rdc_worker_is_active()",
        "lease.status = 'ACTIVE'",
        "lease.expires_at > now()",
        "lease.work_kind = 'RUN_START'",
        "store.scope = 'RUN'",
    ]:
        assert marker in migration
    assert "FOR DELETE" not in migration


def test_phase1o_increment4_reuses_increment3_persistence() -> None:
    source = Path(
        "app/services/worker_key_value_store.py"
    ).read_text(encoding="utf-8")

    for marker in [
        "create_run_key_value_store(",
        "mutate_key_value_record(",
        "object_storage.read_object(",
        '"KV_ACCESS"',
        "key_value_store_capability(",
    ]:
        assert marker in source

    for forbidden in [
        "psycopg",
        "asyncpg.connect",
        "docker.sock",
        "subprocess",
    ]:
        assert forbidden not in source.casefold()


def test_phase1o_increment4_worker_validates_before_forwarding() -> None:
    worker = Path(
        "../../workers/sandbox-runtime/worker.py"
    ).read_text(encoding="utf-8")
    client = Path(
        "../../workers/sandbox-runtime/rdc_worker_client.py"
    ).read_text(encoding="utf-8")

    for marker in [
        "validate_kv_read_request(",
        "validate_kv_read_result(",
        "validate_kv_worker_output(",
        "client.kv_read(",
        "client.kv_mutate(",
        "KV_READ_FAILED",
        "KV_MUTATION_FAILED",
        "config.key_value_store_enabled",
    ]:
        assert marker in worker

    assert 'f"/internal/v1/leases/{lease_id}/kv-read"' in client
    assert 'f"/internal/v1/leases/{lease_id}/kv-mutate"' in client

    run_call = worker.split("code, output_path, log_path = run_agent(", 1)[1]
    run_call = run_call.split(")", 1)[0].casefold()
    for forbidden in [
        "lease_token",
        "worker_token",
        "database",
        "s3_access",
        "s3_secret",
    ]:
        assert forbidden not in run_call


def test_phase1o_increment4_composition_is_conservative() -> None:
    service = Path(
        "app/services/execution_plane.py"
    ).read_text(encoding="utf-8")
    worker = Path(
        "../../workers/sandbox-runtime/worker.py"
    ).read_text(encoding="utf-8")

    assert "dataset and kv_runtime_enabled" in service
    assert "browser and kv_runtime_enabled" in service
    assert "dataset and kv_runtime_enabled" in worker
    assert "browser and kv_runtime_enabled" in worker
