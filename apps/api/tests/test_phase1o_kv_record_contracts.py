from pathlib import Path

from app.core.permissions import role_has_permission, validate_scopes
from app.kv_mutation_protocol import validate_kv_mutation
from app.main import app

ROOT = Path(__file__).resolve().parents[3]


def test_phase1o_increment3_control_plane_protocol_is_canonical() -> None:
    left = validate_kv_mutation(
        {
            "schema_version": "rdc.kv-write/v1",
            "idempotency_key": "set-1",
            "operation": "set",
            "key": "crawler.state",
            "expected_version": 0,
            "content_type": "application/json",
            "encoding": "json",
            "value": {"b": 2, "a": 1},
        }
    )
    right = validate_kv_mutation(
        {
            "schema_version": "rdc.kv-write/v1",
            "idempotency_key": "set-1",
            "operation": "set",
            "key": "crawler.state",
            "expected_version": 0,
            "content_type": "application/json",
            "encoding": "json",
            "value": {"a": 1, "b": 2},
        }
    )
    assert left.request_digest == right.request_digest
    assert left.value_sha256 == right.value_sha256
    assert left.decoded_bytes == 13


def test_phase1o_increment3_permissions_are_least_privilege() -> None:
    assert validate_scopes(
        ["kv.create", "kv.read", "kv.write", "kv.delete"]
    ) == ["kv.create", "kv.delete", "kv.read", "kv.write"]
    assert role_has_permission("developer", "kv.write")
    assert role_has_permission("developer", "kv.delete")
    for role in ["analyst", "operator", "viewer"]:
        assert role_has_permission(role, "kv.read")
        assert not role_has_permission(role, "kv.write")
        assert not role_has_permission(role, "kv.delete")


def test_phase1o_increment3_mutation_routes_are_separated_by_scope() -> None:
    paths = app.openapi()["paths"]
    record_path = "/api/v1/key-value-stores/{store_id}/records"
    assert "put" in paths[record_path]
    assert "delete" in paths[record_path]

    source = (
        ROOT / "apps/api/app/api/routes/key_value_stores.py"
    ).read_text(encoding="utf-8")
    assert 'require_key_value_store_permission("kv.write")' in source
    assert 'require_key_value_store_permission("kv.delete")' in source
    assert 'required_operation="set"' in source
    assert 'required_operation="delete"' in source


def test_phase1o_increment3_migration_is_versioned_rls_and_immutable() -> None:
    source = (
        ROOT
        / "apps/api/migrations/versions/"
        "20260808_0013_key_value_records.py"
    ).read_text(encoding="utf-8")

    for marker in [
        'revision: str = "20260808_0013"',
        'down_revision: str | None = "20260808_0012"',
        "key_value_records",
        "key_value_record_versions",
        "key_value_mutation_receipts",
        "fk_key_value_records_current_version",
        "DEFERRABLE INITIALLY DEFERRED",
        "KV record version history is immutable",
        "KV mutation receipts are immutable",
        "key_value_records_current_pointer_guard",
        "ck_key_value_stores_record_quota",
        "ck_key_value_stores_byte_quota",
        "ENABLE ROW LEVEL SECURITY",
        "key_value_records_tenant",
        "key_value_record_versions_tenant",
        "key_value_mutation_receipts_tenant",
        "security.rdc_key_value_record_org",
    ]:
        assert marker in source

    lowered = source.casefold()
    for forbidden in [
        "execution_worker",
        "worker_id",
        "agent_access_key",
        "chromium",
    ]:
        assert forbidden not in lowered


def test_phase1o_increment3_service_locks_and_replays_before_writes() -> None:
    source = (
        ROOT / "apps/api/app/services/key_value_stores.py"
    ).read_text(encoding="utf-8")

    for marker in [
        "MAX_KV_RECORDS = 10_000",
        "MAX_KV_STORE_BYTES = 268_435_456",
        ".with_for_update()",
        "KV_IDEMPOTENCY_CONFLICT",
        "KV_VERSION_CONFLICT",
        "expected == 0",
        "object_storage.write_object(",
        "object_storage.delete_object(",
        '"kv_record.set"',
        '"kv_record.deleted"',
    ]:
        assert marker in source

    assert "validation.key" not in source[source.index(
        'return (\n        "kv/"'
    ):source.index(
        "async def mutate_key_value_record"
    )]


def test_phase1o_increment3_object_storage_write_is_server_side() -> None:
    source = (
        ROOT / "apps/api/app/core/s3_storage.py"
    ).read_text(encoding="utf-8")
    assert "async def write_object(" in source
    assert "internal_s3_client().put_object(" in source
    assert "sha256_digest" in source


def test_phase1o_increment3_worker_mutation_remains_disabled() -> None:
    worker = (
        ROOT / "workers/sandbox-runtime/kv_protocol.py"
    ).read_text(encoding="utf-8")
    assert "persisted: bool = False" in worker
    assert "worker_write_enabled: bool = False" in worker
    assert "object_storage_write_enabled: bool = False" in worker

    worker_lower = worker.casefold()
    for forbidden in [
        "psycopg",
        "asyncpg",
        "postgresql://",
        "boto3",
        "requests",
        "httpx",
        "subprocess",
    ]:
        assert forbidden not in worker_lower
