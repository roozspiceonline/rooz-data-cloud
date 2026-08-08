from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("Phase 1O verification failed: " + message)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_module(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    require(
        spec is not None and spec.loader is not None,
        "loader unavailable",
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def nested(depth: int) -> object:
    value: object = {"leaf": True}
    for _ in range(depth):
        value = {"next": value}
    return value


def verify_protocol() -> None:
    schema = json.loads(
        read("packages/agent-protocol/schemas/kv-write.schema.json")
    )
    branches = schema.get("oneOf")
    require(
        isinstance(branches, list) and len(branches) == 2,
        "schema branches changed",
    )
    for branch in branches:
        require(
            branch.get("additionalProperties") is False,
            "schema is not strict",
        )
        require(
            branch["properties"]["operation"]["const"] in {"set", "delete"},
            "schema operation changed",
        )

    worker = load_module(
        "workers/sandbox-runtime/kv_protocol.py",
        "rdc_phase1o_worker_kv_protocol",
    )
    control = load_module(
        "apps/api/app/kv_mutation_protocol.py",
        "rdc_phase1o_control_kv_protocol",
    )

    json_a = {
        "schema_version": "rdc.kv-write/v1",
        "idempotency_key": "run-123:json-1",
        "operation": "set",
        "key": "crawler.state",
        "expected_version": None,
        "content_type": "application/json",
        "encoding": "json",
        "value": {"b": 2, "a": 1},
    }
    json_b = {**json_a, "value": {"a": 1, "b": 2}}
    worker_a = worker.validate_kv_mutation(json_a)
    worker_b = worker.validate_kv_mutation(json_b)
    control_a = control.validate_kv_mutation(json_a)
    control_b = control.validate_kv_mutation(json_b)

    require(
        worker_a.request_digest == worker_b.request_digest,
        "worker canonical JSON digest unstable",
    )
    require(
        control_a.request_digest == control_b.request_digest,
        "control canonical JSON digest unstable",
    )
    require(
        worker_a.request_digest == control_a.request_digest,
        "worker/control canonical digest drifted",
    )
    require(
        worker_a.value_sha256 == control_a.value_sha256,
        "worker/control value digest drifted",
    )
    require(
        worker_a.decoded_bytes == control_a.decoded_bytes == 13,
        "JSON lineage changed",
    )

    text_payload = {
        "schema_version": "rdc.kv-write/v1",
        "idempotency_key": "run-123:text-1",
        "operation": "set",
        "key": "status.message",
        "expected_version": 3,
        "content_type": "text/plain; charset=utf-8",
        "encoding": "utf8",
        "value": "ready",
    }
    binary_payload = {
        "schema_version": "rdc.kv-write/v1",
        "idempotency_key": "run-123:bin-1",
        "operation": "set",
        "key": "snapshot.bytes",
        "expected_version": 0,
        "content_type": "application/octet-stream",
        "encoding": "base64",
        "value": "YWJj",
    }
    delete_payload = {
        "schema_version": "rdc.kv-write/v1",
        "idempotency_key": "run-123:delete-1",
        "operation": "delete",
        "key": "crawler.state",
        "expected_version": 4,
    }
    for payload in [text_payload, binary_payload, delete_payload]:
        worker_value = worker.validate_kv_mutation(payload)
        control_value = control.validate_kv_mutation(payload)
        require(
            worker_value.request_digest == control_value.request_digest,
            "worker/control mutation digest drifted",
        )
        require(
            worker_value.value_sha256 == control_value.value_sha256,
            "worker/control mutation value digest drifted",
        )
        require(
            worker_value.decoded_bytes == control_value.decoded_bytes,
            "worker/control decoded byte count drifted",
        )

    invalid = [
        {**json_a, "key": "../secret"},
        {**json_a, "key": "has space"},
        {**json_a, "idempotency_key": "bad key"},
        {**json_a, "operation": "replace"},
        {**json_a, "organization_id": "caller-controlled"},
        {
            **json_a,
            "content_type": "text/plain; charset=utf-8",
        },
        {**json_a, "value": {"bad": math.nan}},
        {**json_a, "expected_version": -1},
        {**json_a, "expected_version": True},
        {
            **json_a,
            "content_type": "application/octet-stream",
            "encoding": "base64",
            "value": "YQ",
        },
        {
            **json_a,
            "content_type": "text/plain; charset=utf-8",
            "encoding": "utf8",
            "value": "x" * (worker.MAX_VALUE_BYTES + 1),
        },
        {**json_a, "value": nested(worker.MAX_DEPTH + 1)},
        {
            "schema_version": "rdc.kv-write/v1",
            "idempotency_key": "run-123:delete-2",
            "operation": "delete",
            "key": "crawler.state",
            "expected_version": 4,
            "value": "forbidden",
        },
    ]
    for payload in invalid:
        worker_failed = False
        control_failed = False
        try:
            worker.validate_kv_mutation(payload)
        except worker.KVProtocolError:
            worker_failed = True
        try:
            control.validate_kv_mutation(payload)
        except control.KVProtocolError:
            control_failed = True
        require(
            worker_failed and control_failed,
            "invalid KV mutation was accepted",
        )

    worker_source = read(
        "workers/sandbox-runtime/kv_protocol.py"
    ).casefold()
    for forbidden in [
        "psycopg",
        "asyncpg",
        "postgresql://",
        "boto3",
        "requests",
        "httpx",
        "socket.",
        "subprocess",
        "docker.sock",
    ]:
        require(
            forbidden not in worker_source,
            "worker protocol gained side effect: " + forbidden,
        )

    worker_original = read("workers/sandbox-runtime/kv_protocol.py")
    for marker in [
        "persisted: bool = False",
        "worker_write_enabled: bool = False",
        "object_storage_write_enabled: bool = False",
    ]:
        require(
            marker in worker_original,
            "worker activation boundary changed: " + marker,
        )


def verify_increment2_baseline() -> None:
    migration12 = read(
        "apps/api/migrations/versions/"
        "20260808_0012_key_value_stores.py"
    )
    for marker in [
        'revision: str = "20260808_0012"',
        'down_revision: str | None = "20260808_0011"',
        "uq_key_value_stores_project_name",
        "uq_key_value_stores_run_name",
        "ck_key_value_stores_scope_lineage",
        "key_value_stores_tenancy_guard",
        "security.rdc_key_value_store_org",
        "ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY key_value_stores_tenant",
        "KV store identity fields are immutable",
    ]:
        require(
            marker in migration12,
            "Increment 2 migration missing: " + marker,
        )
    for forbidden in [
        "key_value_records",
        "key_value_record_versions",
        "key_value_mutation_receipts",
        "execution_worker",
    ]:
        require(
            forbidden not in migration12,
            "Increment 2 migration changed scope: " + forbidden,
        )

    deps_source = read("apps/api/app/api/agent_dependencies.py")
    for marker in [
        "class KeyValueStoreAccess:",
        '"rdc_key_value_store_org"',
        "def require_key_value_store_permission(",
    ]:
        require(
            marker in deps_source,
            "KV auth dependency missing: " + marker,
        )

    service_source = read("apps/api/app/services/key_value_stores.py")
    for marker in [
        'scope="PROJECT"',
        "organization_id=project.organization_id",
        "project_id=project.id",
        'scope="RUN"',
        "organization_id=run.organization_id",
        "project_id=run.project_id",
        "run_id=run.id",
        "agent_id=run.agent_id",
        "agent_version_id=run.agent_version_id",
        'action="kv_store.created"',
    ]:
        require(
            marker in service_source,
            "KV ownership derivation missing: " + marker,
        )


def verify_increment3() -> None:
    migration13 = read(
        "apps/api/migrations/versions/"
        "20260808_0013_key_value_records.py"
    )
    for marker in [
        'revision: str = "20260808_0013"',
        'down_revision: str | None = "20260808_0012"',
        "key_value_records",
        "key_value_record_versions",
        "key_value_mutation_receipts",
        "uq_key_value_records_store_key",
        "uq_key_value_record_versions_record_version",
        "uq_key_value_mutation_receipts_store_key",
        "fk_key_value_records_current_version",
        "DEFERRABLE INITIALLY DEFERRED",
        "KV record version history is immutable",
        "KV mutation receipts are immutable",
        "key_value_records_current_pointer_guard",
        "ck_key_value_stores_record_quota",
        "ck_key_value_stores_byte_quota",
        "security.rdc_key_value_record_org",
        "ENABLE ROW LEVEL SECURITY",
        "key_value_records_tenant",
        "key_value_record_versions_tenant",
        "key_value_mutation_receipts_tenant",
    ]:
        require(
            marker in migration13,
            "Increment 3 migration missing: " + marker,
        )
    lowered_migration = migration13.casefold()
    for forbidden in [
        "execution_worker",
        "worker_id",
        "chromium",
        "agent_access_key",
    ]:
        require(
            forbidden not in lowered_migration,
            "Increment 3 activated worker/Agent boundary: " + forbidden,
        )

    permissions = read("apps/api/app/core/permissions.py")
    for marker in [
        '"kv.create"',
        '"kv.read"',
        '"kv.write"',
        '"kv.delete"',
    ]:
        require(
            marker in permissions,
            "KV permission missing: " + marker,
        )
    require(
        '"kv.export"' not in permissions,
        "KV export permission enabled too early",
    )

    routes = read("apps/api/app/api/routes/key_value_stores.py")
    for marker in [
        '"/projects/{project_id}/key-value-stores"',
        '"/runs/{run_id}/key-value-stores"',
        '"/key-value-stores/{store_id}"',
        '"/key-value-stores/{store_id}/records"',
        'Depends(require_key_value_store_permission("kv.write"))',
        'Depends(require_key_value_store_permission("kv.delete"))',
        'required_operation="set"',
        'required_operation="delete"',
        "Depends(require_csrf)",
    ]:
        require(
            marker in routes,
            "KV route missing: " + marker,
        )

    service = read("apps/api/app/services/key_value_stores.py")
    for marker in [
        "MAX_KV_RECORDS = 10_000",
        "MAX_KV_STORE_BYTES = 268_435_456",
        ".with_for_update()",
        "KV_IDEMPOTENCY_CONFLICT",
        "KV_VERSION_CONFLICT",
        "expected == 0",
        "_server_object_key(",
        "object_storage.write_object(",
        "object_storage.delete_object(",
        '"kv_record.set"',
        '"kv_record.deleted"',
    ]:
        require(
            marker in service,
            "KV mutation service missing: " + marker,
        )

    key_function = service[
        service.index("def _server_object_key("):
        service.index("async def mutate_key_value_record(")
    ]
    require(
        "validation.key" not in key_function,
        "logical KV key entered the object-storage key function",
    )

    s3_source = read("apps/api/app/core/s3_storage.py")
    for marker in [
        "async def write_object(",
        "internal_s3_client().put_object(",
        "sha256_digest",
    ]:
        require(
            marker in s3_source,
            "server-side object write missing: " + marker,
        )

    models = read("apps/api/app/models.py")
    for marker in [
        "class KeyValueRecord(",
        "class KeyValueRecordVersion(",
        "class KeyValueMutationReceipt(",
    ]:
        require(
            marker in models,
            "KV ORM model missing: " + marker,
        )

    schemas = read("apps/api/app/kv_schemas.py")
    require(
        "class KeyValueMutationReceiptSummary(" in schemas,
        "KV mutation response schema missing",
    )

    tests = read("apps/api/tests/test_phase1o_kv_record_contracts.py")
    for marker in [
        "test_phase1o_increment3_control_plane_protocol_is_canonical",
        "test_phase1o_increment3_permissions_are_least_privilege",
        "test_phase1o_increment3_mutation_routes_are_separated_by_scope",
        "test_phase1o_increment3_migration_is_versioned_rls_and_immutable",
        "test_phase1o_increment3_service_locks_and_replays_before_writes",
        "test_phase1o_increment3_worker_mutation_remains_disabled",
    ]:
        require(
            marker in tests,
            "Increment 3 test missing: " + marker,
        )


def verify_docs_and_baseline() -> None:
    for path, markers in {
        "docs/phase1o/README.md": [
            "rdc.kv-write/v1",
            "Increment 3 — versioned records + object-backed values",
            "Worker KV mutation                    disabled",
            "Agent direct PostgreSQL               prohibited",
        ],
        "docs/phase1o/RUNBOOK.md": [
            "path-like keys such as `../secret`",
            "Increment 3 mutation state",
            "same idempotency key + different digest",
            "weakens Phase 1N Dataset controls",
        ],
        "docs/phase1o/THREAT_MODEL.md": [
            "Path traversal / object-key confusion",
            "optimistic concurrency",
            "Increment 3 mutation controls",
            "General untrusted Agent execution remains release-blocked.",
        ],
    }.items():
        source = read(path)
        for marker in markers:
            require(
                marker in source,
                path + " missing: " + marker,
            )

    workflow = read(".github/workflows/ci.yml")
    require(
        "- run: python3 scripts/verify-phase1n.py\n"
        "      - run: python3 scripts/verify-phase1o.py\n"
        in workflow,
        "Phase 1O verifier not chained",
    )

    main_source = read("apps/api/app/main.py")
    for marker in [
        'version="0.14.0-phase1n"',
        '"phase": "1N"',
        '"status": "tenant-dataset-durable-results"',
        '"dataset_public_export_enabled": False',
        '"untrusted_agent_execution_enabled": False',
    ]:
        require(
            marker in main_source,
            "Phase 1N advertised baseline changed: " + marker,
        )


def main() -> None:
    verify_protocol()
    verify_increment2_baseline()
    verify_increment3()
    verify_docs_and_baseline()
    print("Phase 1O Increment 3 KV record verification: PASS")
    print("  contract: rdc.kv-write/v1")
    print("  KV metadata + record persistence + RLS: ENABLED")
    print("  object-backed control-plane SET/DELETE: ENABLED")
    print("  optimistic concurrency + idempotency: ENABLED")
    print("  immutable version/tombstone lineage: ENABLED")
    print("  worker KV path: DISABLED")
    print("  Agent/Chromium DB or object credentials: PROHIBITED")


if __name__ == "__main__":
    main()
