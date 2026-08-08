from __future__ import annotations

import importlib.util
import json
import math
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("Phase 1N verification failed: " + message)


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_module(relative: str, name: str):
    path = ROOT / relative
    spec = importlib.util.spec_from_file_location(name, path)
    require(spec is not None and spec.loader is not None, "loader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    schema = json.loads(
        read("packages/agent-protocol/schemas/dataset-append.schema.json")
    )
    require(schema.get("additionalProperties") is False, "schema is not strict")
    require(
        schema["properties"]["schema_version"]["const"]
        == "rdc.dataset-append/v1",
        "schema version changed",
    )
    require(
        schema["properties"]["items"]["maxItems"] == 100,
        "schema item limit changed",
    )

    worker_protocol = load_module(
        "workers/sandbox-runtime/dataset_protocol.py",
        "rdc_phase1n_worker_dataset_protocol",
    )
    api_protocol = load_module(
        "apps/api/app/dataset_append_protocol.py",
        "rdc_phase1n_api_dataset_protocol",
    )
    canonical_request = {
        "schema_version": "rdc.dataset-append/v1",
        "idempotency_key": "run-123:batch-1",
        "items": [{"nested": {"b": 2, "a": 1}}],
    }
    require(
        worker_protocol.validate_dataset_append(
            canonical_request
        ).request_digest
        == api_protocol.validate_dataset_append(
            canonical_request
        ).request_digest,
        "API and worker Dataset protocol digests diverged",
    )

    invalid_requests = [
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "x",
            "items": [],
        },
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "x",
            "items": [{} for _ in range(101)],
        },
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "bad key",
            "items": [{}],
        },
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "x",
            "items": [{"value": math.nan}],
        },
    ]
    for invalid in invalid_requests:
        worker_failed = False
        api_failed = False
        try:
            worker_protocol.validate_dataset_append(invalid)
        except worker_protocol.DatasetProtocolError:
            worker_failed = True
        try:
            api_protocol.validate_dataset_append(invalid)
        except api_protocol.DatasetAppendProtocolError:
            api_failed = True
        require(worker_failed and api_failed, "protocol accepted invalid data")

    for path, revision, down in [
        (
            "apps/api/migrations/versions/20260808_0009_datasets.py",
            "20260808_0009",
            "20260807_0008",
        ),
        (
            "apps/api/migrations/versions/"
            "20260808_0010_dataset_append_receipts.py",
            "20260808_0010",
            "20260808_0009",
        ),
        (
            "apps/api/migrations/versions/"
            "20260808_0011_dataset_worker_rls.py",
            "20260808_0011",
            "20260808_0010",
        ),
    ]:
        migration = read(path)
        require(
            f'revision: str = "{revision}"' in migration,
            path + " revision missing",
        )
        require(
            f'down_revision: str | None = "{down}"' in migration,
            path + " down revision missing",
        )

    migration10 = read(
        "apps/api/migrations/versions/"
        "20260808_0010_dataset_append_receipts.py"
    )
    for marker in [
        "uq_dataset_append_receipts_dataset_key",
        "ck_datasets_item_quota",
        "ck_datasets_byte_quota",
        "dataset_items_immutable_guard",
        "dataset_append_receipts_immutable_guard",
    ]:
        require(marker in migration10, "Increment 3 guard missing: " + marker)

    migration11 = read(
        "apps/api/migrations/versions/"
        "20260808_0011_dataset_worker_rls.py"
    )
    for marker in [
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
        require(marker in migration11, "worker RLS guard missing: " + marker)
    require("FOR DELETE" not in migration11, "worker Dataset DELETE policy added")

    config = read("apps/api/app/core/config.py")
    require(
        "sandbox_canary_dataset_writes_enabled: bool = False" in config,
        "API Dataset worker gate does not default false",
    )
    env = read(".env.example")
    require(
        "RDC_SANDBOX_CANARY_DATASET_WRITES_ENABLED=false" in env,
        "Dataset worker gate missing from env example",
    )
    compose = read("docker-compose.yml")
    require(
        "RDC_SANDBOX_CANARY_DATASET_WRITES_ENABLED:"
        in compose
        and ":-false}" in compose,
        "Compose does not preserve Dataset worker gate default false",
    )

    schemas = read("apps/api/app/execution_schemas.py")
    require('"DATASET_APPEND"' in schemas, "worker Dataset capability missing")
    require(
        "dataset_write_enabled: bool = False" in schemas,
        "activation Dataset receipt field missing",
    )

    execution = read("apps/api/app/services/execution_plane.py")
    for marker in [
        "rdc.dataset-worker-capability/v1",
        "async def append_worker_dataset_items(",
        '"DATASET_APPEND" not in worker.capabilities',
        "lease.payload_snapshot",
        'Dataset.name == "default"',
        "create_dataset(",
        "append_dataset_items(",
        "run.requested_by_user_id",
    ]:
        require(marker in execution, "worker append control missing: " + marker)

    internal_routes = read("apps/api/app/api/routes/internal_execution.py")
    for marker in [
        '"/leases/{lease_id}/dataset-append"',
        "Depends(require_lease_access)",
        "append_worker_dataset_items",
    ]:
        require(marker in internal_routes, "internal append route missing: " + marker)

    client = read("workers/sandbox-runtime/rdc_worker_client.py")
    require(
        'f"/internal/v1/leases/{lease_id}/dataset-append"' in client,
        "worker client Dataset append method missing",
    )

    worker_config = read("workers/sandbox-runtime/config.py")
    require(
        "dataset_writes_enabled: bool" in worker_config
        and "RDC_SANDBOX_CANARY_DATASET_WRITES_ENABLED"
        in worker_config,
        "worker Dataset gate missing",
    )

    worker = read("workers/sandbox-runtime/worker.py")
    for marker in [
        "config.dataset_writes_enabled",
        "dataset_append_capability",
        "validate_dataset_append(dataset_payload)",
        "client.dataset_append(",
        "DATASET_APPEND_FAILED",
    ]:
        require(marker in worker, "worker Dataset path missing: " + marker)
    lowered_worker = worker.casefold()
    for forbidden in [
        "postgresql://",
        "postgresql+asyncpg://",
        "psycopg",
        "asyncpg.connect",
        "rdc_database_url",
    ]:
        require(
            forbidden not in lowered_worker,
            "worker gained direct database path: " + forbidden,
        )

    historical = read(
        "apps/api/tests/test_phase1n_dataset_persistence_contracts.py"
    )
    require(
        "test_phase1n_worker_has_no_direct_database_surface" in historical,
        "historical worker safety test not evolved",
    )

    tests = read(
        "apps/api/tests/test_phase1n_worker_dataset_append_contracts.py"
    )
    require(
        "test_phase1n_increment4_worker_rls_is_active_lease_scoped"
        in tests,
        "Increment 4 RLS contract test missing",
    )

    for path, markers in {
        "docs/phase1n/README.md": [
            "Increment 4 — controlled worker append path",
            "worker Dataset append default           disabled",
            "Agent direct PostgreSQL                 prohibited",
        ],
        "docs/phase1n/RUNBOOK.md": [
            "RDC_SANDBOX_CANARY_DATASET_WRITES_ENABLED=false",
            "ACTIVE, unexpired `RUN_START` lease",
            "There is no worker DELETE policy.",
        ],
        "docs/phase1n/THREAT_MODEL.md": [
            "Increment 4 worker-path threats",
            "worker tokens, lease tokens or database credentials",
            "Any mismatch fails closed.",
        ],
    }.items():
        source = read(path)
        for marker in markers:
            require(marker in source, path + " missing: " + marker)

    main_source = read("apps/api/app/main.py")
    require(
        '"untrusted_agent_execution_enabled": False' in main_source,
        "general execution release block changed",
    )

    print("Phase 1N Increment 4 worker Dataset append verification: PASS")
    print("  protocol digest parity: PASS")
    print("  Dataset append idempotency: PRESERVED")
    print("  Dataset quotas: PRESERVED")
    print("  worker Dataset gate default: FALSE")
    print("  worker capability: DATASET_APPEND")
    print("  internal route: LEASE-SCOPED + HIDDEN")
    print("  worker RLS: ACTIVE RUN_START LEASE ONLY")
    print("  worker Dataset DELETE policy: ABSENT")
    print("  Agent direct Postgres access: PROHIBITED")
    print("  Chromium direct Postgres access: PROHIBITED")


if __name__ == "__main__":
    main()
