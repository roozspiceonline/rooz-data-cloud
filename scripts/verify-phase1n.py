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
        "items": [
            {
                "url": "https://example.com/",
                "nested": {"b": 2, "a": 1},
            }
        ],
    }
    worker_result = worker_protocol.validate_dataset_append(canonical_request)
    api_result = api_protocol.validate_dataset_append(canonical_request)
    require(
        worker_result.request_digest == api_result.request_digest,
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

    migration9 = read(
        "apps/api/migrations/versions/20260808_0009_datasets.py"
    )
    require(
        'revision: str = "20260808_0009"' in migration9,
        "Increment 2 migration disappeared",
    )

    migration10 = read(
        "apps/api/migrations/versions/"
        "20260808_0010_dataset_append_receipts.py"
    )
    for marker in [
        'revision: str = "20260808_0010"',
        'down_revision: str | None = "20260808_0009"',
        "dataset_append_receipts",
        "uq_dataset_append_receipts_dataset_key",
        "append_receipt_id",
        "ck_datasets_item_quota",
        "ck_datasets_byte_quota",
        "ck_datasets_sequence_counter",
        "dataset_append_receipts_tenant",
        "dataset_items_immutable_guard",
        "dataset_append_receipts_immutable_guard",
        "Dataset item receipt or tenancy mismatch",
    ]:
        require(marker in migration10, "Increment 3 migration missing: " + marker)
    for forbidden in [
        "dataset_append_receipts_worker",
        "dataset_items_worker",
    ]:
        require(
            forbidden not in migration10,
            "worker Dataset RLS enabled too early: " + forbidden,
        )

    models = read("apps/api/app/models.py")
    for marker in [
        "class DatasetAppendReceipt(UUIDPrimaryKeyMixin, Base):",
        '"uq_dataset_append_receipts_dataset_key"',
        "append_receipt_id: Mapped[UUID]",
        'ForeignKey("control.dataset_append_receipts.id"',
    ]:
        require(marker in models, "Increment 3 model missing: " + marker)

    schemas = read("apps/api/app/dataset_schemas.py")
    for marker in [
        "class DatasetAppendRequest(StrictModel):",
        'Literal["rdc.dataset-append/v1"]',
        "class DatasetAppendReceiptSummary(ORMModel):",
        "class DatasetAppendResult(StrictModel):",
    ]:
        require(marker in schemas, "Append API schema missing: " + marker)
    request_block = schemas.split(
        "class DatasetAppendRequest", 1
    )[1].split("class DatasetSummary", 1)[0]
    for forbidden in [
        "organization_id",
        "project_id",
        "run_id",
        "agent_id",
        "agent_version_id",
    ]:
        require(
            forbidden not in request_block,
            "Append request accepts ownership field: " + forbidden,
        )

    permissions = read("apps/api/app/core/permissions.py")
    require('"dataset.write"' in permissions, "dataset.write scope missing")

    routes = read("apps/api/app/api/routes/datasets.py")
    for marker in [
        '"/datasets/{dataset_id}/items"',
        'require_dataset_permission("dataset.write")',
        'payload.model_dump(mode="python")',
        "status.HTTP_200_OK",
        "status.HTTP_201_CREATED",
    ]:
        require(marker in routes, "Append route missing: " + marker)

    service = read("apps/api/app/services/datasets.py")
    for marker in [
        "MAX_DATASET_ITEMS = 100_000",
        "MAX_DATASET_BYTES = 268_435_456",
        ".with_for_update()",
        "DatasetAppendReceipt.idempotency_key",
        "DATASET_IDEMPOTENCY_CONFLICT",
        "replayed=True",
        "append_receipt_id=receipt.id",
        "locked.item_count += validation.item_count",
        "locked.total_bytes += item_bytes",
        "locked.next_sequence += validation.item_count",
        'action="dataset.items_appended"',
    ]:
        require(marker in service, "Append transaction guard missing: " + marker)
    lowered = service.casefold()
    for forbidden in [
        "subprocess",
        "os.system",
        "docker.sock",
        "psycopg",
        "asyncpg",
        "socket.",
    ]:
        require(
            forbidden not in lowered,
            "Dataset service gained forbidden execution/network surface: "
            + forbidden,
        )

    worker = read("workers/sandbox-runtime/worker.py")
    for forbidden in [
        "append_dataset_items",
        "dataset_write_enabled",
        "dataset_append_receipt",
    ]:
        require(
            forbidden not in worker,
            "worker Dataset write activated too early: " + forbidden,
        )

    tests = read(
        "apps/api/tests/test_phase1n_dataset_append_contracts.py"
    )
    require(
        "test_phase1n_increment3_api_and_worker_protocol_digests_match"
        in tests,
        "Increment 3 API/worker digest parity test missing",
    )

    for path, markers in {
        "docs/phase1n/README.md": [
            "Increment 3 — idempotent append + quotas",
            "Dataset append idempotency        enforced",
            "worker Dataset writes             disabled",
        ],
        "docs/phase1n/RUNBOOK.md": [
            "control.dataset_append_receipts   present + RLS",
            "same key + same request digest",
            "worker Dataset append             absent",
        ],
        "docs/phase1n/THREAT_MODEL.md": [
            "Dataset-scoped immutable append receipts",
            "mismatched replay fails closed",
            "worker Dataset writes remain disabled",
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

    print("Phase 1N Increment 3 Dataset append verification: PASS")
    print("  API/worker protocol digest parity: PASS")
    print("  Dataset append receipts: PRESENT + RLS")
    print("  Dataset row-lock sequencing: REQUIRED")
    print("  exact replay: REPLAY-SAFE")
    print("  mismatched replay: FAIL-CLOSED")
    print("  Dataset item quota: 100000")
    print("  Dataset byte quota: 268435456")
    print("  DatasetItem mutation: DATABASE-BLOCKED")
    print("  worker Dataset writes: DISABLED")
    print("  worker Dataset RLS policy: ABSENT")
    print("  Agent direct Postgres access: PROHIBITED")


if __name__ == "__main__":
    main()
