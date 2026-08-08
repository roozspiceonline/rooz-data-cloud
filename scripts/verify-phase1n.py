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


def load_protocol():
    path = ROOT / "workers/sandbox-runtime/dataset_protocol.py"
    spec = importlib.util.spec_from_file_location(
        "rdc_phase1n_dataset_protocol",
        path,
    )
    require(spec is not None and spec.loader is not None, "loader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def expect_rejected(module, value: object, label: str) -> None:
    try:
        module.validate_dataset_append(value)
    except module.DatasetProtocolError:
        return
    raise SystemExit(
        "Phase 1N verification failed: invalid request accepted: " + label
    )


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

    module = load_protocol()
    left = {
        "schema_version": "rdc.dataset-append/v1",
        "idempotency_key": "run-123:batch-1",
        "items": [
            {
                "url": "https://example.com/",
                "title": "Example",
                "nested": {"b": 2, "a": 1},
            }
        ],
    }
    right = {
        "items": [
            {
                "nested": {"a": 1, "b": 2},
                "title": "Example",
                "url": "https://example.com/",
            }
        ],
        "idempotency_key": "run-123:batch-1",
        "schema_version": "rdc.dataset-append/v1",
    }
    first = module.validate_dataset_append(left)
    second = module.validate_dataset_append(right)
    require(first.request_digest == second.request_digest, "digest not canonical")
    require(first.persisted is False, "protocol persistence flag changed")
    require(
        first.worker_write_enabled is False,
        "worker Dataset writes enabled in protocol",
    )

    for value, label in [
        (
            {
                "schema_version": "rdc.dataset-append/v1",
                "idempotency_key": "x",
                "items": [],
            },
            "empty items",
        ),
        (
            {
                "schema_version": "rdc.dataset-append/v1",
                "idempotency_key": "x",
                "items": [{} for _ in range(101)],
            },
            "too many items",
        ),
        (
            {
                "schema_version": "rdc.dataset-append/v1",
                "idempotency_key": "bad key with spaces",
                "items": [{}],
            },
            "bad idempotency key",
        ),
        (
            {
                "schema_version": "rdc.dataset-append/v1",
                "idempotency_key": "x",
                "items": [{"value": math.nan}],
            },
            "NaN",
        ),
        (
            {
                "schema_version": "rdc.dataset-append/v1",
                "idempotency_key": "x",
                "items": [{"value": {"not", "json"}}],
            },
            "non-JSON value",
        ),
        (
            {
                "schema_version": "rdc.dataset-append/v1",
                "idempotency_key": "x",
                "items": [{"payload": "x" * 70_000}],
            },
            "oversized item",
        ),
    ]:
        expect_rejected(module, value, label)

    protocol_source = read("workers/sandbox-runtime/dataset_protocol.py")
    for forbidden in (
        "sqlalchemy",
        "psycopg",
        "asyncpg",
        "socket.",
        "subprocess",
        "requests.",
        "httpx.",
    ):
        require(
            forbidden not in protocol_source,
            "protocol foundation gained side effect: " + forbidden,
        )

    migration = read(
        "apps/api/migrations/versions/20260808_0009_datasets.py"
    )
    for marker in [
        'revision: str = "20260808_0009"',
        'down_revision: str | None = "20260807_0008"',
        '"datasets"',
        '"dataset_items"',
        "uq_datasets_run_name",
        "uq_dataset_items_dataset_sequence",
        "enforce_dataset_tenancy",
        "enforce_dataset_item_tenancy",
        "datasets_tenancy_guard",
        "dataset_items_tenancy_guard",
        "rdc_dataset_org",
        "datasets_tenant",
        "dataset_items_tenant",
        "ENABLE ROW LEVEL SECURITY",
    ]:
        require(marker in migration, "Dataset migration missing: " + marker)
    require(
        "datasets_worker" not in migration
        and "dataset_items_worker" not in migration,
        "worker Dataset RLS policy enabled too early",
    )

    models = read("apps/api/app/models.py")
    for marker in [
        "class Dataset(UUIDPrimaryKeyMixin, TimestampMixin, Base):",
        'ForeignKey("control.runs.id", ondelete="CASCADE")',
        "class DatasetItem(UUIDPrimaryKeyMixin, Base):",
        '"uq_datasets_run_name"',
        '"uq_dataset_items_dataset_sequence"',
    ]:
        require(marker in models, "Dataset model missing: " + marker)

    permissions = read("apps/api/app/core/permissions.py")
    for marker in [
        '"dataset.create"',
        '"dataset.read"',
    ]:
        require(marker in permissions, "Dataset permission missing: " + marker)

    dependencies = read("apps/api/app/api/agent_dependencies.py")
    for marker in [
        "class DatasetAccess:",
        '"rdc_dataset_org"',
        "def require_dataset_permission(",
        "select(Dataset).where(",
    ]:
        require(
            marker in dependencies,
            "Dataset authorization dependency missing: " + marker,
        )

    routes = read("apps/api/app/api/routes/datasets.py")
    for marker in [
        '"/runs/{run_id}/datasets"',
        'require_run_permission("dataset.create")',
        '"/projects/{project_id}/datasets"',
        'require_project_permission("dataset.read")',
        '"/datasets/{dataset_id}"',
        'require_dataset_permission("dataset.read")',
    ]:
        require(marker in routes, "Dataset metadata route missing: " + marker)
    require(
        "/datasets/{dataset_id}/items" not in routes,
        "Dataset item route activated too early",
    )

    service = read("apps/api/app/services/datasets.py")
    for marker in [
        "organization_id=run.organization_id",
        "project_id=run.project_id",
        "run_id=run.id",
        "agent_id=run.agent_id",
        "agent_version_id=run.agent_version_id",
        'action="dataset.created"',
    ]:
        require(
            marker in service,
            "server-derived Dataset lineage missing: " + marker,
        )
    for forbidden in [
        "DatasetItem(",
        "subprocess",
        "os.system",
        "docker.sock",
        "psycopg",
        "asyncpg",
    ]:
        require(
            forbidden not in service,
            "Dataset metadata service gained forbidden surface: " + forbidden,
        )

    schemas = read("apps/api/app/dataset_schemas.py")
    require(
        "class CreateDatasetRequest(StrictModel):" in schemas
        and "organization_id" not in schemas.split(
            "class CreateDatasetRequest", 1
        )[1].split("class DatasetSummary", 1)[0],
        "Dataset creation schema accepts ownership fields",
    )

    main_source = read("apps/api/app/main.py")
    require(
        "from .api.routes.datasets import router as datasets_router"
        in main_source,
        "Dataset router import missing",
    )
    require(
        "v1_router.include_router(datasets_router)" in main_source,
        "Dataset router not mounted",
    )
    require(
        '"untrusted_agent_execution_enabled": False' in main_source,
        "general untrusted execution release block changed",
    )

    worker = read("workers/sandbox-runtime/worker.py")
    for forbidden in [
        "append_dataset_items",
        "create_dataset_item",
        "dataset_write_enabled",
    ]:
        require(
            forbidden not in worker,
            "worker Dataset write path enabled too early: " + forbidden,
        )

    for path, markers in {
        "docs/phase1n/README.md": [
            "Increment 2 — Dataset metadata persistence + RLS",
            "Dataset item append API        disabled",
            "worker Dataset writes          disabled",
        ],
        "docs/phase1n/RUNBOOK.md": [
            "control.datasets                present + RLS",
            "Dataset item append route       absent",
            "no worker Dataset RLS policy",
        ],
        "docs/phase1n/THREAT_MODEL.md": [
            "Increment 2 mitigations",
            "DatasetItem append route exists",
        ],
    }.items():
        source = read(path)
        if path.endswith("THREAT_MODEL.md"):
            require(
                "no DatasetItem append route exists" in source,
                "Threat model does not preserve disabled append",
            )
            continue
        for marker in markers:
            require(marker in source, path + " missing: " + marker)

    print("Phase 1N Increment 2 Dataset persistence verification: PASS")
    print("  Increment 1 protocol: PASS")
    print("  control.datasets: PRESENT + RLS")
    print("  control.dataset_items: PRESENT + RLS")
    print("  Dataset metadata API: AUTHENTICATED")
    print("  server-derived Run lineage: PASS")
    print("  Dataset item append API: DISABLED")
    print("  worker Dataset writes: DISABLED")
    print("  worker Dataset RLS policy: ABSENT")
    print("  Agent direct Postgres access: PROHIBITED")


if __name__ == "__main__":
    main()
