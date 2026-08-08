from __future__ import annotations

import importlib.util
import json
import math
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
    require(first.item_count == 1, "valid item count changed")
    require(first.persisted is False, "persistence enabled too early")
    require(
        first.worker_write_enabled is False,
        "worker Dataset writes enabled too early",
    )

    expect_rejected(
        module,
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "x",
            "items": [],
        },
        "empty items",
    )
    expect_rejected(
        module,
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "x",
            "items": [{} for _ in range(101)],
        },
        "too many items",
    )
    expect_rejected(
        module,
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "bad key with spaces",
            "items": [{}],
        },
        "bad idempotency key",
    )
    expect_rejected(
        module,
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "x",
            "items": [{"value": math.nan}],
        },
        "NaN",
    )
    expect_rejected(
        module,
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "x",
            "items": [{"value": {"not", "json"}}],
        },
        "non-JSON value",
    )
    expect_rejected(
        module,
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "x",
            "items": [{"payload": "x" * 70_000}],
        },
        "oversized item",
    )
    expect_rejected(
        module,
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "x",
            "items": [{}],
            "organization_id": "caller-controlled",
        },
        "caller ownership field",
    )

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

    for path, markers in {
        "docs/phase1n/README.md": [
            "rdc.dataset-append/v1",
            "Dataset persistence            disabled",
            "Agent direct Postgres access   prohibited",
            "Phase 1O",
            "Phase 1P",
        ],
        "docs/phase1n/THREAT_MODEL.md": [
            "Cross-tenant Dataset writes",
            "PostgreSQL RLS",
            "unique idempotency constraint",
            "no direct Agent/Chromium database network path",
        ],
        "docs/phase1n/RUNBOOK.md": [
            "database Dataset tables         absent",
            "worker Dataset append           absent",
            "control-plane mediated",
        ],
    }.items():
        source = read(path)
        for marker in markers:
            require(marker in source, path + " missing: " + marker)

    ci = read(".github/workflows/ci.yml")
    require(
        "python3 scripts/verify-phase1n.py" in ci,
        "Phase 1N verifier is not wired into CI",
    )

    main_source = read("apps/api/app/main.py")
    require(
        '"phase": "1M"' in main_source,
        "Phase 1N foundation changed API phase before persistence exists",
    )
    require(
        '"untrusted_agent_execution_enabled": False' in main_source,
        "general execution release block changed",
    )

    print("Phase 1N Dataset protocol foundation verification: PASS")
    print("  request contract: rdc.dataset-append/v1")
    print("  JSON-object records only: PASS")
    print("  canonical SHA-256 digest: PASS")
    print("  idempotency key required: PASS")
    print("  max items per batch: 100")
    print("  max item bytes: 65536")
    print("  max batch bytes: 262144")
    print("  max JSON depth: 32")
    print("  Dataset persistence: DISABLED")
    print("  worker Dataset writes: DISABLED")
    print("  Agent direct Postgres access: PROHIBITED")


if __name__ == "__main__":
    main()
