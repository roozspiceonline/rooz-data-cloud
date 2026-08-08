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
    require(spec is not None and spec.loader is not None, "loader unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def nested(depth: int) -> object:
    value: object = {"leaf": True}
    for _ in range(depth):
        value = {"next": value}
    return value


def main() -> None:
    schema = json.loads(read("packages/agent-protocol/schemas/kv-write.schema.json"))
    branches = schema.get("oneOf")
    require(isinstance(branches, list) and len(branches) == 2, "schema branches changed")
    for branch in branches:
        require(branch.get("additionalProperties") is False, "schema is not strict")
        require(branch["properties"]["operation"]["const"] in {"set", "delete"}, "schema operation changed")

    protocol = load_module("workers/sandbox-runtime/kv_protocol.py", "rdc_phase1o_worker_kv_protocol")

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
    a = protocol.validate_kv_mutation(json_a)
    b = protocol.validate_kv_mutation(json_b)
    require(a.request_digest == b.request_digest, "canonical JSON digest unstable")
    require(a.decoded_bytes == 13 and a.value_sha256 is not None, "JSON lineage changed")

    text = protocol.validate_kv_mutation({
        "schema_version": "rdc.kv-write/v1", "idempotency_key": "run-123:text-1",
        "operation": "set", "key": "status.message", "expected_version": 3,
        "content_type": "text/plain; charset=utf-8", "encoding": "utf8", "value": "ready",
    })
    require(text.decoded_bytes == 5, "UTF-8 byte count changed")

    binary = protocol.validate_kv_mutation({
        "schema_version": "rdc.kv-write/v1", "idempotency_key": "run-123:bin-1",
        "operation": "set", "key": "snapshot.bytes", "expected_version": 0,
        "content_type": "application/octet-stream", "encoding": "base64", "value": "YWJj",
    })
    require(binary.decoded_bytes == 3, "base64 byte count changed")

    deleted = protocol.validate_kv_mutation({
        "schema_version": "rdc.kv-write/v1", "idempotency_key": "run-123:delete-1",
        "operation": "delete", "key": "crawler.state", "expected_version": 4,
    })
    require(deleted.value_sha256 is None and deleted.decoded_bytes == 0, "delete state changed")

    invalid = [
        {**json_a, "key": "../secret"},
        {**json_a, "key": "has space"},
        {**json_a, "idempotency_key": "bad key"},
        {**json_a, "operation": "replace"},
        {**json_a, "organization_id": "caller-controlled"},
        {**json_a, "content_type": "text/plain; charset=utf-8"},
        {**json_a, "value": {"bad": math.nan}},
        {**json_a, "expected_version": -1},
        {**json_a, "expected_version": True},
        {**json_a, "content_type": "application/octet-stream", "encoding": "base64", "value": "YQ"},
        {**json_a, "content_type": "text/plain; charset=utf-8", "encoding": "utf8", "value": "x" * (protocol.MAX_VALUE_BYTES + 1)},
        {**json_a, "value": nested(protocol.MAX_DEPTH + 1)},
        {"schema_version": "rdc.kv-write/v1", "idempotency_key": "run-123:delete-2", "operation": "delete", "key": "crawler.state", "expected_version": 4, "value": "forbidden"},
    ]
    for payload in invalid:
        try:
            protocol.validate_kv_mutation(payload)
        except protocol.KVProtocolError:
            continue
        raise SystemExit("Phase 1O verification failed: KV protocol accepted invalid mutation")

    source = read("workers/sandbox-runtime/kv_protocol.py").casefold()
    for forbidden in ["psycopg", "asyncpg", "postgresql://", "boto3", "requests", "httpx", "socket.", "subprocess", "docker.sock"]:
        require(forbidden not in source, "protocol gained side effect: " + forbidden)

    protocol_source = read("workers/sandbox-runtime/kv_protocol.py")
    for marker in ["persisted: bool = False", "worker_write_enabled: bool = False", "object_storage_write_enabled: bool = False"]:
        require(marker in protocol_source, "KV activation boundary changed: " + marker)

    for path, markers in {
        "docs/phase1o/README.md": ["rdc.kv-write/v1", "KV persistence                        disabled", "Agent direct PostgreSQL               prohibited"],
        "docs/phase1o/RUNBOOK.md": ["Do not enable or add KV persistence", "path-like keys such as `../secret`", "weakens Phase 1N Dataset controls"],
        "docs/phase1o/THREAT_MODEL.md": ["Path traversal / object-key confusion", "optimistic concurrency", "General untrusted Agent execution remains release-blocked."],
    }.items():
        source_text = read(path)
        for marker in markers:
            require(marker in source_text, path + " missing: " + marker)

    workflow = read(".github/workflows/ci.yml")
    require("- run: python3 scripts/verify-phase1n.py\n      - run: python3 scripts/verify-phase1o.py\n" in workflow, "Phase 1O verifier not chained")

    main_source = read("apps/api/app/main.py")
    for marker in ['version="0.14.0-phase1n"', '"phase": "1N"', '"status": "tenant-dataset-durable-results"', '"dataset_public_export_enabled": False', '"untrusted_agent_execution_enabled": False']:
        require(marker in main_source, "Phase 1N baseline changed: " + marker)

    print("Phase 1O Increment 1 KV protocol verification: PASS")
    print("  contract: rdc.kv-write/v1")
    print("  KV persistence/public API/worker/object writes: DISABLED")
    print("  Agent direct Postgres/object-storage credentials: PROHIBITED")


if __name__ == "__main__":
    main()
