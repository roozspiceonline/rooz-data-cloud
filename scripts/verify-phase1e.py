#!/usr/bin/env python3
"""Static verification for RDC Phase 1E Run control-plane and SSE scope."""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "apps/api/app/run_schemas.py",
    "apps/api/app/services/runs.py",
    "apps/api/app/api/routes/runs.py",
    "apps/api/migrations/versions/20260806_0005_runs_sse.py",
    "apps/api/tests/test_phase1e_contracts.py",
    "apps/console/src/components/run-control-plane.tsx",
    "apps/console/src/app/console/organizations/[orgId]/projects/[projectId]/runs/page.tsx",
    "docs/phase1e/README.md",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("Phase 1E verification failed: " + message)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def main() -> None:
    for relative in REQUIRED_FILES:
        require((ROOT / relative).is_file(), "missing " + relative)

    models = read("apps/api/app/models.py")
    migration = read(
        "apps/api/migrations/versions/20260806_0005_runs_sse.py"
    )
    routes = read("apps/api/app/api/routes/runs.py")
    service = read("apps/api/app/services/runs.py")
    permissions = read("apps/api/app/core/permissions.py")
    frontend = read("apps/console/src/components/run-control-plane.tsx")
    main_api = read("apps/api/app/main.py")
    config = read("apps/api/app/core/config.py")

    for model in ["class Run(", "class RunEvent(", "class RunCommandOutbox("]:
        require(model in models, "missing model " + model)
    for table in ["runs", "run_events", "run_command_outbox"]:
        require(table in migration, "missing migration table " + table)
    for security_control in [
        "ENABLE ROW LEVEL SECURITY",
        "rdc_run_org",
        "runs_tenancy_guard",
        "run_events_tenancy_guard",
        "run_command_outbox_tenancy_guard",
    ]:
        require(security_control in migration, "missing " + security_control)

    for path in [
        '"/agent-versions/{version_id}/runs"',
        '"/runs/{run_id}"',
        '"/runs/{run_id}/cancel"',
        '"/runs/{run_id}/events"',
        '"/projects/{project_id}/runs"',
    ]:
        require(path in routes, "missing Run route " + path)

    for contract in [
        "Idempotency-Key",
        "Last-Event-ID",
        "run.replay_reset",
        "run.heartbeat",
        "text/event-stream",
        "run_sse_max_connections",
        "request.is_disconnected",
    ]:
        require(contract in routes, "missing SSE contract " + contract)

    for control in [
        "BUILD_NOT_READY",
        "RUNTIME_LIMIT_EXCEEDED",
        "rdc.run.requested.v1",
        "rdc.run.cancel.requested.v1",
        "sanitize_event_payload",
        "pg_advisory",
    ]:
        require(control in service, "missing Run service control " + control)

    for permission in ["run.create", "run.read", "run.cancel"]:
        require(permission in permissions, "missing permission " + permission)

    for ui_contract in [
        "Run control plane",
        "Server-Sent Events",
        "EventSource",
        "Queue Run metadata",
        "Cancel Run",
        "No Agent code executes",
    ]:
        require(ui_contract in frontend, "missing console behavior " + ui_contract)

    prohibited = [
        "subprocess",
        "os.system",
        "docker run",
        "kubectl",
        "decrypt_project_secret",
    ]
    combined = service + routes
    for token in prohibited:
        require(token not in combined, "execution primitive present: " + token)

    schema = json.loads(
        read("packages/agent-protocol/schemas/run-event.schema.json")
    )
    required = schema.get("required", [])
    require("sequence" in required, "Run event sequence is not required")
    require("event_type" in required, "Run event type is not required")
    event_types = schema["properties"]["event_type"]["enum"]
    require("run.replay_reset" in event_types, "replay reset missing")
    require("run.completed" in event_types, "terminal event missing")

    require(
        any(
            marker in main_api
            for marker in [
                '"phase": "1E"',
                '"phase": "1F"',
                '"phase": "1G"',
                '"phase": "1H"',
                '"phase": "1I"',
            ]
        ),
        "foundation status is earlier than Phase 1E",
    )
    legacy_execution_disabled = (
        '"run_execution_enabled": False' in main_api
    )
    sandbox_execution_default_off = (
        '"run_execution_enabled": settings.sandbox_execution_enabled'
        in main_api
        and "sandbox_execution_enabled: bool = False" in config
        and '"untrusted_agent_execution_enabled": False' in main_api
    )
    require(
        legacy_execution_disabled or sandbox_execution_default_off,
        "public API execution boundary changed",
    )

    print("Phase 1E Run control-plane and SSE verification passed.")


if __name__ == "__main__":
    main()
