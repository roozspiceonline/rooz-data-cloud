#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def need(path: str, *markers: str) -> None:
    source = (ROOT / path).read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise SystemExit(f"{path} missing: {', '.join(missing)}")


need(
    "apps/api/migrations/versions/20260822_0021_schedules.py",
    "control.schedules",
    "control.schedule_triggers",
    "uq_schedule_triggers_schedule_instant",
    "rdc_schedule_org",
    "security.rdc_current_org_id()",
    "security.rdc_has_org_membership(organization_id)",
    "Schedule definition is immutable",
    "Schedule triggers are immutable",
    "Schedule trigger tenancy mismatch",
)
need(
    "apps/api/app/services/schedules.py",
    "pg_try_advisory_xact_lock",
    "with_for_update(skip_locked=True)",
    "set_tenant_context",
    "MISSED_WINDOW",
    "MISSED_FIRE_ONCE",
    "SCHEDULE_RUN_PAYLOAD_INVALID",
    "create_run(",
)
need(
    "apps/api/app/schedule_schemas.py",
    'Literal["ONCE", "INTERVAL"]',
    'Literal["SKIP", "FIRE_ONCE"]',
    "misfire_grace_seconds",
    "CreateRunRequest",
)
need(
    "apps/api/app/api/routes/schedules.py",
    'require_agent_version_permission("schedule.create")',
    'require_schedule_permission("schedule.update")',
    "decode_schedule_list_cursor",
    "decode_schedule_trigger_cursor",
    'Header(alias="Idempotency-Key")',
)
need(
    "apps/api/app/core/permissions.py",
    '"schedule.create"',
    '"schedule.read"',
    '"schedule.update"',
)
need(
    "apps/api/app/schedule_dispatcher.py",
    "run_dispatch_loop",
    "schedule_dispatch_interval_seconds",
    "schedule_dispatch_batch_size",
)
need(
    "docker-compose.yml",
    "schedule-dispatcher:",
    "app.schedule_dispatcher",
    "RDC_SCHEDULE_DISPATCH_ENABLED",
)
need(
    "infrastructure/systemd/rdc-schedule-dispatcher.service",
    "Restart=always",
    "ProtectSystem=strict",
    "app.schedule_dispatcher",
)
need(
    "apps/api/tests/test_scheduler_contracts.py",
    "test_schedule_cursor_is_resource_and_filter_bound",
    "test_scheduler_migration_contains_security_and_race_guards",
)
need(
    "apps/api/tests/test_scheduler_postgres_integration.py",
    "test_concurrent_dispatchers_create_only_one_run_for_due_instant",
    "test_missed_skip_records_history_without_creating_run",
    "test_recurring_fire_once_collapses_backlog_without_run_burst",
    "test_schedule_guards_reject_definition_and_cross_tenant_history_changes",
)
for path in (
    "docs/scheduler/README.md",
    "docs/scheduler/RUNBOOK.md",
    "docs/scheduler/THREAT_MODEL.md",
):
    need(path, "Scheduler")

print("Scheduler verification passed")
