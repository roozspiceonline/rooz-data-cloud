from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.errors import ApiError
from app.core.pagination import (
    decode_schedule_list_cursor,
    decode_schedule_trigger_cursor,
    encode_schedule_list_cursor,
    encode_schedule_trigger_cursor,
)
from app.core.permissions import role_has_permission
from app.main import app
from app.models import Schedule
from app.schedule_schemas import CreateScheduleRequest
from app.services.schedules import _advance_schedule


def _payload(*, cadence: str = "INTERVAL") -> dict[str, object]:
    return {
        "schema_version": "rdc.schedule/v1",
        "name": "hourly-crawl",
        "cadence_kind": cadence,
        "starts_at": datetime.now(UTC).isoformat(),
        "interval_seconds": 3600 if cadence == "INTERVAL" else None,
        "missed_run_policy": "FIRE_ONCE",
        "misfire_grace_seconds": 300,
        "run": {"build_id": str(uuid4()), "input": {"source": "schedule"}},
    }


def test_schedule_schema_requires_consistent_bounded_cadence() -> None:
    parsed = CreateScheduleRequest.model_validate(_payload())
    assert parsed.interval_seconds == 3600
    invalid = _payload(cadence="ONCE")
    invalid["interval_seconds"] = 60
    with pytest.raises(ValidationError):
        CreateScheduleRequest.model_validate(invalid)
    invalid = _payload()
    invalid["starts_at"] = "2026-08-22T10:00:00"
    with pytest.raises(ValidationError):
        CreateScheduleRequest.model_validate(invalid)


def test_schedule_cursor_is_resource_and_filter_bound() -> None:
    project_id, other_project, resource_id = uuid4(), uuid4(), uuid4()
    created_at = datetime.now(UTC)
    cursor = encode_schedule_list_cursor(
        project_id=project_id,
        status="ACTIVE",
        created_at=created_at,
        resource_id=resource_id,
    )
    assert decode_schedule_list_cursor(
        cursor, project_id=project_id, status="ACTIVE"
    ) is not None
    with pytest.raises(ApiError):
        decode_schedule_list_cursor(
            cursor, project_id=other_project, status="ACTIVE"
        )
    with pytest.raises(ApiError):
        decode_schedule_list_cursor(cursor, project_id=project_id, status="PAUSED")


def test_schedule_trigger_cursor_is_resource_and_filter_bound() -> None:
    schedule_id, other_schedule, resource_id = uuid4(), uuid4(), uuid4()
    created_at = datetime.now(UTC)
    cursor = encode_schedule_trigger_cursor(
        schedule_id=schedule_id,
        outcome="FIRED",
        created_at=created_at,
        resource_id=resource_id,
    )
    assert decode_schedule_trigger_cursor(
        cursor, schedule_id=schedule_id, outcome="FIRED"
    ) is not None
    with pytest.raises(ApiError):
        decode_schedule_trigger_cursor(
            cursor, schedule_id=other_schedule, outcome="FIRED"
        )
    with pytest.raises(ApiError):
        decode_schedule_trigger_cursor(
            cursor, schedule_id=schedule_id, outcome="FAILED"
        )


def test_interval_advance_collapses_missed_backlog_to_one_future_slot() -> None:
    now = datetime.now(UTC)
    due = now - timedelta(hours=8)
    schedule = Schedule(
        organization_id=uuid4(),
        project_id=uuid4(),
        agent_id=uuid4(),
        agent_version_id=uuid4(),
        build_id=uuid4(),
        name="collapse",
        status="ACTIVE",
        cadence_kind="INTERVAL",
        starts_at=due,
        interval_seconds=3600,
        missed_run_policy="FIRE_ONCE",
        misfire_grace_seconds=300,
        run_payload={},
        next_fire_at=due,
        fired_count=0,
        skipped_count=0,
        failed_count=0,
        created_by_user_id=uuid4(),
    )
    _advance_schedule(schedule, scheduled_for=due, now=now)
    assert schedule.next_fire_at is not None
    assert schedule.next_fire_at > now
    assert schedule.next_fire_at <= now + timedelta(hours=1)


def test_scheduler_migration_contains_security_and_race_guards() -> None:
    root = Path(__file__).parents[1]
    migration = (
        root / "migrations/versions/20260822_0021_schedules.py"
    ).read_text()
    service = (root / "app/services/schedules.py").read_text()
    dependencies = (root / "app/api/agent_dependencies.py").read_text()
    assert "rdc_schedule_org" in dependencies
    assert "security.rdc_current_org_id()" in migration
    assert "security.rdc_has_org_membership(organization_id)" in migration
    assert "Schedule definition is immutable" in migration
    assert "Schedule triggers are immutable" in migration
    assert "uq_schedule_triggers_schedule_instant" in migration
    assert "pg_try_advisory_xact_lock" in service
    assert "with_for_update(skip_locked=True)" in service
    assert 'set_config(\'rdc.schedule_dispatcher\'' in service


def test_schedule_routes_and_permissions_are_least_privilege() -> None:
    operations = app.openapi()["paths"]
    assert "post" in operations["/api/v1/agent-versions/{version_id}/schedules"]
    assert "get" in operations["/api/v1/projects/{project_id}/schedules"]
    assert "post" in operations["/api/v1/schedules/{schedule_id}/pause"]
    assert "post" in operations["/api/v1/schedules/{schedule_id}/resume"]
    assert "get" in operations["/api/v1/schedules/{schedule_id}/triggers"]
    assert role_has_permission("developer", "schedule.create")
    assert role_has_permission("developer", "schedule.update")
    assert role_has_permission("viewer", "schedule.read")
    assert not role_has_permission("viewer", "schedule.create")


def test_schedule_creation_derives_all_tenant_ownership_server_side() -> None:
    root = Path(__file__).parents[1]
    schema = (root / "app/schedule_schemas.py").read_text()
    service = (root / "app/services/schedules.py").read_text()
    assert "organization_id" not in schema.split("class CreateScheduleRequest", 1)[1].split(
        "class ScheduleSummary", 1
    )[0]
    assert "project_id" not in schema.split("class CreateScheduleRequest", 1)[1].split(
        "class ScheduleSummary", 1
    )[0]
    assert "organization_id=version.organization_id" in service
    assert "project_id=version.project_id" in service
    assert "agent_id=version.agent_id" in service
