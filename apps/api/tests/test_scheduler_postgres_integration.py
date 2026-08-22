# ruff: noqa: E501
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.database import engine, session_factory
from app.services.schedules import dispatch_due_schedules

pytestmark = pytest.mark.asyncio(loop_scope="module")


@pytest_asyncio.fixture(scope="module", autouse=True, loop_scope="module")
async def _dispose_database_pool() -> AsyncIterator[None]:
    await engine.dispose()
    yield
    await engine.dispose()


async def _database_available() -> bool:
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except (OSError, DBAPIError, OperationalError):
        return False


async def _seed_schedule(
    *,
    starts_at: datetime,
    cadence_kind: str = "ONCE",
    interval_seconds: int | None = None,
    missed_run_policy: str = "FIRE_ONCE",
    misfire_grace_seconds: int = 300,
) -> tuple[UUID, UUID, UUID, UUID, UUID, UUID, UUID]:
    user_id, org_id, project_id, agent_id, version_id, build_id, schedule_id = (
        uuid4() for _ in range(7)
    )
    suffix = uuid4().hex
    manifest = (
        '{"capabilities":{"network":"none","browser":false},'
        '"resources":{"memoryMb":256,"cpuUnits":500,"timeoutSeconds":60}}'
    )
    run_payload = f'{{"build_id":"{build_id}","input":{{"scheduled":true}},"runtime":{{}}}}'
    async with engine.begin() as connection:
        await connection.execute(
            text("INSERT INTO identity.users (id,email_normalized,email_display,password_hash,password_algorithm,display_name,status) VALUES (:u,:e,:e,'x','argon2id','Scheduler','ACTIVE')"),
            {"u": user_id, "e": f"scheduler-{suffix}@example.invalid"},
        )
        await connection.execute(
            text("INSERT INTO identity.organizations (id,name,slug,status,created_by_user_id) VALUES (:o,'Scheduler',:s,'ACTIVE',:u)"),
            {"o": org_id, "s": f"scheduler-{suffix}", "u": user_id},
        )
        await connection.execute(
            text("INSERT INTO identity.organization_memberships (organization_id,user_id,role,status,joined_at,updated_at,created_by_user_id) VALUES (:o,:u,'owner','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,:u)"),
            {"o": org_id, "u": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.projects (id,organization_id,name,slug,status,created_by_user_id) VALUES (:p,:o,'Scheduler',:s,'ACTIVE',:u)"),
            {"p": project_id, "o": org_id, "s": f"scheduler-{suffix}", "u": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.agents (id,organization_id,project_id,name,slug,status,created_by_user_id) VALUES (:a,:o,:p,'Scheduler',:s,'ACTIVE',:u)"),
            {"a": agent_id, "o": org_id, "p": project_id, "s": f"scheduler-{suffix}", "u": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.agent_versions (id,organization_id,project_id,agent_id,version_number,protocol,semantic_version,manifest_schema_version,manifest_digest,manifest,created_by_user_id) VALUES (:v,:o,:p,:a,1,'rdc-agent/v1','1.0.0','rdc.agent/v1',:digest,CAST(:manifest AS jsonb),:u)"),
            {"v": version_id, "o": org_id, "p": project_id, "a": agent_id, "digest": "a" * 64, "manifest": manifest, "u": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.builds (id,organization_id,project_id,agent_id,agent_version_id,manifest_digest,status,artifact_digest,requested_by_user_id) VALUES (:b,:o,:p,:a,:v,:digest,'SUCCEEDED',:artifact,:u)"),
            {"b": build_id, "o": org_id, "p": project_id, "a": agent_id, "v": version_id, "digest": "a" * 64, "artifact": "sha256:" + "b" * 64, "u": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.schedules (id,organization_id,project_id,agent_id,agent_version_id,build_id,name,status,cadence_kind,starts_at,interval_seconds,missed_run_policy,misfire_grace_seconds,run_payload,next_fire_at,created_by_user_id) VALUES (:s,:o,:p,:a,:v,:b,:name,'ACTIVE',:cadence,:starts,:interval,:policy,:grace,CAST(:payload AS jsonb),:starts,:u)"),
            {"s": schedule_id, "o": org_id, "p": project_id, "a": agent_id, "v": version_id, "b": build_id, "name": f"schedule-{suffix}", "cadence": cadence_kind, "starts": starts_at, "interval": interval_seconds, "policy": missed_run_policy, "grace": misfire_grace_seconds, "payload": run_payload, "u": user_id},
        )
    return user_id, org_id, project_id, agent_id, version_id, build_id, schedule_id


async def test_due_schedule_fires_exactly_once_with_immutable_history() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    *_, schedule_id = await _seed_schedule(starts_at=now - timedelta(seconds=1))
    async with session_factory() as session:
        first = await dispatch_due_schedules(
            session, now=now, batch_size=100, request_id="scheduler-first"
        )
        await session.commit()
    async with session_factory() as session:
        second = await dispatch_due_schedules(
            session,
            now=now + timedelta(seconds=1),
            batch_size=100,
            request_id="scheduler-second",
        )
        await session.commit()
    assert first.fired == 1
    assert second.fired == 0
    async with engine.connect() as connection:
        schedule = (
            await connection.execute(
                text("SELECT status,fired_count,next_fire_at FROM control.schedules WHERE id=:id"),
                {"id": schedule_id},
            )
        ).one()
        triggers = (
            await connection.execute(
                text("SELECT outcome,reason,run_id FROM control.schedule_triggers WHERE schedule_id=:id"),
                {"id": schedule_id},
            )
        ).all()
        run_count = await connection.scalar(
            text("SELECT count(*) FROM control.runs WHERE id=:id"),
            {"id": triggers[0].run_id},
        )
    assert schedule == ("COMPLETED", 1, None)
    assert len(triggers) == 1
    assert triggers[0].outcome == "FIRED"
    assert triggers[0].reason == "DUE"
    assert run_count == 1
    with pytest.raises(DBAPIError, match="Schedule triggers are immutable"):
        async with engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM control.schedule_triggers WHERE schedule_id=:id"),
                {"id": schedule_id},
            )


async def test_concurrent_dispatchers_create_only_one_run_for_due_instant() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    *_, schedule_id = await _seed_schedule(starts_at=now - timedelta(seconds=1))

    async def dispatch(label: str) -> tuple[bool, int]:
        async with session_factory() as session:
            result = await dispatch_due_schedules(
                session,
                now=now,
                batch_size=100,
                request_id=f"scheduler-race-{label}",
            )
            await session.commit()
            return result.acquired, result.fired

    outcomes = await asyncio.gather(dispatch("a"), dispatch("b"))
    assert sum(fired for _, fired in outcomes) == 1
    async with engine.connect() as connection:
        trigger_count = await connection.scalar(
            text("SELECT count(*) FROM control.schedule_triggers WHERE schedule_id=:id"),
            {"id": schedule_id},
        )
        scheduled_run_count = await connection.scalar(
            text("SELECT count(*) FROM control.runs WHERE id IN (SELECT run_id FROM control.schedule_triggers WHERE schedule_id=:id)"),
            {"id": schedule_id},
        )
    assert trigger_count == 1
    assert scheduled_run_count == 1


async def test_missed_skip_records_history_without_creating_run() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    *_, schedule_id = await _seed_schedule(
        starts_at=now - timedelta(hours=1),
        missed_run_policy="SKIP",
        misfire_grace_seconds=60,
    )
    async with session_factory() as session:
        result = await dispatch_due_schedules(
            session, now=now, batch_size=100, request_id="scheduler-skip"
        )
        await session.commit()
    assert result.skipped == 1
    async with engine.connect() as connection:
        trigger = (
            await connection.execute(
                text("SELECT outcome,reason,run_id,error_code FROM control.schedule_triggers WHERE schedule_id=:id"),
                {"id": schedule_id},
            )
        ).one()
    assert trigger == ("SKIPPED", "MISSED_WINDOW", None, None)


async def test_recurring_fire_once_collapses_backlog_without_run_burst() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    *_, schedule_id = await _seed_schedule(
        starts_at=now - timedelta(hours=4),
        cadence_kind="INTERVAL",
        interval_seconds=60,
        missed_run_policy="FIRE_ONCE",
        misfire_grace_seconds=60,
    )
    async with session_factory() as session:
        first = await dispatch_due_schedules(
            session, now=now, batch_size=100, request_id="scheduler-fire-once"
        )
        await session.commit()
    async with session_factory() as session:
        second = await dispatch_due_schedules(
            session, now=now, batch_size=100, request_id="scheduler-no-burst"
        )
        await session.commit()
    assert first.fired == 1
    assert second.fired == 0
    async with engine.connect() as connection:
        schedule = (
            await connection.execute(
                text("SELECT status,fired_count,next_fire_at FROM control.schedules WHERE id=:id"),
                {"id": schedule_id},
            )
        ).one()
        history = (
            await connection.execute(
                text("SELECT outcome,reason FROM control.schedule_triggers WHERE schedule_id=:id"),
                {"id": schedule_id},
            )
        ).all()
    assert schedule.status == "ACTIVE"
    assert schedule.fired_count == 1
    assert schedule.next_fire_at > now
    assert history == [("FIRED", "MISSED_FIRE_ONCE")]


async def test_schedule_guards_reject_definition_and_cross_tenant_history_changes() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    _, org_id, project_id, *_, schedule_id = await _seed_schedule(
        starts_at=now + timedelta(hours=1)
    )
    other = await _seed_schedule(starts_at=now + timedelta(hours=1))
    other_run_org, other_run_project = other[1], other[2]
    assert (other_run_org, other_run_project) != (org_id, project_id)
    with pytest.raises(DBAPIError, match="Schedule definition is immutable"):
        async with engine.begin() as connection:
            await connection.execute(
                text("UPDATE control.schedules SET run_payload='{}'::jsonb WHERE id=:id"),
                {"id": schedule_id},
            )
    with pytest.raises(DBAPIError, match="Schedule trigger tenancy mismatch"):
        async with engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO control.schedule_triggers (organization_id,project_id,schedule_id,scheduled_for,observed_at,outcome,reason) VALUES (:o,:p,:s,:now,:now,'SKIPPED','MISSED_WINDOW')"),
                {"o": other_run_org, "p": other_run_project, "s": schedule_id, "now": now},
            )
