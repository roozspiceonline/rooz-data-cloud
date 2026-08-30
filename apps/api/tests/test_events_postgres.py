# ruff: noqa: E501
from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.database import engine, session_factory, set_tenant_context
from app.core.errors import ApiError
from app.models import Event, Project
from app.services.events import emit_event, list_events

pytestmark = pytest.mark.asyncio(loop_scope="module")


@pytest_asyncio.fixture(scope="module", autouse=True, loop_scope="module")
async def _dispose_database_pool() -> AsyncIterator[None]:
    await engine.dispose()
    yield
    await engine.dispose()


async def _database_available() -> bool:
    try:
        async with engine.connect() as connection:
            return bool(
                await connection.scalar(
                    text("SELECT to_regclass('control.events') IS NOT NULL")
                )
            )
    except (OSError, DBAPIError, OperationalError):
        return False


async def _seed() -> dict[str, UUID]:
    ids = {
        name: uuid4()
        for name in (
            "user_a", "org_a", "project_a", "project_a2", "agent_a", "version_a",
            "build_a", "build_a2", "run_a", "user_b", "org_b", "project_b",
        )
    }
    suffix = uuid4().hex
    async with engine.begin() as connection:
        for side in ("a", "b"):
            await connection.execute(
                text("INSERT INTO identity.users (id,email_normalized,email_display,password_hash,password_algorithm,display_name,status) VALUES (:u,:e,:e,'x','argon2id','Events','ACTIVE')"),
                {"u": ids[f"user_{side}"], "e": f"events-{side}-{suffix}@example.invalid"},
            )
            await connection.execute(
                text("INSERT INTO identity.organizations (id,name,slug,status,created_by_user_id) VALUES (:o,'Events',:slug,'ACTIVE',:u)"),
                {"o": ids[f"org_{side}"], "slug": f"events-{side}-{suffix}", "u": ids[f"user_{side}"]},
            )
            await connection.execute(
                text("INSERT INTO identity.organization_memberships (organization_id,user_id,role,status,joined_at,updated_at,created_by_user_id) VALUES (:o,:u,'owner','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,:u)"),
                {"o": ids[f"org_{side}"], "u": ids[f"user_{side}"]},
            )
            await connection.execute(
                text("INSERT INTO control.projects (id,organization_id,name,slug,status,created_by_user_id) VALUES (:p,:o,'Events',:slug,'ACTIVE',:u)"),
                {"p": ids[f"project_{side}"], "o": ids[f"org_{side}"], "slug": f"events-project-{side}-{suffix}", "u": ids[f"user_{side}"]},
            )
        await connection.execute(
            text("INSERT INTO control.projects (id,organization_id,name,slug,status,created_by_user_id) VALUES (:p,:o,'Events Other',:slug,'ACTIVE',:u)"),
            {"p": ids["project_a2"], "o": ids["org_a"], "slug": f"events-project-a2-{suffix}", "u": ids["user_a"]},
        )
        await connection.execute(
            text("INSERT INTO control.agents (id,organization_id,project_id,name,slug,status,created_by_user_id) VALUES (:a,:o,:p,'Events',:slug,'ACTIVE',:u)"),
            {"a": ids["agent_a"], "o": ids["org_a"], "p": ids["project_a"], "slug": f"events-agent-{suffix}", "u": ids["user_a"]},
        )
        await connection.execute(
            text("INSERT INTO control.agent_versions (id,organization_id,project_id,agent_id,version_number,protocol,semantic_version,manifest_schema_version,manifest_digest,manifest,created_by_user_id) VALUES (:v,:o,:p,:a,1,'rdc-agent/v1','1.0.0','rdc.agent/v1',:digest,'{}',:u)"),
            {"v": ids["version_a"], "o": ids["org_a"], "p": ids["project_a"], "a": ids["agent_a"], "digest": "a" * 64, "u": ids["user_a"]},
        )
        for build_name in ("build_a", "build_a2"):
            await connection.execute(
                text("INSERT INTO control.builds (id,organization_id,project_id,agent_id,agent_version_id,manifest_digest,status,requested_by_user_id) VALUES (:b,:o,:p,:a,:v,:digest,'QUEUED',:u)"),
                {"b": ids[build_name], "o": ids["org_a"], "p": ids["project_a"], "a": ids["agent_a"], "v": ids["version_a"], "digest": "a" * 64, "u": ids["user_a"]},
            )
        await connection.execute(
            text("INSERT INTO control.runs (id,organization_id,project_id,agent_id,agent_version_id,build_id,status,input_reference,runtime_configuration,memory_mb,cpu_millis,timeout_seconds,requested_by_user_id,queued_at) VALUES (:r,:o,:p,:a,:v,:b,'QUEUED','{}','{}',128,100,60,:u,CURRENT_TIMESTAMP)"),
            {"r": ids["run_a"], "o": ids["org_a"], "p": ids["project_a"], "a": ids["agent_a"], "v": ids["version_a"], "b": ids["build_a"], "u": ids["user_a"]},
        )
    return ids


async def _emit_seed_events(ids: dict[str, UUID]) -> tuple[Event, Event]:
    async with session_factory() as session:
        await set_tenant_context(session, user_id=ids["user_a"], organization_id=ids["org_a"])
        project = await session.scalar(select(Project).where(Project.id == ids["project_a"]))
        assert project is not None
        build_event = await emit_event(
            session,
            organization_id=project.organization_id,
            project_id=project.id,
            event_type="build.created",
            subject_type="build",
            subject_id=ids["build_a"],
            payload={"agent_id": str(ids["agent_a"]), "agent_version_id": str(ids["version_a"]), "status": "QUEUED"},
            request_id="events-build-create",
        )
        replay = await emit_event(
            session,
            organization_id=ids["org_b"],
            project_id=project.id,
            event_type="build.created",
            subject_type="build",
            subject_id=ids["build_a"],
            payload={"agent_id": str(ids["agent_a"]), "agent_version_id": str(ids["version_a"]), "status": "QUEUED"},
            request_id="events-build-replay",
        )
        assert replay.id == build_event.id
        run_event = await emit_event(
            session,
            organization_id=project.organization_id,
            project_id=project.id,
            event_type="run.created",
            subject_type="run",
            subject_id=ids["run_a"],
            payload={"agent_id": str(ids["agent_a"]), "agent_version_id": str(ids["version_a"]), "build_id": str(ids["build_a"]), "status": "QUEUED"},
            request_id="events-run-create",
        )
        await session.commit()
    return build_event, run_event


async def test_event_persistence_is_immutable_replay_safe_and_server_owned() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL events migration is unavailable")
    ids = await _seed()
    build_event, _run_event = await _emit_seed_events(ids)
    assert build_event.organization_id == ids["org_a"]
    with pytest.raises(DBAPIError, match="RDC events are immutable"):
        async with engine.begin() as connection:
            await connection.execute(text("UPDATE control.events SET request_id='changed' WHERE id=:id"), {"id": build_event.id})
    with pytest.raises(DBAPIError, match="RDC events are immutable"):
        async with engine.begin() as connection:
            await connection.execute(text("DELETE FROM control.events WHERE id=:id"), {"id": build_event.id})
    with pytest.raises(DBAPIError, match="Event project reference is invalid"):
        async with engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO control.events (organization_id,project_id,event_type,schema_version,subject_type,subject_id,payload,payload_digest,emitter,request_id) VALUES (:o,:p,'build.created','rdc.event/v1','build',:b,CAST(:payload AS jsonb),:digest,'control-plane','invalid-project')"),
                {"o": ids["org_a"], "p": uuid4(), "b": ids["build_a"], "payload": '{}', "digest": "0" * 64},
            )
    with pytest.raises(DBAPIError, match="Event Build reference is invalid"):
        async with engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO control.events (organization_id,project_id,event_type,schema_version,subject_type,subject_id,payload,payload_digest,emitter,request_id) VALUES (:o,:p,'build.created','rdc.event/v1','build',:b,CAST(:payload AS jsonb),:digest,'control-plane','cross-project')"),
                {"o": ids["org_a"], "p": ids["project_a2"], "b": ids["build_a2"], "payload": '{"agent_id":"00000000-0000-0000-0000-000000000000","agent_version_id":"00000000-0000-0000-0000-000000000000","status":"QUEUED"}', "digest": "0" * 64},
            )


async def test_event_rls_denies_cross_org_and_cross_project_reads() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL events migration is unavailable")
    ids = await _seed()
    await _emit_seed_events(ids)
    async with engine.begin() as connection:
        await connection.execute(text("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rdc_events_rls_test') THEN CREATE ROLE rdc_events_rls_test NOLOGIN; END IF; END $$"))
        await connection.execute(text("GRANT USAGE ON SCHEMA control,security TO rdc_events_rls_test"))
        await connection.execute(text("GRANT SELECT,INSERT,UPDATE,DELETE ON control.events TO rdc_events_rls_test"))
    try:
        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL ROLE rdc_events_rls_test"))
            await connection.execute(text("SELECT set_config('rdc.current_user_id',:v,true)"), {"v": str(ids["user_a"])})
            await connection.execute(text("SELECT set_config('rdc.current_organization_id',:v,true)"), {"v": str(ids["org_a"])})
            await connection.execute(text("SELECT set_config('rdc.current_project_id',:v,true)"), {"v": str(ids["project_a"])})
            assert await connection.scalar(text("SELECT count(*) FROM control.events")) == 2
            await connection.execute(text("SELECT set_config('rdc.current_project_id',:v,true)"), {"v": str(ids["project_a2"])})
            assert await connection.scalar(text("SELECT count(*) FROM control.events")) == 0
            with pytest.raises(DBAPIError, match="row-level security policy"):
                async with connection.begin_nested():
                    await connection.execute(
                        text("INSERT INTO control.events (organization_id,project_id,event_type,schema_version,subject_type,subject_id,payload,payload_digest,emitter,request_id) VALUES (:o,:p,'build.created','rdc.event/v1','build',:b,CAST(:payload AS jsonb),:digest,'control-plane','cross-project-rls')"),
                        {
                            "o": ids["org_a"],
                            "p": ids["project_a"],
                            "b": ids["build_a"],
                            "payload": (
                                f'{{"agent_id":"{ids["agent_a"]}",'
                                f'"agent_version_id":"{ids["version_a"]}",'
                                '"status":"QUEUED"}'
                            ),
                            "digest": "0" * 64,
                        },
                    )
            await connection.execute(text("SELECT set_config('rdc.current_user_id',:v,true)"), {"v": str(ids["user_b"])})
            await connection.execute(text("SELECT set_config('rdc.current_organization_id',:v,true)"), {"v": str(ids["org_b"])})
            await connection.execute(text("SELECT set_config('rdc.current_project_id',:v,true)"), {"v": str(ids["project_a"])})
            assert await connection.scalar(text("SELECT count(*) FROM control.events")) == 0
    finally:
        async with engine.begin() as connection:
            await connection.execute(text("DROP OWNED BY rdc_events_rls_test"))
            await connection.execute(text("DROP ROLE rdc_events_rls_test"))


async def test_event_history_order_and_pagination_are_stable() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL events migration is unavailable")
    ids = await _seed()
    await _emit_seed_events(ids)
    async with session_factory() as session:
        await set_tenant_context(session, user_id=ids["user_a"], organization_id=ids["org_a"])
        first, has_more = await list_events(session, project_id=ids["project_a"], event_type=None, cursor=None, limit=1)
        assert len(first) == 1 and has_more is True
        from app.core.pagination import CursorPosition
        second, second_more = await list_events(
            session,
            project_id=ids["project_a"],
            event_type=None,
            cursor=CursorPosition(created_at=first[0].occurred_at, resource_id=first[0].id),
            limit=1,
        )
        assert len(second) == 1 and second[0].id != first[0].id
        assert second_more is False
        await session.commit()


async def test_event_service_rejects_unsupported_or_sensitive_content() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL events migration is unavailable")
    ids = await _seed()
    async with session_factory() as session:
        await set_tenant_context(session, user_id=ids["user_a"], organization_id=ids["org_a"])
        with pytest.raises(ApiError, match="invalid"):
            await emit_event(
                session,
                organization_id=ids["org_a"],
                project_id=ids["project_a"],
                event_type="webhook.requested",
                subject_type="webhook",
                subject_id=uuid4(),
                payload={"authorization": "Bearer no"},
                request_id="unsafe-event",
            )
        await session.rollback()
