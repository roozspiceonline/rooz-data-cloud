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
from app.services.execution_plane import reap_expired_leases

pytestmark = pytest.mark.asyncio(loop_scope="module")


@pytest_asyncio.fixture(scope="module", autouse=True, loop_scope="module")
async def _dispose_database_pool() -> AsyncIterator[None]:
    yield
    await engine.dispose()


async def _database_available() -> bool:
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except (OSError, DBAPIError, OperationalError):
        return False


async def _seed_deadline_lease(
    *,
    work_kind: str,
    now: datetime,
    overdue: bool,
) -> tuple[UUID, UUID, UUID]:
    user_id, org_id, project_id, agent_id, version_id = (
        uuid4() for _ in range(5)
    )
    build_id, run_id, source_id, worker_id, lease_id = (
        uuid4() for _ in range(5)
    )
    suffix = uuid4().hex
    claimed_at = now - timedelta(minutes=2)
    deadline_at = (
        now - timedelta(seconds=1)
        if overdue
        else now + timedelta(hours=1)
    )
    expires_at = (
        deadline_at
        if overdue
        else now + timedelta(minutes=30)
    )
    async with engine.begin() as connection:
        await connection.execute(
            text("INSERT INTO identity.users (id,email_normalized,email_display,password_hash,password_algorithm,display_name,status) VALUES (:u,:e,:e,'x','argon2id','Deadline','ACTIVE')"),
            {"u": user_id, "e": f"deadline-{suffix}@example.invalid"},
        )
        await connection.execute(
            text("INSERT INTO identity.organizations (id,name,slug,status,created_by_user_id) VALUES (:o,'Deadline',:s,'ACTIVE',:u)"),
            {"o": org_id, "s": f"deadline-{suffix}", "u": user_id},
        )
        await connection.execute(
            text("INSERT INTO identity.organization_memberships (organization_id,user_id,role,status,joined_at,updated_at,created_by_user_id) VALUES (:o,:u,'owner','ACTIVE',:now,:now,:u)"),
            {"o": org_id, "u": user_id, "now": now},
        )
        await connection.execute(
            text("INSERT INTO control.projects (id,organization_id,name,slug,status,created_by_user_id) VALUES (:p,:o,'Deadline',:s,'ACTIVE',:u)"),
            {"p": project_id, "o": org_id, "s": f"deadline-{suffix}", "u": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.agents (id,organization_id,project_id,name,slug,status,created_by_user_id) VALUES (:a,:o,:p,'Deadline',:s,'ACTIVE',:u)"),
            {"a": agent_id, "o": org_id, "p": project_id, "s": f"deadline-{suffix}", "u": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.agent_versions (id,organization_id,project_id,agent_id,version_number,protocol,semantic_version,manifest_schema_version,manifest_digest,manifest,created_by_user_id) VALUES (:v,:o,:p,:a,1,'rdc-agent/v1','1.0.0','rdc.agent/v1',:digest,CAST(:manifest AS jsonb),:u)"),
            {"v": version_id, "o": org_id, "p": project_id, "a": agent_id, "digest": "a" * 64, "manifest": '{"resources":{"timeoutSeconds":60}}', "u": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.builds (id,organization_id,project_id,agent_id,agent_version_id,manifest_digest,status,requested_by_user_id) VALUES (:b,:o,:p,:a,:v,:digest,'RUNNING',:u)"),
            {"b": build_id, "o": org_id, "p": project_id, "a": agent_id, "v": version_id, "digest": "a" * 64, "u": user_id},
        )
        if work_kind == "BUILD":
            await connection.execute(
                text("INSERT INTO control.build_dispatch_outbox (id,organization_id,project_id,build_id,topic,payload,status,attempts,available_at,claimed_at) VALUES (:s,:o,:p,:b,'rdc.build.requested.v1','{}','CLAIMED',1,:now,:now)"),
                {"s": source_id, "o": org_id, "p": project_id, "b": build_id, "now": now},
            )
            target_values = {"build_id": build_id, "run_id": None}
        else:
            await connection.execute(
                text("INSERT INTO control.runs (id,organization_id,project_id,agent_id,agent_version_id,build_id,status,input_reference,runtime_configuration,memory_mb,cpu_millis,timeout_seconds,requested_by_user_id,queued_at) VALUES (:r,:o,:p,:a,:v,:b,'RUNNING','{}','{}',128,100,60,:u,:now)"),
                {"r": run_id, "o": org_id, "p": project_id, "a": agent_id, "v": version_id, "b": build_id, "u": user_id, "now": now},
            )
            await connection.execute(
                text("INSERT INTO control.run_command_outbox (id,organization_id,project_id,run_id,command,topic,payload,status,attempts,available_at,claimed_at) VALUES (:s,:o,:p,:r,'START','rdc.run.requested.v1','{}','CLAIMED',1,:now,:now)"),
                {"s": source_id, "o": org_id, "p": project_id, "r": run_id, "now": now},
            )
            target_values = {"build_id": None, "run_id": run_id}
        await connection.execute(
            text("INSERT INTO security.worker_identities (id,name,public_prefix,last_four,token_digest,capabilities,max_concurrency,status,protocol_version,software_version,metadata_json) VALUES (:w,:name,:prefix,'0001',:digest,CAST(:capabilities AS jsonb),1,'ACTIVE','rdc-worker/v1','test','{}')"),
            {"w": worker_id, "name": f"deadline-{suffix}", "prefix": suffix[:12], "digest": uuid4().bytes + uuid4().bytes, "capabilities": f'["{work_kind}"]'},
        )
        await connection.execute(
            text("INSERT INTO control.execution_leases (id,worker_id,organization_id,project_id,work_kind,source_outbox_id,source_topic,build_id,run_id,lease_token_digest,payload_digest,payload_snapshot,status,attempt,claimed_at,expires_at,deadline_at) VALUES (:l,:w,:o,:p,:kind,:source,'test',:build_id,:run_id,:token,:payload_digest,'{}','ACTIVE',1,:claimed,:expires,:deadline)"),
            {"l": lease_id, "w": worker_id, "o": org_id, "p": project_id, "kind": work_kind, "source": source_id, "token": uuid4().bytes + uuid4().bytes, "payload_digest": "b" * 64, "claimed": claimed_at, "expires": expires_at, "deadline": deadline_at, **target_values},
        )
    return lease_id, source_id, build_id if work_kind == "BUILD" else run_id


async def test_postgres_execution_deadline_is_immutable() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    lease_id, _, _ = await _seed_deadline_lease(
        work_kind="BUILD",
        now=now,
        overdue=False,
    )
    with pytest.raises(DBAPIError, match="Execution deadline is immutable"):
        async with engine.begin() as connection:
            await connection.execute(
                text("UPDATE control.execution_leases SET deadline_at=deadline_at+INTERVAL '1 minute' WHERE id=:lease"),
                {"lease": lease_id},
            )


@pytest.mark.parametrize("work_kind", ["BUILD", "RUN_START"])
async def test_postgres_overdue_workload_is_terminally_timed_out(
    work_kind: str,
) -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    lease_id, source_id, target_id = await _seed_deadline_lease(
        work_kind=work_kind,
        now=now,
        overdue=True,
    )
    async with session_factory() as session:
        assert await reap_expired_leases(
            session,
            now=now,
            request_id=f"deadline-{work_kind}",
        ) == 1
        await session.commit()
    source_table = (
        "control.build_dispatch_outbox"
        if work_kind == "BUILD"
        else "control.run_command_outbox"
    )
    target_table = "control.builds" if work_kind == "BUILD" else "control.runs"
    error_column = "error_code" if work_kind == "BUILD" else "failure_code"
    async with engine.connect() as connection:
        lease = (
            await connection.execute(
                text("SELECT status,failure_code FROM control.execution_leases WHERE id=:id"),
                {"id": lease_id},
            )
        ).one()
        source = (
            await connection.execute(
                text(f"SELECT status,last_error_code FROM {source_table} WHERE id=:id"),
                {"id": source_id},
            )
        ).one()
        target = (
            await connection.execute(
                text(f"SELECT status,{error_column} FROM {target_table} WHERE id=:id"),
                {"id": target_id},
            )
        ).one()
        audit = (
            await connection.execute(
                text("SELECT action,details->>'retry_scheduled',details->>'deadline_exceeded' FROM security.audit_events WHERE resource_id=:id AND action='execution.lease.deadline_exceeded'"),
                {"id": str(lease_id)},
            )
        ).one()
    expected = ("FAILED", "WORKLOAD_DEADLINE_EXCEEDED")
    assert lease == expected
    assert source == expected
    assert target == ("TIMED_OUT", "WORKLOAD_DEADLINE_EXCEEDED")
    assert audit == ("execution.lease.deadline_exceeded", "false", "true")


async def test_postgres_concurrent_deadline_reapers_are_single_winner() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    await _seed_deadline_lease(
        work_kind="BUILD",
        now=now,
        overdue=True,
    )

    async def reap(request_id: str) -> int:
        async with session_factory() as session:
            result = await reap_expired_leases(
                session,
                now=now,
                request_id=request_id,
            )
            await session.commit()
            return result

    results = await asyncio.gather(reap("deadline-race-a"), reap("deadline-race-b"))
    assert sorted(results) == [0, 1]
