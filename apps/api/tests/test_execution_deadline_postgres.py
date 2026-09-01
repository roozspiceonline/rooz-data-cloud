# ruff: noqa: E501
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.database import engine, session_factory
from app.core.errors import ApiError
from app.execution_schemas import (
    ClaimWorkRequest,
    CompleteLeaseRequest,
    RegisterWorkerRequest,
    WorkerHeartbeatRequest,
)
from app.models import ExecutionLease, Run, WorkerIdentity
from app.services.execution_plane import (
    claim_work,
    complete_lease,
    heartbeat_worker,
    reap_expired_leases,
    reap_overdue_cancellations,
    register_worker,
)
from app.services.execution_recovery_sweeper import (
    read_execution_admission_health,
    read_execution_recovery_health,
    record_execution_recovery_failure,
    run_execution_recovery_sweep,
)
from app.services.runs import cancel_run
from app.services.runtime_metrics import read_runtime_metrics

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
) -> tuple[UUID, UUID, UUID, UUID, UUID, UUID, UUID]:
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
    return (
        lease_id,
        source_id,
        build_id if work_kind == "BUILD" else run_id,
        user_id,
        org_id,
        project_id,
        worker_id,
    )


async def test_postgres_execution_deadline_is_immutable() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    lease_id, *_ = await _seed_deadline_lease(
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


async def test_postgres_runtime_metrics_read_one_cross_process_snapshot() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    *_, worker_id = await _seed_deadline_lease(
        work_kind="BUILD",
        now=now,
        overdue=False,
    )
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE security.worker_identities "
                "SET last_seen_at=:now WHERE id=:worker_id"
            ),
            {"now": now, "worker_id": worker_id},
        )
    async with session_factory() as session:
        metrics = await read_runtime_metrics(
            session,
            worker_fresh_after_seconds=45,
        )
    assert metrics.active_execution_leases >= 1
    assert metrics.active_workers >= 1
    assert all(value >= 0 for value in metrics.__dict__.values())


@pytest.mark.parametrize("work_kind", ["BUILD", "RUN_START"])
async def test_postgres_overdue_workload_is_terminally_timed_out(
    work_kind: str,
) -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    lease_id, source_id, target_id, *_ = await _seed_deadline_lease(
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


async def test_postgres_concurrent_cancel_dispatch_is_idempotent() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    _, _, run_id, user_id, _, _, _ = await _seed_deadline_lease(
        work_kind="RUN_START",
        now=now,
        overdue=False,
    )

    async def cancel(key: str) -> str:
        async with session_factory() as session:
            run = await session.scalar(select(Run).where(Run.id == run_id))
            assert run is not None
            result = await cancel_run(
                session,
                record=run,
                user_id=user_id,
                idempotency_key=key,
                request_id=f"cancel-{key}",
            )
            await session.commit()
            return str(result["status"])

    statuses = await asyncio.gather(
        cancel(f"cancel-a-{uuid4().hex}"),
        cancel(f"cancel-b-{uuid4().hex}"),
    )
    assert statuses == ["ABORTING", "ABORTING"]
    async with engine.connect() as connection:
        count = await connection.scalar(
            text("SELECT count(*) FROM control.run_command_outbox WHERE run_id=:run AND command='CANCEL'"),
            {"run": run_id},
        )
        run = (
            await connection.execute(
                text("SELECT status,cancel_requested_at IS NOT NULL,cancel_deadline_at > cancel_requested_at FROM control.runs WHERE id=:run"),
                {"run": run_id},
            )
        ).one()
    assert count == 1
    assert run == ("ABORTING", True, True)
    with pytest.raises(DBAPIError, match="Run cancellation deadline is immutable"):
        async with engine.begin() as connection:
            await connection.execute(
                text("UPDATE control.runs SET cancel_deadline_at=cancel_deadline_at+INTERVAL '1 minute' WHERE id=:run"),
                {"run": run_id},
            )


async def test_postgres_cancellation_revokes_worker_run_lease_authority() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    _, _, run_id, _, org_id, project_id, worker_id = (
        await _seed_deadline_lease(
            work_kind="RUN_START",
            now=now,
            overdue=False,
        )
    )
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('rdc.current_worker_id',:worker,true)"),
            {"worker": str(worker_id)},
        )
        before = await connection.scalar(
            text(
                "SELECT security.rdc_worker_has_active_run_lease(:org,:project)"
            ),
            {"org": org_id, "project": project_id},
        )
        await connection.execute(
            text("UPDATE control.runs SET status='ABORTING',cancel_requested_at=:requested,cancel_deadline_at=:deadline WHERE id=:run"),
            {
                "run": run_id,
                "requested": now,
                "deadline": now + timedelta(minutes=5),
            },
        )
        after = await connection.scalar(
            text(
                "SELECT security.rdc_worker_has_active_run_lease(:org,:project)"
            ),
            {"org": org_id, "project": project_id},
        )
    assert before is True
    assert after is False


async def test_postgres_overdue_cancellation_fences_and_aborts_run() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    lease_id, start_source_id, run_id, _, org_id, project_id, _ = (
        await _seed_deadline_lease(
            work_kind="RUN_START",
            now=now,
            overdue=False,
        )
    )
    cancel_source_id = uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text("UPDATE control.runs SET status='ABORTING',cancel_requested_at=:requested,cancel_deadline_at=:deadline WHERE id=:run"),
            {"run": run_id, "requested": now - timedelta(minutes=10), "deadline": now - timedelta(minutes=5)},
        )
        await connection.execute(
            text("INSERT INTO control.run_command_outbox (id,organization_id,project_id,run_id,command,topic,payload,status,attempts,available_at) VALUES (:id,:org,:project,:run,'CANCEL','rdc.run.cancel.requested.v1','{}','PENDING',0,:now)"),
            {"id": cancel_source_id, "org": org_id, "project": project_id, "run": run_id, "now": now},
        )
    async with session_factory() as session:
        assert await reap_overdue_cancellations(
            session,
            now=now,
            request_id="overdue-cancellation",
        ) == 1
        await session.commit()
    async with engine.connect() as connection:
        run = (
            await connection.execute(
                text("SELECT status,failure_code,finished_at IS NOT NULL FROM control.runs WHERE id=:id"),
                {"id": run_id},
            )
        ).one()
        lease = (
            await connection.execute(
                text("SELECT status,failure_code FROM control.execution_leases WHERE id=:id"),
                {"id": lease_id},
            )
        ).one()
        commands = (
            await connection.execute(
                text("SELECT id,status,last_error_code FROM control.run_command_outbox WHERE id IN (:start,:cancel) ORDER BY id"),
                {"start": start_source_id, "cancel": cancel_source_id},
            )
        ).all()
        audit = await connection.scalar(
            text("SELECT count(*) FROM security.audit_events WHERE resource_id=:run AND action='run.cancellation_converged' AND details->>'reason'='CANCEL_DEADLINE_EXCEEDED'"),
            {"run": str(run_id)},
        )
    assert run == ("ABORTED", None, True)
    assert lease == ("CANCELLED", "RUN_CANCELLED")
    assert {row[1:] for row in commands} == {
        ("CANCELLED", "RUN_CANCELLATION_CONVERGED")
    }
    assert audit == 1


async def test_postgres_concurrent_cancellation_reapers_are_single_winner() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    _, _, run_id, _, _, _, _ = await _seed_deadline_lease(
        work_kind="RUN_START",
        now=now,
        overdue=False,
    )
    async with engine.begin() as connection:
        await connection.execute(
            text("UPDATE control.runs SET status='ABORTING',cancel_requested_at=:requested,cancel_deadline_at=:deadline WHERE id=:run"),
            {
                "run": run_id,
                "requested": now - timedelta(minutes=10),
                "deadline": now - timedelta(minutes=5),
            },
        )

    async def reap(request_id: str) -> int:
        async with session_factory() as session:
            count = await reap_overdue_cancellations(
                session,
                now=now,
                request_id=request_id,
                batch_size=1,
            )
            await session.commit()
            return count

    results = await asyncio.gather(
        reap("cancellation-race-a"),
        reap("cancellation-race-b"),
    )
    assert sorted(results) == [0, 1]


async def test_postgres_lost_run_lease_converges_pending_cancellation() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    lease_id, _, run_id, _, org_id, project_id, _ = await _seed_deadline_lease(
        work_kind="RUN_START",
        now=now,
        overdue=True,
    )
    async with engine.begin() as connection:
        await connection.execute(
            text("UPDATE control.runs SET status='ABORTING',cancel_requested_at=:requested,cancel_deadline_at=:deadline WHERE id=:run"),
            {"run": run_id, "requested": now - timedelta(minutes=2), "deadline": now + timedelta(minutes=3)},
        )
        await connection.execute(
            text("INSERT INTO control.run_command_outbox (organization_id,project_id,run_id,command,topic,payload,status,attempts,available_at) VALUES (:org,:project,:run,'CANCEL','rdc.run.cancel.requested.v1','{}','PENDING',0,:now)"),
            {"org": org_id, "project": project_id, "run": run_id, "now": now},
        )
    async with session_factory() as session:
        assert await reap_expired_leases(
            session,
            now=now,
            request_id="lost-run-cancellation",
        ) == 1
        await session.commit()
    async with engine.connect() as connection:
        run_status = await connection.scalar(
            text("SELECT status FROM control.runs WHERE id=:id"),
            {"id": run_id},
        )
        lease_status = await connection.scalar(
            text("SELECT status FROM control.execution_leases WHERE id=:id"),
            {"id": lease_id},
        )
        retries = await connection.scalar(
            text("SELECT count(*) FROM control.run_command_outbox WHERE run_id=:run AND status='PENDING'"),
            {"run": run_id},
        )
    assert run_status == "ABORTED"
    assert lease_status == "CANCELLED"
    assert retries == 0


async def test_postgres_late_run_completion_cannot_override_cancellation() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    lease_id, _, run_id, _, org_id, project_id, worker_id = (
        await _seed_deadline_lease(
            work_kind="RUN_START",
            now=now,
            overdue=False,
        )
    )
    async with engine.begin() as connection:
        await connection.execute(
            text("UPDATE control.runs SET status='ABORTING',cancel_requested_at=:requested,cancel_deadline_at=:deadline WHERE id=:run"),
            {"run": run_id, "requested": now, "deadline": now + timedelta(minutes=5)},
        )
        await connection.execute(
            text("INSERT INTO control.run_command_outbox (organization_id,project_id,run_id,command,topic,payload,status,attempts,available_at) VALUES (:org,:project,:run,'CANCEL','rdc.run.cancel.requested.v1','{}','PENDING',0,:now)"),
            {"org": org_id, "project": project_id, "run": run_id, "now": now},
        )
    async with session_factory() as session:
        lease = await session.scalar(
            select(ExecutionLease).where(ExecutionLease.id == lease_id)
        )
        worker = await session.scalar(
            select(WorkerIdentity).where(WorkerIdentity.id == worker_id)
        )
        assert lease is not None
        assert worker is not None
        result = await complete_lease(
            session,
            lease=lease,
            worker=worker,
            payload=CompleteLeaseRequest(outcome="SUCCEEDED"),
            request_id="late-run-completion",
        )
        await session.commit()
    assert result.status == "CANCELLED"
    async with engine.connect() as connection:
        run_status = await connection.scalar(
            text("SELECT status FROM control.runs WHERE id=:id"),
            {"id": run_id},
        )
        event_count = await connection.scalar(
            text("SELECT count(*) FROM control.run_events WHERE run_id=:run AND event_type='run.completed' AND payload->>'reason'='LATE_RUN_START_COMPLETION'"),
            {"run": run_id},
        )
    assert run_status == "ABORTED"
    assert event_count == 1


async def test_postgres_recovery_sweep_is_singleton_and_restart_safe() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    lease_id, *_ = await _seed_deadline_lease(
        work_kind="BUILD",
        now=now,
        overdue=True,
    )
    first_session = session_factory()
    second_session = session_factory()
    try:
        first = await run_execution_recovery_sweep(
            first_session,
            now=now,
            owner_id="sweeper-before-crash",
            batch_size=1,
            request_id="sweep-before-crash",
        )
        assert first.acquired is True
        assert first.leases_reaped == 1
        competing = await run_execution_recovery_sweep(
            second_session,
            now=now,
            owner_id="competing-sweeper",
            batch_size=1,
            request_id="competing-sweep",
        )
        assert competing.acquired is False
        await second_session.rollback()
        await first_session.rollback()
    finally:
        await second_session.close()
        await first_session.close()

    async with engine.connect() as connection:
        status_after_crash = await connection.scalar(
            text("SELECT status FROM control.execution_leases WHERE id=:lease"),
            {"lease": lease_id},
        )
    assert status_after_crash == "ACTIVE"

    async with session_factory() as restart_session:
        restarted = await run_execution_recovery_sweep(
            restart_session,
            now=now,
            owner_id="sweeper-after-restart",
            batch_size=1,
            request_id="sweep-after-restart",
        )
        await restart_session.commit()
    assert restarted.acquired is True
    assert restarted.leases_reaped == 1
    health_session = session_factory()
    try:
        health = await read_execution_recovery_health(health_session)
    finally:
        await health_session.close()
    assert health.status == "HEALTHY"
    assert health.last_leases_reaped == 1
    assert health.total_sweeps >= 1


async def test_postgres_recovery_sweep_enforces_bounded_batches() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    first_lease, *_ = await _seed_deadline_lease(
        work_kind="BUILD",
        now=now,
        overdue=True,
    )
    second_lease, *_ = await _seed_deadline_lease(
        work_kind="BUILD",
        now=now,
        overdue=True,
    )
    async with session_factory() as session:
        first = await run_execution_recovery_sweep(
            session,
            now=now,
            owner_id="bounded-sweeper",
            batch_size=1,
            request_id="bounded-sweep-1",
        )
        await session.commit()
    assert first.leases_reaped == 1
    async with engine.connect() as connection:
        active_after_first = await connection.scalar(
            text(
                "SELECT count(*) FROM control.execution_leases "
                "WHERE id IN (:first,:second) AND status='ACTIVE'"
            ),
            {"first": first_lease, "second": second_lease},
        )
    assert active_after_first == 1
    async with session_factory() as session:
        second = await run_execution_recovery_sweep(
            session,
            now=now,
            owner_id="bounded-sweeper",
            batch_size=1,
            request_id="bounded-sweep-2",
        )
        await session.commit()
    assert second.leases_reaped == 1


async def test_postgres_delayed_failure_cannot_overwrite_newer_health() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    async with session_factory() as session:
        await record_execution_recovery_failure(
            session,
            now=now,
            failed_started_at=now,
            owner_id="failed-sweeper",
            error_code="ExpectedTestFailure",
        )
        await session.commit()
    async with session_factory() as session:
        failed = await read_execution_recovery_health(session)
    assert failed.status == "FAILED"
    async with session_factory() as session:
        recovered = await run_execution_recovery_sweep(
            session,
            now=now + timedelta(seconds=2),
            owner_id="healthy-sweeper",
            batch_size=1,
            request_id="healthy-after-failure",
        )
        await session.commit()
    assert recovered.acquired is True
    async with session_factory() as session:
        await record_execution_recovery_failure(
            session,
            now=now + timedelta(seconds=3),
            failed_started_at=now + timedelta(seconds=1),
            owner_id="delayed-failed-sweeper",
            error_code="DelayedFailure",
        )
        await session.commit()
    async with session_factory() as session:
        final = await read_execution_recovery_health(session)
    assert final.status == "HEALTHY"
    assert final.total_failures == failed.total_failures


async def _prepare_run_start_admission(
    *,
    now: datetime,
    project_limit: int,
    worker_limit: int,
) -> tuple[UUID, UUID, UUID, UUID]:
    lease_id, source_id, first_run_id, _, org_id, project_id, first_worker_id = (
        await _seed_deadline_lease(
            work_kind="RUN_START",
            now=now,
            overdue=False,
        )
    )
    second_run_id = uuid4()
    second_source_id = uuid4()
    second_worker_id = uuid4()
    suffix = uuid4().hex
    async with engine.begin() as connection:
        await connection.execute(
            text("UPDATE control.projects SET max_active_leases=:limit WHERE id=:project"),
            {"limit": project_limit, "project": project_id},
        )
        await connection.execute(
            text("UPDATE security.worker_identities SET max_concurrency=:limit WHERE id=:worker"),
            {"limit": worker_limit, "worker": first_worker_id},
        )
        await connection.execute(
            text("UPDATE control.execution_leases SET status='COMPLETED',completed_at=:now WHERE id=:lease"),
            {"now": now, "lease": lease_id},
        )
        await connection.execute(
            text("UPDATE control.run_command_outbox SET status='PENDING',attempts=1,claimed_at=NULL,available_at=:available_at,payload=CAST(:payload AS jsonb),updated_at=:now WHERE id=:source"),
            {
                "now": now,
                "available_at": now - timedelta(days=1),
                "source": source_id,
                "payload": '{"runtime":{"timeout_seconds":60}}',
            },
        )
        await connection.execute(
            text("UPDATE control.runs SET status='QUEUED',started_at=NULL,updated_at=:now WHERE id=:run"),
            {"now": now, "run": first_run_id},
        )
        await connection.execute(
            text("INSERT INTO control.runs (id,organization_id,project_id,agent_id,agent_version_id,build_id,status,input_reference,runtime_configuration,memory_mb,cpu_millis,timeout_seconds,requested_by_user_id,queued_at) SELECT :second,organization_id,project_id,agent_id,agent_version_id,build_id,'QUEUED',input_reference,runtime_configuration,memory_mb,cpu_millis,timeout_seconds,requested_by_user_id,:now FROM control.runs WHERE id=:first"),
            {"second": second_run_id, "first": first_run_id, "now": now},
        )
        await connection.execute(
            text("INSERT INTO control.run_command_outbox (id,organization_id,project_id,run_id,command,topic,payload,status,attempts,available_at) VALUES (:source,:org,:project,:run,'START','rdc.run.requested.v1',CAST(:payload AS jsonb),'PENDING',0,:available_at)"),
            {
                "source": second_source_id,
                "org": org_id,
                "project": project_id,
                "run": second_run_id,
                "available_at": now - timedelta(days=1),
                "payload": '{"runtime":{"timeout_seconds":60}}',
            },
        )
        await connection.execute(
            text("INSERT INTO security.worker_identities (id,name,public_prefix,last_four,token_digest,capabilities,max_concurrency,status,protocol_version,software_version,metadata_json) VALUES (:worker,:name,:prefix,'0002',:digest,'[\"RUN_START\"]',:limit,'ACTIVE','rdc-worker/v1','test','{}')"),
            {
                "worker": second_worker_id,
                "name": f"admission-{suffix}",
                "prefix": suffix[:12],
                "digest": uuid4().bytes + uuid4().bytes,
                "limit": worker_limit,
            },
        )
    return first_worker_id, second_worker_id, project_id, first_run_id


async def _claim_run_start(worker_id: UUID, request_id: str) -> str:
    async with session_factory() as session:
        worker = await session.scalar(
            select(WorkerIdentity).where(WorkerIdentity.id == worker_id)
        )
        assert worker is not None
        try:
            result = await claim_work(
                session,
                worker=worker,
                payload=ClaimWorkRequest(kinds=["RUN_START"]),
                request_id=request_id,
            )
            await session.commit()
            return "CLAIMED" if result is not None else "NO_CAPACITY"
        except ApiError as exc:
            await session.rollback()
            return exc.code


async def test_postgres_project_admission_is_single_winner_and_releases() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    first_worker, second_worker, project_id, _ = (
        await _prepare_run_start_admission(
            now=now,
            project_limit=1,
            worker_limit=1,
        )
    )
    results = await asyncio.gather(
        _claim_run_start(first_worker, "project-admission-a"),
        _claim_run_start(second_worker, "project-admission-b"),
    )
    assert results.count("CLAIMED") == 1
    assert set(results) <= {"CLAIMED", "NO_CAPACITY", "PROJECT_CONCURRENCY_LIMIT"}
    async with engine.begin() as connection:
        active_lease = (
            await connection.execute(
                text("SELECT id,worker_id FROM control.execution_leases WHERE project_id=:project AND status='ACTIVE' AND work_kind='RUN_START'"),
                {"project": project_id},
            )
        ).one()
        await connection.execute(
            text("UPDATE control.execution_leases SET status='COMPLETED',completed_at=:now WHERE id=:lease"),
            {"now": now, "lease": active_lease.id},
        )
    losing_worker = (
        second_worker if active_lease.worker_id == first_worker else first_worker
    )
    assert await _claim_run_start(
        losing_worker,
        "project-admission-after-release",
    ) == "CLAIMED"


async def test_postgres_worker_admission_is_single_winner() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    worker_id, _, project_id, _ = await _prepare_run_start_admission(
        now=now,
        project_limit=2,
        worker_limit=1,
    )
    results = await asyncio.gather(
        _claim_run_start(worker_id, "worker-admission-a"),
        _claim_run_start(worker_id, "worker-admission-b"),
    )
    assert sorted(results) == ["CLAIMED", "WORKER_CONCURRENCY_LIMIT"]
    async with engine.connect() as connection:
        active_count = await connection.scalar(
            text("SELECT count(*) FROM control.execution_leases WHERE project_id=:project AND worker_id=:worker AND status='ACTIVE'"),
            {"project": project_id, "worker": worker_id},
        )
    assert active_count == 1


async def test_postgres_run_cancel_bypasses_saturated_project_admission() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    _, _, run_id, _, org_id, project_id, _ = await _seed_deadline_lease(
        work_kind="RUN_START",
        now=now,
        overdue=False,
    )
    cancel_source_id = uuid4()
    cancel_worker_id = uuid4()
    suffix = uuid4().hex
    cancel_deadline = now + timedelta(minutes=5)
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.projects SET max_active_leases=1 "
                "WHERE id=:project"
            ),
            {"project": project_id},
        )
        await connection.execute(
            text(
                "UPDATE control.runs SET status='ABORTING',"
                "cancel_requested_at=:now,cancel_deadline_at=:deadline "
                "WHERE id=:run"
            ),
            {"run": run_id, "now": now, "deadline": cancel_deadline},
        )
        await connection.execute(
            text(
                "INSERT INTO control.run_command_outbox "
                "(id,organization_id,project_id,run_id,command,topic,payload,"
                "status,attempts,available_at) VALUES "
                "(:source,:org,:project,:run,'CANCEL',"
                "'rdc.run.cancel.requested.v1',CAST(:payload AS jsonb),"
                "'PENDING',0,:now)"
            ),
            {
                "source": cancel_source_id,
                "org": org_id,
                "project": project_id,
                "run": run_id,
                "payload": (
                    '{"cancel_deadline_at":"'
                    f"{cancel_deadline.isoformat()}"
                    '"}'
                ),
                "now": now - timedelta(days=3650),
            },
        )
        await connection.execute(
            text(
                "INSERT INTO security.worker_identities "
                "(id,name,public_prefix,last_four,token_digest,capabilities,"
                "max_concurrency,status,protocol_version,software_version,"
                "metadata_json) VALUES "
                "(:worker,:name,:prefix,'0003',:digest,'[\"RUN_CANCEL\"]',"
                "1,'ACTIVE','rdc-worker/v1','test','{}')"
            ),
            {
                "worker": cancel_worker_id,
                "name": f"cancel-admission-{suffix}",
                "prefix": suffix[:12],
                "digest": uuid4().bytes + uuid4().bytes,
            },
        )
    async with session_factory() as session:
        worker = await session.scalar(
            select(WorkerIdentity).where(
                WorkerIdentity.id == cancel_worker_id
            )
        )
        assert worker is not None
        claim = await claim_work(
            session,
            worker=worker,
            payload=ClaimWorkRequest(kinds=["RUN_CANCEL"]),
            request_id="cancel-bypasses-project-admission",
        )
        await session.commit()
    assert claim is not None
    assert claim.work_kind == "RUN_CANCEL"
    assert claim.run_id == run_id
    assert claim.payload["admission"] == {
        "worker_active_before_claim": 0,
        "worker_max_concurrency": 1,
        "project_active_before_claim": 1,
        "project_max_active_leases": 1,
        "project_slot_consumed": False,
    }
    async with engine.connect() as connection:
        active_slots = await connection.scalar(
            text(
                "SELECT count(*) FROM control.execution_leases "
                "WHERE project_id=:project AND status='ACTIVE' "
                "AND work_kind IN ('BUILD','RUN_START')"
            ),
            {"project": project_id},
        )
        active_cancellations = await connection.scalar(
            text(
                "SELECT count(*) FROM control.execution_leases "
                "WHERE project_id=:project AND status='ACTIVE' "
                "AND work_kind='RUN_CANCEL'"
            ),
            {"project": project_id},
        )
    assert active_slots == 1
    assert active_cancellations == 1


async def test_postgres_admission_limits_are_database_bounded() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    _, _, _, _, _, project_id, worker_id = await _seed_deadline_lease(
        work_kind="BUILD",
        now=now,
        overdue=False,
    )
    with pytest.raises(DBAPIError, match="ck_projects_max_active_leases"):
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE control.projects SET max_active_leases=0 "
                    "WHERE id=:project"
                ),
                {"project": project_id},
            )
    with pytest.raises(
        DBAPIError,
        match="ck_worker_identities_max_concurrency",
    ):
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE security.worker_identities SET max_concurrency=17 "
                    "WHERE id=:worker"
                ),
                {"worker": worker_id},
            )


async def test_postgres_admission_health_reports_aggregate_saturation() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    _, _, _, _, _, project_id, _ = await _seed_deadline_lease(
        work_kind="BUILD",
        now=now,
        overdue=False,
    )
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.projects SET max_active_leases=1 "
                "WHERE id=:project"
            ),
            {"project": project_id},
        )
    async with session_factory() as session:
        health = await read_execution_admission_health(session)
    assert health.active_leases >= 1
    assert health.saturated_projects >= 1
    assert health.saturated_workers >= 1


async def test_postgres_worker_registration_is_server_capped() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    suffix = uuid4().hex
    async with session_factory() as session:
        result = await register_worker(
            session,
            payload=RegisterWorkerRequest(
                name=f"capped-{suffix}",
                capabilities=["BUILD"],
                max_concurrency=256,
                software_version="test",
            ),
            request_id="worker-registration-cap",
        )
        await session.commit()
    assert result.worker.max_concurrency == 16


async def test_postgres_lost_worker_is_fenced_and_requires_cleanup_recovery() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    now = datetime.now(UTC)
    lease_id, source_id, _, _, _, _, worker_id = await _seed_deadline_lease(
        work_kind="BUILD",
        now=now,
        overdue=False,
    )
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE security.worker_identities "
                "SET last_seen_at=:last_seen WHERE id=:worker"
            ),
            {
                "last_seen": now - timedelta(minutes=2),
                "worker": worker_id,
            },
        )
    async with session_factory() as session:
        result = await run_execution_recovery_sweep(
            session,
            now=now,
            owner_id="worker-loss-test",
            batch_size=100,
            request_id="worker-loss-test",
        )
        await session.commit()
    assert result.workers_lost == 1
    assert result.worker_leases_fenced == 1
    assert result.leases_reaped >= 1
    async with engine.connect() as connection:
        worker = (
            await connection.execute(
                text(
                    "SELECT last_lost_at,last_recovered_at,"
                    "sandbox_execution_enabled,cleanup_generation "
                    "FROM security.worker_identities WHERE id=:worker"
                ),
                {"worker": worker_id},
            )
        ).one()
        lease = (
            await connection.execute(
                text(
                    "SELECT status,failure_code FROM control.execution_leases "
                    "WHERE id=:lease"
                ),
                {"lease": lease_id},
            )
        ).one()
        source = (
            await connection.execute(
                text(
                    "SELECT status,last_error_code "
                    "FROM control.build_dispatch_outbox WHERE id=:source"
                ),
                {"source": source_id},
            )
        ).one()
        lost_audits = await connection.scalar(
            text(
                "SELECT count(*) FROM security.audit_events "
                "WHERE resource_id=:worker AND action='worker.lost'"
            ),
            {"worker": str(worker_id)},
        )
        await connection.execute(
            text("SELECT set_config('rdc.current_worker_id', :worker, true)"),
            {"worker": str(worker_id)},
        )
        worker_rls_active = await connection.scalar(
            text("SELECT security.rdc_worker_is_active()")
        )
    assert worker.last_lost_at == now
    assert worker.last_recovered_at is None
    assert worker.sandbox_execution_enabled is False
    assert worker.cleanup_generation == 0
    assert lease == ("EXPIRED", "WORKER_LOST")
    assert source == ("PENDING", "WORKER_LOST")
    assert lost_audits == 1
    assert worker_rls_active is False

    async with session_factory() as session:
        worker_record = await session.scalar(
            select(WorkerIdentity).where(WorkerIdentity.id == worker_id)
        )
        assert worker_record is not None
        with pytest.raises(ApiError, match="managed-runtime cleanup"):
            await heartbeat_worker(
                session,
                worker=worker_record,
                payload=WorkerHeartbeatRequest(
                    software_version="restart-test",
                    active_lease_count=0,
                ),
                request_id="worker-recovery-missing-cleanup",
            )
        await session.rollback()

    startup_id = uuid4()
    async with session_factory() as session:
        worker_record = await session.scalar(
            select(WorkerIdentity).where(WorkerIdentity.id == worker_id)
        )
        assert worker_record is not None
        recovered = await heartbeat_worker(
            session,
            worker=worker_record,
            payload=WorkerHeartbeatRequest(
                software_version="restart-test",
                active_lease_count=0,
                recovery={
                    "schema_version": "rdc.worker-recovery/v1",
                    "startup_id": startup_id,
                    "forced_cleanup_completed": True,
                    "managed_containers_removed": 1,
                    "workspace_directories_removed": 2,
                },
            ),
            request_id="worker-recovered-after-cleanup",
        )
        await session.commit()
    assert recovered.last_recovered_at is not None
    assert recovered.last_recovered_at >= now
    assert recovered.last_cleanup_at == recovered.last_recovered_at
    assert recovered.cleanup_generation == 1
    assert recovered.metadata["recovery_startup_id"] == str(startup_id)

    recovery_payload = WorkerHeartbeatRequest(
        software_version="restart-test",
        active_lease_count=0,
        recovery={
            "schema_version": "rdc.worker-recovery/v1",
            "startup_id": startup_id,
            "forced_cleanup_completed": True,
            "managed_containers_removed": 1,
            "workspace_directories_removed": 2,
        },
    )
    async with session_factory() as session:
        worker_record = await session.scalar(
            select(WorkerIdentity).where(WorkerIdentity.id == worker_id)
        )
        assert worker_record is not None
        duplicate = await heartbeat_worker(
            session,
            worker=worker_record,
            payload=recovery_payload,
            request_id="worker-recovery-report-retried",
        )
        await session.commit()
    assert duplicate.cleanup_generation == 1
    assert duplicate.last_cleanup_at == recovered.last_cleanup_at

    assert recovered.last_recovered_at is not None
    replay_loss_at = recovered.last_recovered_at + timedelta(seconds=1)
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE security.worker_identities "
                "SET last_lost_at=:lost_at WHERE id=:worker_id"
            ),
            {"lost_at": replay_loss_at, "worker_id": worker_id},
        )
    async with session_factory() as session:
        worker_record = await session.scalar(
            select(WorkerIdentity).where(WorkerIdentity.id == worker_id)
        )
        assert worker_record is not None
        with pytest.raises(ApiError, match="already accepted"):
            await heartbeat_worker(
                session,
                worker=worker_record,
                payload=recovery_payload,
                request_id="worker-recovery-report-replayed",
            )
        await session.rollback()
