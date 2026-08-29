# ruff: noqa: E501
from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.database import engine, session_factory
from app.core.errors import ApiError
from app.egress_health_protocol import EgressHealthObservationRequest
from app.models import ExecutionLease, WorkerIdentity
from app.services.egress_health import (
    record_egress_health_observation,
    summarize_egress_health_routes,
)

pytestmark = pytest.mark.asyncio(loop_scope="module")


@pytest_asyncio.fixture(scope="module", autouse=True, loop_scope="module")
async def _dispose_database_pool() -> AsyncIterator[None]:
    yield
    await engine.dispose()


async def _database_available() -> bool:
    try:
        async with engine.connect() as connection:
            return bool(
                await connection.scalar(
                    text(
                        "SELECT to_regclass('control.egress_health_observations') IS NOT NULL"
                    )
                )
            )
    except (OSError, DBAPIError, OperationalError):
        return False


async def _seed() -> tuple[UUID, UUID, UUID, UUID, UUID]:
    user_id, org_id, project_id, agent_id, version_id, build_id, run_id = (
        uuid4() for _ in range(7)
    )
    worker_id, lease_id, source_id = (uuid4() for _ in range(3))
    suffix = uuid4().hex
    now = datetime.now(UTC)
    snapshot = (
        '{"activation":{"capability_profile":"brokered-web-egress",'
        '"egress_policy_digest":"' + "a" * 64 + '"}}'
    )
    async with engine.begin() as connection:
        await connection.execute(text("INSERT INTO identity.users (id,email_normalized,email_display,password_hash,password_algorithm,display_name,status) VALUES (:u,:e,:e,'x','argon2id','Health','ACTIVE')"), {"u": user_id, "e": f"health-{suffix}@example.invalid"})
        await connection.execute(text("INSERT INTO identity.organizations (id,name,slug,status,created_by_user_id) VALUES (:o,'Health',:s,'ACTIVE',:u)"), {"o": org_id, "s": f"health-{suffix}", "u": user_id})
        await connection.execute(text("INSERT INTO identity.organization_memberships (organization_id,user_id,role,status,joined_at,updated_at,created_by_user_id) VALUES (:o,:u,'owner','ACTIVE',:now,:now,:u)"), {"o": org_id, "u": user_id, "now": now})
        await connection.execute(text("INSERT INTO control.projects (id,organization_id,name,slug,status,created_by_user_id) VALUES (:p,:o,'Health',:s,'ACTIVE',:u)"), {"p": project_id, "o": org_id, "s": f"health-{suffix}", "u": user_id})
        await connection.execute(text("INSERT INTO control.agents (id,organization_id,project_id,name,slug,status,created_by_user_id) VALUES (:a,:o,:p,'Health',:s,'ACTIVE',:u)"), {"a": agent_id, "o": org_id, "p": project_id, "s": f"health-{suffix}", "u": user_id})
        await connection.execute(text("INSERT INTO control.agent_versions (id,organization_id,project_id,agent_id,version_number,protocol,semantic_version,manifest_schema_version,manifest_digest,manifest,created_by_user_id) VALUES (:v,:o,:p,:a,1,'rdc-agent/v1','1.0.0','rdc.agent/v1',:digest,'{}',:u)"), {"v": version_id, "o": org_id, "p": project_id, "a": agent_id, "digest": "b" * 64, "u": user_id})
        await connection.execute(text("INSERT INTO control.builds (id,organization_id,project_id,agent_id,agent_version_id,manifest_digest,status,requested_by_user_id) VALUES (:b,:o,:p,:a,:v,:digest,'SUCCEEDED',:u)"), {"b": build_id, "o": org_id, "p": project_id, "a": agent_id, "v": version_id, "digest": "b" * 64, "u": user_id})
        await connection.execute(text("INSERT INTO control.runs (id,organization_id,project_id,agent_id,agent_version_id,build_id,status,input_reference,runtime_configuration,memory_mb,cpu_millis,timeout_seconds,requested_by_user_id,queued_at) VALUES (:r,:o,:p,:a,:v,:b,'RUNNING','{}','{}',128,100,60,:u,:now)"), {"r": run_id, "o": org_id, "p": project_id, "a": agent_id, "v": version_id, "b": build_id, "u": user_id, "now": now})
        await connection.execute(text("INSERT INTO control.run_command_outbox (id,organization_id,project_id,run_id,command,topic,payload,status,attempts,available_at,claimed_at) VALUES (:s,:o,:p,:r,'START','rdc.run.requested.v1','{}','CLAIMED',1,:now,:now)"), {"s": source_id, "o": org_id, "p": project_id, "r": run_id, "now": now})
        await connection.execute(text("INSERT INTO security.worker_identities (id,name,public_prefix,last_four,token_digest,capabilities,max_concurrency,status,protocol_version,software_version,metadata_json) VALUES (:w,:name,:prefix,'0001',:digest,'[\"RUN_START\",\"EVENT_INGEST\"]',1,'ACTIVE','rdc.worker/v1','test','{}')"), {"w": worker_id, "name": f"health-{suffix}", "prefix": suffix[:12], "digest": uuid4().bytes + uuid4().bytes})
        await connection.execute(text("INSERT INTO control.execution_leases (id,worker_id,organization_id,project_id,work_kind,source_outbox_id,source_topic,run_id,lease_token_digest,payload_digest,payload_snapshot,status,attempt,claimed_at,expires_at,deadline_at) VALUES (:l,:w,:o,:p,'RUN_START',:source,'test',:r,:token,:digest,CAST(:snapshot AS jsonb),'ACTIVE',1,:now,:expires,:expires)"), {"l": lease_id, "w": worker_id, "o": org_id, "p": project_id, "source": source_id, "r": run_id, "token": uuid4().bytes + uuid4().bytes, "digest": "c" * 64, "snapshot": snapshot, "now": now, "expires": now + timedelta(hours=1)})
    return user_id, org_id, project_id, worker_id, lease_id


async def test_service_is_idempotent_and_database_rows_are_immutable() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress-health migration is unavailable")
    _, _, _, worker_id, lease_id = await _seed()
    observation_id = uuid4()
    payload = EgressHealthObservationRequest.model_validate(
        {"observation_id": observation_id, "evidence": {"http_status": 429, "response_bytes": 10, "latency_ms": 5}}
    )
    async with session_factory() as session:
        lease = await session.scalar(select(ExecutionLease).where(ExecutionLease.id == lease_id))
        worker = await session.scalar(select(WorkerIdentity).where(WorkerIdentity.id == worker_id))
        assert lease is not None and worker is not None
        first = await record_egress_health_observation(session, lease=lease, worker=worker, payload=payload, request_id="health-first")
        replay = await record_egress_health_observation(session, lease=lease, worker=worker, payload=payload, request_id="health-replay")
        assert first.outcome == "HTTP_429"
        assert (first.provider_key, first.region_key) == (
            "static-canary",
            "local",
        )
        assert replay.id == first.id and replay.replayed is True
        with pytest.raises(ApiError) as conflict:
            await record_egress_health_observation(
                session,
                lease=lease,
                worker=worker,
                payload=EgressHealthObservationRequest.model_validate({"observation_id": observation_id, "evidence": {"http_status": 200, "response_bytes": 10, "latency_ms": 5}}),
                request_id="health-conflict",
            )
        assert conflict.value.code == "EGRESS_HEALTH_REPLAY_CONFLICT"
        for index in range(4):
            await record_egress_health_observation(
                session,
                lease=lease,
                worker=worker,
                payload=EgressHealthObservationRequest.model_validate(
                    {
                        "observation_id": uuid4(),
                        "evidence": {
                            "http_status": 200,
                            "response_bytes": 10,
                            "latency_ms": index + 1,
                        },
                    }
                ),
                request_id=f"health-route-{index}",
            )
        summary = await summarize_egress_health_routes(
            session,
            project_id=lease.project_id,
            window_hours=1,
        )
        assert summary["minimum_samples"] == 5
        assert summary["routes"] == [
            {
                "provider_key": "static-canary",
                "region_key": "local",
                "total": 5,
                "healthy": 4,
                "unhealthy": 1,
                "retryable": 1,
                "healthy_basis_points": 8000,
                "outcomes": {"HTTP_429": 1, "SUCCESS": 4},
            }
        ]
    with pytest.raises(DBAPIError, match="observations are immutable"):
        async with engine.begin() as connection:
            await connection.execute(text("UPDATE control.egress_health_observations SET healthy=false WHERE id=:id"), {"id": first.id})
    direct_id = uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text("INSERT INTO control.egress_health_observations (organization_id,project_id,run_id,lease_id,worker_id,client_observation_id,evidence,evidence_digest,outcome,healthy,retryable) SELECT organization_id,project_id,run_id,id,worker_id,:client,CAST(:evidence AS jsonb),:digest,'SUCCESS',true,false FROM control.execution_leases WHERE id=:lease"),
            {"client": direct_id, "evidence": '{"http_status":429,"response_bytes":1,"latency_ms":2}', "digest": "e" * 64, "lease": lease_id},
        )
        derived = (
            await connection.execute(
                text("SELECT outcome,healthy,retryable,evidence,http_status,response_bytes,latency_ms FROM control.egress_health_observations WHERE client_observation_id=:client"),
                {"client": direct_id},
            )
        ).one()
        assert derived == ("HTTP_429", False, True, None, 429, 1, 2)
        assert await connection.scalar(
            text(
                "SELECT count(*) FROM security.audit_events WHERE action='egress_health.observed' AND resource_id=:resource"
            ),
            {"resource": str(first.id)},
        ) == 0
        index_names = set(
            (
                await connection.execute(
                    text(
                        "SELECT indexname FROM pg_indexes WHERE schemaname='control' AND tablename='egress_health_observations'"
                    )
                )
            ).scalars()
        )
        assert {
            "egress_health_observations_pkey",
            "uq_egress_health_observations_lease_client",
            "ix_egress_health_observations_project_id_observed_at",
            "ix_egress_health_observations_project_route_time",
        } == index_names
    async with session_factory() as session:
        suppressed = await summarize_egress_health_routes(
            session,
            project_id=lease.project_id,
            window_hours=1,
        )
        assert len(suppressed["routes"]) == 1
    with pytest.raises(DBAPIError):
        async with engine.begin() as connection:
            await connection.execute(
                text("INSERT INTO control.egress_health_observations (organization_id,project_id,run_id,lease_id,worker_id,client_observation_id,evidence,evidence_digest,outcome,healthy,retryable,provider_key,region_key) SELECT organization_id,project_id,run_id,id,worker_id,:client,CAST(:evidence AS jsonb),:digest,'SUCCESS',true,false,'Invalid Provider','local' FROM control.execution_leases WHERE id=:lease"),
                {"client": uuid4(), "evidence": '{"http_status":200,"latency_ms":1}', "digest": "f" * 64, "lease": lease_id},
            )
    async with engine.begin() as connection:
        await connection.execute(
            text("INSERT INTO control.egress_health_observations (organization_id,project_id,run_id,lease_id,worker_id,client_observation_id,evidence,evidence_digest,outcome,healthy,retryable,provider_key,region_key) SELECT organization_id,project_id,run_id,id,worker_id,gen_random_uuid(),CAST(:evidence AS jsonb),:digest,'SUCCESS',true,false,'route-' || route_number::text,'local' FROM control.execution_leases CROSS JOIN generate_series(1,33) route_number WHERE id=:lease"),
            {"evidence": '{"http_status":200,"latency_ms":1}', "digest": "1" * 64, "lease": lease_id},
        )
    async with session_factory() as session:
        with pytest.raises(ApiError) as cardinality:
            await summarize_egress_health_routes(
                session,
                project_id=lease.project_id,
                window_hours=1,
            )
        assert cardinality.value.code == "EGRESS_HEALTH_ROUTE_CARDINALITY_EXCEEDED"


async def test_cross_tenant_reference_is_rejected_and_rls_hides_rows() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress-health migration is unavailable")
    user_a, org_a, project_a, worker_a, lease_a = await _seed()
    _, org_b, project_b, _, _ = await _seed()
    with pytest.raises(DBAPIError, match="lease tenancy mismatch"):
        async with engine.begin() as connection:
            await connection.execute(text("INSERT INTO control.egress_health_observations (organization_id,project_id,run_id,lease_id,worker_id,client_observation_id,evidence,evidence_digest,outcome,healthy,retryable) SELECT :org,:project,run_id,id,worker_id,:client,CAST(:evidence AS jsonb),:digest,'SUCCESS',true,false FROM control.execution_leases WHERE id=:lease"), {"org": org_b, "project": project_b, "client": uuid4(), "evidence": '{"http_status":200,"latency_ms":1}', "digest": "d" * 64, "lease": lease_a})
    async with engine.begin() as connection:
        await connection.execute(text("DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rdc_health_rls_test') THEN CREATE ROLE rdc_health_rls_test NOLOGIN; END IF; END $$"))
        await connection.execute(text("GRANT USAGE ON SCHEMA control,security TO rdc_health_rls_test"))
        await connection.execute(text("GRANT SELECT,INSERT,UPDATE,DELETE ON control.egress_health_observations TO rdc_health_rls_test"))
        await connection.execute(text("GRANT SELECT ON control.execution_leases TO rdc_health_rls_test"))
    try:
        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL ROLE rdc_health_rls_test"))
            await connection.execute(text("SELECT set_config('rdc.current_user_id',:u,true)"), {"u": str(user_a)})
            await connection.execute(text("SELECT set_config('rdc.current_organization_id',:o,true)"), {"o": str(org_a)})
            assert await connection.scalar(text("SELECT count(*) FROM control.egress_health_observations WHERE organization_id=:o"), {"o": org_b}) == 0
    finally:
        async with engine.begin() as connection:
            await connection.execute(text("DROP OWNED BY rdc_health_rls_test"))
            await connection.execute(text("DROP ROLE rdc_health_rls_test"))
