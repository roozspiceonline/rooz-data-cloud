# ruff: noqa: E501
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.database import engine, session_factory
from app.core.errors import ApiError
from app.services.request_queues import claim_next_request, reclaim_expired_requests
from app.services.worker_request_queue import complete_worker_queue_request

pytestmark = pytest.mark.asyncio(loop_scope="module")


async def _database_available() -> bool:
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except (OSError, DBAPIError, OperationalError):
        return False


async def _seed() -> tuple[UUID, UUID, UUID, UUID, UUID]:
    user_id, org_id, project_id, queue_id, request_id = (uuid4() for _ in range(5))
    suffix = uuid4().hex
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO identity.users (id,email_normalized,email_display,password_hash,password_algorithm,display_name,status) VALUES (:u,:e,:e,'x','argon2id','Phase1P','ACTIVE')"
            ),
            {"u": user_id, "e": f"phase1p-{suffix}@example.invalid"},
        )
        await connection.execute(
            text(
                "INSERT INTO identity.organizations (id,name,slug,status,created_by_user_id) VALUES (:o,'Phase1P',:s,'ACTIVE',:u)"
            ),
            {"o": org_id, "s": f"phase1p-{suffix}", "u": user_id},
        )
        await connection.execute(
            text(
                "INSERT INTO identity.organization_memberships (organization_id,user_id,role,status,joined_at,updated_at,created_by_user_id) VALUES (:o,:u,'owner','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,:u)"
            ),
            {"o": org_id, "u": user_id},
        )
        await connection.execute(
            text(
                "INSERT INTO control.projects (id,organization_id,name,slug,status,created_by_user_id) VALUES (:p,:o,'Phase1P',:s,'ACTIVE',:u)"
            ),
            {"p": project_id, "o": org_id, "s": f"phase1p-{suffix}", "u": user_id},
        )
        await connection.execute(
            text(
                "INSERT INTO control.request_queues (id,organization_id,project_id,name,created_by_user_id) VALUES (:q,:o,:p,'default',:u)"
            ),
            {"q": queue_id, "o": org_id, "p": project_id, "u": user_id},
        )
        await connection.execute(
            text(
                "INSERT INTO control.request_queue_requests (id,organization_id,project_id,queue_id,request_url,identity_digest,user_data,created_by_user_id) VALUES (:r,:o,:p,:q,'https://example.com/','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','{}',:u)"
            ),
            {"r": request_id, "o": org_id, "p": project_id, "q": queue_id, "u": user_id},
        )
        await connection.execute(
            text("UPDATE control.request_queues SET pending_count=1 WHERE id=:q"), {"q": queue_id}
        )
    return user_id, org_id, project_id, queue_id, request_id


async def test_postgres_simultaneous_claim_is_single_winner_and_counters_hold() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    seeded = await _seed()
    _, _, _, queue_id, request_id = seeded

    async def claim(worker: str) -> UUID | None:
        async with session_factory() as session:
            result = await claim_next_request(session, queue_id=queue_id, worker_id=worker)
            await session.commit()
            return result.id if result else None

    winners = await asyncio.gather(claim("worker-a"), claim("worker-b"))
    assert winners.count(request_id) == 1
    assert winners.count(None) == 1
    async with engine.connect() as connection:
        counts = (
            await connection.execute(
                text("SELECT pending_count,claimed_count FROM control.request_queues WHERE id=:q"),
                {"q": queue_id},
            )
        ).one()
        assert counts == (0, 1)


async def test_postgres_tenancy_trigger_rejects_cross_project_queue_request() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    seeded = await _seed()
    user_id, org_id, _, queue_id, _ = seeded
    with pytest.raises(DBAPIError):
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO control.request_queue_requests (organization_id,project_id,queue_id,request_url,identity_digest,user_data,created_by_user_id) VALUES (:o,:wrong,:q,'https://example.com/x','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','{}',:u)"
                ),
                {"o": org_id, "wrong": uuid4(), "q": queue_id, "u": user_id},
            )


async def test_postgres_expired_claim_requeues_and_reconciles_counters() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    _, _, _, queue_id, request_id = await _seed()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.request_queue_requests SET status='CLAIMED',attempt_count=1,claimed_by='worker',claim_token=gen_random_uuid(),claim_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE id=:r"
            ),
            {"r": request_id},
        )
        await connection.execute(
            text("UPDATE control.request_queues SET pending_count=0,claimed_count=1 WHERE id=:q"),
            {"q": queue_id},
        )
    async with session_factory() as session:
        assert await reclaim_expired_requests(session, queue_id=queue_id) == 1
        await session.commit()
    async with engine.connect() as connection:
        row = (
            await connection.execute(
                text("SELECT status,attempt_count FROM control.request_queue_requests WHERE id=:r"),
                {"r": request_id},
            )
        ).one()
        counts = (
            await connection.execute(
                text(
                    "SELECT pending_count,claimed_count,failed_count FROM control.request_queues WHERE id=:q"
                ),
                {"q": queue_id},
            )
        ).one()
        assert row == ("PENDING", 1)
        assert counts == (1, 0, 0)


async def test_postgres_retry_exhaustion_fails_and_reconciles_counters() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    _, _, _, queue_id, request_id = await _seed()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.request_queue_requests SET status='CLAIMED',attempt_count=3,max_attempts=3,claimed_by='worker',claim_token=gen_random_uuid(),claim_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE id=:r"
            ),
            {"r": request_id},
        )
        await connection.execute(
            text("UPDATE control.request_queues SET pending_count=0,claimed_count=1 WHERE id=:q"),
            {"q": queue_id},
        )
    async with session_factory() as session:
        assert await reclaim_expired_requests(session, queue_id=queue_id) == 1
        await session.commit()
    async with engine.connect() as connection:
        row = (
            await connection.execute(
                text("SELECT status,failure_code FROM control.request_queue_requests WHERE id=:r"),
                {"r": request_id},
            )
        ).one()
        counts = (
            await connection.execute(
                text(
                    "SELECT pending_count,claimed_count,failed_count FROM control.request_queues WHERE id=:q"
                ),
                {"q": queue_id},
            )
        ).one()
        assert row == ("FAILED", "LEASE_EXPIRED")
        assert counts == (0, 0, 1)


async def test_postgres_cross_tenant_resolver_denies_queue_discovery() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    user_a, org_a, _, _, _ = await _seed()
    _, _, _, queue_b, _ = await _seed()
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('rdc.current_user_id',:u,true)"), {"u": str(user_a)}
        )
        await connection.execute(
            text("SELECT set_config('rdc.current_organization_id',:o,true)"), {"o": str(org_a)}
        )
        assert (
            await connection.scalar(
                text("SELECT security.rdc_request_queue_org(:q)"), {"q": queue_b}
            )
            is None
        )


async def test_postgres_stale_claim_token_cannot_complete(monkeypatch: pytest.MonkeyPatch) -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    _, org_id, project_id, queue_id, request_id = await _seed()
    worker_id, real_token = uuid4(), uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.request_queue_requests SET status='CLAIMED',attempt_count=1,claimed_by=:w,claim_token=:t,claim_expires_at=CURRENT_TIMESTAMP+INTERVAL '1 minute' WHERE id=:r"
            ),
            {"w": str(worker_id), "t": real_token, "r": request_id},
        )
        await connection.execute(
            text("UPDATE control.request_queues SET pending_count=0,claimed_count=1 WHERE id=:q"),
            {"q": queue_id},
        )
    from app.services import worker_request_queue as worker_service

    monkeypatch.setattr(worker_service.settings, "sandbox_execution_enabled", True)
    monkeypatch.setattr(worker_service.settings, "sandbox_activation_mode", "canary")
    monkeypatch.setattr(worker_service.settings, "sandbox_canary_request_queue_enabled", True)
    monkeypatch.setattr(worker_service.settings, "sandbox_canary_worker_name", "phase1p-worker")
    monkeypatch.setattr(
        worker_service.settings, "sandbox_canary_agent_version_id", "phase1p-version"
    )
    lease = SimpleNamespace(
        id=uuid4(),
        organization_id=org_id,
        project_id=project_id,
        work_kind="RUN",
        payload_snapshot={
            "agent_version_id": "phase1p-version",
            "manifest": {"capabilities": {"requestQueue": True}},
        },
    )
    worker = SimpleNamespace(
        id=worker_id, name="phase1p-worker", capabilities=["REQUEST_QUEUE_ACCESS"]
    )
    payload = {
        "queue_id": str(queue_id),
        "request_id": str(request_id),
        "claim_token": str(uuid4()),
        "status": "HANDLED",
        "failure_code": None,
        "failure_summary": None,
    }
    async with session_factory() as session:
        with pytest.raises(ApiError, match="stale or invalid"):
            await complete_worker_queue_request(
                session, lease=lease, worker=worker, payload=payload
            )  # type: ignore[arg-type]
