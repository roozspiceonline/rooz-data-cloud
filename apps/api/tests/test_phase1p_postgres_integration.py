# ruff: noqa: E501
from __future__ import annotations

import asyncio
from uuid import UUID, uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.database import engine, session_factory
from app.services.request_queues import claim_next_request

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
