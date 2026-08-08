# ruff: noqa: E501
from __future__ import annotations

import asyncio
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.database import engine, session_factory
from app.core.errors import ApiError
from app.core.pagination import (
    QueueTransitionCursorPosition,
    RequestQueueListCursorPosition,
)
from app.models import RequestQueue
from app.request_queue_protocol import validate_queue_enqueue
from app.services.request_queues import (
    claim_next_request,
    enqueue_request,
    list_queue_transitions,
    list_request_queues,
    reclaim_expired_requests,
)
from app.services.worker_request_queue import complete_worker_queue_request

pytestmark = pytest.mark.asyncio(loop_scope="module")


async def _database_available() -> bool:
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
        return True
    except (OSError, DBAPIError, OperationalError):
        return False


async def _seed(
    *, with_request: bool = True, queue_created_at: str | None = None
) -> tuple[UUID, UUID, UUID, UUID, UUID]:
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
                "INSERT INTO control.request_queues (id,organization_id,project_id,name,created_by_user_id,created_at) VALUES (:q,:o,:p,'default',:u,COALESCE(CAST(:created_at AS timestamptz),CURRENT_TIMESTAMP))"
            ),
            {"q": queue_id, "o": org_id, "p": project_id, "u": user_id, "created_at": queue_created_at},
        )
        if with_request:
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
            result = await claim_next_request(
                session,
                queue_id=queue_id,
                worker_id=worker,
                request_id=f"claim-{worker}",
            )
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
        audit = (
            await connection.execute(
                text(
                    "SELECT action,resource_id,details->>'queue_id' FROM security.audit_events WHERE resource_id=:r AND action='request_queue.request_claimed'"
                ),
                {"r": str(request_id)},
            )
        ).one()
        assert audit == (
            "request_queue.request_claimed",
            str(request_id),
            str(queue_id),
        )


async def test_postgres_idempotent_enqueue_emits_one_tenant_bound_audit_event() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    user_id, org_id, project_id, queue_id, _ = await _seed(with_request=False)
    validated = validate_queue_enqueue(
        {
            "schema_version": "rdc.queue-enqueue/v1",
            "idempotency_key": f"phase1p-{uuid4().hex}",
            "url": "https://example.com/audit",
            "unique_key": None,
            "user_data": {"safe": True},
        }
    )
    async with session_factory() as session:
        queue = await session.scalar(select(RequestQueue).where(RequestQueue.id == queue_id))
        assert queue is not None
        first = await enqueue_request(
            session,
            queue=queue,
            user_id=user_id,
            actor_type="user",
            actor_id=str(user_id),
            request_id="enqueue-original",
            validated=validated,
        )
        replay = await enqueue_request(
            session,
            queue=queue,
            user_id=user_id,
            actor_type="user",
            actor_id=str(user_id),
            request_id="enqueue-replay",
            validated=validated,
        )
        assert replay.replayed is True
        assert replay.receipt.id == first.receipt.id
        await session.commit()
    async with engine.connect() as connection:
        audit_rows = (
            await connection.execute(
                text(
                    "SELECT organization_id,project_id,request_id,details->>'queue_id' FROM security.audit_events WHERE resource_id=:r AND action='request_queue.request_enqueued'"
                ),
                {"r": str(first.receipt.request_id)},
            )
        ).all()
        assert audit_rows == [(org_id, project_id, "enqueue-original", str(queue_id))]


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


async def test_postgres_transition_rejects_request_from_another_queue() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    user_id, org_id, project_id, queue_id, _ = await _seed()
    other_queue_id, other_request_id = uuid4(), uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO control.request_queues (id,organization_id,project_id,name,created_by_user_id) VALUES (:q,:o,:p,'other',:u)"
            ),
            {"q": other_queue_id, "o": org_id, "p": project_id, "u": user_id},
        )
        await connection.execute(
            text(
                "INSERT INTO control.request_queue_requests (id,organization_id,project_id,queue_id,request_url,identity_digest,user_data,created_by_user_id) VALUES (:r,:o,:p,:q,'https://example.com/other','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','{}',:u)"
            ),
            {"r": other_request_id, "o": org_id, "p": project_id, "q": other_queue_id, "u": user_id},
        )
    with pytest.raises(DBAPIError, match="request tenancy mismatch"):
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO control.request_queue_transitions (organization_id,project_id,queue_id,request_id,from_status,to_status,reason,attempt_count,details) VALUES (:o,:p,:q,:r,NULL,'PENDING','ENQUEUED',0,'{}')"
                ),
                {"o": org_id, "p": project_id, "q": queue_id, "r": other_request_id},
            )


async def test_postgres_request_identity_and_enqueue_receipts_are_immutable() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    user_id, org_id, project_id, queue_id, request_id = await _seed()
    receipt_id = uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO control.request_queue_enqueue_receipts (id,organization_id,project_id,queue_id,request_id,idempotency_key,request_digest,identity_digest,created_by_user_id) VALUES (:id,:o,:p,:q,:r,'immutable-receipt','bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',:u)"
            ),
            {"id": receipt_id, "o": org_id, "p": project_id, "q": queue_id, "r": request_id, "u": user_id},
        )
    with pytest.raises(DBAPIError, match="request identity is immutable"):
        async with engine.begin() as connection:
            await connection.execute(
                text("UPDATE control.request_queue_requests SET request_url='https://example.com/changed' WHERE id=:r"),
                {"r": request_id},
            )
    with pytest.raises(DBAPIError, match="enqueue receipts are immutable"):
        async with engine.begin() as connection:
            await connection.execute(
                text("UPDATE control.request_queue_enqueue_receipts SET request_digest=:digest WHERE id=:id"),
                {"id": receipt_id, "digest": "c" * 64},
            )
    with pytest.raises(DBAPIError, match="enqueue receipts are immutable"):
        async with engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM control.request_queue_enqueue_receipts WHERE id=:id"),
                {"id": receipt_id},
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
        assert await reclaim_expired_requests(
            session,
            queue_id=queue_id,
            worker_id="reclaimer",
            request_id="reclaim-request",
        ) == 1
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
        audit = (
            await connection.execute(
                text(
                    "SELECT action,actor_id,details->>'reason' FROM security.audit_events WHERE resource_id=:r AND action='request_queue.request_reclaimed'"
                ),
                {"r": str(request_id)},
            )
        ).one()
        assert audit == ("request_queue.request_reclaimed", "reclaimer", "LEASE_EXPIRED")


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
        assert await reclaim_expired_requests(
            session,
            queue_id=queue_id,
            worker_id="reclaimer",
            request_id="retry-exhausted",
        ) == 1
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
        audit = (
            await connection.execute(
                text(
                    "SELECT action,details->>'reason' FROM security.audit_events WHERE resource_id=:r AND action='request_queue.request_failed'"
                ),
                {"r": str(request_id)},
            )
        ).one()
        assert audit == ("request_queue.request_failed", "LEASE_EXPIRED")


async def test_postgres_audit_events_reject_cross_tenant_projects_and_mutation() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    user_a, org_a, project_a, _, request_a = await _seed()
    user_b, org_b, project_b, _, request_b = await _seed()
    with pytest.raises(DBAPIError, match="tenancy mismatch"):
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO security.audit_events (organization_id,project_id,actor_type,actor_id,action,resource_type,resource_id,request_id,details,created_at) VALUES (:o,:p,'user',:actor,'request_queue.request_enqueued','request_queue_request',:r,'cross-tenant','{}',CURRENT_TIMESTAMP)"
                ),
                {
                    "o": org_a,
                    "p": project_b,
                    "actor": str(user_a),
                    "r": str(request_a),
                },
            )
    audit_id = uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO security.audit_events (id,organization_id,project_id,actor_type,actor_id,action,resource_type,resource_id,request_id,details,created_at) VALUES (:id,:o,:p,'user',:actor,'request_queue.request_enqueued','request_queue_request',:r,'immutable','{}',CURRENT_TIMESTAMP)"
            ),
            {
                "id": audit_id,
                "o": org_a,
                "p": project_a,
                "actor": str(user_a),
                "r": str(request_a),
            },
        )
    with pytest.raises(DBAPIError, match="immutable"):
        async with engine.begin() as connection:
            await connection.execute(
                text("UPDATE security.audit_events SET details='{}' WHERE id=:id"),
                {"id": audit_id},
            )
    with pytest.raises(DBAPIError, match="immutable"):
        async with engine.begin() as connection:
            await connection.execute(
                text("DELETE FROM security.audit_events WHERE id=:id"),
                {"id": audit_id},
            )
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO security.audit_events (organization_id,project_id,actor_type,actor_id,action,resource_type,resource_id,request_id,details,created_at) VALUES (:o,:p,'user',:actor,'request_queue.request_enqueued','request_queue_request',:r,'tenant-b','{}',CURRENT_TIMESTAMP)"
            ),
            {
                "o": org_b,
                "p": project_b,
                "actor": str(user_b),
                "r": str(request_b),
            },
        )
        await connection.execute(
            text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rdc_phase1p_audit_rls_test') THEN CREATE ROLE rdc_phase1p_audit_rls_test NOLOGIN; END IF; END $$"
            )
        )
        await connection.execute(
            text("GRANT USAGE ON SCHEMA security TO rdc_phase1p_audit_rls_test")
        )
        await connection.execute(
            text(
                "GRANT SELECT ON security.audit_events TO rdc_phase1p_audit_rls_test"
            )
        )
    try:
        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL ROLE rdc_phase1p_audit_rls_test"))
            await connection.execute(
                text("SELECT set_config('rdc.current_user_id',:u,true)"),
                {"u": str(user_a)},
            )
            await connection.execute(
                text("SELECT set_config('rdc.current_organization_id',:o,true)"),
                {"o": str(org_a)},
            )
            visible = (
                await connection.execute(
                    text(
                        "SELECT resource_id FROM security.audit_events WHERE resource_id IN (:a,:b) ORDER BY resource_id"
                    ),
                    {"a": str(request_a), "b": str(request_b)},
                )
            ).scalars().all()
            assert visible == [str(request_a)]
    finally:
        async with engine.begin() as connection:
            await connection.execute(
                text("DROP OWNED BY rdc_phase1p_audit_rls_test")
            )
            await connection.execute(text("DROP ROLE rdc_phase1p_audit_rls_test"))


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


async def test_postgres_queue_pagination_is_stable_at_equal_timestamps() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    equal_created_at = "2026-08-09T06:00:00+00:00"
    user_id, org_id, project_id, first_queue_id, request_id = await _seed(
        queue_created_at=equal_created_at
    )
    second_queue_id = uuid4()
    transition_ids = [uuid4(), uuid4()]
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO control.request_queues (id,organization_id,project_id,name,created_by_user_id,created_at) VALUES (:q,:o,:p,'second',:u,CAST(:created_at AS timestamptz))"
            ),
            {
                "q": second_queue_id,
                "o": org_id,
                "p": project_id,
                "u": user_id,
                "created_at": equal_created_at,
            },
        )
        for transition_id, to_status, reason in (
            (transition_ids[0], "PENDING", "ENQUEUED"),
            (transition_ids[1], "CLAIMED", "CLAIMED"),
        ):
            await connection.execute(
                text(
                    "INSERT INTO control.request_queue_transitions (id,organization_id,project_id,queue_id,request_id,from_status,to_status,reason,attempt_count,details,created_at) VALUES (:id,:o,:p,:q,:r,NULL,:status,:reason,0,'{}','2026-08-09T06:00:00+00:00')"
                ),
                {
                    "id": transition_id,
                    "o": org_id,
                    "p": project_id,
                    "q": first_queue_id,
                    "r": request_id,
                    "status": to_status,
                    "reason": reason,
                },
            )
    async with session_factory() as session:
        queue_page_one, queue_has_more = await list_request_queues(
            session,
            project_id=project_id,
            cursor=None,
            limit=1,
        )
        assert queue_has_more is True
        queue_page_two, queue_has_more_two = await list_request_queues(
            session,
            project_id=project_id,
            cursor=RequestQueueListCursorPosition(
                created_at=queue_page_one[-1].created_at,
                resource_id=queue_page_one[-1].id,
            ),
            limit=1,
        )
        assert queue_has_more_two is False
        assert {queue_page_one[0].id, queue_page_two[0].id} == {
            first_queue_id,
            second_queue_id,
        }

        transition_page_one, transition_has_more = await list_queue_transitions(
            session,
            queue_id=first_queue_id,
            request_id=request_id,
            cursor=None,
            limit=1,
        )
        assert transition_has_more is True
        transition_page_two, transition_has_more_two = await list_queue_transitions(
            session,
            queue_id=first_queue_id,
            request_id=request_id,
            cursor=QueueTransitionCursorPosition(
                created_at=transition_page_one[-1].created_at,
                resource_id=transition_page_one[-1].id,
            ),
            limit=1,
        )
        assert transition_has_more_two is False
        assert {transition_page_one[0].id, transition_page_two[0].id} == set(
            transition_ids
        )


async def test_postgres_queue_and_transition_rls_hide_other_tenant() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    user_a, org_a, project_a, queue_a, request_a = await _seed()
    _, org_b, project_b, queue_b, request_b = await _seed()
    async with engine.begin() as connection:
        for org_id, project_id, queue_id, request_id in (
            (org_a, project_a, queue_a, request_a),
            (org_b, project_b, queue_b, request_b),
        ):
            await connection.execute(
                text(
                    "INSERT INTO control.request_queue_transitions (organization_id,project_id,queue_id,request_id,from_status,to_status,reason,attempt_count,details) VALUES (:o,:p,:q,:r,NULL,'PENDING','ENQUEUED',0,'{}')"
                ),
                {"o": org_id, "p": project_id, "q": queue_id, "r": request_id},
            )
        await connection.execute(
            text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rdc_phase1p_queue_rls_test') THEN CREATE ROLE rdc_phase1p_queue_rls_test NOLOGIN; END IF; END $$"
            )
        )
        await connection.execute(
            text(
                "GRANT USAGE ON SCHEMA control,security TO rdc_phase1p_queue_rls_test"
            )
        )
        await connection.execute(
            text(
                "GRANT SELECT,UPDATE,DELETE ON control.request_queues,control.request_queue_requests,control.request_queue_transitions,control.request_queue_enqueue_receipts TO rdc_phase1p_queue_rls_test"
            )
        )
    try:
        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL ROLE rdc_phase1p_queue_rls_test"))
            await connection.execute(
                text("SELECT set_config('rdc.current_user_id',:u,true)"),
                {"u": str(user_a)},
            )
            await connection.execute(
                text("SELECT set_config('rdc.current_organization_id',:o,true)"),
                {"o": str(org_a)},
            )
            visible_queues = (
                await connection.execute(
                    text(
                        "SELECT id FROM control.request_queues WHERE id IN (:a,:b) ORDER BY id"
                    ),
                    {"a": queue_a, "b": queue_b},
                )
            ).scalars().all()
            visible_transitions = (
                await connection.execute(
                    text(
                        "SELECT queue_id FROM control.request_queue_transitions WHERE queue_id IN (:a,:b) ORDER BY queue_id"
                    ),
                    {"a": queue_a, "b": queue_b},
                )
            ).scalars().all()
            visible_requests = (
                await connection.execute(
                    text(
                        "SELECT id FROM control.request_queue_requests WHERE id IN (:a,:b) ORDER BY id"
                    ),
                    {"a": request_a, "b": request_b},
                )
            ).scalars().all()
            request_update = await connection.execute(
                text("UPDATE control.request_queue_requests SET status='FAILED' WHERE id=:r"),
                {"r": request_a},
            )
            queue_delete = await connection.execute(
                text("DELETE FROM control.request_queues WHERE id=:q"),
                {"q": queue_a},
            )
            assert visible_queues == [queue_a]
            assert visible_transitions == [queue_a]
            assert visible_requests == [request_a]
            assert request_update.rowcount == 0
            assert queue_delete.rowcount == 0
    finally:
        async with engine.begin() as connection:
            await connection.execute(text("DROP OWNED BY rdc_phase1p_queue_rls_test"))
            await connection.execute(text("DROP ROLE rdc_phase1p_queue_rls_test"))


@pytest.mark.parametrize(
    ("target", "action"),
    [
        ("HANDLED", "request_queue.request_handled"),
        ("FAILED", "request_queue.request_failed"),
    ],
)
async def test_postgres_worker_completion_emits_tenant_bound_audit_event(
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    action: str,
) -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL integration database is unavailable")
    _, org_id, project_id, queue_id, request_id = await _seed()
    worker_id, claim_token = uuid4(), uuid4()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.request_queue_requests SET status='CLAIMED',attempt_count=1,claimed_by=:w,claim_token=:t,claim_expires_at=CURRENT_TIMESTAMP+INTERVAL '1 minute' WHERE id=:r"
            ),
            {"w": str(worker_id), "t": claim_token, "r": request_id},
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
        work_kind="RUN_START",
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
        "claim_token": str(claim_token),
        "status": target,
        "failure_code": "FETCH_FAILED" if target == "FAILED" else None,
        "failure_summary": "private failure detail" if target == "FAILED" else None,
    }
    async with session_factory() as session:
        result = await complete_worker_queue_request(
            session,
            lease=lease,
            worker=worker,
            payload=payload,
            request_id=f"complete-{target.casefold()}",
        )  # type: ignore[arg-type]
        assert result.status == target
        await session.commit()
    async with engine.connect() as connection:
        audit = (
            await connection.execute(
                text(
                    "SELECT organization_id,project_id,action,actor_id,details->>'queue_id',details ? 'failure_summary' FROM security.audit_events WHERE resource_id=:r AND action=:action"
                ),
                {"r": str(request_id), "action": action},
            )
        ).one()
        assert audit == (
            org_id,
            project_id,
            action,
            str(worker_id),
            str(queue_id),
            False,
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
        work_kind="RUN_START",
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
                session,
                lease=lease,
                worker=worker,
                payload=payload,
                request_id="stale-completion",
            )  # type: ignore[arg-type]
