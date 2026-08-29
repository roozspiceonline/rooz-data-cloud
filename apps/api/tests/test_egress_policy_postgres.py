# ruff: noqa: E501
from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.database import engine, session_factory
from app.core.errors import ApiError
from app.core.security import canonical_fingerprint
from app.egress_policy_protocol import validate_egress_policy
from app.egress_policy_schemas import (
    CreateEgressPolicyRequest,
    CreateEgressPolicyRevisionRequest,
)
from app.models import Project, ProjectSecret, RunCommandOutbox
from app.services import egress_credential_canaries as canary_service
from app.services import execution_plane
from app.services.egress_credential_canaries import (
    claim_credential_rotation_canaries,
    complete_credential_rotation_canary,
    enqueue_credential_rotation_canaries,
    list_credential_rotation_canaries,
    load_credential_rotation_canary_secret,
)
from app.services.egress_policies import (
    activate_egress_policy,
    create_egress_policy,
    create_egress_policy_revision,
    disable_egress_policy,
)

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
                    text("SELECT to_regclass('control.egress_policies') IS NOT NULL")
                )
            )
    except (OSError, DBAPIError, OperationalError):
        return False


async def _seed() -> tuple[UUID, UUID, UUID, UUID, UUID, UUID]:
    user_id, org_id, project_id, secret_id, policy_id, revision_id = (uuid4() for _ in range(6))
    suffix = uuid4().hex
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO identity.users (id,email_normalized,email_display,password_hash,password_algorithm,display_name,status) VALUES (:u,:e,:e,'x','argon2id','Egress','ACTIVE')"
            ),
            {"u": user_id, "e": f"egress-{suffix}@example.invalid"},
        )
        await connection.execute(
            text(
                "INSERT INTO identity.organizations (id,name,slug,status,created_by_user_id) VALUES (:o,'Egress',:s,'ACTIVE',:u)"
            ),
            {"o": org_id, "s": f"egress-{suffix}", "u": user_id},
        )
        await connection.execute(
            text(
                "INSERT INTO identity.organization_memberships (organization_id,user_id,role,status,joined_at,updated_at,created_by_user_id) VALUES (:o,:u,'owner','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,:u)"
            ),
            {"o": org_id, "u": user_id},
        )
        await connection.execute(
            text(
                "INSERT INTO control.projects (id,organization_id,name,slug,status,created_by_user_id) VALUES (:p,:o,'Egress',:s,'ACTIVE',:u)"
            ),
            {"p": project_id, "o": org_id, "s": f"egress-{suffix}", "u": user_id},
        )
        await connection.execute(
            text(
                "INSERT INTO security.project_secrets (id,organization_id,project_id,name,environment,encrypted_value,value_nonce,wrapped_data_key,key_nonce,encryption_algorithm,master_key_version,created_by_user_id,updated_by_user_id) VALUES (:s,:o,:p,'PROXY_AUTH','production',decode('00','hex'),decode('000000000000000000000000','hex'),decode('00','hex'),decode('000000000000000000000000','hex'),'AES-256-GCM','test-v1',:u,:u)"
            ),
            {"s": secret_id, "o": org_id, "p": project_id, "u": user_id},
        )
        await connection.execute(
            text(
                "INSERT INTO control.egress_policies (id,organization_id,project_id,name,created_by_user_id) VALUES (:e,:o,:p,'default',:u)"
            ),
            {"e": policy_id, "o": org_id, "p": project_id, "u": user_id},
        )
        await connection.execute(
            text(
                "INSERT INTO control.egress_policy_revisions (id,organization_id,project_id,policy_id,revision_number,allowed_hosts,allowed_methods,max_requests,max_response_bytes,max_total_bytes,max_redirects,connect_timeout_seconds,request_timeout_seconds,credential_secret_id,policy_digest,created_by_user_id) VALUES (:r,:o,:p,:e,1,'[\"api.example.com\"]','[\"GET\"]',16,1048576,4194304,0,5,15,:s,:digest,:u)"
            ),
            {
                "r": revision_id,
                "o": org_id,
                "p": project_id,
                "e": policy_id,
                "s": secret_id,
                "digest": "a" * 64,
                "u": user_id,
            },
        )
    return user_id, org_id, project_id, secret_id, policy_id, revision_id


async def test_revisions_and_ownership_are_database_immutable() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress migration is unavailable")
    _, _, _, _, policy_id, revision_id = await _seed()
    with pytest.raises(DBAPIError, match="revisions are immutable"):
        async with engine.begin() as connection:
            await connection.execute(
                text("UPDATE control.egress_policy_revisions SET max_requests=17 WHERE id=:r"),
                {"r": revision_id},
            )
    with pytest.raises(DBAPIError, match="ownership is immutable"):
        async with engine.begin() as connection:
            await connection.execute(
                text("UPDATE control.egress_policies SET name='changed' WHERE id=:p"),
                {"p": policy_id},
            )


async def test_active_revision_and_credential_are_exact_tenant_references() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress migration is unavailable")
    user_a, org_a, project_a, _, policy_a, _ = await _seed()
    _, _, _, secret_b, _, revision_b = await _seed()
    with pytest.raises(DBAPIError, match="active revision mismatch"):
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "UPDATE control.egress_policies SET active_revision_id=:r,status='ACTIVE',activated_at=CURRENT_TIMESTAMP WHERE id=:p"
                ),
                {"r": revision_b, "p": policy_a},
            )
    with pytest.raises(DBAPIError, match="credential tenancy mismatch"):
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO control.egress_policy_revisions (organization_id,project_id,policy_id,revision_number,allowed_hosts,allowed_methods,max_requests,max_response_bytes,max_total_bytes,max_redirects,connect_timeout_seconds,request_timeout_seconds,credential_secret_id,policy_digest,created_by_user_id) VALUES (:o,:p,:e,2,'[\"api.example.com\"]','[\"GET\"]',16,1048576,4194304,0,5,15,:s,:digest,:u)"
                ),
                {
                    "o": org_a,
                    "p": project_a,
                    "e": policy_a,
                    "s": secret_b,
                    "digest": "b" * 64,
                    "u": user_a,
                },
            )
    with pytest.raises(DBAPIError, match="methods are not canonical"):
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO control.egress_policy_revisions (organization_id,project_id,policy_id,revision_number,allowed_hosts,allowed_methods,max_requests,max_response_bytes,max_total_bytes,max_redirects,connect_timeout_seconds,request_timeout_seconds,policy_digest,created_by_user_id) VALUES (:o,:p,:e,2,'[\"api.example.com\"]','[\"POST\"]',16,1048576,4194304,0,5,15,:digest,:u)"
                ),
                {"o": org_a, "p": project_a, "e": policy_a, "digest": "c" * 64, "u": user_a},
            )
    with pytest.raises(DBAPIError, match="host is not canonical"):
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "INSERT INTO control.egress_policy_revisions (organization_id,project_id,policy_id,revision_number,allowed_hosts,allowed_methods,max_requests,max_response_bytes,max_total_bytes,max_redirects,connect_timeout_seconds,request_timeout_seconds,policy_digest,created_by_user_id) VALUES (:o,:p,:e,2,'[\"127.0.0.1\"]','[\"GET\"]',16,1048576,4194304,0,5,15,:digest,:u)"
                ),
                {"o": org_a, "p": project_a, "e": policy_a, "digest": "d" * 64, "u": user_a},
            )


async def test_rls_and_resolver_hide_other_tenant() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress migration is unavailable")
    user_a, org_a, _, _, policy_a, revision_a = await _seed()
    _, _, _, _, policy_b, revision_b = await _seed()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rdc_egress_rls_test') THEN CREATE ROLE rdc_egress_rls_test NOLOGIN; END IF; END $$"
            )
        )
        await connection.execute(
            text("GRANT USAGE ON SCHEMA control,security TO rdc_egress_rls_test")
        )
        await connection.execute(
            text(
                "GRANT SELECT,INSERT,UPDATE,DELETE ON control.egress_policies,control.egress_policy_revisions TO rdc_egress_rls_test"
            )
        )
    try:
        async with engine.begin() as connection:
            await connection.execute(text("SET LOCAL ROLE rdc_egress_rls_test"))
            await connection.execute(
                text("SELECT set_config('rdc.current_user_id',:u,true)"), {"u": str(user_a)}
            )
            await connection.execute(
                text("SELECT set_config('rdc.current_organization_id',:o,true)"), {"o": str(org_a)}
            )
            policies = (
                (
                    await connection.execute(
                        text(
                            "SELECT id FROM control.egress_policies WHERE id IN (:a,:b) ORDER BY id"
                        ),
                        {"a": policy_a, "b": policy_b},
                    )
                )
                .scalars()
                .all()
            )
            revisions = (
                (
                    await connection.execute(
                        text(
                            "SELECT id FROM control.egress_policy_revisions WHERE id IN (:a,:b) ORDER BY id"
                        ),
                        {"a": revision_a, "b": revision_b},
                    )
                )
                .scalars()
                .all()
            )
            assert policies == [policy_a]
            assert revisions == [revision_a]
            assert (
                await connection.scalar(
                    text("SELECT security.rdc_egress_policy_org(:p)"), {"p": policy_b}
                )
                is None
            )
            hidden_update = await connection.execute(
                text("UPDATE control.egress_policies SET status='DISABLED' WHERE id=:p"),
                {"p": policy_b},
            )
            hidden_delete = await connection.execute(
                text("DELETE FROM control.egress_policy_revisions WHERE id=:r"), {"r": revision_b}
            )
            assert hidden_update.rowcount == 0
            assert hidden_delete.rowcount == 0
    finally:
        async with engine.begin() as connection:
            await connection.execute(text("DROP OWNED BY rdc_egress_rls_test"))
            await connection.execute(text("DROP ROLE rdc_egress_rls_test"))


async def test_service_idempotency_rotation_and_optimistic_lifecycle() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress migration is unavailable")
    user_id, _, project_id, secret_id, _, _ = await _seed()
    _, _, _, foreign_secret_id, _, _ = await _seed()
    create_payload = CreateEgressPolicyRequest.model_validate(
        {
            "name": f"service-{uuid4().hex}",
            "spec": {
                "allowed_hosts": ["API.Example.COM."],
                "allowed_methods": ["GET"],
                "credential_secret_id": str(secret_id),
            },
        }
    )
    idempotency_key = f"egress-{uuid4().hex}"
    async with session_factory() as session:
        project = await session.scalar(select(Project).where(Project.id == project_id))
        assert project is not None
        created = await create_egress_policy(
            session,
            project=project,
            user_id=user_id,
            actor_type="user",
            actor_id=str(user_id),
            idempotency_key=idempotency_key,
            request_id="egress-create",
            payload=create_payload,
        )
        replay = await create_egress_policy(
            session,
            project=project,
            user_id=user_id,
            actor_type="user",
            actor_id=str(user_id),
            idempotency_key=idempotency_key,
            request_id="egress-replay",
            payload=create_payload,
        )
        assert replay["replayed"] is True
        assert replay["policy"] == created["policy"]
        policy_id = UUID(str(created["policy"]["id"]))  # type: ignore[index]
        revision_id = UUID(str(created["revision"]["id"]))  # type: ignore[index]
        activated = await activate_egress_policy(
            session,
            policy_id=policy_id,
            revision_id=revision_id,
            expected_version=1,
            actor_type="user",
            actor_id=str(user_id),
            request_id="egress-activate",
        )
        assert activated.status == "ACTIVE"
        with pytest.raises(ApiError, match="changed"):
            await disable_egress_policy(
                session,
                policy_id=policy_id,
                expected_version=1,
                actor_type="user",
                actor_id=str(user_id),
                request_id="stale-disable",
            )
        foreign_payload = CreateEgressPolicyRevisionRequest.model_validate(
            {
                "expected_version": 2,
                "spec": {
                    "allowed_hosts": ["next.example.com"],
                    "credential_secret_id": str(foreign_secret_id),
                },
            }
        )
        with pytest.raises(ApiError) as failure:
            await create_egress_policy_revision(
                session,
                policy_id=policy_id,
                user_id=user_id,
                actor_type="user",
                actor_id=str(user_id),
                request_id="foreign-credential",
                payload=foreign_payload,
            )
        assert failure.value.status_code == 404
        await session.rollback()


async def test_credential_rotation_canary_is_idempotent_fenced_and_immutable() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress migration is unavailable")
    user_id, org_id, project_id, secret_id, policy_id, revision_id = await _seed()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.egress_policies SET status='ACTIVE',active_revision_id=:r,activated_at=CURRENT_TIMESTAMP WHERE id=:p"
            ),
            {"r": revision_id, "p": policy_id},
        )
    original = (
        canary_service.settings.egress_credential_canary_enabled,
        canary_service.settings.egress_credential_canary_target_url,
    )
    canary_service.settings.egress_credential_canary_enabled = True
    canary_service.settings.egress_credential_canary_target_url = (
        "https://canary.example.com/auth-check"
    )
    try:
        async with session_factory() as session:
            secret = await session.scalar(
                select(ProjectSecret).where(ProjectSecret.id == secret_id)
            )
            assert secret is not None
            await session.execute(
                text("SELECT set_config('rdc.current_user_id',:u,true)"),
                {"u": str(user_id)},
            )
            await session.execute(
                text("SELECT set_config('rdc.current_organization_id',:o,true)"),
                {"o": str(org_id)},
            )
            assert await enqueue_credential_rotation_canaries(
                session, secret=secret, request_id="canary-enqueue"
            ) == 1
            assert await enqueue_credential_rotation_canaries(
                session, secret=secret, request_id="canary-replay"
            ) == 0
            now = datetime.now(UTC)
            claimed = await claim_credential_rotation_canaries(
                session, now=now, batch_size=10
            )
            attempt = next(
                claim for claim in claimed if claim.credential_secret_id == secret_id
            )
            assert attempt.claim_token is not None
            with pytest.raises(ApiError) as stale_claim:
                await complete_credential_rotation_canary(
                    session,
                    attempt_id=attempt.id,
                    claim_token=secrets.token_hex(32),
                    outcome="SUCCESS",
                    now=now,
                )
            assert stale_claim.value.code == "EGRESS_CREDENTIAL_CANARY_CLAIM_STALE"
            result = await complete_credential_rotation_canary(
                session,
                attempt_id=attempt.id,
                claim_token=attempt.claim_token,
                outcome="SUCCESS",
                now=now,
            )
            assert (result.status, result.outcome, result.healthy) == (
                "SUCCEEDED",
                "SUCCESS",
                True,
            )
            summaries = await list_credential_rotation_canaries(
                session, project_id=project_id, limit=10
            )
            assert summaries[0]["status"] == "SUCCEEDED"
            assert "credential_secret_id" not in summaries[0]
            await session.commit()
        async with engine.connect() as connection:
            transitions = (
                (
                    await connection.execute(
                        text(
                            "SELECT event FROM control.egress_credential_canary_transitions WHERE attempt_id=:a ORDER BY attempt_version"
                        ),
                        {"a": result.id},
                    )
                )
                .scalars()
                .all()
            )
            assert transitions == ["ENQUEUED", "CLAIMED", "SUCCEEDED"]
            assert await connection.scalar(
                text(
                    "SELECT count(*) FROM security.audit_events WHERE action='egress.credential_canary.enqueued' AND resource_id=:a"
                ),
                {"a": str(result.id)},
            ) == 1
        with pytest.raises(DBAPIError, match="transition is invalid"):
            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        "UPDATE control.egress_credential_canary_attempts SET status='PENDING',version=version+1 WHERE id=:a"
                    ),
                    {"a": result.id},
                )
        with pytest.raises(DBAPIError, match="history is immutable"):
            async with engine.begin() as connection:
                await connection.execute(
                    text(
                        "DELETE FROM control.egress_credential_canary_transitions WHERE attempt_id=:a"
                    ),
                    {"a": result.id},
                )

        _, foreign_org, foreign_project, _, _, _ = await _seed()
        async with engine.begin() as connection:
            await connection.execute(
                text(
                    "DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='rdc_canary_rls_test') THEN CREATE ROLE rdc_canary_rls_test NOLOGIN; END IF; END $$"
                )
            )
            await connection.execute(
                text("GRANT USAGE ON SCHEMA control TO rdc_canary_rls_test")
            )
            await connection.execute(
                text(
                    "GRANT SELECT,UPDATE ON control.egress_credential_canary_attempts TO rdc_canary_rls_test"
                )
            )
            await connection.execute(
                text("GRANT SELECT ON control.egress_credential_canary_transitions TO rdc_canary_rls_test")
            )
        try:
            async with engine.begin() as connection:
                await connection.execute(text("SET LOCAL ROLE rdc_canary_rls_test"))
                await connection.execute(
                    text("SELECT set_config('rdc.current_user_id',:u,true)"),
                    {"u": str(user_id)},
                )
                await connection.execute(
                    text("SELECT set_config('rdc.current_organization_id',:o,true)"),
                    {"o": str(org_id)},
                )
                await connection.execute(
                    text("SELECT set_config('rdc.egress_canary_scheduler','1',true)")
                )
                assert await connection.scalar(
                    text(
                        "SELECT count(*) FROM control.egress_credential_canary_attempts WHERE organization_id=:o"
                    ),
                    {"o": foreign_org},
                ) == 0
                changed = await connection.execute(
                    text(
                        "UPDATE control.egress_credential_canary_attempts SET version=version+1 WHERE organization_id=:o RETURNING id"
                    ),
                    {"o": foreign_org},
                )
                assert changed.first() is None
                assert await connection.scalar(
                    text(
                        "SELECT count(*) FROM control.egress_credential_canary_transitions WHERE project_id=:p"
                    ),
                    {"p": foreign_project},
                ) == 0
            with pytest.raises(DBAPIError, match="permission denied"):
                async with engine.begin() as connection:
                    await connection.execute(text("SET LOCAL ROLE rdc_canary_rls_test"))
                    await connection.execute(
                        text(
                            "SELECT * FROM control.claim_egress_credential_canaries(CURRENT_TIMESTAMP,1,30,3)"
                        )
                    )
                assert await connection.scalar(
                    text(
                        "SELECT count(*) FROM control.egress_credential_canary_attempts WHERE project_id=:p"
                    ),
                    {"p": foreign_project},
                ) == 0
        finally:
            async with engine.begin() as connection:
                await connection.execute(text("DROP OWNED BY rdc_canary_rls_test"))
                await connection.execute(text("DROP ROLE rdc_canary_rls_test"))
    finally:
        (
            canary_service.settings.egress_credential_canary_enabled,
            canary_service.settings.egress_credential_canary_target_url,
        ) = original


async def test_credential_rotation_canary_claim_is_single_winner() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress migration is unavailable")
    user_id, org_id, _, secret_id, policy_id, revision_id = await _seed()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.egress_policies SET status='ACTIVE',active_revision_id=:r,activated_at=CURRENT_TIMESTAMP WHERE id=:p"
            ),
            {"r": revision_id, "p": policy_id},
        )
    original = (
        canary_service.settings.egress_credential_canary_enabled,
        canary_service.settings.egress_credential_canary_target_url,
    )
    canary_service.settings.egress_credential_canary_enabled = True
    canary_service.settings.egress_credential_canary_target_url = (
        "https://canary.example.com/auth-check"
    )
    try:
        async with session_factory() as session:
            secret = await session.scalar(
                select(ProjectSecret).where(ProjectSecret.id == secret_id)
            )
            assert secret is not None
            await session.execute(
                text("SELECT set_config('rdc.current_user_id',:u,true)"),
                {"u": str(user_id)},
            )
            await session.execute(
                text("SELECT set_config('rdc.current_organization_id',:o,true)"),
                {"o": str(org_id)},
            )
            assert await enqueue_credential_rotation_canaries(
                session, secret=secret, request_id="canary-race-enqueue"
            ) == 1
            await session.commit()

        now = datetime.now(UTC)

        async def claim_once() -> list[UUID]:
            async with session_factory() as session:
                claims = await claim_credential_rotation_canaries(
                    session, now=now, batch_size=50
                )
                identifiers = [
                    claim.id
                    for claim in claims
                    if claim.credential_secret_id == secret_id
                ]
                await session.commit()
                return identifiers

        winners = await asyncio.gather(claim_once(), claim_once())
        flattened = [identifier for batch in winners for identifier in batch]
        assert len(flattened) == 1
    finally:
        (
            canary_service.settings.egress_credential_canary_enabled,
            canary_service.settings.egress_credential_canary_target_url,
        ) = original


async def test_credential_canary_database_derives_exact_active_binding() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress migration is unavailable")
    _, org_id, project_id, secret_id, policy_id, revision_id = await _seed()
    statement = text(
        "SELECT * FROM control.enqueue_egress_credential_canaries_for_secret("
        ":secret,:digest,'static-canary','local')"
    )
    async with engine.begin() as connection:
        await connection.execute(
            text("SELECT set_config('rdc.current_user_id',:u,true)"),
            {"u": str(uuid4())},
        )
        await connection.execute(
            text("SELECT set_config('rdc.current_organization_id',:o,true)"),
            {"o": str(org_id)},
        )
        assert (await connection.execute(statement, {"secret": secret_id, "digest": "b" * 64})).first() is None
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.egress_policies SET status='ACTIVE',active_revision_id=:r,activated_at=CURRENT_TIMESTAMP WHERE id=:p"
            ),
            {"r": revision_id, "p": policy_id},
        )
        user_id = await connection.scalar(
            text("SELECT created_by_user_id FROM identity.organizations WHERE id=:o"),
            {"o": org_id},
        )
        await connection.execute(text("SELECT set_config('rdc.current_user_id',:u,true)"), {"u": str(user_id)})
        await connection.execute(text("SELECT set_config('rdc.current_organization_id',:o,true)"), {"o": str(org_id)})
        derived = (
            await connection.execute(
                statement,
                {
                    "secret": secret_id,
                    "digest": "b" * 64,
                },
            )
        ).one()
    assert derived[1:] == (policy_id, revision_id)


async def _create_claimed_canary(now: datetime):
    user_id, org_id, _, secret_id, policy_id, revision_id = await _seed()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.egress_policies SET status='ACTIVE',active_revision_id=:r,activated_at=CURRENT_TIMESTAMP WHERE id=:p"
            ),
            {"r": revision_id, "p": policy_id},
        )
    async with session_factory() as session:
        secret = await session.scalar(
            select(ProjectSecret).where(ProjectSecret.id == secret_id)
        )
        assert secret is not None
        await session.execute(
            text("SELECT set_config('rdc.current_user_id',:u,true)"),
            {"u": str(user_id)},
        )
        await session.execute(
            text("SELECT set_config('rdc.current_organization_id',:o,true)"),
            {"o": str(org_id)},
        )
        assert await enqueue_credential_rotation_canaries(
            session, secret=secret, request_id="hardening-race-enqueue"
        ) == 1
        await session.commit()
    async with session_factory() as session:
        claims = await claim_credential_rotation_canaries(
            session,
            now=now,
            batch_size=canary_service.settings.egress_credential_canary_batch_size,
        )
        await session.commit()
    return secret_id, next(
        claim for claim in claims if claim.credential_secret_id == secret_id
    )


async def test_canary_claim_digest_reclaim_expiry_and_duplicate_fencing() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress migration is unavailable")
    original = (
        canary_service.settings.egress_credential_canary_enabled,
        canary_service.settings.egress_credential_canary_target_url,
        canary_service.settings.egress_credential_canary_batch_size,
    )
    canary_service.settings.egress_credential_canary_enabled = True
    canary_service.settings.egress_credential_canary_target_url = (
        "https://canary.example.com/auth-check"
    )
    canary_service.settings.egress_credential_canary_batch_size = 100
    try:
        now = datetime.now(UTC)
        _, first = await _create_claimed_canary(now)
        assert len(first.claim_token) == 64
        async with engine.connect() as connection:
            persisted = await connection.scalar(
                text(
                    "SELECT claim_token_digest FROM control.egress_credential_canary_attempts WHERE id=:a"
                ),
                {"a": first.id},
            )
            assert persisted is not None and len(persisted) == 64
            assert persisted != first.claim_token
            assert await connection.scalar(
                text(
                    "SELECT count(*) FROM information_schema.columns WHERE table_schema='control' AND table_name='egress_credential_canary_attempts' AND column_name='claim_token'"
                )
            ) == 0
        expired_at = first.claim_expires_at + timedelta(microseconds=1)
        async with session_factory() as session:
            with pytest.raises(ApiError, match="stale"):
                await complete_credential_rotation_canary(
                    session,
                    attempt_id=first.id,
                    claim_token=first.claim_token,
                    outcome="SUCCESS",
                    now=expired_at,
                )
            await session.rollback()
        async with session_factory() as session:
            claims = await claim_credential_rotation_canaries(
                session,
                now=expired_at,
                batch_size=canary_service.settings.egress_credential_canary_batch_size,
            )
            await session.commit()
        reclaimed = next(claim for claim in claims if claim.id == first.id)
        assert reclaimed.claim_token != first.claim_token
        async with session_factory() as session:
            with pytest.raises(ApiError, match="stale"):
                await complete_credential_rotation_canary(
                    session,
                    attempt_id=first.id,
                    claim_token=first.claim_token,
                    outcome="SUCCESS",
                    now=expired_at,
                )
            await session.rollback()
        async with session_factory() as session:
            result = await complete_credential_rotation_canary(
                session,
                attempt_id=reclaimed.id,
                claim_token=reclaimed.claim_token,
                outcome="SUCCESS",
                now=expired_at,
            )
            await session.commit()
        assert result.status == "SUCCEEDED"
        async with session_factory() as session:
            with pytest.raises(ApiError, match="stale"):
                await complete_credential_rotation_canary(
                    session,
                    attempt_id=reclaimed.id,
                    claim_token=reclaimed.claim_token,
                    outcome="SUCCESS",
                    now=expired_at,
                )
            await session.rollback()
        async with engine.connect() as connection:
            events = (
                (
                    await connection.execute(
                        text(
                            "SELECT event FROM control.egress_credential_canary_transitions WHERE attempt_id=:a ORDER BY attempt_version"
                        ),
                        {"a": first.id},
                    )
                )
                .scalars()
                .all()
            )
        assert events == ["ENQUEUED", "CLAIMED", "RECLAIMED", "CLAIMED", "SUCCEEDED"]
    finally:
        (
            canary_service.settings.egress_credential_canary_enabled,
            canary_service.settings.egress_credential_canary_target_url,
            canary_service.settings.egress_credential_canary_batch_size,
        ) = original


async def test_canary_completion_and_rotation_use_deterministic_secret_first_locking() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress migration is unavailable")
    original = (
        canary_service.settings.egress_credential_canary_enabled,
        canary_service.settings.egress_credential_canary_target_url,
        canary_service.settings.egress_credential_canary_batch_size,
    )
    canary_service.settings.egress_credential_canary_enabled = True
    canary_service.settings.egress_credential_canary_target_url = (
        "https://canary.example.com/auth-check"
    )
    canary_service.settings.egress_credential_canary_batch_size = 100
    try:
        now = datetime.now(UTC)

        # Completion owns the secret lock first; rotation waits and version N succeeds.
        secret_id, completion_first = await _create_claimed_canary(now)
        async with session_factory() as completion_session:
            result = await complete_credential_rotation_canary(
                completion_session,
                attempt_id=completion_first.id,
                claim_token=completion_first.claim_token,
                outcome="SUCCESS",
                now=now,
            )

            async def rotate_after_completion() -> None:
                async with session_factory() as rotation_session:
                    await rotation_session.execute(
                        text(
                            "UPDATE security.project_secrets SET version=version+1 WHERE id=:s"
                        ),
                        {"s": secret_id},
                    )
                    await rotation_session.commit()

            rotation = asyncio.create_task(rotate_after_completion())
            await asyncio.sleep(0)
            await completion_session.commit()
            await rotation
        assert result.status == "SUCCEEDED"

        # Rotation owns the secret lock first; completion waits and becomes superseded.
        secret_id, rotation_first = await _create_claimed_canary(now)
        async with session_factory() as rotation_session:
            await rotation_session.execute(
                select(ProjectSecret)
                .where(ProjectSecret.id == secret_id)
                .with_for_update()
            )
            await rotation_session.execute(
                text("UPDATE security.project_secrets SET version=version+1 WHERE id=:s"),
                {"s": secret_id},
            )

            async def complete_after_rotation():
                async with session_factory() as completion_session:
                    completed = await complete_credential_rotation_canary(
                        completion_session,
                        attempt_id=rotation_first.id,
                        claim_token=rotation_first.claim_token,
                        outcome="SUCCESS",
                        now=now,
                    )
                    await completion_session.commit()
                    return completed

            completion = asyncio.create_task(complete_after_rotation())
            await asyncio.sleep(0)
            await rotation_session.commit()
            result = await completion
        assert (result.status, result.outcome) == (
            "SUPERSEDED",
            "SECRET_VERSION_SUPERSEDED",
        )

        # Simultaneous release may choose either lock winner, but cannot persist a
        # stale success after a winning rotation; the row result records that order.
        secret_id, simultaneous = await _create_claimed_canary(now)
        gate = asyncio.Event()

        async def concurrent_rotation() -> None:
            await gate.wait()
            async with session_factory() as session:
                await session.execute(
                    text("UPDATE security.project_secrets SET version=version+1 WHERE id=:s"),
                    {"s": secret_id},
                )
                await session.commit()

        async def concurrent_completion():
            await gate.wait()
            async with session_factory() as session:
                completed = await complete_credential_rotation_canary(
                    session,
                    attempt_id=simultaneous.id,
                    claim_token=simultaneous.claim_token,
                    outcome="SUCCESS",
                    now=now,
                )
                await session.commit()
                return completed

        rotation_task = asyncio.create_task(concurrent_rotation())
        completion_task = asyncio.create_task(concurrent_completion())
        gate.set()
        _, simultaneous_result = await asyncio.gather(
            rotation_task, completion_task
        )
        assert simultaneous_result.status in {"SUCCEEDED", "SUPERSEDED"}
        if simultaneous_result.status == "SUPERSEDED":
            assert simultaneous_result.outcome == "SECRET_VERSION_SUPERSEDED"
        else:
            assert simultaneous_result.outcome == "SUCCESS"
    finally:
        (
            canary_service.settings.egress_credential_canary_enabled,
            canary_service.settings.egress_credential_canary_target_url,
            canary_service.settings.egress_credential_canary_batch_size,
        ) = original


async def _seed_bound_run() -> tuple[UUID, UUID, UUID, UUID]:
    user_id, org_id, project_id, _, _, _ = await _seed()
    policy_id, revision_id, agent_id, version_id, build_id, run_id, source_id = (
        uuid4() for _ in range(7)
    )
    suffix = uuid4().hex
    validated = validate_egress_policy(
        allowed_hosts=["api.example.com"],
        allowed_methods=["GET"],
        max_requests=4,
        max_response_bytes=65_536,
        max_total_bytes=131_072,
        max_redirects=0,
        connect_timeout_seconds=2,
        request_timeout_seconds=5,
    )
    runtime_policy = {
        "schema_version": "rdc.egress/v1",
        "mode": "brokered",
        "allowed_schemes": ["https"],
        "allowed_methods": validated.allowed_methods,
        "allowed_hosts": validated.allowed_hosts,
        "deny_ip_literals": True,
        "require_global_dns": True,
        "revalidate_redirects": True,
        "container_network": "none",
        "max_requests": validated.max_requests,
        "max_response_bytes": validated.max_response_bytes,
        "max_total_bytes": validated.max_total_bytes,
        "max_redirects": validated.max_redirects,
        "connect_timeout_seconds": validated.connect_timeout_seconds,
        "request_timeout_seconds": validated.request_timeout_seconds,
    }
    receipt_base = {
        "schema_version": "rdc.run-egress-policy-receipt/v1",
        "policy_id": str(policy_id),
        "revision_id": str(revision_id),
        "revision_number": 1,
        "policy_digest": validated.policy_digest,
        "runtime_policy_digest": canonical_fingerprint(runtime_policy),
        "credential_configured": False,
    }
    receipt = {
        **receipt_base,
        "binding_digest": canonical_fingerprint(receipt_base),
    }
    input_reference = json.dumps(
        {
            "kind": "inline",
            "value": {},
            "project_egress_policy": runtime_policy,
            "project_egress_policy_receipt": receipt,
        }
    )
    async with engine.begin() as connection:
        await connection.execute(
            text("INSERT INTO control.egress_policies (id,organization_id,project_id,name,created_by_user_id) VALUES (:policy,:org,:project,:name,:user)"),
            {"policy": policy_id, "org": org_id, "project": project_id, "name": f"bound-{suffix}", "user": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.egress_policy_revisions (id,organization_id,project_id,policy_id,revision_number,allowed_hosts,allowed_methods,max_requests,max_response_bytes,max_total_bytes,max_redirects,connect_timeout_seconds,request_timeout_seconds,policy_digest,created_by_user_id) VALUES (:revision,:org,:project,:policy,1,'[\"api.example.com\"]','[\"GET\"]',4,65536,131072,0,2,5,:digest,:user)"),
            {"revision": revision_id, "org": org_id, "project": project_id, "policy": policy_id, "digest": validated.policy_digest, "user": user_id},
        )
        await connection.execute(
            text("UPDATE control.egress_policies SET status='ACTIVE',active_revision_id=:revision,activated_at=CURRENT_TIMESTAMP WHERE id=:policy"),
            {"revision": revision_id, "policy": policy_id},
        )
        await connection.execute(
            text("INSERT INTO control.agents (id,organization_id,project_id,name,slug,status,created_by_user_id) VALUES (:agent,:org,:project,'Bound',:slug,'ACTIVE',:user)"),
            {"agent": agent_id, "org": org_id, "project": project_id, "slug": f"bound-{suffix}", "user": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.agent_versions (id,organization_id,project_id,agent_id,version_number,protocol,semantic_version,manifest_schema_version,manifest_digest,manifest,created_by_user_id) VALUES (:version,:org,:project,:agent,1,'rdc-agent/v1','1.0.0','rdc.agent/v1',:digest,'{}',:user)"),
            {"version": version_id, "org": org_id, "project": project_id, "agent": agent_id, "digest": "b" * 64, "user": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.builds (id,organization_id,project_id,agent_id,agent_version_id,manifest_digest,status,requested_by_user_id) VALUES (:build,:org,:project,:agent,:version,:digest,'RUNNING',:user)"),
            {"build": build_id, "org": org_id, "project": project_id, "agent": agent_id, "version": version_id, "digest": "b" * 64, "user": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.runs (id,organization_id,project_id,agent_id,agent_version_id,build_id,status,input_reference,runtime_configuration,memory_mb,cpu_millis,timeout_seconds,requested_by_user_id,queued_at) VALUES (:run,:org,:project,:agent,:version,:build,'QUEUED',CAST(:input AS jsonb),'{}',128,100,60,:user,CURRENT_TIMESTAMP)"),
            {"run": run_id, "org": org_id, "project": project_id, "agent": agent_id, "version": version_id, "build": build_id, "input": input_reference, "user": user_id},
        )
        await connection.execute(
            text("INSERT INTO control.run_command_outbox (id,organization_id,project_id,run_id,command,topic,payload,status,attempts,available_at) VALUES (:source,:org,:project,:run,'START','rdc.run.requested.v1','{}','PENDING',0,CURRENT_TIMESTAMP)"),
            {"source": source_id, "org": org_id, "project": project_id, "run": run_id},
        )
    return policy_id, revision_id, run_id, source_id


async def test_bound_run_admission_serializes_with_policy_disable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress migration is unavailable")
    policy_id, _, run_id, source_id = await _seed_bound_run()
    monkeypatch.setattr(
        execution_plane,
        "_egress_policy_payload",
        lambda: {
            "allowed_hosts": ["api.example.com"],
            "max_requests": 8,
            "max_response_bytes": 1_048_576,
            "max_total_bytes": 4_194_304,
            "max_redirects": 3,
            "connect_timeout_seconds": 5,
            "request_timeout_seconds": 15,
        },
    )
    async with session_factory() as admission_session:
        source = await admission_session.scalar(
            select(RunCommandOutbox).where(RunCommandOutbox.id == source_id)
        )
        assert source is not None
        assert await execution_plane._bound_run_egress_policy_is_current(
            admission_session,
            source=source,
            now=execution_plane.datetime.now(execution_plane.UTC),
            request_id="postgres-binding-admission",
        )

        async def disable() -> None:
            async with engine.begin() as connection:
                await connection.execute(
                    text("UPDATE control.egress_policies SET status='DISABLED',disabled_at=CURRENT_TIMESTAMP WHERE id=:policy"),
                    {"policy": policy_id},
                )

        disable_task = asyncio.create_task(disable())
        await asyncio.sleep(0.05)
        assert not disable_task.done()
        await admission_session.commit()
        await asyncio.wait_for(disable_task, timeout=2)

    async with session_factory() as revoked_session:
        source = await revoked_session.scalar(
            select(RunCommandOutbox).where(RunCommandOutbox.id == source_id)
        )
        assert source is not None
        assert not await execution_plane._bound_run_egress_policy_is_current(
            revoked_session,
            source=source,
            now=execution_plane.datetime.now(execution_plane.UTC),
            request_id="postgres-binding-revoked",
        )
        await revoked_session.commit()
    async with engine.connect() as connection:
        statuses = (
            await connection.execute(
                text("SELECT r.status,r.failure_code,o.status,o.last_error_code,(SELECT count(*) FROM control.execution_leases l WHERE l.run_id=r.id) FROM control.runs r JOIN control.run_command_outbox o ON o.run_id=r.id WHERE r.id=:run"),
                {"run": run_id},
            )
        ).one()
    assert statuses == (
        "FAILED",
        "EGRESS_POLICY_BINDING_REVOKED",
        "FAILED",
        "EGRESS_POLICY_BINDING_REVOKED",
        0,
    )


async def test_live_canary_secret_loader_requires_exact_unexpired_claim() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL egress migration is unavailable")
    user_id, org_id, _, secret_id, policy_id, revision_id = await _seed()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.egress_policies SET status='ACTIVE',active_revision_id=:r,"
                "activated_at=CURRENT_TIMESTAMP WHERE id=:p"
            ),
            {"r": revision_id, "p": policy_id},
        )
    original = (
        canary_service.settings.egress_credential_canary_enabled,
        canary_service.settings.egress_credential_canary_target_url,
    )
    canary_service.settings.egress_credential_canary_enabled = True
    canary_service.settings.egress_credential_canary_target_url = (
        "https://canary.example.com/auth-check"
    )
    try:
        async with session_factory() as session:
            await session.execute(
                text("SELECT set_config('rdc.current_user_id',:u,true)"),
                {"u": str(user_id)},
            )
            await session.execute(
                text("SELECT set_config('rdc.current_organization_id',:o,true)"),
                {"o": str(org_id)},
            )
            secret = await session.scalar(
                select(ProjectSecret).where(ProjectSecret.id == secret_id)
            )
            assert secret is not None
            assert await enqueue_credential_rotation_canaries(
                session, secret=secret, request_id="live-loader-enqueue"
            ) == 1
            now = datetime.now(UTC)
            claims = await claim_credential_rotation_canaries(
                session, now=now, batch_size=10
            )
            claim = next(item for item in claims if item.credential_secret_id == secret_id)
            assert await load_credential_rotation_canary_secret(
                session,
                attempt_id=claim.id,
                claim_token=secrets.token_hex(32),
            ) is None
            material = await load_credential_rotation_canary_secret(
                session,
                attempt_id=claim.id,
                claim_token=claim.claim_token,
            )
            assert material is not None
            assert material.credential_secret_id == secret_id
            assert material.secret_version == claim.secret_version
            assert material.target_digest == claim.target_digest
            await session.commit()
        async with engine.connect() as connection:
            digest = await connection.scalar(
                text(
                    "SELECT claim_token_digest FROM control.egress_credential_canary_attempts "
                    "WHERE id=:id"
                ),
                {"id": claim.id},
            )
        assert isinstance(digest, str) and len(digest) == 64
        assert claim.claim_token not in digest
    finally:
        (
            canary_service.settings.egress_credential_canary_enabled,
            canary_service.settings.egress_credential_canary_target_url,
        ) = original
