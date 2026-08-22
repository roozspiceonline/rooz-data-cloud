# ruff: noqa: E501
from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import select, text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.database import engine, session_factory
from app.core.errors import ApiError
from app.egress_policy_schemas import (
    CreateEgressPolicyRequest,
    CreateEgressPolicyRevisionRequest,
)
from app.models import Project
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
