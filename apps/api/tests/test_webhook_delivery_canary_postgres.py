# ruff: noqa: E501
from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
import pytest_asyncio
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, OperationalError

from app.core.database import engine, session_factory
from app.core.envelope_encryption import decrypt_project_secret, encrypt_project_secret
from app.core.errors import ApiError
from app.services.webhook_delivery_canary import (
    ClaimedWebhookDeliveryCanary,
    claim_webhook_delivery_canaries,
    complete_webhook_delivery_canary,
    load_webhook_delivery_material,
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
                    text(
                        "SELECT to_regprocedure("
                        "'control.claim_webhook_delivery_canary(timestamptz,integer,integer,text)'"
                        ") IS NOT NULL"
                    )
                )
            )
    except (OSError, DBAPIError, OperationalError):
        return False


async def _seed_delivery() -> dict[str, UUID]:
    ids = {
        name: uuid4()
        for name in (
            "user",
            "org",
            "project",
            "agent",
            "version",
            "build",
            "event",
            "secret",
            "destination",
            "delivery",
        )
    }
    suffix = uuid4().hex
    secret_name = f"WEBHOOK_{ids['destination'].hex.upper()}"
    encrypted = encrypt_project_secret(
        "s" * 32,
        organization_id=ids["org"],
        project_id=ids["project"],
        secret_id=ids["secret"],
        name=secret_name,
        version=1,
    )
    event_payload = json.dumps(
        {
            "agent_id": str(ids["agent"]),
            "agent_version_id": str(ids["version"]),
            "status": "QUEUED",
        }
    )
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "INSERT INTO identity.users (id,email_normalized,email_display,password_hash,password_algorithm,display_name,status) VALUES (:u,:e,:e,'x','argon2id','Webhook','ACTIVE')"
            ),
            {"u": ids["user"], "e": f"webhook-{suffix}@example.invalid"},
        )
        await connection.execute(
            text(
                "INSERT INTO identity.organizations (id,name,slug,status,created_by_user_id) VALUES (:o,'Webhook',:slug,'ACTIVE',:u)"
            ),
            {"o": ids["org"], "slug": f"webhook-{suffix}", "u": ids["user"]},
        )
        await connection.execute(
            text(
                "INSERT INTO identity.organization_memberships (organization_id,user_id,role,status,joined_at,updated_at,created_by_user_id) VALUES (:o,:u,'owner','ACTIVE',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,:u)"
            ),
            {"o": ids["org"], "u": ids["user"]},
        )
        await connection.execute(
            text(
                "INSERT INTO control.projects (id,organization_id,name,slug,status,created_by_user_id) VALUES (:p,:o,'Webhook',:slug,'ACTIVE',:u)"
            ),
            {
                "p": ids["project"],
                "o": ids["org"],
                "slug": f"webhook-project-{suffix}",
                "u": ids["user"],
            },
        )
        await connection.execute(
            text(
                "INSERT INTO control.agents (id,organization_id,project_id,name,slug,status,created_by_user_id) VALUES (:a,:o,:p,'Webhook',:slug,'ACTIVE',:u)"
            ),
            {
                "a": ids["agent"],
                "o": ids["org"],
                "p": ids["project"],
                "slug": f"webhook-agent-{suffix}",
                "u": ids["user"],
            },
        )
        await connection.execute(
            text(
                "INSERT INTO control.agent_versions (id,organization_id,project_id,agent_id,version_number,protocol,semantic_version,manifest_schema_version,manifest_digest,manifest,created_by_user_id) VALUES (:v,:o,:p,:a,1,'rdc-agent/v1','1.0.0','rdc.agent/v1',:digest,'{}',:u)"
            ),
            {
                "v": ids["version"],
                "o": ids["org"],
                "p": ids["project"],
                "a": ids["agent"],
                "digest": "a" * 64,
                "u": ids["user"],
            },
        )
        await connection.execute(
            text(
                "INSERT INTO control.builds (id,organization_id,project_id,agent_id,agent_version_id,manifest_digest,status,requested_by_user_id) VALUES (:b,:o,:p,:a,:v,:digest,'QUEUED',:u)"
            ),
            {
                "b": ids["build"],
                "o": ids["org"],
                "p": ids["project"],
                "a": ids["agent"],
                "v": ids["version"],
                "digest": "a" * 64,
                "u": ids["user"],
            },
        )
        await connection.execute(
            text(
                "INSERT INTO control.events (id,organization_id,project_id,event_type,schema_version,subject_type,subject_id,payload,payload_digest,emitter,request_id) VALUES (:id,:o,:p,'build.created','rdc.event/v1','build',:b,CAST(:payload AS jsonb),:digest,'control-plane',:request_id)"
            ),
            {
                "id": ids["event"],
                "o": ids["org"],
                "p": ids["project"],
                "b": ids["build"],
                "payload": event_payload,
                "digest": "0" * 64,
                "request_id": f"webhook-{suffix}",
            },
        )
        await connection.execute(
            text(
                "INSERT INTO security.project_secrets (id,organization_id,project_id,name,description,environment,encrypted_value,value_nonce,wrapped_data_key,key_nonce,encryption_algorithm,master_key_version,created_by_user_id,updated_by_user_id,version) VALUES (:id,:o,:p,:name,'Webhook signing secret','development',:value,:value_nonce,:wrapped,:key_nonce,:algorithm,:master_version,:u,:u,1)"
            ),
            {
                "id": ids["secret"],
                "o": ids["org"],
                "p": ids["project"],
                "name": secret_name,
                "value": encrypted.ciphertext,
                "value_nonce": encrypted.value_nonce,
                "wrapped": encrypted.wrapped_data_key,
                "key_nonce": encrypted.key_nonce,
                "algorithm": encrypted.algorithm,
                "master_version": encrypted.master_key_version,
                "u": ids["user"],
            },
        )
        await connection.execute(
            text(
                "INSERT INTO control.webhook_destinations (id,organization_id,project_id,name,endpoint_url,endpoint_origin,event_types,status,signing_secret_id,signing_secret_version,created_by_user_id,updated_by_user_id) VALUES (:id,:o,:p,'Canary','https://hooks.example.com/rdc','https://hooks.example.com',CAST('[\"build.created\"]' AS jsonb),'PENDING_VERIFICATION',:s,1,:u,:u)"
            ),
            {
                "id": ids["destination"],
                "o": ids["org"],
                "p": ids["project"],
                "s": ids["secret"],
                "u": ids["user"],
            },
        )
        await connection.execute(
            text(
                "INSERT INTO control.webhook_delivery_attempts (id,organization_id,project_id,destination_id,event_id,endpoint_url,signing_secret_id,signing_secret_version,status,attempt_count,max_attempts,available_at,version) VALUES (:id,:o,:p,:d,:e,'https://ignored.invalid/',:s,99,'PENDING',0,3,CURRENT_TIMESTAMP,1)"
            ),
            {
                "id": ids["delivery"],
                "o": ids["org"],
                "p": ids["project"],
                "d": ids["destination"],
                "e": ids["event"],
                "s": ids["secret"],
            },
        )
    return ids


async def _claim_once(worker_id: str) -> list[ClaimedWebhookDeliveryCanary]:
    async with session_factory() as session:
        claims = await claim_webhook_delivery_canaries(
            session,
            now=datetime.now(UTC),
            batch_size=1,
            claim_seconds=60,
            worker_id=worker_id,
        )
        await session.commit()
        return claims


async def test_claim_is_single_winner_digest_only_and_material_is_claim_scoped() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL trusted webhook migration is unavailable")
    ids = await _seed_delivery()
    left, right = await asyncio.gather(_claim_once("webhook-left"), _claim_once("webhook-right"))
    claims = left + right
    assert len(claims) == 1
    claim = claims[0]
    assert claim.id == ids["delivery"]
    assert claim.claim_token not in repr(claim)
    async with engine.connect() as connection:
        persisted = (
            (
                await connection.execute(
                    text(
                        "SELECT claim_token,claim_token_digest,endpoint_url,signing_secret_version FROM control.webhook_delivery_attempts WHERE id=:id"
                    ),
                    {"id": claim.id},
                )
            )
            .mappings()
            .one()
        )
    assert persisted["claim_token"] is None
    assert len(persisted["claim_token_digest"]) == 64
    assert persisted["endpoint_url"] == "https://hooks.example.com/rdc"
    assert persisted["signing_secret_version"] == 1

    async with session_factory() as session:
        assert (
            await load_webhook_delivery_material(session, delivery_id=claim.id, claim_token="wrong")
            is None
        )
        material = await load_webhook_delivery_material(
            session, delivery_id=claim.id, claim_token=claim.claim_token
        )
    assert material is not None
    plaintext = decrypt_project_secret(
        ciphertext=material.encrypted_value,
        value_nonce=material.value_nonce,
        wrapped_data_key=material.wrapped_data_key,
        key_nonce=material.key_nonce,
        organization_id=material.organization_id,
        project_id=material.project_id,
        secret_id=material.signing_secret_id,
        name=material.secret_name,
        version=material.secret_version,
    )
    assert plaintext == b"s" * 32

    async with session_factory() as session:
        with pytest.raises(DBAPIError, match="completion clock"):
            await session.execute(
                text(
                    "SELECT * FROM control.complete_webhook_delivery_canary("
                    ":id,:digest,'DELIVERED',204,:now)"
                ),
                {
                    "id": claim.id,
                    "digest": hashlib.sha256(claim.claim_token.encode("ascii")).hexdigest(),
                    "now": datetime(2000, 1, 1, tzinfo=UTC),
                },
            )
        await session.rollback()
        with pytest.raises(ApiError, match="stale"):
            await complete_webhook_delivery_canary(
                session,
                delivery_id=claim.id,
                claim_token="wrong",
                outcome="DELIVERED",
                http_status=204,
                now=datetime.now(UTC),
            )
        await session.rollback()
        completed = await complete_webhook_delivery_canary(
            session,
            delivery_id=claim.id,
            claim_token=claim.claim_token,
            outcome="DELIVERED",
            http_status=204,
            now=datetime.now(UTC),
        )
        await session.commit()
    assert (completed.status, completed.outcome, completed.retry_scheduled) == (
        "SUCCEEDED",
        "DELIVERED",
        False,
    )


async def test_rotation_invalidates_material_and_completion_converges_generically() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL trusted webhook migration is unavailable")
    ids = await _seed_delivery()
    claims = await _claim_once("webhook-rotation")
    assert len(claims) == 1
    claim = claims[0]
    async with engine.begin() as connection:
        await connection.execute(
            text("UPDATE security.project_secrets SET version=2 WHERE id=:id"),
            {"id": ids["secret"]},
        )
        await connection.execute(
            text("UPDATE control.webhook_destinations SET version=version+1 WHERE id=:id"),
            {"id": ids["destination"]},
        )
    async with session_factory() as session:
        assert (
            await load_webhook_delivery_material(
                session, delivery_id=claim.id, claim_token=claim.claim_token
            )
            is None
        )
        completed = await complete_webhook_delivery_canary(
            session,
            delivery_id=claim.id,
            claim_token=claim.claim_token,
            outcome="DELIVERED",
            http_status=204,
            now=datetime.now(UTC),
        )
        await session.commit()
    assert completed.status == "DEAD_LETTERED"
    assert completed.outcome == "CONFIGURATION_ERROR"


async def test_expired_final_claim_converges_without_overclaiming() -> None:
    if not await _database_available():
        pytest.skip("PostgreSQL trusted webhook migration is unavailable")
    ids = await _seed_delivery()
    async with engine.begin() as connection:
        await connection.execute(
            text(
                "UPDATE control.webhook_delivery_attempts SET status='CLAIMED',"
                "attempt_count=max_attempts,claim_token_digest=:digest,claimed_by='expired-worker',"
                "claim_expires_at=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE id=:id"
            ),
            {"id": ids["delivery"], "digest": "a" * 64},
        )
    assert await _claim_once("webhook-after-expiry") == []
    async with engine.connect() as connection:
        row = (
            (
                await connection.execute(
                    text(
                        "SELECT status,claim_token_digest,claimed_by,claim_expires_at,"
                        "last_error_code FROM control.webhook_delivery_attempts WHERE id=:id"
                    ),
                    {"id": ids["delivery"]},
                )
            )
            .mappings()
            .one()
        )
    assert row == {
        "status": "DEAD_LETTERED",
        "claim_token_digest": None,
        "claimed_by": None,
        "claim_expires_at": None,
        "last_error_code": "CLAIM_EXPIRED",
    }
