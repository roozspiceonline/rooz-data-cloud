from uuid import uuid4

from app.core.security import (
    derive_api_key,
    derive_csrf_token,
    hash_password,
    secret_digest,
    verify_csrf_token,
    verify_password,
)


def test_argon2id_password_hash() -> None:
    encoded = hash_password("Correct-Horse-Battery-Staple-9!")
    assert encoded.startswith("$argon2id$")
    assert verify_password(
        encoded,
        "Correct-Horse-Battery-Staple-9!",
    )
    assert not verify_password(encoded, "wrong-password")


def test_csrf_token_is_session_bound() -> None:
    session_id = uuid4()
    token_digest = secret_digest(
        "opaque-session-token",
        "s" * 40,
    )
    token = derive_csrf_token(
        session_id=session_id,
        session_token_digest=token_digest,
        pepper="c" * 40,
    )
    stored_digest = secret_digest(token, "c" * 40)

    assert verify_csrf_token(
        supplied_token=token,
        session_id=session_id,
        session_token_digest=token_digest,
        expected_digest=stored_digest,
        pepper="c" * 40,
    )
    assert not verify_csrf_token(
        supplied_token=token,
        session_id=uuid4(),
        session_token_digest=token_digest,
        expected_digest=stored_digest,
        pepper="c" * 40,
    )


def test_api_key_is_idempotently_derived() -> None:
    organization_id = uuid4()
    principal_id = uuid4()
    first = derive_api_key(
        environment="live",
        organization_id=organization_id,
        principal_id=principal_id,
        idempotency_key="request-00000001",
        issuance_secret="i" * 40,
    )
    second = derive_api_key(
        environment="live",
        organization_id=organization_id,
        principal_id=principal_id,
        idempotency_key="request-00000001",
        issuance_secret="i" * 40,
    )
    different = derive_api_key(
        environment="live",
        organization_id=organization_id,
        principal_id=principal_id,
        idempotency_key="request-00000002",
        issuance_secret="i" * 40,
    )

    assert first == second
    assert first.raw_token != different.raw_token
    assert first.raw_token.startswith("rdc_live_")
