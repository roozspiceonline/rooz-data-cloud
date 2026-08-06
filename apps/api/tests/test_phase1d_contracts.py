import base64
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError

from app.build_secret_schemas import (
    CreateProjectSecretRequest,
    ReplaceProjectSecretRequest,
)
from app.core.envelope_encryption import encrypt_project_secret, secret_aad
from app.core.errors import ApiError
from app.core.permissions import role_has_permission, validate_scopes
from app.services.builds_secrets import (
    parse_secret_if_match,
    secret_etag,
    validate_idempotency_key,
)


def test_phase1d_permissions_follow_contract() -> None:
    assert role_has_permission("developer", "secret.create")
    assert role_has_permission("developer", "secret.replace")
    assert role_has_permission("developer", "build.create")
    assert role_has_permission("viewer", "build.read")
    assert not role_has_permission("viewer", "secret.read_metadata")
    assert validate_scopes(["build.read", "secret.read_metadata"]) == [
        "build.read",
        "secret.read_metadata",
    ]


def test_secret_inputs_reject_unsafe_names_and_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        CreateProjectSecretRequest.model_validate(
            {"name": "lowercase", "value": "secret"}
        )
    with pytest.raises(ValidationError):
        ReplaceProjectSecretRequest.model_validate(
            {"value": "secret", "reveal": True}
        )


def test_secret_envelope_encryption_uses_random_data_key() -> None:
    organization_id = uuid4()
    project_id = uuid4()
    secret_id = uuid4()
    first = encrypt_project_secret(
        "private-value",
        organization_id=organization_id,
        project_id=project_id,
        secret_id=secret_id,
        name="PROXY_TOKEN",
        version=1,
    )
    second = encrypt_project_secret(
        "private-value",
        organization_id=organization_id,
        project_id=project_id,
        secret_id=secret_id,
        name="PROXY_TOKEN",
        version=1,
    )
    assert first.algorithm == "AES-256-GCM"
    assert first.ciphertext != b"private-value"
    assert first.ciphertext != second.ciphertext
    assert first.wrapped_data_key != second.wrapped_data_key

    master_key = base64.b64decode(
        "ZGV2ZWxvcG1lbnQtcmRjLXNlY3JldC1rZXktMzJiISE="
    )
    aad = secret_aad(
        organization_id=organization_id,
        project_id=project_id,
        secret_id=secret_id,
        name="PROXY_TOKEN",
        version=1,
    )
    data_key = AESGCM(master_key).decrypt(
        first.key_nonce,
        first.wrapped_data_key,
        aad,
    )
    plaintext = AESGCM(data_key).decrypt(
        first.value_nonce,
        first.ciphertext,
        aad,
    )
    assert plaintext == b"private-value"


def test_secret_etag_and_idempotency_validation() -> None:
    secret_id = uuid4()
    etag = secret_etag(secret_id, 4)
    assert parse_secret_if_match(etag, secret_id=secret_id) == 4
    with pytest.raises(ApiError):
        parse_secret_if_match('"stale"', secret_id=secret_id)
    with pytest.raises(ApiError):
        validate_idempotency_key("short")


def test_phase1d_migration_has_encryption_rls_and_outbox() -> None:
    migration = Path(
        "migrations/versions/20260806_0004_secrets_builds.py"
    ).read_text(encoding="utf-8")
    assert "encrypted_value" in migration
    assert "wrapped_data_key" in migration
    assert "ENABLE ROW LEVEL SECURITY" in migration
    assert "project_secrets_tenancy_guard" in migration
    assert "builds_tenancy_guard" in migration
    assert "build_dispatch_outbox" in migration
    assert "response_snapshot" in migration
    assert "rdc_project_secret_org" in migration
    assert "rdc_build_org" in migration


def test_phase1d_routes_match_approved_inventory() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/api/v1/projects/{project_id}/secrets" in paths
    assert "/api/v1/secrets/{secret_id}" in paths
    assert "/api/v1/agent-versions/{version_id}/builds" in paths
    assert "/api/v1/builds/{build_id}" in paths
    assert "/api/v1/agents/{agent_id}/builds" in paths
    assert all("reveal" not in path for path in paths)


def test_control_plane_has_no_build_execution_primitive() -> None:
    service = Path("app/services/builds_secrets.py").read_text(encoding="utf-8")
    assert "pg_advisory_xact_lock" in service
    for prohibited in ["subprocess", "os.system", "BuildKit", "docker build", "eval("]:
        assert prohibited not in service
