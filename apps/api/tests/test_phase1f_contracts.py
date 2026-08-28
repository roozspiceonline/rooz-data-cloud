import base64
import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import ValidationError

from app.agent_schemas import AgentManifest
from app.core.permissions import role_has_permission, validate_scopes
from app.core.security import issue_lease_token, issue_worker_token
from app.core.worker_crypto import (
    encrypt_secret_payload_for_worker,
    worker_egress_credential_aad,
    worker_secret_aad,
)
from app.execution_schemas import RegisterWorkerRequest, SecretEnvelopeRequest


def manifest_payload() -> dict[str, object]:
    return {
        "protocol": "rooz.agent/v1",
        "name": "phase-one-agent",
        "version": "1.0.0",
        "runtime": {
            "kind": "container",
            "entrypoint": ["python", "main.py"],
        },
        "schemas": {
            "input": "schemas/input.json",
            "output": "schemas/output.json",
        },
        "capabilities": {
            "network": "none",
            "browser": False,
            "dataset": False,
            "keyValueStore": False,
            "requestQueue": False,
        },
        "resources": {
            "memoryMb": 512,
            "cpuUnits": 500,
            "timeoutSeconds": 300,
            "maxProcesses": 16,
            "ephemeralDiskMb": 512,
        },
        "secrets": ["OPENAI_API_KEY", "ERP_TOKEN"],
    }


def test_phase1f_permissions_are_metadata_only_for_console() -> None:
    assert role_has_permission("developer", "execution.read")
    assert role_has_permission("operator", "execution.read")
    assert role_has_permission("viewer", "execution.read")
    assert validate_scopes(["execution.read"]) == ["execution.read"]


def test_manifest_declares_unique_secret_names() -> None:
    manifest = AgentManifest.model_validate(manifest_payload())
    assert manifest.secrets == ["OPENAI_API_KEY", "ERP_TOKEN"]

    duplicate = manifest_payload()
    duplicate["secrets"] = ["OPENAI_API_KEY", "OPENAI_API_KEY"]
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(duplicate)

    invalid = manifest_payload()
    invalid["secrets"] = ["not-valid"]
    with pytest.raises(ValidationError):
        AgentManifest.model_validate(invalid)


def test_worker_registration_and_secret_requests_are_strict() -> None:
    worker = RegisterWorkerRequest.model_validate(
        {
            "name": "worker-a1",
            "capabilities": ["BUILD", "RUN_START", "EVENT_INGEST"],
            "max_concurrency": 4,
            "software_version": "0.1.0",
        }
    )
    assert worker.protocol_version == "rdc.worker/v1"

    with pytest.raises(ValidationError):
        RegisterWorkerRequest.model_validate(
            {
                "name": "worker-a1",
                "capabilities": ["BUILD", "BUILD"],
                "max_concurrency": 4,
                "software_version": "0.1.0",
            }
        )

    request = SecretEnvelopeRequest.model_validate(
        {
            "names": ["ERP_TOKEN", "OPENAI_API_KEY"],
            "environment": "production",
            "worker_public_key_b64": base64.b64encode(b"x" * 32).decode(),
        }
    )
    assert request.names == ["ERP_TOKEN", "OPENAI_API_KEY"]


def test_worker_and_lease_credentials_have_distinct_prefixes() -> None:
    worker = issue_worker_token()
    lease = issue_lease_token(pepper="x" * 32)
    assert worker.raw_token.startswith("rdc_worker_")
    assert lease.raw_token.startswith("rdc_lease_")
    assert len(lease.digest) == 32
    assert worker.raw_token != lease.raw_token


def test_secret_envelope_round_trip_uses_x25519_and_aead() -> None:
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    aad = worker_secret_aad(
        lease_id="lease-id",
        worker_id="worker-id",
        run_id="run-id",
    )
    plaintext = b'{"secrets":{"TOKEN":"private"}}'
    envelope = encrypt_secret_payload_for_worker(
        plaintext,
        worker_public_key=public_key,
        aad=aad,
    )
    ephemeral = X25519PrivateKey.from_private_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    peer_public = private_key.public_key()
    assert ephemeral.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ) == peer_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    shared = private_key.exchange(
        X25519PublicKey.from_public_bytes(envelope.ephemeral_public_key)
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"rdc/execution-secret-envelope/v1",
    ).derive(shared)
    decrypted = AESGCM(key).decrypt(
        envelope.nonce,
        envelope.ciphertext,
        aad,
    )
    assert decrypted == plaintext
    assert envelope.algorithm == "X25519-HKDF-SHA256-AES-256-GCM"


def test_egress_credential_envelope_is_bound_to_policy_and_lease() -> None:
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    binding_digest = "a" * 64
    aad = worker_egress_credential_aad(
        lease_id="lease-id",
        worker_id="worker-id",
        run_id="run-id",
        policy_binding_digest=binding_digest,
    )
    plaintext = b'{"authorization":"Bearer private"}'
    envelope = encrypt_secret_payload_for_worker(
        plaintext,
        worker_public_key=public_key,
        aad=aad,
    )
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

    shared = private_key.exchange(
        X25519PublicKey.from_public_bytes(envelope.ephemeral_public_key)
    )
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"rdc/execution-secret-envelope/v1",
    ).derive(shared)
    assert AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, aad) == plaintext
    wrong_aad = worker_egress_credential_aad(
        lease_id="other-lease",
        worker_id="worker-id",
        run_id="run-id",
        policy_binding_digest=binding_digest,
    )
    with pytest.raises(InvalidTag):
        AESGCM(key).decrypt(envelope.nonce, envelope.ciphertext, wrong_aad)


def test_phase1f_routes_keep_internal_protocol_out_of_public_openapi() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/api/v1/projects/{project_id}/execution-leases" in paths
    assert "/api/v1/projects/{project_id}/execution-artifacts" in paths
    assert "/internal/v1/leases/claim" not in paths
    assert (
        str(app.url_path_for("claim_work_route"))
        == "/internal/v1/leases/claim"
    )


def test_phase1f_migration_has_leases_artifacts_secrets_rls_and_guards() -> None:
    migration = Path(
        "migrations/versions/20260806_0006_execution_plane.py"
    ).read_text(encoding="utf-8")
    for marker in [
        "worker_identities",
        "execution_leases",
        "execution_artifacts",
        "secret_injection_grants",
        "uq_execution_leases_active_source",
        "ENABLE ROW LEVEL SECURITY",
        "execution_leases_tenancy_guard",
        "execution_artifacts_tenancy_guard",
        "secret_injection_grants_tenancy_guard",
        "rdc_current_worker_id",
        "audit_execution_worker_insert",
    ]:
        assert marker in migration


def test_worker_protocol_schemas_remain_strict_and_execution_is_gated() -> None:
    schema_root = (
        Path(__file__).parents[3] / "packages/agent-protocol/schemas"
    )
    claim = json.loads(
        (schema_root / "worker-lease-claim.schema.json").read_text()
    )
    envelope = json.loads(
        (schema_root / "worker-secret-envelope.schema.json").read_text()
    )
    assert claim["additionalProperties"] is False
    assert claim["properties"]["payload"]["properties"][
        "execution_enabled"
    ] == {"type": "boolean"}
    assert "sandbox" in claim["properties"]["payload"]["required"]
    assert envelope["properties"]["algorithm"]["const"] == (
        "X25519-HKDF-SHA256-AES-256-GCM"
    )


def test_phase1f_does_not_execute_untrusted_agent_code() -> None:
    source = "\n".join(
        [
            Path("app/services/execution_plane.py").read_text(),
            Path("app/api/routes/internal_execution.py").read_text(),
        ]
    )
    for prohibited in [
        "subprocess",
        "os.system",
        "docker run",
        "kubectl",
        "BuildKit",
        "eval(",
        "exec(",
    ]:
        assert prohibited not in source
    assert (
        'claim_payload["execution_enabled"] = sandbox_policy is not None'
        in source
        or (
            "execution_enabled = sandbox_policy is not None and activation is not None"
            in source
            and 'claim_payload["execution_enabled"] = execution_enabled'
            in source
        )
    )
