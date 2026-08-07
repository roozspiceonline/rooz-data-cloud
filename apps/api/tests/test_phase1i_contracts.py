import json
from pathlib import Path

from app.execution_schemas import SandboxActivation

ROOT = Path(__file__).parents[3]


def test_phase1i_activation_contract_is_strict() -> None:
    activation = SandboxActivation(
        agent_version_id="11111111-1111-4111-8111-111111111111",
        worker_name="rdc-canary-worker",
        attestation_digest="a" * 64,
        sandbox_policy_digest="b" * 64,
        constraints_digest="c" * 64,
    )
    assert activation.mode == "canary"
    assert activation.no_secrets is True
    assert activation.capability_profile == "offline-minimal"
    assert activation.max_concurrency == 1


def test_phase1i_canary_manifest_is_offline_and_secretless() -> None:
    from app.agent_schemas import AgentManifest

    raw = json.loads(
        (ROOT / "examples/canary-agent/agent.json").read_text(encoding="utf-8")
    )
    manifest = AgentManifest.model_validate(raw)
    assert manifest.name == "rdc-canary"
    assert manifest.secrets == []
    assert manifest.capabilities.network == "none"
    assert manifest.capabilities.browser is False
    assert manifest.capabilities.dataset is False
    assert manifest.capabilities.key_value_store is False
    assert manifest.capabilities.request_queue is False
    assert manifest.resources.memory_mb <= 256
    assert manifest.resources.cpu_units <= 500
    assert manifest.resources.max_processes <= 64
    assert manifest.resources.ephemeral_disk_mb <= 256
    assert manifest.resources.timeout_seconds <= 120


def test_phase1i_claim_schema_requires_activation_when_enabled() -> None:
    root = ROOT / "packages/agent-protocol/schemas"
    claim = json.loads((root / "worker-lease-claim.schema.json").read_text())
    payload = claim["properties"]["payload"]
    assert "activation" in payload["required"]
    activation = payload["properties"]["activation"]
    assert {"$ref": "sandbox-activation.schema.json"} in activation["anyOf"]
    condition = payload["allOf"][0]
    assert condition["if"]["properties"]["execution_enabled"] == {"const": True}
    assert condition["then"]["properties"]["activation"] == {
        "$ref": "sandbox-activation.schema.json"
    }


def test_phase1i_control_plane_has_no_runtime_primitive() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("app").rglob("*.py")
    )
    for prohibited in [
        "subprocess.run(",
        "subprocess.Popen(",
        "os.system(",
        "docker.sock",
    ]:
        assert prohibited not in source


def test_phase1i_activation_lineage_is_enforced() -> None:
    service = Path("app/services/execution_plane.py").read_text(
        encoding="utf-8"
    )
    for marker in [
        "_canary_activation",
        "worker.max_concurrency != 1",
        "ARTIFACT_ACTIVATION_MISMATCH",
        "ARTIFACT_LINEAGE_INVALID",
        "source_sha256",
        "image_digest",
        "sandbox_activation_mode",
    ]:
        assert marker in service
