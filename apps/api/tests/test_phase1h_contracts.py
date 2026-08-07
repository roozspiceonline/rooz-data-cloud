import json
from pathlib import Path

from app.execution_schemas import SandboxAttestation


def safe_attestation() -> SandboxAttestation:
    return SandboxAttestation(
        apparmor_profile="rdc-agent-default",
        max_memory_mb=4096,
        max_cpu_millis=4000,
        max_pids=512,
        max_ephemeral_disk_mb=8192,
        max_build_seconds=900,
        max_run_seconds=600,
    )


def test_phase1h_attestation_is_strict() -> None:
    value = safe_attestation()
    assert value.schema_version == "rdc.sandbox/v1"
    assert value.rootless is True
    assert value.no_host_docker_socket is True
    assert value.network_policy == "deny-all"


def test_phase1h_worker_claim_schema_gates_execution_on_sandbox() -> None:
    root = Path(__file__).parents[3] / "packages/agent-protocol/schemas"
    schema = json.loads((root / "worker-lease-claim.schema.json").read_text())
    execution = schema["properties"]["payload"]["properties"]["execution_enabled"]
    assert execution == {"type": "boolean"}
    sandbox = schema["properties"]["payload"]["properties"]["sandbox"]
    assert {"$ref": "sandbox-capabilities.schema.json"} in sandbox["anyOf"]


def test_phase1h_api_does_not_invoke_container_runtime() -> None:
    source = "\n".join(
        path.read_text(encoding="utf-8")
        for path in Path("app").rglob("*.py")
    )
    for prohibited in ["subprocess.run(", "subprocess.Popen(", "docker.sock"]:
        assert prohibited not in source


def test_phase1h_worker_uses_fixed_argv_and_no_shell_true() -> None:
    root = Path(__file__).parents[3] / "workers/sandbox-runtime"
    source = "\n".join(path.read_text() for path in root.glob("*.py"))
    assert "buildctl" in source
    assert "nerdctl" in source
    assert "trivy" in source
    assert "shell=True" not in source
    assert "--cap-drop" in source
    assert '"ALL"' in source
    assert '"--network"' in source
    assert '"none"' in source
    assert "/var/run/docker.sock" in source
