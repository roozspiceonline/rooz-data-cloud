#!/usr/bin/env python3
"""Verify the Phase 1I controlled sandbox activation contract."""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "apps/api/app/services/execution_plane.py",
    "apps/api/tests/test_phase1i_contracts.py",
    "apps/console/tests/phase1i-contract.test.mjs",
    "docs/phase1i/README.md",
    "docs/phase1i/RUNBOOK.md",
    "examples/canary-agent/Dockerfile",
    "examples/canary-agent/agent.json",
    "examples/canary-agent/main.py",
    "examples/canary-agent/schemas/input.json",
    "examples/canary-agent/schemas/output.json",
    "packages/agent-protocol/schemas/sandbox-activation.schema.json",
    "packages/agent-protocol/schemas/worker-lease-claim.schema.json",
    "scripts/build-phase1i-canary-source.py",
    "workers/sandbox-runtime/worker.py",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("PHASE1I VERIFICATION FAILED: " + message)


def read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def main() -> None:
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    require(not missing, "missing required files: " + ", ".join(missing))

    for path in (ROOT / "apps/api/app").rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for path in (ROOT / "workers/sandbox-runtime").glob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    ast.parse(
        read("scripts/build-phase1i-canary-source.py"),
        filename="build-phase1i-canary-source.py",
    )
    ast.parse(
        read("examples/canary-agent/main.py"),
        filename="canary-main.py",
    )

    config = read("apps/api/app/core/config.py")
    for marker in [
        'sandbox_execution_enabled: bool = False',
        'sandbox_activation_mode: Literal["disabled", "canary"] = "disabled"',
        'sandbox_canary_agent_version_id: str = ""',
        'sandbox_canary_worker_name: str = ""',
    ]:
        require(marker in config, "missing safe activation default: " + marker)

    main_api = read("apps/api/app/main.py")
    require('"phase": "1I"' in main_api, "foundation phase is not 1I")
    require(
        '"untrusted_agent_execution_enabled": False' in main_api,
        "general untrusted execution was enabled",
    )
    require(
        '"controlled_canary_execution_enabled"' in main_api,
        "canary status signal is missing",
    )

    service = read("apps/api/app/services/execution_plane.py")
    for marker in [
        "_canary_activation",
        "worker.max_concurrency != 1",
        "sandbox_activation_mode != \"canary\"",
        "ARTIFACT_ACTIVATION_MISMATCH",
        "ARTIFACT_LINEAGE_INVALID",
        "source_sha256",
        "image_digest",
        'capabilities.get("network") != "none"',
        "secrets",
    ]:
        require(marker in service, "missing canary control: " + marker)
    for prohibited in [
        "subprocess.run(",
        "subprocess.Popen(",
        "os.system(",
        "docker.sock",
    ]:
        require(prohibited not in service, "API runtime primitive: " + prohibited)

    activation = json.loads(
        read("packages/agent-protocol/schemas/sandbox-activation.schema.json")
    )
    require(
        activation["additionalProperties"] is False,
        "activation schema is open",
    )
    require(
        activation["properties"]["mode"]["const"] == "canary",
        "activation mode changed",
    )
    require(
        activation["properties"]["no_secrets"]["const"] is True,
        "canary secrets guard changed",
    )
    require(
        activation["properties"]["max_concurrency"]["const"] == 1,
        "canary concurrency guard changed",
    )

    claim = json.loads(
        read("packages/agent-protocol/schemas/worker-lease-claim.schema.json")
    )
    payload = claim["properties"]["payload"]
    require("activation" in payload["required"], "claim activation is optional")
    require(
        {"$ref": "sandbox-activation.schema.json"}
        in payload["properties"]["activation"]["anyOf"],
        "claim activation schema is missing",
    )

    manifest = json.loads(read("examples/canary-agent/agent.json"))
    caps = manifest["capabilities"]
    require(manifest.get("secrets") == [], "canary declares secrets")
    require(caps["network"] == "none", "canary network is not disabled")
    for name in [
        "browser",
        "dataset",
        "keyValueStore",
        "requestQueue",
    ]:
        require(caps[name] is False, "canary capability enabled: " + name)

    resources = manifest["resources"]
    require(resources["memoryMb"] <= 256, "canary memory too broad")
    require(resources["cpuUnits"] <= 500, "canary CPU too broad")
    require(resources["maxProcesses"] <= 64, "canary PID limit too broad")
    require(
        resources["ephemeralDiskMb"] <= 256,
        "canary disk limit too broad",
    )
    require(resources["timeoutSeconds"] <= 120, "canary timeout too broad")

    dockerfile = read("examples/canary-agent/Dockerfile")
    require(
        dockerfile.startswith("FROM python:3.12-slim\n"),
        "canary base image is not approved",
    )
    require("RUN " not in dockerfile, "canary Dockerfile runs build commands")
    require("USER 65532:65532" in dockerfile, "canary user is not non-root")

    canary_source = read("examples/canary-agent/main.py")
    for prohibited in [
        "socket",
        "urllib",
        "requests",
        "http.client",
        "subprocess",
    ]:
        require(
            prohibited not in canary_source,
            "canary code has external primitive: " + prohibited,
        )

    worker = read("workers/sandbox-runtime/worker.py")
    for marker in [
        "_require_canary_activation",
        "sandbox_policy_digest",
        "max_concurrency=1",
        "source_sha256",
        "image_digest",
    ]:
        require(marker in worker, "worker canary control missing: " + marker)
    require("shell=True" not in worker, "worker uses shell=True")

    workflow = read(".github/workflows/ci.yml")
    require(
        "verify-phase1i.py" in workflow,
        "CI does not run the Phase 1I verifier",
    )
    require(
        "RDC_SANDBOX_ACTIVATION_MODE: disabled" in workflow,
        "CI activation mode is not disabled",
    )

    print("RDC_PHASE1I_VERIFICATION_PASSED")


if __name__ == "__main__":
    main()
