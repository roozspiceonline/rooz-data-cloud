#!/usr/bin/env python3
"""Verify the static Phase 1H sandbox-runtime foundation contract."""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = [
    "apps/api/migrations/versions/20260807_0008_sandbox_runtime.py",
    "apps/api/tests/test_phase1h_contracts.py",
    "packages/agent-protocol/schemas/sandbox-capabilities.schema.json",
    "packages/agent-protocol/schemas/build-execution-result.schema.json",
    "packages/agent-protocol/schemas/runtime-execution-result.schema.json",
    "workers/sandbox-runtime/policy.py",
    "workers/sandbox-runtime/dockerfile_policy.py",
    "workers/sandbox-runtime/build_executor.py",
    "workers/sandbox-runtime/run_executor.py",
    "workers/sandbox-runtime/worker.py",
    "infrastructure/buildkit/buildkitd.toml",
    "infrastructure/sandbox/seccomp-rdc-default.json",
    "infrastructure/sandbox/rdc-agent-default.apparmor",
    "docs/phase1h/README.md",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("PHASE1H VERIFICATION FAILED: " + message)


def main() -> None:
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    require(not missing, "missing required files: " + ", ".join(missing))
    for path in (ROOT / "apps/api/app").rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for path in (ROOT / "workers/sandbox-runtime").glob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    ast.parse(
        (ROOT / "apps/api/migrations/versions/20260807_0008_sandbox_runtime.py").read_text(),
        filename="20260807_0008_sandbox_runtime.py",
    )
    sandbox = json.loads(
        (ROOT / "packages/agent-protocol/schemas/sandbox-capabilities.schema.json").read_text()
    )
    require(sandbox["additionalProperties"] is False, "sandbox schema is open")
    require(sandbox["properties"]["rootless"]["const"] is True, "rootless guard missing")
    require(
        sandbox["properties"]["no_host_docker_socket"]["const"] is True,
        "Docker-socket guard missing",
    )
    require(
        sandbox["properties"]["network_policy"]["const"] == "deny-all",
        "Phase 1H network must default deny",
    )
    config = (ROOT / "apps/api/app/core/config.py").read_text()
    require(
        "sandbox_execution_enabled: bool = False" in config,
        "sandbox execution must be disabled by default",
    )
    service = (ROOT / "apps/api/app/services/execution_plane.py").read_text()
    require("_sandbox_claim_policy" in service, "claim policy gate missing")
    require("sha256_object" in service, "artifact digest verification missing")
    api_source = "\n".join(path.read_text() for path in (ROOT / "apps/api/app").rglob("*.py"))
    for prohibited in ["subprocess.run(", "subprocess.Popen(", "os.system("]:
        require(prohibited not in api_source, "control plane invokes runtime: " + prohibited)
    worker_source = "\n".join(
        path.read_text() for path in (ROOT / "workers/sandbox-runtime").glob("*.py")
    )
    for marker in ["buildctl", "nerdctl", "trivy", "/var/run/docker.sock", "--cap-drop"]:
        require(marker in worker_source, "worker control missing: " + marker)
    require("shell=True" not in worker_source, "worker uses shell=True")
    workflow = (ROOT / ".github/workflows/ci.yml").read_text()
    require("verify-phase1h.py" in workflow, "CI does not run Phase 1H verifier")
    print("RDC_PHASE1H_VERIFICATION_PASSED")


if __name__ == "__main__":
    main()
