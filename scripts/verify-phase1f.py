#!/usr/bin/env python3
"""Verify the static Phase 1F execution-plane foundation contract."""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_FILES = [
    "apps/api/app/execution_schemas.py",
    "apps/api/app/core/worker_crypto.py",
    "apps/api/app/api/internal_dependencies.py",
    "apps/api/app/api/routes/internal_execution.py",
    "apps/api/app/api/routes/execution.py",
    "apps/api/app/services/execution_plane.py",
    "apps/api/migrations/versions/20260806_0006_execution_plane.py",
    "apps/api/tests/test_phase1f_contracts.py",
    "apps/console/src/components/execution-plane-overview.tsx",
    "apps/console/src/app/console/organizations/[orgId]/projects/"
    "[projectId]/execution/page.tsx",
    "packages/agent-protocol/schemas/worker-lease-claim.schema.json",
    "packages/agent-protocol/schemas/worker-secret-envelope.schema.json",
    "docs/phase1f/README.md",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("PHASE1F VERIFICATION FAILED: " + message)


def foundation_phase_at_least(
    source: str,
    *,
    minimum_major: int,
    minimum_letter: str,
) -> bool:
    marker = re.search(r'"phase": "(\d+)([A-Z])"', source)
    if marker is None:
        return False
    current = (int(marker.group(1)), ord(marker.group(2)))
    minimum = (minimum_major, ord(minimum_letter))
    return current >= minimum


def main() -> None:
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    require(not missing, "missing required files: " + ", ".join(missing))

    for path in (ROOT / "apps/api/app").rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    migration = ROOT / "apps/api/migrations/versions/20260806_0006_execution_plane.py"
    ast.parse(migration.read_text(encoding="utf-8"), filename=str(migration))

    claim_schema = json.loads(
        (
            ROOT
            / "packages/agent-protocol/schemas/worker-lease-claim.schema.json"
        ).read_text(encoding="utf-8")
    )
    secret_schema = json.loads(
        (
            ROOT
            / "packages/agent-protocol/schemas/worker-secret-envelope.schema.json"
        ).read_text(encoding="utf-8")
    )
    require(claim_schema["additionalProperties"] is False, "claim schema is open")
    execution_flag = claim_schema["properties"]["payload"]["properties"][
        "execution_enabled"
    ]
    require(execution_flag == {"type": "boolean"}, "execution flag schema changed")
    require(
        "sandbox" in claim_schema["properties"]["payload"]["required"],
        "sandbox claim gate is absent",
    )
    require(
        secret_schema["properties"]["algorithm"]["const"]
        == "X25519-HKDF-SHA256-AES-256-GCM",
        "secret-envelope algorithm changed",
    )

    main_source = (ROOT / "apps/api/app/main.py").read_text(encoding="utf-8")
    require(
        foundation_phase_at_least(
            main_source,
            minimum_major=1,
            minimum_letter="F",
        ),
        "foundation phase is earlier than 1F",
    )
    require(
        '"untrusted_agent_execution_enabled": False' in main_source,
        "untrusted execution was enabled",
    )

    route_source = (
        ROOT / "apps/api/app/api/routes/internal_execution.py"
    ).read_text(encoding="utf-8")
    require("include_in_schema=False" in route_source, "internal API is public")

    service_source = (
        ROOT / "apps/api/app/services/execution_plane.py"
    ).read_text(encoding="utf-8")
    for prohibited in ["subprocess", "docker run", "kubectl", "eval(", "exec("]:
        require(prohibited not in service_source, "prohibited primitive: " + prohibited)
    require(
        (
            'claim_payload["execution_enabled"] = sandbox_policy is not None'
            in service_source
        )
        or (
            "execution_enabled = sandbox_policy is not None and activation is not None"
            in service_source
            and 'claim_payload["execution_enabled"] = execution_enabled'
            in service_source
        ),
        "claim payload sandbox gate is absent",
    )

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    runner = (ROOT / "scripts/run-verifiers.py").read_text(encoding="utf-8")
    require(
        "run-verifiers.py" in workflow and '"verify-phase1f.py"' in runner,
        "CI does not run Phase 1F verifier",
    )

    print("RDC_PHASE1F_VERIFICATION_PASSED")


if __name__ == "__main__":
    main()
