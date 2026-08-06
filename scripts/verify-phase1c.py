#!/usr/bin/env python3
"""Static Phase 1C boundary and contract verification."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "apps/api/app/agent_schemas.py",
    "apps/api/app/api/agent_dependencies.py",
    "apps/api/app/api/routes/agents.py",
    "apps/api/app/core/pagination.py",
    "apps/api/app/services/agents.py",
    "apps/api/migrations/versions/20260806_0003_agent_registry.py",
    "apps/api/tests/test_phase1c_contracts.py",
    "apps/console/src/components/agent-registry.tsx",
    "apps/console/src/components/agent-detail.tsx",
    "apps/console/src/components/agent-version-detail.tsx",
    "apps/console/tests/agent-contract.test.mjs",
]

for relative in REQUIRED:
    path = ROOT / relative
    if not path.is_file():
        raise SystemExit(f"Missing Phase 1C file: {relative}")

routes = (ROOT / "apps/api/app/api/routes/agents.py").read_text()
for path in [
    "/projects/{project_id}/agents",
    "/agents/{agent_id}",
    "/agents/{agent_id}/versions",
    "/agent-versions/{version_id}",
]:
    if path not in routes:
        raise SystemExit(f"Missing approved Agent route: {path}")

migration = (
    ROOT
    / "apps/api/migrations/versions/20260806_0003_agent_registry.py"
).read_text()
for marker in [
    "ENABLE ROW LEVEL SECURITY",
    "agent_versions_immutable",
    "rdc_project_org",
    "rdc_agent_org",
    "rdc_agent_version_org",
]:
    if marker not in migration:
        raise SystemExit(f"Missing migration control: {marker}")

service = (ROOT / "apps/api/app/services/agents.py").read_text()
for prohibited in [
    "subprocess",
    "os.system",
    "eval(",
    "exec(",
    "docker",
    "BuildKit",
]:
    if prohibited in service:
        raise SystemExit(f"Execution boundary violation: {prohibited}")

frontend = (ROOT / "apps/console/src/components/agent-detail.tsx").read_text()
if "Build and Run" not in frontend or "remain disabled" not in frontend:
    raise SystemExit("Frontend must state the Phase 1C execution boundary")

client = (ROOT / "packages/api-client/src/index.ts").read_text()
if "localStorage" in client or "sessionStorage" in client:
    raise SystemExit("Browser credential storage is prohibited")

print("RDC_PHASE1C_AGENT_REGISTRY_OK")
