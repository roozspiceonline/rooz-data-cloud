#!/usr/bin/env python3
"""Static Phase 1D boundary and contract verification."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    "apps/api/app/build_secret_schemas.py",
    "apps/api/app/core/envelope_encryption.py",
    "apps/api/app/api/routes/builds_secrets.py",
    "apps/api/app/services/builds_secrets.py",
    "apps/api/migrations/versions/20260806_0004_secrets_builds.py",
    "apps/api/tests/test_phase1d_contracts.py",
    "apps/console/src/components/project-secret-manager.tsx",
    "apps/console/src/components/build-control-plane.tsx",
    "apps/console/tests/phase1d-contract.test.mjs",
]

for relative in REQUIRED:
    if not (ROOT / relative).is_file():
        raise SystemExit(f"Missing Phase 1D file: {relative}")

routes = (ROOT / "apps/api/app/api/routes/builds_secrets.py").read_text()
for marker in [
    "/projects/{project_id}/secrets",
    "/secrets/{secret_id}",
    "/agent-versions/{version_id}/builds",
    "/builds/{build_id}",
    "/agents/{agent_id}/builds",
]:
    if marker not in routes:
        raise SystemExit(f"Missing approved Phase 1D route: {marker}")
if "reveal" in routes.casefold():
    raise SystemExit("Project-secret reveal endpoints are prohibited")

migration = (
    ROOT / "apps/api/migrations/versions/20260806_0004_secrets_builds.py"
).read_text()
for marker in [
    "encrypted_value",
    "wrapped_data_key",
    "ENABLE ROW LEVEL SECURITY",
    "build_dispatch_outbox",
    "response_snapshot",
    "rdc_project_secret_org",
    "rdc_build_org",
]:
    if marker not in migration:
        raise SystemExit(f"Missing Phase 1D migration control: {marker}")

service = (ROOT / "apps/api/app/services/builds_secrets.py").read_text()
for prohibited in [
    "subprocess",
    "os.system",
    "BuildKit",
    "docker build",
    "eval(",
    "exec(",
]:
    if prohibited in service:
        raise SystemExit(f"Execution boundary violation: {prohibited}")

client = (ROOT / "packages/api-client/src/index.ts").read_text()
for prohibited in ["localStorage", "sessionStorage", "revealSecret"]:
    if prohibited in client:
        raise SystemExit(f"Frontend security boundary violation: {prohibited}")

print("RDC_PHASE1D_SECRETS_BUILDS_OK")
