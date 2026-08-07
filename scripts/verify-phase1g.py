#!/usr/bin/env python3
"""Verify the static Phase 1G source and artifact-delivery contract."""

from __future__ import annotations

import ast
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = [
    "apps/api/app/core/source_archive.py",
    "apps/api/app/core/s3_storage.py",
    "apps/api/app/storage_schemas.py",
    "apps/api/app/api/routes/storage.py",
    "apps/api/app/services/storage_delivery.py",
    "apps/api/migrations/versions/20260806_0007_storage_delivery.py",
    "apps/api/tests/test_phase1g_contracts.py",
    "apps/console/src/components/source-upload-panel.tsx",
    "apps/console/src/components/storage-manager.tsx",
    "apps/console/src/app/console/organizations/[orgId]/projects/[projectId]/storage/page.tsx",
    "packages/agent-protocol/schemas/source-upload-intent.schema.json",
    "docs/phase1g/README.md",
]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit("PHASE1G VERIFICATION FAILED: " + message)


def main() -> None:
    missing = [path for path in REQUIRED_FILES if not (ROOT / path).is_file()]
    require(not missing, "missing required files: " + ", ".join(missing))

    for path in (ROOT / "apps/api/app").rglob("*.py"):
        ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    migration = ROOT / "apps/api/migrations/versions/20260806_0007_storage_delivery.py"
    ast.parse(migration.read_text(encoding="utf-8"), filename=str(migration))

    schema = json.loads(
        (
            ROOT
            / "packages/agent-protocol/schemas/source-upload-intent.schema.json"
        ).read_text(encoding="utf-8")
    )
    require(schema["additionalProperties"] is False, "source schema is open")
    require(schema["properties"]["kind"]["const"] == "AGENT_SOURCE", "kind changed")

    main_source = (ROOT / "apps/api/app/main.py").read_text(encoding="utf-8")
    require(
        '"phase": "1G"' in main_source or '"phase": "1H"' in main_source,
        "foundation phase is earlier than 1G",
    )
    require(
        '"secure_source_ingestion_enabled": True' in main_source,
        "source ingestion is not enabled",
    )
    config_source = (ROOT / "apps/api/app/core/config.py").read_text(encoding="utf-8")
    require(
        "sandbox_execution_enabled: bool = False" in config_source,
        "sandbox execution is not disabled by default",
    )

    archive_source = (
        ROOT / "apps/api/app/core/source_archive.py"
    ).read_text(encoding="utf-8")
    for marker in [
        "SOURCE_ARCHIVE_PATH_INVALID",
        "SOURCE_ARCHIVE_SPECIAL_FILE",
        "SOURCE_ARCHIVE_NESTED_ARCHIVE",
        "SOURCE_ARCHIVE_COMPRESSION_RATIO",
        "SOURCE_SCHEMA_MISSING",
    ]:
        require(marker in archive_source, "missing archive control: " + marker)

    service_source = (
        ROOT / "apps/api/app/services/storage_delivery.py"
    ).read_text(encoding="utf-8").casefold()
    for prohibited in [
        "subprocess",
        "docker.sock",
        "docker run",
        "kubectl",
        "buildkit",
        "eval(",
        "exec(",
    ]:
        require(prohibited not in service_source, "prohibited primitive: " + prohibited)

    internal_routes = (
        ROOT / "apps/api/app/api/routes/internal_execution.py"
    ).read_text(encoding="utf-8")
    require("include_in_schema=False" in internal_routes, "internal API is public")
    require("source-download" in internal_routes, "worker source grant is missing")

    migration_source = migration.read_text(encoding="utf-8")
    for marker in [
        "storage_objects_tenant",
        "storage_objects_worker",
        "storage_grants_tenant",
        "storage_grants_worker",
        "rdc_storage_object_org",
        "Nullable rollout",
    ]:
        require(marker in migration_source, "missing migration control: " + marker)

    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    require("verify-phase1g.py" in workflow, "CI does not run Phase 1G verifier")

    print("RDC_PHASE1G_VERIFICATION_PASSED")


if __name__ == "__main__":
    main()
