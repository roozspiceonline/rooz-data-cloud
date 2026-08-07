import io
import json
import stat
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.agent_schemas import CreateAgentVersionRequest
from app.core.permissions import role_has_permission, validate_scopes
from app.core.source_archive import SourceArchiveError, inspect_source_archive
from app.storage_schemas import CreateSourceUploadRequest


def manifest() -> dict[str, object]:
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
        "secrets": [],
        "extensions": {},
    }


def archive_bytes(
    *,
    extra: dict[str, bytes] | None = None,
    special: tuple[str, int] | None = None,
) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("agent.json", json.dumps(manifest()))
        archive.writestr("schemas/input.json", '{"type":"object"}')
        archive.writestr("schemas/output.json", '{"type":"object"}')
        for name, content in (extra or {}).items():
            archive.writestr(name, content)
        if special is not None:
            name, mode = special
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = mode << 16
            archive.writestr(info, b"target")
    return output.getvalue()


def inspect(content: bytes):
    return inspect_source_archive(
        content,
        expected_agent_slug="phase-one-agent",
        max_archive_bytes=2_000_000,
        max_expanded_bytes=8_000_000,
        max_files=100,
        max_single_file_bytes=2_000_000,
        max_compression_ratio=100.0,
    )


def test_phase1g_source_archive_passes_manifest_and_schema_contract() -> None:
    result = inspect(archive_bytes(extra={"main.py": b"print('safe')"}))
    assert result.manifest["name"] == "phase-one-agent"
    assert result.file_count == 4
    assert len(result.manifest_digest) == 64
    assert "schemas/input.json" in result.paths


def test_phase1g_source_archive_rejects_traversal_links_and_nested_archives() -> None:
    with pytest.raises(SourceArchiveError) as traversal:
        inspect(archive_bytes(extra={"../escape.py": b"bad"}))
    assert traversal.value.code == "SOURCE_ARCHIVE_PATH_INVALID"

    with pytest.raises(SourceArchiveError) as symlink:
        inspect(
            archive_bytes(
                special=("link", stat.S_IFLNK | 0o777),
            )
        )
    assert symlink.value.code == "SOURCE_ARCHIVE_SPECIAL_FILE"

    with pytest.raises(SourceArchiveError) as nested:
        inspect(archive_bytes(extra={"payload.zip": b"not another archive"}))
    assert nested.value.code == "SOURCE_ARCHIVE_NESTED_ARCHIVE"


def test_phase1g_source_archive_enforces_expansion_and_schema_presence() -> None:
    content = archive_bytes(extra={"large.txt": b"a" * 200_000})
    with pytest.raises(SourceArchiveError) as expanded:
        inspect_source_archive(
            content,
            expected_agent_slug="phase-one-agent",
            max_archive_bytes=2_000_000,
            max_expanded_bytes=100_000,
            max_files=100,
            max_single_file_bytes=2_000_000,
            max_compression_ratio=1000.0,
        )
    assert expanded.value.code == "SOURCE_ARCHIVE_EXPANDED_LIMIT"

    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("agent.json", json.dumps(manifest()))
        archive.writestr("schemas/input.json", '{}')
    with pytest.raises(SourceArchiveError) as missing:
        inspect(output.getvalue())
    assert missing.value.code == "SOURCE_SCHEMA_MISSING"


def test_phase1g_upload_and_version_schemas_are_strict() -> None:
    upload = CreateSourceUploadRequest.model_validate(
        {
            "file_name": "agent-source.zip",
            "media_type": "application/zip",
            "size_bytes": 1024,
            "sha256_digest": "a" * 64,
        }
    )
    assert upload.file_name == "agent-source.zip"

    with pytest.raises(ValidationError):
        CreateSourceUploadRequest.model_validate(
            {
                "file_name": "../agent-source.zip",
                "size_bytes": 1024,
                "sha256_digest": "a" * 64,
            }
        )

    version = CreateAgentVersionRequest.model_validate(
        {
            "source_object_id": str(uuid4()),
            "manifest": manifest(),
            "release_notes": None,
        }
    )
    assert version.source_object_id


def test_phase1g_permissions_cover_storage_without_upload_for_read_only_roles() -> None:
    assert role_has_permission("developer", "storage.upload")
    assert role_has_permission("viewer", "storage.read")
    assert role_has_permission("viewer", "storage.download")
    assert not role_has_permission("viewer", "storage.upload")
    assert validate_scopes(["storage.read", "storage.download"]) == [
        "storage.download",
        "storage.read",
    ]


def test_phase1g_routes_expose_public_metadata_and_hide_internal_delivery() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/api/v1/agents/{agent_id}/source-uploads" in paths
    assert "/api/v1/storage-objects/{storage_object_id}/complete" in paths
    assert "/api/v1/projects/{project_id}/storage-objects" in paths
    assert "/internal/v1/leases/{lease_id}/source-download" not in paths
    assert (
        str(app.url_path_for("issue_source_download_route", lease_id=uuid4()))
        .startswith("/internal/v1/leases/")
    )


def test_phase1g_migration_contains_storage_rls_guards_and_safe_rollout() -> None:
    migration = Path(
        "migrations/versions/20260806_0007_storage_delivery.py"
    ).read_text(encoding="utf-8")
    for marker in [
        "storage_objects",
        "storage_grants",
        "rdc_storage_object_org",
        "storage_objects_tenant",
        "storage_objects_worker",
        "storage_grants_tenant",
        "storage_grants_worker",
        "storage_objects_tenancy_guard",
        "storage_grants_tenancy_guard",
        "source_object_id",
        "Nullable rollout",
    ]:
        assert marker in migration


def test_phase1g_storage_service_contains_no_execution_primitive() -> None:
    source = Path("app/services/storage_delivery.py").read_text(encoding="utf-8")
    lowered = source.casefold()
    for prohibited in [
        "subprocess",
        "os.system",
        "docker.sock",
        "buildkit",
        "kubernetes",
        "eval(",
        "exec(",
    ]:
        assert prohibited not in lowered
