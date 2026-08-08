from pathlib import Path

from app.core.permissions import role_has_permission, validate_scopes
from app.main import app

ROOT = Path(__file__).resolve().parents[3]


def test_phase1o_increment2_migration_is_chained_and_tenant_scoped() -> None:
    source = (
        ROOT
        / "apps/api/migrations/versions/"
        "20260808_0012_key_value_stores.py"
    ).read_text(encoding="utf-8")
    for marker in [
        'revision: str = "20260808_0012"',
        'down_revision: str | None = "20260808_0011"',
        "uq_key_value_stores_project_name",
        "uq_key_value_stores_run_name",
        "ck_key_value_stores_scope_lineage",
        "key_value_stores_tenancy_guard",
        "security.rdc_key_value_store_org",
        "ENABLE ROW LEVEL SECURITY",
        "CREATE POLICY key_value_stores_tenant",
        "KV store identity fields are immutable",
    ]:
        assert marker in source
    for forbidden in [
        "key_value_records",
        "key_value_record_versions",
        "kv_mutation_receipts",
        "execution_worker",
        "FOR DELETE",
    ]:
        assert forbidden not in source


def test_phase1o_increment2_metadata_routes_exist_without_record_mutation() -> None:
    paths = app.openapi()["paths"]
    assert "post" in paths["/api/v1/projects/{project_id}/key-value-stores"]
    assert "get" in paths["/api/v1/projects/{project_id}/key-value-stores"]
    assert "post" in paths["/api/v1/runs/{run_id}/key-value-stores"]
    assert "get" in paths["/api/v1/key-value-stores/{store_id}"]
    for path in paths:
        assert "/records" not in path


def test_phase1o_increment2_permissions_are_metadata_only() -> None:
    assert validate_scopes(["kv.create", "kv.read"]) == ["kv.create", "kv.read"]
    assert role_has_permission("developer", "kv.create")
    assert role_has_permission("developer", "kv.read")
    for role in ["analyst", "operator", "viewer"]:
        assert role_has_permission(role, "kv.read")
        assert not role_has_permission(role, "kv.create")
    for forbidden in ["kv.write", "kv.delete", "kv.export"]:
        try:
            validate_scopes([forbidden])
        except ValueError:
            pass
        else:
            raise AssertionError(f"unexpected KV mutation scope: {forbidden}")


def test_phase1o_increment2_service_derives_ownership_server_side() -> None:
    source = (
        ROOT / "apps/api/app/services/key_value_stores.py"
    ).read_text(encoding="utf-8")
    for marker in [
        "organization_id=project.organization_id",
        "project_id=project.id",
        'scope="PROJECT"',
        "organization_id=run.organization_id",
        "project_id=run.project_id",
        'scope="RUN"',
        "run_id=run.id",
        "agent_id=run.agent_id",
        "agent_version_id=run.agent_version_id",
        'action="kv_store.created"',
    ]:
        assert marker in source
    for forbidden in [
        "organization_id=payload.",
        "project_id=payload.",
        "run_id=payload.",
        "agent_id=payload.",
        "agent_version_id=payload.",
    ]:
        assert forbidden not in source


def test_phase1o_increment2_record_storage_remains_disabled() -> None:
    protocol = (
        ROOT / "workers/sandbox-runtime/kv_protocol.py"
    ).read_text(encoding="utf-8")
    assert "persisted: bool = False" in protocol
    assert "worker_write_enabled: bool = False" in protocol
    assert "object_storage_write_enabled: bool = False" in protocol

    routes = (
        ROOT / "apps/api/app/api/routes/key_value_stores.py"
    ).read_text(encoding="utf-8").casefold()
    for forbidden in ["/records", "validate_kv_mutation", "storage_object", "s3"]:
        assert forbidden not in routes
