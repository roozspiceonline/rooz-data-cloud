from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.permissions import role_has_permission, validate_scopes
from app.dataset_schemas import CreateDatasetRequest


def test_phase1n_increment2_dataset_schema_is_strict() -> None:
    payload = CreateDatasetRequest.model_validate({"name": "default"})
    assert payload.name == "default"

    with pytest.raises(ValidationError):
        CreateDatasetRequest.model_validate(
            {
                "name": "default",
                "organization_id": str(uuid4()),
            }
        )

    with pytest.raises(ValidationError):
        CreateDatasetRequest.model_validate({"name": "bad name"})


def test_phase1n_increment2_permissions_are_tenant_role_scoped() -> None:
    assert role_has_permission("developer", "dataset.create")
    assert role_has_permission("developer", "dataset.read")
    assert role_has_permission("analyst", "dataset.read")
    assert role_has_permission("operator", "dataset.read")
    assert role_has_permission("viewer", "dataset.read")
    assert not role_has_permission("viewer", "dataset.create")
    assert validate_scopes(["dataset.create", "dataset.read"]) == [
        "dataset.create",
        "dataset.read",
    ]


def test_phase1n_increment2_metadata_routes_remain_available() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/api/v1/runs/{run_id}/datasets" in paths
    assert "/api/v1/projects/{project_id}/datasets" in paths
    assert "/api/v1/datasets/{dataset_id}" in paths


def test_phase1n_increment2_migration_has_rls_and_lineage_guards() -> None:
    migration = Path(
        "migrations/versions/20260808_0009_datasets.py"
    ).read_text(encoding="utf-8")

    for marker in [
        "datasets",
        "dataset_items",
        "uq_datasets_run_name",
        "uq_dataset_items_dataset_sequence",
        "enforce_dataset_tenancy",
        "enforce_dataset_item_tenancy",
        "datasets_tenancy_guard",
        "dataset_items_tenancy_guard",
        "rdc_dataset_org",
        "datasets_tenant",
        "dataset_items_tenant",
        "ENABLE ROW LEVEL SECURITY",
    ]:
        assert marker in migration

    assert "datasets_worker" not in migration
    assert "dataset_items_worker" not in migration


def test_phase1n_dataset_service_has_no_execution_or_direct_db_surface() -> None:
    source = Path("app/services/datasets.py").read_text(encoding="utf-8")
    lowered = source.casefold()

    for prohibited in [
        "subprocess",
        "os.system",
        "docker.sock",
        "buildkit",
        "kubernetes",
        "socket.",
        "psycopg",
        "asyncpg",
    ]:
        assert prohibited not in lowered


def test_phase1n_increment2_worker_dataset_write_remains_disabled() -> None:
    worker = Path(
        "../../workers/sandbox-runtime/worker.py"
    ).read_text(encoding="utf-8")

    for forbidden in [
        "append_dataset_items",
        "create_dataset_item",
        "dataset_write_enabled",
    ]:
        assert forbidden not in worker
