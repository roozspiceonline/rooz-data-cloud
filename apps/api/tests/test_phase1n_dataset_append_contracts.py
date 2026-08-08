import importlib.util
import math
import sys
from pathlib import Path
from uuid import uuid4

import pytest
from pydantic import ValidationError

from app.core.permissions import role_has_permission, validate_scopes
from app.dataset_append_protocol import validate_dataset_append
from app.dataset_schemas import DatasetAppendRequest

ROOT = Path(__file__).resolve().parents[3]


def load_worker_protocol():
    path = ROOT / "workers/sandbox-runtime/dataset_protocol.py"
    spec = importlib.util.spec_from_file_location(
        "rdc_phase1n_worker_dataset_protocol_test",
        path,
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_phase1n_increment3_api_and_worker_protocol_digests_match() -> None:
    payload = {
        "schema_version": "rdc.dataset-append/v1",
        "idempotency_key": "run-1:batch-1",
        "items": [
            {
                "url": "https://example.com/",
                "nested": {"b": 2, "a": 1},
            }
        ],
    }
    api_result = validate_dataset_append(payload)
    worker = load_worker_protocol()
    worker_result = worker.validate_dataset_append(payload)
    assert api_result.request_digest == worker_result.request_digest


def test_phase1n_increment3_append_schema_is_strict_and_finite() -> None:
    request = DatasetAppendRequest.model_validate(
        {
            "schema_version": "rdc.dataset-append/v1",
            "idempotency_key": "batch-1",
            "items": [{"value": 1}],
        }
    )
    assert request.idempotency_key == "batch-1"

    with pytest.raises(ValidationError):
        DatasetAppendRequest.model_validate(
            {
                "schema_version": "rdc.dataset-append/v1",
                "idempotency_key": "batch-1",
                "items": [{"value": 1}],
                "organization_id": str(uuid4()),
            }
        )

    with pytest.raises(ValidationError):
        DatasetAppendRequest.model_validate(
            {
                "schema_version": "rdc.dataset-append/v1",
                "idempotency_key": "batch-1",
                "items": [{"value": math.nan}],
            }
        )


def test_phase1n_increment3_permissions_limit_dataset_write() -> None:
    assert role_has_permission("developer", "dataset.write")
    assert not role_has_permission("analyst", "dataset.write")
    assert not role_has_permission("operator", "dataset.write")
    assert not role_has_permission("viewer", "dataset.write")
    assert validate_scopes(["dataset.read", "dataset.write"]) == [
        "dataset.read",
        "dataset.write",
    ]


def test_phase1n_increment3_route_exposes_control_plane_append() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/api/v1/datasets/{dataset_id}/items" in paths
    operation = paths["/api/v1/datasets/{dataset_id}/items"]["post"]
    assert "requestBody" in operation


def test_phase1n_increment3_migration_binds_receipts_items_and_quotas() -> None:
    migration = Path(
        "migrations/versions/20260808_0010_dataset_append_receipts.py"
    ).read_text(encoding="utf-8")
    for marker in [
        "dataset_append_receipts",
        "uq_dataset_append_receipts_dataset_key",
        "request_digest",
        "append_receipt_id",
        "ck_datasets_item_quota",
        "ck_datasets_byte_quota",
        "ck_datasets_sequence_counter",
        "dataset_append_receipts_tenant",
        "dataset_items_immutable_guard",
        "dataset_append_receipts_immutable_guard",
        "Dataset item receipt or tenancy mismatch",
    ]:
        assert marker in migration

    assert "dataset_append_receipts_worker" not in migration
    assert "dataset_items_worker" not in migration


def test_phase1n_increment3_service_is_transactional_and_replay_safe() -> None:
    source = Path("app/services/datasets.py").read_text(encoding="utf-8")
    for marker in [
        ".with_for_update()",
        "DatasetAppendReceipt.idempotency_key",
        "DATASET_IDEMPOTENCY_CONFLICT",
        "MAX_DATASET_ITEMS = 100_000",
        "MAX_DATASET_BYTES = 268_435_456",
        "locked.next_sequence += validation.item_count",
        "locked.item_count += validation.item_count",
        "locked.total_bytes += item_bytes",
        'action="dataset.items_appended"',
        "replayed=True",
    ]:
        assert marker in source

    lowered = source.casefold()
    for forbidden in [
        "subprocess",
        "os.system",
        "docker.sock",
        "psycopg",
        "asyncpg",
        "socket.",
    ]:
        assert forbidden not in lowered


def test_phase1n_increment3_worker_write_path_remains_disabled() -> None:
    worker = (
        ROOT / "workers/sandbox-runtime/worker.py"
    ).read_text(encoding="utf-8")
    for forbidden in [
        "append_dataset_items",
        "dataset_write_enabled",
        "dataset_append_receipt",
    ]:
        assert forbidden not in worker
