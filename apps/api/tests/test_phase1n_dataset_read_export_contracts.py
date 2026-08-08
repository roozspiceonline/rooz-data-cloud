from uuid import uuid4

import pytest

from app.core.errors import ApiError
from app.core.pagination import (
    decode_dataset_item_cursor,
    encode_dataset_item_cursor,
)
from app.core.permissions import role_has_permission, validate_scopes


def test_phase1n_dataset_item_cursor_is_signed_and_dataset_bound() -> None:
    dataset_id = uuid4()
    cursor = encode_dataset_item_cursor(
        dataset_id=dataset_id,
        sequence=17,
    )
    position = decode_dataset_item_cursor(
        cursor,
        dataset_id=dataset_id,
    )
    assert position is not None
    assert position.sequence == 17

    with pytest.raises(ApiError) as exc_info:
        decode_dataset_item_cursor(
            cursor,
            dataset_id=uuid4(),
        )
    assert exc_info.value.code == "INVALID_CURSOR"


def test_phase1n_dataset_export_has_explicit_scope() -> None:
    assert validate_scopes(["dataset.export"]) == ["dataset.export"]
    for role in [
        "owner",
        "administrator",
        "developer",
        "analyst",
        "operator",
        "viewer",
    ]:
        assert role_has_permission(role, "dataset.export")


def test_phase1n_dataset_read_and_export_routes_are_bounded() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    item_path = paths["/api/v1/datasets/{dataset_id}/items"]
    assert "get" in item_path
    assert "post" in item_path
    for forbidden in ["put", "patch", "delete"]:
        assert forbidden not in item_path

    export_path = paths["/api/v1/datasets/{dataset_id}/export"]
    assert "post" in export_path

    route_source = (
        __import__("pathlib").Path("app/api/routes/datasets.py")
        .read_text(encoding="utf-8")
    )
    assert 'Depends(require_dataset_permission("dataset.export"))' in route_source
    assert "Depends(require_csrf)" in route_source
    assert 'media_type="application/x-ndjson"' in route_source


def test_phase1n_dataset_service_enforces_export_bounds_and_audit() -> None:
    source = (
        __import__("pathlib").Path("app/services/datasets.py")
        .read_text(encoding="utf-8")
    )
    for marker in [
        "MAX_DATASET_EXPORT_ITEMS = 10_000",
        "MAX_DATASET_EXPORT_BYTES = 16_777_216",
        ".limit(MAX_DATASET_EXPORT_ITEMS + 1)",
        "DATASET_EXPORT_ITEM_LIMIT_EXCEEDED",
        "DATASET_EXPORT_BYTE_LIMIT_EXCEEDED",
        "DATASET_EXPORT_SEQUENCE_GAP",
        "canonical_json_bytes(item.item_json)",
        'action="dataset.exported"',
        '"agent_version_id": str(dataset.agent_version_id)',
    ]:
        assert marker in source


def test_phase1n_dataset_status_remains_explicit_and_fail_closed() -> None:
    source = __import__("pathlib").Path("app/main.py").read_text(encoding="utf-8")
    for marker in [
        '"dataset_item_read_enabled": True',
        '"dataset_bounded_export_enabled": True',
        '"dataset_public_export_enabled": False',
        '"dataset_worker_append_canary_enabled": _dataset_worker_canary_enabled()',
        '"untrusted_agent_execution_enabled": False',
    ]:
        assert marker in source
