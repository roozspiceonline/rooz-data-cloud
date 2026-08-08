from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from app.core.errors import ApiError
from app.core.pagination import (
    decode_queue_request_cursor,
    decode_queue_transition_cursor,
    decode_request_queue_list_cursor,
    encode_queue_request_cursor,
    encode_queue_transition_cursor,
    encode_request_queue_list_cursor,
)

POSITION_TIME = datetime(2026, 8, 9, 6, 0, tzinfo=UTC)


def _tamper(cursor: str) -> str:
    index = len(cursor) // 2
    replacement = "A" if cursor[index] != "A" else "B"
    return cursor[:index] + replacement + cursor[index + 1 :]


def _assert_invalid(operation: Callable[[], object]) -> None:
    with pytest.raises(ApiError) as exc_info:
        operation()
    assert exc_info.value.code == "INVALID_CURSOR"


def test_request_queue_list_cursor_is_signed_and_project_bound() -> None:
    project_id, queue_id = uuid4(), uuid4()
    cursor = encode_request_queue_list_cursor(
        project_id=project_id,
        created_at=POSITION_TIME,
        resource_id=queue_id,
    )
    position = decode_request_queue_list_cursor(cursor, project_id=project_id)
    assert position is not None
    assert position.created_at == POSITION_TIME
    assert position.resource_id == queue_id

    _assert_invalid(
        lambda: decode_request_queue_list_cursor(
            _tamper(cursor), project_id=project_id
        )
    )
    _assert_invalid(lambda: decode_request_queue_list_cursor(cursor, project_id=uuid4()))
    _assert_invalid(lambda: decode_request_queue_list_cursor(cursor + "=", project_id=project_id))


def test_queue_transition_cursor_is_queue_and_request_filter_bound() -> None:
    queue_id, request_id, transition_id = uuid4(), uuid4(), uuid4()
    cursor = encode_queue_transition_cursor(
        queue_id=queue_id,
        request_id=request_id,
        created_at=POSITION_TIME,
        resource_id=transition_id,
    )
    position = decode_queue_transition_cursor(
        cursor,
        queue_id=queue_id,
        request_id=request_id,
    )
    assert position is not None
    assert position.resource_id == transition_id

    _assert_invalid(
        lambda: decode_queue_transition_cursor(
            _tamper(cursor), queue_id=queue_id, request_id=request_id
        )
    )
    _assert_invalid(
        lambda: decode_queue_transition_cursor(
            cursor, queue_id=uuid4(), request_id=request_id
        )
    )
    _assert_invalid(
        lambda: decode_queue_transition_cursor(
            cursor, queue_id=queue_id, request_id=uuid4()
        )
    )
    _assert_invalid(
        lambda: decode_queue_transition_cursor(
            cursor, queue_id=queue_id, request_id=None
        )
    )


def test_queue_request_cursor_rejects_tampering_and_filter_replay() -> None:
    queue_id, request_id = uuid4(), uuid4()
    cursor = encode_queue_request_cursor(
        queue_id=queue_id,
        status="PENDING",
        created_at=POSITION_TIME,
        resource_id=request_id,
    )
    position = decode_queue_request_cursor(
        cursor,
        queue_id=queue_id,
        status="PENDING",
    )
    assert position is not None
    assert position.resource_id == request_id

    _assert_invalid(
        lambda: decode_queue_request_cursor(
            _tamper(cursor), queue_id=queue_id, status="PENDING"
        )
    )
    _assert_invalid(lambda: decode_queue_request_cursor(cursor, queue_id=uuid4(), status="PENDING"))
    _assert_invalid(lambda: decode_queue_request_cursor(cursor, queue_id=queue_id, status="FAILED"))
    _assert_invalid(lambda: decode_queue_request_cursor(cursor, queue_id=queue_id, status=None))


def test_queue_cursor_kinds_cannot_cross_collection_boundaries() -> None:
    project_id, queue_id = uuid4(), uuid4()
    list_cursor = encode_request_queue_list_cursor(
        project_id=project_id,
        created_at=POSITION_TIME,
        resource_id=queue_id,
    )
    _assert_invalid(
        lambda: decode_queue_transition_cursor(
            list_cursor,
            queue_id=queue_id,
            request_id=None,
        )
    )


def test_queue_collection_routes_are_bounded_and_cursor_paginated() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    queue_parameters = {
        item["name"]
        for item in paths["/api/v1/projects/{project_id}/request-queues"]["get"][
            "parameters"
        ]
    }
    transition_parameters = {
        item["name"]
        for item in paths["/api/v1/request-queues/{queue_id}/transitions"]["get"][
            "parameters"
        ]
    }
    assert {"project_id", "cursor", "limit"} <= queue_parameters
    assert {"queue_id", "cursor", "limit", "request_id"} <= transition_parameters

    source = Path("app/api/routes/request_queues.py").read_text(encoding="utf-8")
    for marker in (
        "decode_request_queue_list_cursor",
        "encode_request_queue_list_cursor",
        "decode_queue_transition_cursor",
        "encode_queue_transition_cursor",
        '"next_cursor": next_cursor',
        '"has_more": next_cursor is not None',
    ):
        assert marker in source
