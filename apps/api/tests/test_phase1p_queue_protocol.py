import pytest

from app.request_queue_protocol import (
    RequestQueueProtocolError,
    validate_queue_enqueue,
)


def payload() -> dict[str, object]:
    return {
        "schema_version": "rdc.queue-enqueue/v1",
        "idempotency_key": "enqueue-1",
        "url": "https://example.com/path?a=1#fragment",
        "unique_key": None,
        "user_data": {"b": 2, "a": 1},
    }


def test_phase1p_enqueue_protocol_is_canonical_and_bounded() -> None:
    left = validate_queue_enqueue(payload())
    right_value = payload()
    right_value["user_data"] = {"a": 1, "b": 2}
    right = validate_queue_enqueue(right_value)
    assert left.request_digest == right.request_digest
    assert left.identity_digest == right.identity_digest
    assert left.request["url"] == "https://example.com/path?a=1"


@pytest.mark.parametrize("field,value", [
    ("url", "http://example.com/"),
    ("url", "https://127.0.0.1/"),
    ("url", "https://user:pass@example.com/"),
    ("idempotency_key", "bad key"),
    ("unique_key", "../unsafe"),
])
def test_phase1p_enqueue_protocol_rejects_unsafe_input(
    field: str, value: object
) -> None:
    value_payload = payload()
    value_payload[field] = value
    with pytest.raises(RequestQueueProtocolError):
        validate_queue_enqueue(value_payload)
