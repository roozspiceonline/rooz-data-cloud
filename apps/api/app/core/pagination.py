# ruff: noqa: E501
import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from .config import get_settings
from .errors import ApiError

settings = get_settings()


@dataclass(frozen=True)
class DatasetItemCursorPosition:
    sequence: int


@dataclass(frozen=True)
class CursorPosition:
    created_at: datetime
    resource_id: UUID


@dataclass(frozen=True)
class KeyValueRecordCursorPosition:
    key: str


@dataclass(frozen=True)
class QueueRequestCursorPosition:
    created_at: datetime
    resource_id: UUID


def normalize_limit(limit: int) -> int:
    if not 1 <= limit <= 200:
        raise ApiError(
            status_code=422,
            code="VALIDATION_FAILED",
            message="The page limit must be between 1 and 200.",
        )
    return limit


def encode_cursor(*, created_at: datetime, resource_id: UUID) -> str:
    payload = json.dumps(
        {
            "created_at": created_at.isoformat(),
            "id": str(resource_id),
            "v": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    signature = hmac.new(
        settings.cursor_signing_key.encode(),
        payload,
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(payload + signature).decode().rstrip("=")


def decode_cursor(value: str | None) -> CursorPosition | None:
    if value is None:
        return None
    if not value or len(value) > 512:
        raise _invalid_cursor()
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode())
        canonical = base64.urlsafe_b64encode(decoded).decode().rstrip("=")
        if not hmac.compare_digest(canonical, value):
            raise ValueError("cursor encoding is not canonical")
        if len(decoded) <= hashlib.sha256().digest_size:
            raise ValueError("cursor is too short")
        payload = decoded[: -hashlib.sha256().digest_size]
        supplied = decoded[-hashlib.sha256().digest_size :]
        expected = hmac.new(
            settings.cursor_signing_key.encode(),
            payload,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(supplied, expected):
            raise ValueError("cursor signature mismatch")
        data = json.loads(payload.decode())
        if data.get("v") != 1:
            raise ValueError("unsupported cursor version")
        return CursorPosition(
            created_at=datetime.fromisoformat(str(data["created_at"])),
            resource_id=UUID(str(data["id"])),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _invalid_cursor() from exc


def encode_dataset_item_cursor(
    *,
    dataset_id: UUID,
    sequence: int,
) -> str:
    if sequence < 1:
        raise ValueError("Dataset item cursor sequence must be positive")
    payload = json.dumps(
        {
            "dataset_id": str(dataset_id),
            "kind": "dataset-items",
            "sequence": sequence,
            "v": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    signature = hmac.new(
        settings.cursor_signing_key.encode(),
        payload,
        hashlib.sha256,
    ).digest()
    return base64.urlsafe_b64encode(payload + signature).decode().rstrip("=")


def decode_dataset_item_cursor(
    value: str | None,
    *,
    dataset_id: UUID,
) -> DatasetItemCursorPosition | None:
    if value is None:
        return None
    if not value or len(value) > 512:
        raise _invalid_cursor()
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode())
        canonical = base64.urlsafe_b64encode(decoded).decode().rstrip("=")
        if not hmac.compare_digest(canonical, value):
            raise ValueError("cursor encoding is not canonical")
        if len(decoded) <= hashlib.sha256().digest_size:
            raise ValueError("cursor is too short")
        payload = decoded[: -hashlib.sha256().digest_size]
        supplied = decoded[-hashlib.sha256().digest_size :]
        expected = hmac.new(
            settings.cursor_signing_key.encode(),
            payload,
            hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(supplied, expected):
            raise ValueError("cursor signature mismatch")
        data = json.loads(payload.decode())
        raw_sequence = data["sequence"]
        if (
            data.get("v") != 1
            or data.get("kind") != "dataset-items"
            or data.get("dataset_id") != str(dataset_id)
            or not isinstance(raw_sequence, int)
            or isinstance(raw_sequence, bool)
            or raw_sequence < 1
        ):
            raise ValueError("Dataset item cursor binding is invalid")
        return DatasetItemCursorPosition(sequence=raw_sequence)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _invalid_cursor() from exc


def encode_key_value_record_cursor(*, store_id: UUID, key: str) -> str:
    payload = json.dumps(
        {
            "kind": "key-value-records",
            "key": key,
            "store_id": str(store_id),
            "v": 1,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    signature = hmac.new(settings.cursor_signing_key.encode(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + signature).decode().rstrip("=")


def decode_key_value_record_cursor(
    value: str | None, *, store_id: UUID
) -> KeyValueRecordCursorPosition | None:
    if value is None:
        return None
    if not value or len(value) > 512:
        raise _invalid_cursor()
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode())
        canonical = base64.urlsafe_b64encode(decoded).decode().rstrip("=")
        if not hmac.compare_digest(canonical, value):
            raise ValueError("cursor encoding is not canonical")
        if len(decoded) <= hashlib.sha256().digest_size:
            raise ValueError("cursor is too short")
        payload = decoded[: -hashlib.sha256().digest_size]
        supplied = decoded[-hashlib.sha256().digest_size :]
        expected = hmac.new(settings.cursor_signing_key.encode(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(supplied, expected):
            raise ValueError("cursor signature mismatch")
        data = json.loads(payload.decode())
        key = data["key"]
        if (
            data.get("v") != 1
            or data.get("kind") != "key-value-records"
            or data.get("store_id") != str(store_id)
            or not isinstance(key, str)
            or not key
        ):
            raise ValueError("cursor binding is invalid")
        return KeyValueRecordCursorPosition(key=key)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _invalid_cursor() from exc


def encode_queue_request_cursor(*, queue_id: UUID, status: str | None, created_at: datetime, resource_id: UUID) -> str:
    payload = json.dumps({"created_at": created_at.isoformat(), "id": str(resource_id), "kind": "queue-requests", "queue_id": str(queue_id), "status": status, "v": 1}, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(settings.cursor_signing_key.encode(), payload, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(payload + signature).decode().rstrip("=")


def decode_queue_request_cursor(value: str | None, *, queue_id: UUID, status: str | None) -> QueueRequestCursorPosition | None:
    if value is None:
        return None
    if not value or len(value) > 512:
        raise _invalid_cursor()
    try:
        decoded = base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode())
        payload, supplied = decoded[:-32], decoded[-32:]
        expected = hmac.new(settings.cursor_signing_key.encode(), payload, hashlib.sha256).digest()
        data = json.loads(payload.decode())
        if not hmac.compare_digest(supplied, expected) or data.get("v") != 1 or data.get("kind") != "queue-requests" or data.get("queue_id") != str(queue_id) or data.get("status") != status:
            raise ValueError("cursor binding is invalid")
        return QueueRequestCursorPosition(created_at=datetime.fromisoformat(str(data["created_at"])), resource_id=UUID(str(data["id"])))
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise _invalid_cursor() from exc


def _invalid_cursor() -> ApiError:
    return ApiError(
        status_code=400,
        code="INVALID_CURSOR",
        message="The pagination cursor is invalid or expired.",
    )
