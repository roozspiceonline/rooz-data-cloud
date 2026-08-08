from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import NoReturn

SCHEMA_VERSION = "rdc.kv-write/v1"
MAX_KEY_LENGTH = 256
MAX_VALUE_BYTES = 1_048_576
MAX_ENVELOPE_BYTES = 1_572_864
MAX_DEPTH = 32
MAX_EXPECTED_VERSION = 9_223_372_036_854_775_807

_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_LOGICAL_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_CONTENT_ENCODINGS = {
    "application/json": "json",
    "text/plain; charset=utf-8": "utf8",
    "application/octet-stream": "base64",
}


class KVProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedKVMutation:
    request: dict[str, object]
    schema_version: str
    idempotency_key: str
    request_digest: str
    operation: str
    key: str
    expected_version: int | None
    content_type: str | None
    encoding: str | None
    value_sha256: str | None
    decoded_bytes: int
    value_bytes: bytes | None


def _fail(message: str) -> NoReturn:
    raise KVProtocolError(message)


def _validate_json_value(value: object, *, depth: int) -> None:
    if depth > MAX_DEPTH:
        _fail("KV JSON value exceeds the maximum nesting depth.")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail("KV JSON values cannot contain NaN or Infinity.")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("KV JSON object keys must be strings.")
            _validate_json_value(item, depth=depth + 1)
        return
    _fail("KV JSON values must contain JSON-compatible values only.")


def canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise KVProtocolError(
            "KV mutation cannot be canonically JSON encoded."
        ) from exc


def _expected_version(value: object) -> int | None:
    if value is None:
        return None
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or value < 0
        or value > MAX_EXPECTED_VERSION
    ):
        _fail("KV expected_version is invalid.")
    return value


def _decoded_set_value(
    *,
    content_type: object,
    encoding: object,
    value: object,
) -> tuple[str, str, object, bytes]:
    if (
        not isinstance(content_type, str)
        or content_type not in _CONTENT_ENCODINGS
    ):
        _fail("KV content_type is unsupported.")

    expected_encoding = _CONTENT_ENCODINGS[content_type]
    if not isinstance(encoding, str) or encoding != expected_encoding:
        _fail("KV content_type and encoding do not match.")

    if encoding == "json":
        _validate_json_value(value, depth=0)
        value_bytes = canonical_json_bytes(value)
        normalized_value = value
    elif encoding == "utf8":
        if not isinstance(value, str):
            _fail("KV UTF-8 value must be a string.")
        value_bytes = value.encode("utf-8")
        normalized_value = value
    else:
        if not isinstance(value, str):
            _fail("KV base64 value must be a string.")
        try:
            raw = value.encode("ascii")
            value_bytes = base64.b64decode(raw, validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
            raise KVProtocolError(
                "KV binary value is not canonical base64."
            ) from exc
        canonical = base64.b64encode(value_bytes).decode("ascii")
        if value != canonical:
            _fail("KV binary value is not canonical base64.")
        normalized_value = canonical

    if len(value_bytes) > MAX_VALUE_BYTES:
        _fail("KV value exceeds the maximum decoded size.")

    return content_type, encoding, normalized_value, value_bytes


def validate_kv_mutation(value: object) -> ValidatedKVMutation:
    if not isinstance(value, dict):
        _fail("KV mutation request must be an object.")

    operation = value.get("operation")
    if operation == "set":
        expected_fields = {
            "schema_version",
            "idempotency_key",
            "operation",
            "key",
            "expected_version",
            "content_type",
            "encoding",
            "value",
        }
    elif operation == "delete":
        expected_fields = {
            "schema_version",
            "idempotency_key",
            "operation",
            "key",
            "expected_version",
        }
    else:
        _fail("KV operation is unsupported.")

    if set(value) != expected_fields:
        _fail("KV mutation request fields are invalid.")
    if value.get("schema_version") != SCHEMA_VERSION:
        _fail("KV mutation schema version is unsupported.")

    idempotency_key = value.get("idempotency_key")
    if (
        not isinstance(idempotency_key, str)
        or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
    ):
        _fail("KV mutation idempotency key is invalid.")

    key = value.get("key")
    if (
        not isinstance(key, str)
        or len(key) > MAX_KEY_LENGTH
        or _LOGICAL_KEY.fullmatch(key) is None
    ):
        _fail("KV logical key is invalid.")

    expected_version = _expected_version(value.get("expected_version"))

    if operation == "set":
        content_type, encoding, normalized_value, value_bytes = (
            _decoded_set_value(
                content_type=value.get("content_type"),
                encoding=value.get("encoding"),
                value=value.get("value"),
            )
        )
        normalized: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "idempotency_key": idempotency_key,
            "operation": operation,
            "key": key,
            "expected_version": expected_version,
            "content_type": content_type,
            "encoding": encoding,
            "value": normalized_value,
        }
        value_sha256 = hashlib.sha256(value_bytes).hexdigest()
        decoded_bytes = len(value_bytes)
    else:
        normalized = {
            "schema_version": SCHEMA_VERSION,
            "idempotency_key": idempotency_key,
            "operation": operation,
            "key": key,
            "expected_version": expected_version,
        }
        content_type = None
        encoding = None
        value_sha256 = None
        decoded_bytes = 0
        value_bytes = None

    encoded = canonical_json_bytes(normalized)
    if len(encoded) > MAX_ENVELOPE_BYTES:
        _fail("KV mutation envelope exceeds the maximum encoded size.")

    return ValidatedKVMutation(
        request=normalized,
        schema_version=SCHEMA_VERSION,
        idempotency_key=idempotency_key,
        request_digest=hashlib.sha256(encoded).hexdigest(),
        operation=operation,
        key=key,
        expected_version=expected_version,
        content_type=content_type,
        encoding=encoding,
        value_sha256=value_sha256,
        decoded_bytes=decoded_bytes,
        value_bytes=value_bytes,
    )
