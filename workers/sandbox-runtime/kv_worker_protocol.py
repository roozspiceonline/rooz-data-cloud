from __future__ import annotations

import base64
import binascii
import hashlib
import json
import math
import re
from typing import NoReturn

from kv_protocol import (
    KVProtocolError,
    MAX_ENVELOPE_BYTES,
    MAX_KEY_LENGTH,
    MAX_VALUE_BYTES,
    validate_kv_mutation,
)

READ_SCHEMA_VERSION = "rdc.kv-worker-read/v1"
READ_RESULT_SCHEMA_VERSION = "rdc.kv-worker-read-result/v1"
OUTPUT_SCHEMA_VERSION = "rdc.kv-worker-output/v1"
MAX_WORKER_READ_KEYS = 16
MAX_WORKER_READ_TOTAL_BYTES = 262_144
MAX_WORKER_MUTATIONS = 4

_LOGICAL_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class KVWorkerBoundaryError(ValueError):
    pass


def _fail(message: str) -> NoReturn:
    raise KVWorkerBoundaryError(message)


def _canonical_json_bytes(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            sort_keys=True,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise KVWorkerBoundaryError(
            "KV worker value cannot be canonically JSON encoded."
        ) from exc


def _validate_json_value(value: object, *, depth: int = 0) -> None:
    if depth > 32:
        _fail("KV worker JSON value exceeds the maximum nesting depth.")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail("KV worker JSON values cannot contain NaN or Infinity.")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("KV worker JSON object keys must be strings.")
            _validate_json_value(item, depth=depth + 1)
        return
    _fail("KV worker JSON values must be JSON-compatible.")


def validate_kv_read_request(value: object):
    if not isinstance(value, dict):
        _fail("KV read request must be an object.")
    if set(value) != {"schema_version", "keys"}:
        _fail("KV read request fields are invalid.")
    if value.get("schema_version") != READ_SCHEMA_VERSION:
        _fail("KV read schema version is unsupported.")

    raw_keys = value.get("keys")
    if (
        not isinstance(raw_keys, list)
        or not 1 <= len(raw_keys) <= MAX_WORKER_READ_KEYS
    ):
        _fail("KV read key count is invalid.")

    keys: list[str] = []
    for key in raw_keys:
        if (
            not isinstance(key, str)
            or len(key) > MAX_KEY_LENGTH
            or _LOGICAL_KEY.fullmatch(key) is None
        ):
            _fail("KV read logical key is invalid.")
        keys.append(key)
    if len(set(keys)) != len(keys):
        _fail("KV read logical keys must be unique.")

    normalized: dict[str, object] = {
        "schema_version": READ_SCHEMA_VERSION,
        "keys": keys,
    }
    encoded = _canonical_json_bytes(normalized)
    if len(encoded) > 4096:
        _fail("KV read request is too large.")

    return {
        "request": normalized,
        "request_digest": hashlib.sha256(encoded).hexdigest(),
        "keys": tuple(keys),
    }


def _read_value_bytes(
    *,
    content_type: object,
    encoding: object,
    value: object,
) -> tuple[object, bytes]:
    if content_type == "application/json" and encoding == "json":
        _validate_json_value(value)
        return value, _canonical_json_bytes(value)

    if (
        content_type == "text/plain; charset=utf-8"
        and encoding == "utf8"
    ):
        if not isinstance(value, str):
            _fail("KV UTF-8 read value must be a string.")
        return value, value.encode("utf-8")

    if (
        content_type == "application/octet-stream"
        and encoding == "base64"
    ):
        if not isinstance(value, str):
            _fail("KV binary read value must be canonical base64.")
        try:
            raw_ascii = value.encode("ascii")
            decoded = base64.b64decode(raw_ascii, validate=True)
        except (UnicodeEncodeError, binascii.Error, ValueError) as exc:
            raise KVWorkerBoundaryError(
                "KV binary read value is not canonical base64."
            ) from exc
        canonical = base64.b64encode(decoded).decode("ascii")
        if canonical != value:
            _fail("KV binary read value is not canonical base64.")
        return canonical, decoded

    _fail("KV read content type or encoding is unsupported.")


def validate_kv_read_result(
    value: object,
    *,
    expected_keys: tuple[str, ...],
) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail("KV read result must be an object.")
    if set(value) != {"schema_version", "store_name", "records"}:
        _fail("KV read result fields are invalid.")
    if value.get("schema_version") != READ_RESULT_SCHEMA_VERSION:
        _fail("KV read result schema version is unsupported.")
    if value.get("store_name") != "default":
        _fail("KV read result store is invalid.")

    records = value.get("records")
    if not isinstance(records, list) or len(records) != len(expected_keys):
        _fail("KV read result record count is invalid.")

    normalized_records: list[dict[str, object]] = []
    total_bytes = 0
    for index, expected_key in enumerate(expected_keys):
        record = records[index]
        if not isinstance(record, dict):
            _fail("KV read result record is invalid.")
        expected_fields = {
            "key",
            "found",
            "version",
            "content_type",
            "encoding",
            "value_sha256",
            "size_bytes",
            "value",
        }
        if set(record) != expected_fields or record.get("key") != expected_key:
            _fail("KV read result record fields are invalid.")

        found = record.get("found")
        if not isinstance(found, bool):
            _fail("KV read result found flag is invalid.")

        if not found:
            for field in (
                "version",
                "content_type",
                "encoding",
                "value_sha256",
                "size_bytes",
                "value",
            ):
                if record.get(field) is not None:
                    _fail("Missing KV record carried value metadata.")
            normalized_records.append(dict(record))
            continue

        version = record.get("version")
        digest = record.get("value_sha256")
        size_bytes = record.get("size_bytes")
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or version < 1
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or isinstance(size_bytes, bool)
            or not isinstance(size_bytes, int)
            or size_bytes < 0
            or size_bytes > MAX_VALUE_BYTES
        ):
            _fail("KV read result lineage is invalid.")

        normalized_value, raw = _read_value_bytes(
            content_type=record.get("content_type"),
            encoding=record.get("encoding"),
            value=record.get("value"),
        )
        if len(raw) != size_bytes:
            _fail("KV read result size lineage is invalid.")
        if hashlib.sha256(raw).hexdigest() != digest:
            _fail("KV read result digest lineage is invalid.")

        total_bytes += len(raw)
        if total_bytes > MAX_WORKER_READ_TOTAL_BYTES:
            _fail("KV read result exceeds the worker total byte limit.")

        normalized_records.append(
            {
                **record,
                "value": normalized_value,
            }
        )

    return {
        "schema_version": READ_RESULT_SCHEMA_VERSION,
        "store_name": "default",
        "records": normalized_records,
    }


def validate_kv_worker_output(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail("KV worker output must be an object.")
    if set(value) != {"schema_version", "result", "mutations"}:
        _fail("KV worker output fields are invalid.")
    if value.get("schema_version") != OUTPUT_SCHEMA_VERSION:
        _fail("KV worker output schema version is unsupported.")

    result = value.get("result")
    _validate_json_value(result)
    mutations = value.get("mutations")
    if not isinstance(mutations, list) or len(mutations) > MAX_WORKER_MUTATIONS:
        _fail("KV worker mutation count is invalid.")

    normalized_mutations: list[dict[str, object]] = []
    idempotency_keys: list[str] = []
    for mutation in mutations:
        try:
            validated = validate_kv_mutation(mutation)
        except KVProtocolError as exc:
            raise KVWorkerBoundaryError(str(exc)) from exc
        normalized_mutations.append(validated.request)
        idempotency = validated.request.get("idempotency_key")
        if not isinstance(idempotency, str):
            _fail("KV mutation idempotency key is invalid.")
        idempotency_keys.append(idempotency)

    if len(idempotency_keys) != len(set(idempotency_keys)):
        _fail("KV worker mutation idempotency keys must be unique.")

    normalized = {
        "schema_version": OUTPUT_SCHEMA_VERSION,
        "result": result,
        "mutations": normalized_mutations,
    }
    if len(_canonical_json_bytes(normalized)) > MAX_ENVELOPE_BYTES:
        _fail("KV worker output exceeds the maximum encoded size.")
    return normalized
