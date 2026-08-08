from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import NoReturn

READ_SCHEMA_VERSION = "rdc.kv-worker-read/v1"
MAX_KEY_LENGTH = 256
MAX_WORKER_READ_KEYS = 16
MAX_WORKER_READ_TOTAL_BYTES = 262_144

_LOGICAL_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class KVWorkerProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedKVReadRequest:
    request: dict[str, object]
    request_digest: str
    keys: tuple[str, ...]


def _fail(message: str) -> NoReturn:
    raise KVWorkerProtocolError(message)


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
        raise KVWorkerProtocolError(
            "KV worker request cannot be canonically JSON encoded."
        ) from exc


def validate_kv_read_request(value: object) -> ValidatedKVReadRequest:
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

    return ValidatedKVReadRequest(
        request=normalized,
        request_digest=hashlib.sha256(encoded).hexdigest(),
        keys=tuple(keys),
    )
