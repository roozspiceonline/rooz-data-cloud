from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from typing import NoReturn

SCHEMA_VERSION = "rdc.dataset-append/v1"
MAX_ITEMS = 100
MAX_ITEM_BYTES = 65_536
MAX_BATCH_BYTES = 262_144
MAX_DEPTH = 32

_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class DatasetAppendProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedDatasetAppend:
    schema_version: str
    idempotency_key: str
    items: tuple[dict[str, object], ...]
    request_digest: str
    encoded_bytes: int

    @property
    def item_count(self) -> int:
        return len(self.items)


def _fail(message: str) -> NoReturn:
    raise DatasetAppendProtocolError(message)


def _validate_json_value(value: object, *, depth: int) -> None:
    if depth > MAX_DEPTH:
        _fail("Dataset item exceeds the maximum JSON nesting depth.")

    if value is None or isinstance(value, (bool, int, str)):
        return

    if isinstance(value, float):
        if not math.isfinite(value):
            _fail("Dataset items cannot contain NaN or Infinity.")
        return

    if isinstance(value, list):
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return

    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("Dataset object keys must be strings.")
            _validate_json_value(item, depth=depth + 1)
        return

    _fail("Dataset items must contain JSON-compatible values only.")


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
        raise DatasetAppendProtocolError(
            "Dataset request cannot be canonically encoded."
        ) from exc


def validate_dataset_append(value: object) -> ValidatedDatasetAppend:
    if not isinstance(value, dict):
        _fail("Dataset append request must be an object.")

    if set(value) != {"schema_version", "idempotency_key", "items"}:
        _fail("Dataset append request fields are invalid.")

    if value.get("schema_version") != SCHEMA_VERSION:
        _fail("Dataset append schema version is unsupported.")

    idempotency_key = value.get("idempotency_key")
    if (
        not isinstance(idempotency_key, str)
        or _IDEMPOTENCY_KEY.fullmatch(idempotency_key) is None
    ):
        _fail("Dataset append idempotency key is invalid.")

    raw_items = value.get("items")
    if (
        not isinstance(raw_items, list)
        or not 1 <= len(raw_items) <= MAX_ITEMS
    ):
        _fail("Dataset append item count is outside the safe limit.")

    normalized_items: list[dict[str, object]] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, dict):
            _fail("Each Dataset item must be a JSON object.")

        normalized_item: dict[str, object] = {}
        for key, item in raw_item.items():
            if not isinstance(key, str):
                _fail("Dataset object keys must be strings.")
            _validate_json_value(item, depth=1)
            normalized_item[key] = item

        item_bytes = canonical_json_bytes(normalized_item)
        if len(item_bytes) > MAX_ITEM_BYTES:
            _fail("Dataset item exceeds the maximum encoded size.")
        normalized_items.append(normalized_item)

    normalized: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "idempotency_key": idempotency_key,
        "items": normalized_items,
    }
    encoded = canonical_json_bytes(normalized)
    if len(encoded) > MAX_BATCH_BYTES:
        _fail("Dataset append batch exceeds the maximum encoded size.")

    return ValidatedDatasetAppend(
        schema_version=SCHEMA_VERSION,
        idempotency_key=idempotency_key,
        items=tuple(normalized_items),
        request_digest=hashlib.sha256(encoded).hexdigest(),
        encoded_bytes=len(encoded),
    )
