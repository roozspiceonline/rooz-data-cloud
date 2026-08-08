from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
from dataclasses import dataclass
from typing import NoReturn
from urllib.parse import urlsplit, urlunsplit

SCHEMA_VERSION = "rdc.queue-enqueue/v1"
MAX_ENVELOPE_BYTES = 98_304
MAX_URL_LENGTH = 2_048
MAX_USER_DATA_BYTES = 65_536
MAX_DEPTH = 32
_SAFE_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")


class RequestQueueProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedQueueEnqueue:
    request: dict[str, object]
    request_digest: str
    identity_digest: str


def _fail(message: str) -> NoReturn:
    raise RequestQueueProtocolError(message)


def _json(value: object, *, depth: int = 0) -> None:
    if depth > MAX_DEPTH:
        _fail("Queue user data exceeds the maximum JSON nesting depth.")
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail("Queue user data cannot contain NaN or Infinity.")
        return
    if isinstance(value, list):
        for item in value:
            _json(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail("Queue user data object keys must be strings.")
            _json(item, depth=depth + 1)
        return
    _fail("Queue user data must be JSON-compatible.")


def _canonical(value: object) -> bytes:
    try:
        return json.dumps(
            value, sort_keys=True, ensure_ascii=False, allow_nan=False,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RequestQueueProtocolError(
            "Queue request cannot be canonically encoded."
        ) from exc


def _url(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= MAX_URL_LENGTH:
        _fail("Queue URL is outside the safe length limit.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        if (
            parsed.scheme != "https"
            or not hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port not in {None, 443}
        ):
            raise ValueError("unsupported URL authority")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError("IP literals are forbidden")
        if any(character.isspace() for character in value):
            raise ValueError("whitespace")
        normalized = urlunsplit(
            ("https", parsed.netloc.lower(), parsed.path or "/", parsed.query, "")
        )
    except ValueError as exc:
        raise RequestQueueProtocolError(
            "Queue URL must be an HTTPS hostname without credentials or IP literals."
        ) from exc
    return normalized


def validate_queue_enqueue(value: object) -> ValidatedQueueEnqueue:
    if not isinstance(value, dict):
        _fail("Queue enqueue request must be an object.")
    fields = {"schema_version", "idempotency_key", "url", "unique_key", "user_data"}
    if set(value) != fields or value.get("schema_version") != SCHEMA_VERSION:
        _fail("Queue enqueue request fields or schema version are invalid.")
    idempotency_key = value.get("idempotency_key")
    unique_key = value.get("unique_key")
    if not isinstance(idempotency_key, str) or _SAFE_KEY.fullmatch(idempotency_key) is None:
        _fail("Queue idempotency key is invalid.")
    if unique_key is not None and (
        not isinstance(unique_key, str) or _SAFE_KEY.fullmatch(unique_key) is None
    ):
        _fail("Queue unique key is invalid.")
    url = _url(value.get("url"))
    user_data = value.get("user_data")
    _json(user_data)
    if len(_canonical(user_data)) > MAX_USER_DATA_BYTES:
        _fail("Queue user data exceeds the maximum encoded size.")
    identity = {"url": url, "unique_key": unique_key, "user_data": user_data}
    normalized = {"schema_version": SCHEMA_VERSION, "idempotency_key": idempotency_key, **identity}
    encoded = _canonical(normalized)
    if len(encoded) > MAX_ENVELOPE_BYTES:
        _fail("Queue enqueue envelope exceeds the maximum encoded size.")
    return ValidatedQueueEnqueue(
        request=normalized,
        request_digest=hashlib.sha256(encoded).hexdigest(),
        identity_digest=hashlib.sha256(_canonical(identity)).hexdigest(),
    )
