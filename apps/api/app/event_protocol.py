"""Strict, credential-free RDC lifecycle-event envelope validation."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import cast
from uuid import UUID

EVENT_SCHEMA_VERSION = "rdc.event/v1"
MAX_EVENT_PAYLOAD_BYTES = 16_384


class EventProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class EventDefinition:
    subject_type: str
    payload_keys: frozenset[str]
    allowed_statuses: frozenset[str]


EVENT_DEFINITIONS: dict[str, EventDefinition] = {
    "build.created": EventDefinition(
        subject_type="build",
        payload_keys=frozenset({"agent_id", "agent_version_id", "status"}),
        allowed_statuses=frozenset({"QUEUED"}),
    ),
    "run.created": EventDefinition(
        subject_type="run",
        payload_keys=frozenset(
            {"agent_id", "agent_version_id", "build_id", "status"}
        ),
        allowed_statuses=frozenset({"DRAFT", "QUEUED"}),
    ),
}

_SENSITIVE_KEY = re.compile(
    r"authorization|password|secret|credential|token|cookie|databaseurl|"
    r"redisurl|s3accesskey|s3secretkey|objectstoragecredential"
)


def _validate_safe_value(value: object, *, depth: int = 0) -> None:
    if depth > 8:
        raise EventProtocolError("Event payload nesting exceeds the safe bound")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool):
        if abs(value) > 9_007_199_254_740_991:
            raise EventProtocolError("Event payload integer exceeds the safe bound")
        return
    if isinstance(value, str):
        if len(value.encode("utf-8")) > 2048:
            raise EventProtocolError("Event payload string exceeds the safe bound")
        return
    if isinstance(value, list):
        if len(value) > 100:
            raise EventProtocolError("Event payload array exceeds the safe bound")
        for item in value:
            _validate_safe_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 64:
            raise EventProtocolError("Event payload object exceeds the safe bound")
        for key, item in value.items():
            if not isinstance(key, str) or not 1 <= len(key) <= 64:
                raise EventProtocolError("Event payload keys must be bounded strings")
            normalized = re.sub(r"[^a-z0-9]", "", key.casefold())
            if _SENSITIVE_KEY.search(normalized):
                raise EventProtocolError("Sensitive event payload keys are prohibited")
            _validate_safe_value(item, depth=depth + 1)
        return
    raise EventProtocolError("Event payload contains an unsupported value type")


def validate_event_payload(
    *,
    event_type: str,
    subject_type: str,
    payload: dict[str, object],
) -> dict[str, object]:
    definition = EVENT_DEFINITIONS.get(event_type)
    if definition is None:
        raise EventProtocolError("Event type is not allowlisted")
    if subject_type != definition.subject_type:
        raise EventProtocolError("Event subject type does not match the event type")
    if set(payload) != definition.payload_keys:
        raise EventProtocolError("Event payload shape does not match the event type")
    status = payload.get("status")
    if not isinstance(status, str) or status not in definition.allowed_statuses:
        raise EventProtocolError("Event status does not match the event type")
    for key in definition.payload_keys - {"status"}:
        value = payload.get(key)
        if not isinstance(value, str):
            raise EventProtocolError("Event resource identifiers must be strings")
        try:
            parsed = UUID(value)
        except ValueError as exc:
            raise EventProtocolError("Event resource identifier is invalid") from exc
        if str(parsed) != value:
            raise EventProtocolError("Event resource identifier must be canonical")
    _validate_safe_value(payload)
    encoded = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_EVENT_PAYLOAD_BYTES:
        raise EventProtocolError("Event payload exceeds the byte limit")
    return cast(dict[str, object], json.loads(encoded))
