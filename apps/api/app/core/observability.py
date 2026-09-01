from __future__ import annotations

import json
import logging
import math
import re
from contextvars import ContextVar, Token
from datetime import UTC, datetime
from typing import Final

LOG_SCHEMA_VERSION: Final = "rdc.log/v1"
_NAME = re.compile(r"^[a-z][a-z0-9_.]{0,63}$")
_FIELD_NAME = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_FORBIDDEN_FIELD_PARTS = frozenset(
    {
        "authorization",
        "body",
        "cookie",
        "credential",
        "header",
        "host",
        "password",
        "payload",
        "query",
        "secret",
        "token",
        "url",
    }
)
_CONTEXT_FIELDS = frozenset({"lease_id", "request_id", "run_id", "worker_id"})
_RESERVED_FIELDS = _CONTEXT_FIELDS | frozenset(
    {
        "deployment_id",
        "environment",
        "event",
        "exception_type",
        "schema_version",
        "service",
        "severity",
        "timestamp",
    }
)
_context: ContextVar[dict[str, str] | None] = ContextVar(
    "rdc_log_context", default=None
)


def _safe_name(value: str, *, field: bool = False) -> str:
    expression = _FIELD_NAME if field else _NAME
    if expression.fullmatch(value) is None:
        raise ValueError(f"invalid structured log name: {value!r}")
    if field and any(part in value for part in _FORBIDDEN_FIELD_PARTS):
        raise ValueError(f"forbidden structured log field: {value!r}")
    return value


def _safe_value(value: object) -> bool | float | int | str | None:
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not -(2**63) <= value < 2**63:
            raise ValueError("structured log integer is outside the 64-bit bound")
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("structured log float must be finite")
        return value
    if not isinstance(value, str):
        raise TypeError("structured log values must be scalar")
    if len(value) > 200 or any(ord(character) < 32 for character in value):
        raise ValueError("structured log string is invalid or too long")
    return value


def _safe_field_name(value: str) -> str:
    name = _safe_name(value, field=True)
    if name in _RESERVED_FIELDS:
        raise ValueError(f"reserved structured log field: {name!r}")
    return name


def bind_log_context(**fields: str) -> Token[dict[str, str] | None]:
    normalized: dict[str, str] = {}
    for name, value in fields.items():
        if name not in _CONTEXT_FIELDS:
            raise ValueError(f"unsupported correlation field: {name!r}")
        normalized[name] = str(_safe_value(value))
    return _context.set(normalized)


def reset_log_context(token: Token[dict[str, str] | None]) -> None:
    _context.reset(token)


class RdcJsonFormatter(logging.Formatter):
    def __init__(self, *, service: str, environment: str, deployment_id: str) -> None:
        super().__init__()
        self.service = _safe_name(service)
        self.environment = _safe_name(environment)
        self.deployment_id = _safe_value(deployment_id)

    def format(self, record: logging.LogRecord) -> str:
        event = _safe_name(str(getattr(record, "rdc_event", record.getMessage())))
        raw_fields = getattr(record, "rdc_fields", {})
        if not isinstance(raw_fields, dict):
            raise TypeError("structured log fields must be a mapping")
        payload: dict[str, object] = {
            "schema_version": LOG_SCHEMA_VERSION,
            "timestamp": datetime.now(UTC).isoformat(),
            "severity": record.levelname.lower(),
            "service": self.service,
            "environment": self.environment,
            "event": event,
        }
        if self.deployment_id:
            payload["deployment_id"] = self.deployment_id
        context = getattr(record, "rdc_context", {})
        if isinstance(context, dict):
            for name, value in context.items():
                if name not in _CONTEXT_FIELDS:
                    raise ValueError(f"unsupported correlation field: {name!r}")
                payload[name] = _safe_value(value)
        for name, value in raw_fields.items():
            payload[_safe_field_name(str(name))] = _safe_value(value)
        if record.exc_info is not None and record.exc_info[0] is not None:
            payload["exception_type"] = record.exc_info[0].__name__
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def configure_structured_logging(
    *,
    service: str,
    environment: str,
    deployment_id: str = "",
) -> None:
    logger = logging.getLogger("rdc")
    handler = logging.StreamHandler()
    handler.setFormatter(
        RdcJsonFormatter(
            service=service,
            environment=environment,
            deployment_id=deployment_id,
        )
    )
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    **fields: object,
) -> None:
    normalized_event = _safe_name(event)
    normalized_fields = {
        _safe_field_name(name): _safe_value(value)
        for name, value in fields.items()
    }
    logger.log(
        level,
        normalized_event,
        extra={
            "rdc_context": dict(_context.get() or {}),
            "rdc_event": normalized_event,
            "rdc_fields": normalized_fields,
        },
    )
