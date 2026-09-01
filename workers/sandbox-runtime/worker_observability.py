from __future__ import annotations

import json
import os
import re
import sys
from datetime import UTC, datetime
from uuid import UUID

LOG_SCHEMA_VERSION = "rdc.log/v1"
_EVENT = re.compile(r"^worker\.[a-z_]+(?:\.[a-z_]+)*$")
_REQUEST_ID = re.compile(r"^(?:lease|worker)_[0-9a-f]{32}$")
_WORK_KINDS = frozenset({"BUILD", "RUN_CANCEL", "RUN_START"})
_OUTCOMES = frozenset({"aborted", "failed", "succeeded"})
_ENVIRONMENTS = frozenset({"development", "production", "staging", "test"})


def _uuid(value: str) -> str:
    return str(UUID(value))


def log_worker_event(
    event: str,
    *,
    request_id: str,
    worker_id: str,
    lease_id: str | None = None,
    run_id: str | None = None,
    work_kind: str | None = None,
    outcome: str | None = None,
    error_type: str | None = None,
) -> None:
    if _EVENT.fullmatch(event) is None:
        raise ValueError("invalid worker log event")
    if _REQUEST_ID.fullmatch(request_id) is None:
        raise ValueError("invalid worker request correlation")
    environment = os.environ.get("RDC_ENV", "development")
    if environment not in _ENVIRONMENTS:
        raise ValueError("invalid worker environment")
    payload: dict[str, object] = {
        "schema_version": LOG_SCHEMA_VERSION,
        "timestamp": datetime.now(UTC).isoformat(),
        "severity": "error" if error_type is not None else "info",
        "service": "sandbox_worker",
        "environment": environment,
        "event": event,
        "request_id": request_id,
        "worker_id": _uuid(worker_id),
    }
    deployment_id = os.environ.get("RDC_DEPLOYMENT_ID", "")
    if deployment_id:
        if len(deployment_id) > 100 or any(ord(item) < 32 for item in deployment_id):
            raise ValueError("invalid deployment identifier")
        payload["deployment_id"] = deployment_id
    if lease_id is not None:
        payload["lease_id"] = _uuid(lease_id)
    if run_id is not None:
        payload["run_id"] = _uuid(run_id)
    if work_kind is not None:
        if work_kind not in _WORK_KINDS:
            raise ValueError("invalid work kind")
        payload["work_kind"] = work_kind
    if outcome is not None:
        if outcome not in _OUTCOMES:
            raise ValueError("invalid worker outcome")
        payload["outcome"] = outcome
    if error_type is not None:
        if re.fullmatch(r"^[A-Za-z][A-Za-z0-9_]{0,99}$", error_type) is None:
            raise ValueError("invalid worker error type")
        payload["error_type"] = error_type
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")), file=sys.stderr)
