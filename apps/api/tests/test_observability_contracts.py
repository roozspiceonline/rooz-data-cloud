from __future__ import annotations

import json
import logging
from io import StringIO

import pytest
from fastapi.testclient import TestClient

from app.core.observability import (
    LOG_SCHEMA_VERSION,
    RdcJsonFormatter,
    bind_log_context,
    log_event,
    reset_log_context,
)
from app.main import app


def _capture_logger() -> tuple[logging.Logger, StringIO]:
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        RdcJsonFormatter(
            service="contract_test",
            environment="test",
            deployment_id="deploy_test",
        )
    )
    logger = logging.getLogger("rdc.contract_test")
    logger.handlers[:] = [handler]
    logger.setLevel(logging.INFO)
    logger.propagate = False
    return logger, stream


def test_structured_log_has_bounded_correlation_and_scalar_fields() -> None:
    logger, stream = _capture_logger()
    token = bind_log_context(
        request_id="req_contract",
        run_id="00000000-0000-0000-0000-000000000001",
    )
    try:
        log_event(
            logger,
            logging.INFO,
            "run.claim.completed",
            outcome="accepted",
            duration_ms=12,
        )
    finally:
        reset_log_context(token)
    payload = json.loads(stream.getvalue())
    assert payload["schema_version"] == LOG_SCHEMA_VERSION
    assert payload["service"] == "contract_test"
    assert payload["event"] == "run.claim.completed"
    assert payload["request_id"] == "req_contract"
    assert payload["duration_ms"] == 12
    assert set(payload) == {
        "deployment_id",
        "duration_ms",
        "environment",
        "event",
        "outcome",
        "request_id",
        "run_id",
        "schema_version",
        "service",
        "severity",
        "timestamp",
    }


@pytest.mark.parametrize(
    "field_name",
    ["authorization", "access_token", "request_body", "target_url", "headers"],
)
def test_structured_log_rejects_secret_bearing_field_classes(
    field_name: str,
) -> None:
    logger, _ = _capture_logger()
    with pytest.raises(ValueError):
        log_event(logger, logging.INFO, "security.rejected", **{field_name: "value"})


def test_structured_log_rejects_nested_or_unbounded_values() -> None:
    logger, _ = _capture_logger()
    with pytest.raises(TypeError):
        log_event(logger, logging.INFO, "security.rejected", details={"key": "value"})
    with pytest.raises(ValueError):
        log_event(logger, logging.INFO, "security.rejected", summary="x" * 201)
    with pytest.raises(ValueError):
        log_event(logger, logging.INFO, "security.rejected", duration=float("nan"))
    with pytest.raises(ValueError):
        log_event(logger, logging.INFO, "security.rejected", schema_version="forged")


def test_http_completion_uses_route_template_and_omits_query_string() -> None:
    stream = StringIO()
    handler = logging.StreamHandler(stream)
    handler.setFormatter(
        RdcJsonFormatter(service="api", environment="test", deployment_id="")
    )
    parent = logging.getLogger("rdc")
    previous_handlers = list(parent.handlers)
    parent.handlers[:] = [handler]
    try:
        response = TestClient(app).get(
            "/api/v1/system/foundation?authorization=must-not-appear",
            headers={"X-Request-ID": "req_safe-correlation"},
        )
    finally:
        parent.handlers[:] = previous_handlers

    assert response.status_code == 200
    assert response.headers["X-Request-ID"] == "req_safe-correlation"
    payload = json.loads(stream.getvalue())
    assert payload["event"] == "http.request.completed"
    assert payload["request_id"] == "req_safe-correlation"
    assert payload["route"] == "/api/v1/system/foundation"
    assert "must-not-appear" not in stream.getvalue()
    assert "authorization" not in stream.getvalue()
