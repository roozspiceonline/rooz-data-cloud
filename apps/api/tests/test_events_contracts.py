from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest

from app.core.errors import ApiError
from app.core.pagination import decode_event_cursor, encode_event_cursor
from app.core.permissions import role_has_permission, validate_scopes
from app.event_protocol import EventProtocolError, validate_event_payload
from app.main import app

ROOT = Path(__file__).parents[1]


def _run_payload() -> dict[str, object]:
    return {
        "agent_id": str(uuid4()),
        "agent_version_id": str(uuid4()),
        "build_id": str(uuid4()),
        "status": "QUEUED",
    }


def test_event_envelope_is_allowlisted_bounded_and_deterministic() -> None:
    payload = _run_payload()
    assert validate_event_payload(
        event_type="run.created",
        subject_type="run",
        payload=payload,
    ) == payload
    with pytest.raises(EventProtocolError, match="allowlisted"):
        validate_event_payload(
            event_type="webhook.delivery.requested",
            subject_type="webhook",
            payload=payload,
        )
    with pytest.raises(EventProtocolError, match="shape"):
        validate_event_payload(
            event_type="run.created",
            subject_type="run",
            payload={**payload, "authorization": "Bearer must-not-persist"},
        )
    sensitive = _run_payload()
    sensitive["build_id"] = "not-a-uuid"
    with pytest.raises(EventProtocolError, match="identifier"):
        validate_event_payload(
            event_type="run.created",
            subject_type="run",
            payload=sensitive,
        )


def test_event_cursor_is_project_and_filter_bound() -> None:
    project_id, other_project, event_id = uuid4(), uuid4(), uuid4()
    cursor = encode_event_cursor(
        project_id=project_id,
        event_type="run.created",
        occurred_at=datetime.now(UTC),
        resource_id=event_id,
    )
    assert decode_event_cursor(
        cursor,
        project_id=project_id,
        event_type="run.created",
    ) is not None
    with pytest.raises(ApiError):
        decode_event_cursor(
            cursor,
            project_id=other_project,
            event_type="run.created",
        )
    with pytest.raises(ApiError):
        decode_event_cursor(
            cursor,
            project_id=project_id,
            event_type="build.created",
        )


def test_event_history_is_authenticated_read_only_and_least_privilege() -> None:
    operation = app.openapi()["paths"]["/api/v1/projects/{project_id}/events"]
    assert set(operation) == {"get"}
    assert validate_scopes(["event.read"]) == ["event.read"]
    for role in ("owner", "administrator", "developer", "analyst", "operator", "viewer"):
        assert role_has_permission(role, "event.read")
    assert not role_has_permission("billing_manager", "event.read")


def test_event_migration_and_emission_preserve_security_boundary() -> None:
    migration = (
        ROOT / "migrations/versions/20260829_0029_events_foundation.py"
    ).read_text(encoding="utf-8")
    for marker in (
        'down_revision: str | None = "20260829_0028"',
        "ENABLE ROW LEVEL SECURITY",
        "events_tenant_project_select",
        "security.rdc_current_project_id()",
        "Event project reference is invalid",
        "Event Run reference is invalid",
        "Event Build reference is invalid",
        "RDC events are immutable",
        "control.event_payload_is_safe",
        "octet_length(convert_to(payload::text, 'UTF8')) <= 16384",
        "uq_events_project_type_subject",
    ):
        assert marker in migration
    runs = (ROOT / "app/services/runs.py").read_text(encoding="utf-8")
    builds = (ROOT / "app/services/builds_secrets.py").read_text(encoding="utf-8")
    assert 'event_type="run.created"' in runs
    assert 'event_type="build.created"' in builds
    events = (ROOT / "app/services/events.py").read_text(encoding="utf-8")
    assert "enqueue_matching_webhook_deliveries" in events
    assert "httpx" not in events.casefold()
    assert "decrypt_project_secret" not in events.casefold()
