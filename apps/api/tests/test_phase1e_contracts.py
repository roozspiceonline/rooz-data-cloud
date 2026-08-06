import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.errors import ApiError
from app.core.permissions import role_has_permission, validate_scopes
from app.run_schemas import CreateRunRequest
from app.services.runs import sanitize_event_payload


def test_phase1e_permissions_follow_contract() -> None:
    assert role_has_permission("developer", "run.create")
    assert role_has_permission("developer", "run.cancel")
    assert role_has_permission("operator", "run.create")
    assert role_has_permission("viewer", "run.read")
    assert not role_has_permission("viewer", "run.cancel")
    assert validate_scopes(["run.cancel", "run.read"]) == [
        "run.cancel",
        "run.read",
    ]


def test_run_input_is_strict_and_size_limited() -> None:
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(
            {
                "build_id": "00000000-0000-0000-0000-000000000001",
                "input": {},
                "runtime": {},
                "execute_in_api": True,
            }
        )
    with pytest.raises(ValidationError):
        CreateRunRequest.model_validate(
            {
                "build_id": "00000000-0000-0000-0000-000000000001",
                "input": {"payload": "x" * 70_000},
                "runtime": {},
            }
        )


def test_run_event_payload_is_sanitized_and_redacted() -> None:
    result = sanitize_event_payload(
        {
            "message": "\u001b[31mhello\u001b[0m",
            "api_token": "private",
            "nested": {"password": "never-log-this"},
        }
    )
    assert result["message"] == "hello"
    assert result["api_token"] == "[REDACTED]"
    assert result["nested"] == {"password": "[REDACTED]"}


def test_run_event_payload_rejects_oversized_data() -> None:
    with pytest.raises(ApiError):
        sanitize_event_payload({"items": ["x" * 20_000] * 5})


def test_phase1e_migration_has_rls_resolver_events_and_outbox() -> None:
    migration = Path(
        "migrations/versions/20260806_0005_runs_sse.py"
    ).read_text(encoding="utf-8")
    assert "control.runs" in migration
    assert "run_events" in migration
    assert "run_command_outbox" in migration
    assert "runs_tenancy_guard" in migration
    assert "run_events_tenancy_guard" in migration
    assert "run_command_outbox_tenancy_guard" in migration
    assert "rdc_run_org" in migration
    assert "ENABLE ROW LEVEL SECURITY" in migration
    assert "uq_run_events_run_sequence" in migration


def test_phase1e_routes_match_approved_inventory() -> None:
    from app.main import app

    paths = app.openapi()["paths"]
    assert "/api/v1/agent-versions/{version_id}/runs" in paths
    assert "/api/v1/runs/{run_id}" in paths
    assert "/api/v1/runs/{run_id}/cancel" in paths
    assert "/api/v1/runs/{run_id}/events" in paths
    assert "/api/v1/projects/{project_id}/runs" in paths


def test_sse_contract_has_replay_heartbeat_and_sequence_ids() -> None:
    route = Path("app/api/routes/runs.py").read_text(encoding="utf-8")
    assert "Last-Event-ID" in route
    assert "run.replay_reset" in route
    assert "run.heartbeat" in route
    assert 'f"id: {event_id:016d}"' in route
    assert "run_sse_max_connections" in route
    assert "request.is_disconnected" in route
    tenant_context = route.index("await set_tenant_context(")
    authorization_check = route.index("if not await _stream_authorized(")
    assert tenant_context < authorization_check


def test_run_event_protocol_schema_matches_api_envelope() -> None:
    schema_path = (
        Path(__file__).parents[3]
        / "packages/agent-protocol/schemas/run-event.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["required"] == [
        "schema_version",
        "event_type",
        "run_id",
        "sequence",
        "timestamp",
        "payload",
    ]
    event_types = schema["properties"]["event_type"]["enum"]
    assert "run.replay_reset" in event_types
    assert "run.completed" in event_types
    assert "stream.connected" not in event_types


def test_control_plane_has_no_run_execution_primitive() -> None:
    source = "\n".join(
        [
            Path("app/services/runs.py").read_text(encoding="utf-8"),
            Path("app/api/routes/runs.py").read_text(encoding="utf-8"),
        ]
    )
    for prohibited in [
        "subprocess",
        "os.system",
        "docker run",
        "kubectl",
        "eval(",
        "decrypt_project_secret",
    ]:
        assert prohibited not in source
    assert "rdc.run.requested.v1" in source
    assert "rdc.run.cancel.requested.v1" in source
