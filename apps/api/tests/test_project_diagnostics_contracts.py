from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from app.api.routes.diagnostics import project_diagnostics_payload
from app.core.permissions import role_has_permission
from app.main import app
from app.services.project_diagnostics import ProjectDiagnostics

ROOT = Path(__file__).resolve().parents[3]


def _diagnostics() -> ProjectDiagnostics:
    return ProjectDiagnostics(
        observed_at=datetime(2026, 9, 1, 12, 0, tzinfo=UTC),
        active_execution_leases=2,
        build_dispatch_ready=3,
        run_commands_ready=5,
        schedules_due=7,
        request_queue_ready=11,
        request_queue_claimed=13,
        request_queue_failed=17,
        credential_canaries_ready=19,
        credential_canaries_claimed=23,
        credential_canaries_failed=29,
        webhook_deliveries_ready=31,
        webhook_deliveries_claimed=37,
        webhook_deliveries_dead_lettered=41,
    )


def test_project_diagnostics_payload_is_fixed_and_identifier_free() -> None:
    payload = project_diagnostics_payload(_diagnostics())
    assert payload == {
        "observed_at": "2026-09-01T12:00:00+00:00",
        "execution": {
            "active_leases": 2,
            "build_dispatch_ready": 3,
            "run_commands_ready": 5,
        },
        "schedules": {"due": 7},
        "request_queues": {"ready": 11, "claimed": 13, "failed": 17},
        "credential_canaries": {"ready": 19, "claimed": 23, "failed": 29},
        "webhook_deliveries": {
            "ready": 31,
            "claimed": 37,
            "dead_lettered": 41,
        },
    }
    encoded = json.dumps(payload, sort_keys=True)
    for prohibited in (
        "organization_id",
        "project_id",
        "user_id",
        "worker_id",
        "lease_id",
        "run_id",
        "queue_id",
        "destination_id",
        "policy_id",
        "attempt_id",
        "url",
        "payload",
        "claim_token",
        "credential_secret_id",
        "secret",
        "http_status",
        "error_code",
        "error_summary",
    ):
        assert prohibited not in encoded


def test_project_diagnostics_query_is_fixed_scoped_and_timeout_bounded() -> None:
    source = (
        ROOT / "apps/api/app/services/project_diagnostics.py"
    ).read_text(encoding="utf-8")
    assert source.count("await session.execute(") == 1
    assert source.count("= :project_id") == 13
    assert "PROJECT_DIAGNOSTICS_TIMEOUT_SECONDS = 2.0" in source
    assert "asyncio.timeout(PROJECT_DIAGNOSTICS_TIMEOUT_SECONDS)" in source
    assert "await set_project_context(session, project_id)" in source
    assert "CURRENT_TIMESTAMP AS observed_at" in source
    for prohibited in (
        "endpoint_url",
        "request_url",
        "payload_snapshot",
        "claim_token_digest",
        "failure_summary",
        "last_error_code",
        "last_http_status",
    ):
        assert prohibited not in source


def test_project_diagnostics_has_dedicated_read_scope() -> None:
    for role in ("owner", "administrator", "developer", "analyst", "operator", "viewer"):
        assert role_has_permission(role, "diagnostic.read")
    assert not role_has_permission("billing_manager", "diagnostic.read")


def test_project_diagnostics_route_is_authenticated_and_documented() -> None:
    route_source = (
        ROOT / "apps/api/app/api/routes/diagnostics.py"
    ).read_text(encoding="utf-8")
    assert 'require_project_permission("diagnostic.read")' in route_source
    assert "success_payload(request" in route_source
    path = "/api/v1/projects/{project_id}/diagnostics"
    assert set(app.openapi()["paths"][path]) == {"get"}


def test_project_diagnostics_is_exposed_by_the_typed_client() -> None:
    client = (ROOT / "packages/api-client/src/index.ts").read_text(encoding="utf-8")
    shared = (
        ROOT / "packages/shared-types/src/index.ts"
    ).read_text(encoding="utf-8")
    assert "interface ProjectDiagnosticsSummary" in shared
    assert "async function projectDiagnostics(" in client
    assert "Promise<ProjectDiagnosticsSummary>" in client
    assert "/diagnostics`" in client
