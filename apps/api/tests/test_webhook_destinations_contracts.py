from pathlib import Path

import pytest

from app.core.permissions import role_has_permission, validate_scopes
from app.main import app
from app.webhook_destination_protocol import (
    WebhookDestinationProtocolError,
    validate_webhook_destination,
)
from app.webhook_destination_schemas import WebhookDestinationSummary

ROOT = Path(__file__).parents[1]


def test_destination_protocol_normalizes_and_rejects_ssrf_shapes() -> None:
    validated = validate_webhook_destination(
        endpoint_url="https://Hooks.Example.COM/callback?source=rdc",
        event_types=["run.created", "build.created"],
    )
    assert validated.endpoint_url == "https://hooks.example.com/callback?source=rdc"
    assert validated.event_types == ["build.created", "run.created"]
    for url in (
        "http://hooks.example.com/callback",
        "https://127.0.0.1/callback",
        "https://[::1]/callback",
        "https://metadata.internal/callback",
        "https://hooks_example.com/callback",
        "https://h\u00f6oks.example.com/callback",
        "https://user:pass@hooks.example.com/callback",
        "https://hooks.example.com:8443/callback",
    ):
        with pytest.raises(WebhookDestinationProtocolError):
            validate_webhook_destination(endpoint_url=url, event_types=["run.created"])


def test_destination_api_is_write_only_for_secrets_and_exposes_explicit_verification() -> None:
    openapi = app.openapi()
    paths = openapi["paths"]
    assert "/api/v1/projects/{project_id}/webhook-destinations" in paths
    summary_schema = str(WebhookDestinationSummary.model_json_schema())
    assert "signing_secret_id" not in summary_schema
    assert 'signing_secret"' not in summary_schema
    assert (
        "/api/v1/projects/{project_id}/webhook-destinations/{destination_id}/verify"
        in paths
    )
    assert not any("activate" in path for path in paths if "webhook" in path)


def test_destination_permissions_are_least_privilege() -> None:
    assert validate_scopes(["webhook.create", "webhook.read", "webhook.update"])
    assert role_has_permission("developer", "webhook.create")
    assert role_has_permission("operator", "webhook.update")
    assert role_has_permission("viewer", "webhook.read")
    assert not role_has_permission("viewer", "webhook.update")
    assert not role_has_permission("billing_manager", "webhook.read")


def test_destination_migration_has_server_tenancy_and_rls() -> None:
    migration = (ROOT / "migrations/versions/20260830_0030_webhook_destinations.py").read_text()
    for marker in (
        'down_revision: str | None = "20260829_0029"',
        "ENABLE ROW LEVEL SECURITY",
        "webhook_destinations_select",
        "webhook_destinations_insert",
        "webhook_destinations_update",
        "Webhook signing secret reference is invalid",
        "PENDING_VERIFICATION",
    ):
        assert marker in migration


def test_destination_managed_secret_matches_project_secret_constraints() -> None:
    service = (ROOT / "app/services/webhook_destinations.py").read_text()
    assert 'f"WEBHOOK_{destination_id.hex.upper()}"' in service
    assert "environment=get_settings().env" in service
    assert 'environment="webhook"' not in service
