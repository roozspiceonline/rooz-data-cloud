from pathlib import Path

from app.main import app
from app.webhook_delivery_schemas import WebhookDeliverySummary

ROOT = Path(__file__).parents[1]


def test_delivery_migration_has_fenced_bounded_lifecycle() -> None:
    source = (ROOT / "migrations/versions/20260830_0031_webhook_delivery_attempts.py").read_text()
    for marker in (
        'down_revision: str | None = "20260830_0030"',
        "PENDING",
        "CLAIMED",
        "RETRY_WAIT",
        "SUCCEEDED",
        "DEAD_LETTERED",
        "CANCELLED",
        "attempt_count BETWEEN 0 AND max_attempts",
        "claim_token IS NOT NULL",
        "Webhook delivery transitions are immutable",
        "ENABLE ROW LEVEL SECURITY",
        "Webhook delivery lineage is invalid",
    ):
        assert marker in source


def test_delivery_service_is_claim_fenced_and_race_safe() -> None:
    source = (ROOT / "app/services/webhook_deliveries.py").read_text()
    for marker in (
        ".with_for_update(skip_locked=True)",
        "WEBHOOK_CLAIM_FENCED",
        "delivery.claim_token_digest != _claim_digest(claim_token)",
        "secrets.token_hex(32)",
        "claim_token=None",
        "delivery.attempt_count >= delivery.max_attempts",
        "min(3600",
        "ATTEMPTS_EXHAUSTED",
    ):
        assert marker in source


def test_delivery_history_is_public_but_network_execution_stays_separate() -> None:
    paths = app.openapi()["paths"]
    assert "/api/v1/projects/{project_id}/webhook-deliveries" in paths
    assert "/api/v1/projects/{project_id}/webhook-deliveries/{delivery_id}" in paths
    assert (
        "/api/v1/projects/{project_id}/webhook-deliveries/{delivery_id}/replay" in paths
    )
    source = (ROOT / "app/services/webhook_deliveries.py").read_text().casefold()
    for prohibited in ("httpx", "requests.", "aiohttp", "socket", "decrypt_project_secret"):
        assert prohibited not in source


def test_trusted_delivery_migration_is_claim_scoped_and_never_persists_tokens() -> None:
    source = (ROOT / "migrations/versions/20260831_0032_webhook_trusted_delivery.py").read_text()
    for marker in (
        'down_revision: str | None = "20260830_0031"',
        "claim_webhook_delivery_canary",
        "load_webhook_delivery_claim",
        "complete_webhook_delivery_canary",
        "SECURITY DEFINER",
        "claim_token_digest",
        "claim_token IS NULL",
        "REVOKE ALL ON FUNCTION",
        "FOR UPDATE SKIP LOCKED",
        "destination.status='PENDING_VERIFICATION'",
        "secret.version=delivery.signing_secret_version",
        "clock_timestamp()",
    ):
        assert marker in source


def test_trusted_runner_is_separate_false_by_default_and_minimally_credentialed() -> None:
    runner = (ROOT / "app/webhook_delivery_runner.py").read_text()
    for marker in (
        "load_webhook_delivery_material",
        "decrypt_project_secret",
        "sign_webhook_request",
        "run_webhook_delivery_transport",
        "for index in range(len(plaintext))",
        "webhook_delivery_canary_enabled",
    ):
        assert marker in runner
    for prohibited in ("logger.exception", "material.endpoint_url)", "material.secret_name)"):
        assert prohibited not in runner

    compose = (ROOT.parents[1] / "docker-compose.yml").read_text()
    start = compose.index("  webhook-delivery-runner:")
    end = compose.index("  console:", start)
    service = compose[start:end]
    assert 'command: ["python", "-m", "app.webhook_delivery_runner"]' in service
    assert "${RDC_WEBHOOK_DELIVERY_CANARY_ENABLED:-false}" in service
    for prohibited in ("RDC_S3_SECRET_KEY", "RDC_REDIS_URL", "RDC_SESSION_TOKEN_PEPPER"):
        assert prohibited not in service


def test_replay_history_contract_is_secret_free_and_database_fenced() -> None:
    schema = str(WebhookDeliverySummary.model_json_schema())
    for prohibited in (
        "endpoint_url",
        "claim_token",
        "claim_token_digest",
        "signing_secret",
        "event_payload",
        "last_replay_key_digest",
    ):
        assert prohibited not in schema
    migration = (
        ROOT
        / "migrations/versions/20260901_0033_webhook_replay_failure_controls.py"
    ).read_text()
    for marker in (
        'down_revision: str | None = "20260831_0032"',
        "AUTO_FAILURE_THRESHOLD",
        "consecutive_failure_count",
        "destination.status IN ('PENDING_VERIFICATION','ACTIVE')",
        "status='ACTIVE'",
        "verified_at=COALESCE",
        "last_replay_key_digest",
        "replay_requested_by_user_id",
    ):
        assert marker in migration


def test_replay_route_requires_idempotency_header_and_update_permission() -> None:
    operation = app.openapi()["paths"][
        "/api/v1/projects/{project_id}/webhook-deliveries/{delivery_id}/replay"
    ]["post"]
    headers = [
        parameter
        for parameter in operation["parameters"]
        if parameter["in"] == "header"
    ]
    assert any(item["name"] == "Idempotency-Key" and item["required"] for item in headers)
    source = (ROOT / "app/api/routes/webhook_deliveries.py").read_text()
    assert 'require_project_permission("webhook.update")' in source
    assert "Depends(require_csrf)" in source
