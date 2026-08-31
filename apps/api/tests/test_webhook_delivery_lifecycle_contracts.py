from pathlib import Path

from app.main import app

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


def test_delivery_foundation_has_no_public_or_network_execution_path() -> None:
    paths = app.openapi()["paths"]
    assert not any("deliveries" in path for path in paths if "webhook" in path)
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
