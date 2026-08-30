from pathlib import Path

from app.main import app

ROOT = Path(__file__).parents[1]


def test_delivery_migration_has_fenced_bounded_lifecycle() -> None:
    source = (
        ROOT / "migrations/versions/20260830_0031_webhook_delivery_attempts.py"
    ).read_text()
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
        "delivery.claim_token != claim_token",
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
