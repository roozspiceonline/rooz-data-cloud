from pathlib import Path

ROOT = Path(__file__).parents[1]


def need(path: str, *markers: str) -> None:
    source = (ROOT / path).read_text()
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise SystemExit(f"{path} is missing: {', '.join(missing)}")


need(
    "apps/api/migrations/versions/20260901_0033_webhook_replay_failure_controls.py",
    'down_revision: str | None = "20260831_0032"',
    "AUTO_FAILURE_THRESHOLD",
    "consecutive_failure_count",
    "verified_at=COALESCE",
    "last_replay_key_digest",
)
need(
    "apps/api/app/services/webhook_deliveries.py",
    "enqueue_matching_webhook_deliveries",
    "MANUAL_REPLAY",
    "WEBHOOK_REPLAY_CONFIGURATION_CHANGED",
    "last_replay_key_digest == key_digest",
)
need(
    "apps/api/app/api/routes/webhook_deliveries.py",
    'require_project_permission("webhook.read")',
    'require_project_permission("webhook.update")',
    'Header(alias="Idempotency-Key")',
    "Depends(require_csrf)",
)
need(
    "apps/api/app/main.py",
    '"webhook_delivery_replay_enabled": True',
    '"webhook_automatic_failure_disablement_enabled": True',
)
print("Webhook replay and automatic failure control verification passed")
