from pathlib import Path

ROOT = Path(__file__).parents[1]


def need(path: str, *markers: str) -> None:
    source = (ROOT / path).read_text()
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise SystemExit(f"{path} is missing: {', '.join(missing)}")


need("apps/api/migrations/versions/20260830_0031_webhook_delivery_attempts.py",
     "Webhook delivery transitions are immutable", "ENABLE ROW LEVEL SECURITY",
     "claim_token IS NOT NULL", "DEAD_LETTERED")
need("apps/api/app/services/webhook_deliveries.py", "skip_locked=True",
     "WEBHOOK_CLAIM_FENCED", "ATTEMPTS_EXHAUSTED", "min(3600")
need("apps/api/app/main.py", '"webhook_delivery_enabled": False')
print("Webhook delivery lifecycle verification passed")
