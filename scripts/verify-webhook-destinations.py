from pathlib import Path

ROOT = Path(__file__).parents[1]


def need(path: str, *markers: str) -> None:
    source = (ROOT / path).read_text()
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise SystemExit(f"{path} is missing: {', '.join(missing)}")


need("apps/api/migrations/versions/20260830_0030_webhook_destinations.py",
     "ENABLE ROW LEVEL SECURITY", "Webhook signing secret reference is invalid",
     "PENDING_VERIFICATION", "security.project_secrets")
need("apps/api/app/webhook_destination_protocol.py", "IP literals are prohibited",
     'ALLOWED_WEBHOOK_EVENT_TYPES', 'parsed.scheme.casefold() != "https"')
need("apps/api/app/services/webhook_destinations.py", "encrypt_project_secret",
     "acquire_idempotency_lock", "signing_secret_rotated")
need("apps/api/app/main.py", '"webhook_delivery_enabled": False',
     '"webhook_destination_activation_enabled": True')
print("Webhook destination foundation verification passed")
