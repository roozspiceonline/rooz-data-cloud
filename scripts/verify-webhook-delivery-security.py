from pathlib import Path

ROOT = Path(__file__).parents[1]


def need(path: str, *markers: str) -> None:
    source = (ROOT / path).read_text()
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise SystemExit(f"{path} is missing: {', '.join(missing)}")


need(
    "apps/api/app/webhook_delivery_security.py",
    "hmac.new",
    "RDC-Signature",
    "validate_dns_resolution",
    "validate_connected_peer",
    "Webhook redirects are disabled",
    "MAX_WEBHOOK_RESPONSE_BYTES = 65_536",
)
need(
    "apps/api/app/webhook_delivery_transport.py",
    "asyncio.open_connection",
    "server_hostname=hostname",
    "validate_connected_peer",
    'f"POST {request_target} HTTP/1.1',
)
need(
    "apps/api/app/services/webhook_delivery_canary.py",
    "load_webhook_delivery_claim",
    "complete_webhook_delivery_canary",
    "hashlib.sha256",
)
need(
    "apps/api/app/webhook_delivery_runner.py",
    "decrypt_project_secret",
    "sign_webhook_request",
    "run_webhook_delivery_transport",
    "for index in range(len(plaintext))",
    "max_retries=0",
)
need(
    "apps/api/migrations/versions/20260831_0032_webhook_trusted_delivery.py",
    "claim_webhook_delivery_canary",
    "claim_token_digest",
    "claim_token IS NULL",
    "SECURITY DEFINER",
    "REVOKE ALL ON FUNCTION",
)
config = (ROOT / "apps/api/app/core/config.py").read_text()
if "webhook_delivery_canary_enabled: bool = False" not in config:
    raise SystemExit("webhook delivery canary must default false")
print("Trusted webhook delivery canary verification passed")
