from pathlib import Path

ROOT = Path(__file__).parents[1]
source = (ROOT / "apps/api/app/webhook_delivery_security.py").read_text()
for marker in ("hmac.new", "RDC-Signature", "validate_dns_resolution", "validate_connected_peer", "Webhook redirects are disabled", "MAX_WEBHOOK_RESPONSE_BYTES = 65_536"):
    if marker not in source:
        raise SystemExit(f"webhook delivery security missing: {marker}")
config = (ROOT / "apps/api/app/core/config.py").read_text()
if "webhook_delivery_canary_enabled: bool = False" not in config:
    raise SystemExit("webhook delivery canary must default false")
print("Webhook delivery security foundation verification passed")
