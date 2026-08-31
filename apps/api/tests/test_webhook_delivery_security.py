import hashlib
import hmac
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from app.core.config import Settings
from app.webhook_delivery_security import (
    WebhookDeliverySecurityError,
    reject_webhook_response,
    sign_webhook_request,
    validate_delivery_peer,
    validate_delivery_target,
)


def test_webhook_signature_is_canonical_and_timestamp_bound() -> None:
    delivery_id, event_id = uuid4(), uuid4()
    timestamp = datetime(2026, 8, 30, tzinfo=UTC)
    signed = sign_webhook_request(
        secret=b"s" * 32, delivery_id=delivery_id, event_id=event_id,
        event_type="run.created", occurred_at=timestamp,
        payload={"status": "QUEUED"}, timestamp=timestamp,
    )
    expected = hmac.new(
        b"s" * 32,
        signed.headers["RDC-Timestamp"].encode() + b"." + signed.body,
        hashlib.sha256,
    ).hexdigest()
    assert signed.headers["RDC-Signature"] == f"v1={expected}"
    assert str(delivery_id).encode() in signed.body


def test_webhook_network_policy_rejects_private_dns_rebinding_and_redirects() -> None:
    with pytest.raises(WebhookDeliverySecurityError):
        validate_delivery_target("https://hooks.example.com/callback", ["127.0.0.1"])
    target = validate_delivery_target("https://hooks.example.com/callback", ["8.8.8.8"])
    with pytest.raises(WebhookDeliverySecurityError):
        validate_delivery_peer(target, "1.1.1.1")
    assert validate_delivery_peer(target, "8.8.8.8") == "8.8.8.8"
    with pytest.raises(WebhookDeliverySecurityError, match="redirects"):
        reject_webhook_response(302, 0)
    with pytest.raises(WebhookDeliverySecurityError, match="bounds"):
        reject_webhook_response(200, 65_537)


def test_webhook_canary_is_false_by_default_and_bounded() -> None:
    settings = Settings()
    assert settings.webhook_delivery_canary_enabled is False
    assert settings.webhook_delivery_max_response_bytes == 65_536
    with pytest.raises(ValueError):
        Settings(webhook_delivery_total_timeout_seconds=31)
    with pytest.raises(ValueError):
        Settings(webhook_delivery_claim_seconds=15, webhook_delivery_total_timeout_seconds=15)
