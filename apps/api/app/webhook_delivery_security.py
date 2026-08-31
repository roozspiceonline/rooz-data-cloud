"""Fail-closed signing and network policy for the webhook delivery canary."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit
from uuid import UUID

from .egress_canary_network_policy import (
    CanaryNetworkPolicyError,
    ValidatedCanaryTarget,
    normalize_canary_hostname,
    validate_connected_peer,
    validate_dns_resolution,
)

MAX_WEBHOOK_BODY_BYTES = 16_384
MAX_WEBHOOK_RESPONSE_BYTES = 65_536
MAX_WEBHOOK_CLOCK_SKEW_SECONDS = 300


class WebhookDeliverySecurityError(ValueError):
    pass


@dataclass(frozen=True)
class SignedWebhookRequest:
    body: bytes
    headers: dict[str, str]


def canonical_event_body(
    *,
    delivery_id: UUID,
    event_id: UUID,
    event_type: str,
    occurred_at: datetime,
    payload: dict[str, object],
) -> bytes:
    body = json.dumps(
        {
            "delivery_id": str(delivery_id),
            "event": {
                "id": str(event_id),
                "type": event_type,
                "occurred_at": occurred_at.astimezone(UTC).isoformat(),
                "payload": payload,
            },
            "schema_version": "rdc.webhook-delivery/v1",
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(body) > MAX_WEBHOOK_BODY_BYTES:
        raise WebhookDeliverySecurityError("Webhook request body exceeds its limit")
    return body


def sign_webhook_request(
    *,
    secret: bytes | bytearray,
    delivery_id: UUID,
    event_id: UUID,
    event_type: str,
    occurred_at: datetime,
    payload: dict[str, object],
    timestamp: datetime,
) -> SignedWebhookRequest:
    if not 32 <= len(secret) <= 512:
        raise WebhookDeliverySecurityError("Webhook signing secret is invalid")
    unix_timestamp = str(int(timestamp.astimezone(UTC).timestamp()))
    body = canonical_event_body(
        delivery_id=delivery_id,
        event_id=event_id,
        event_type=event_type,
        occurred_at=occurred_at,
        payload=payload,
    )
    signed = unix_timestamp.encode("ascii") + b"." + body
    signature = hmac.new(secret, signed, hashlib.sha256).hexdigest()
    return SignedWebhookRequest(
        body=body,
        headers={
            "Content-Type": "application/json",
            "RDC-Delivery-ID": str(delivery_id),
            "RDC-Event-ID": str(event_id),
            "RDC-Signature": f"v1={signature}",
            "RDC-Timestamp": unix_timestamp,
            "User-Agent": "rdc-webhook-canary/1",
        },
    )


def validate_delivery_target(url: str, addresses: list[str]) -> ValidatedCanaryTarget:
    try:
        parsed = urlsplit(url)
        if (
            parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.port not in {None, 443}
        ):
            raise WebhookDeliverySecurityError("Webhook target must be exact HTTPS")
        hostname = normalize_canary_hostname(parsed.hostname)
        return validate_dns_resolution(hostname, addresses)
    except (ValueError, CanaryNetworkPolicyError) as exc:
        if isinstance(exc, WebhookDeliverySecurityError):
            raise
        raise WebhookDeliverySecurityError("Webhook target resolution is unsafe") from exc


def validate_delivery_peer(target: ValidatedCanaryTarget, peer_address: str) -> str:
    try:
        return validate_connected_peer(target, peer_address)
    except CanaryNetworkPolicyError as exc:
        raise WebhookDeliverySecurityError("Webhook connected peer is unsafe") from exc


def reject_webhook_response(status_code: int, response_bytes: int) -> None:
    if 300 <= status_code <= 399:
        raise WebhookDeliverySecurityError("Webhook redirects are disabled")
    if not 100 <= status_code <= 599 or not 0 <= response_bytes <= MAX_WEBHOOK_RESPONSE_BYTES:
        raise WebhookDeliverySecurityError("Webhook response is outside safe bounds")
