from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


class WebhookDestinationProtocolError(ValueError):
    pass


@dataclass(frozen=True)
class ValidatedWebhookDestination:
    endpoint_url: str
    endpoint_origin: str
    event_types: list[str]


ALLOWED_WEBHOOK_EVENT_TYPES = frozenset({"build.created", "run.created"})


def validate_webhook_destination(
    *, endpoint_url: str, event_types: list[str]
) -> ValidatedWebhookDestination:
    if not 1 <= len(endpoint_url) <= 2048:
        raise WebhookDestinationProtocolError("Webhook endpoint URL is invalid.")
    try:
        parsed = urlsplit(endpoint_url)
        port = parsed.port
    except ValueError as exc:
        raise WebhookDestinationProtocolError("Webhook endpoint URL is invalid.") from exc
    host = (parsed.hostname or "").casefold().rstrip(".")
    if (
        parsed.scheme.casefold() != "https"
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in (None, 443)
    ):
        raise WebhookDestinationProtocolError("Webhook endpoints require canonical HTTPS.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise WebhookDestinationProtocolError("Webhook endpoint IP literals are prohibited.")
    labels = host.split(".")
    if (
        len(labels) < 2
        or any(not label or len(label) > 63 for label in labels)
        or host == "localhost"
        or host.endswith((".localhost", ".local", ".internal", ".home", ".lan"))
    ):
        raise WebhookDestinationProtocolError("Webhook endpoint hostname is prohibited.")
    normalized_events = sorted(set(event_types))
    if (
        not normalized_events
        or len(normalized_events) != len(event_types)
        or not set(normalized_events) <= ALLOWED_WEBHOOK_EVENT_TYPES
    ):
        raise WebhookDestinationProtocolError("Webhook event types are invalid.")
    netloc = host if port is None else f"{host}:443"
    path = parsed.path or "/"
    normalized_url = urlunsplit(("https", netloc, path, parsed.query, ""))
    return ValidatedWebhookDestination(
        endpoint_url=normalized_url,
        endpoint_origin=f"https://{netloc}",
        event_types=normalized_events,
    )
