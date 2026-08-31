"""Claim-fenced database boundary for the trusted webhook delivery runner."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.errors import ApiError


@dataclass(frozen=True)
class ClaimedWebhookDeliveryCanary:
    id: UUID
    organization_id: UUID
    project_id: UUID
    destination_id: UUID
    event_id: UUID
    attempt_count: int
    claim_token: str = field(repr=False)
    claim_expires_at: datetime


@dataclass(frozen=True)
class WebhookDeliveryMaterial:
    organization_id: UUID
    project_id: UUID
    destination_id: UUID
    event_id: UUID
    endpoint_url: str
    event_type: str
    event_occurred_at: datetime
    event_payload: dict[str, object]
    signing_secret_id: UUID
    secret_name: str
    secret_version: int
    encrypted_value: bytes = field(repr=False)
    value_nonce: bytes = field(repr=False)
    wrapped_data_key: bytes = field(repr=False)
    key_nonce: bytes = field(repr=False)
    encryption_algorithm: str
    master_key_version: str


@dataclass(frozen=True)
class CompletedWebhookDeliveryCanary:
    id: UUID
    status: str
    outcome: str
    retry_scheduled: bool
    available_at: datetime


def _claim_digest(claim_token: str) -> str | None:
    try:
        return hashlib.sha256(claim_token.encode("ascii")).hexdigest()
    except UnicodeEncodeError:
        return None


async def claim_webhook_delivery_canaries(
    session: AsyncSession,
    *,
    now: datetime,
    batch_size: int,
    claim_seconds: int,
    worker_id: str,
) -> list[ClaimedWebhookDeliveryCanary]:
    rows = (
        (
            await session.execute(
                text(
                    "SELECT * FROM control.claim_webhook_delivery_canary("
                    ":now, :batch_size, :claim_seconds, :worker_id)"
                ),
                {
                    "now": now,
                    "batch_size": batch_size,
                    "claim_seconds": claim_seconds,
                    "worker_id": worker_id,
                },
            )
        )
        .mappings()
        .all()
    )
    return [
        ClaimedWebhookDeliveryCanary(
            id=row["delivery_id"],
            organization_id=row["organization_id"],
            project_id=row["project_id"],
            destination_id=row["destination_id"],
            event_id=row["event_id"],
            attempt_count=row["attempt_count"],
            claim_token=row["claim_token"],
            claim_expires_at=row["claim_expires_at"],
        )
        for row in rows
    ]


async def load_webhook_delivery_material(
    session: AsyncSession,
    *,
    delivery_id: UUID,
    claim_token: str,
) -> WebhookDeliveryMaterial | None:
    token_digest = _claim_digest(claim_token)
    if token_digest is None:
        return None
    row = (
        (
            await session.execute(
                text(
                    "SELECT * FROM control.load_webhook_delivery_claim("
                    ":delivery_id, :claim_token_digest)"
                ),
                {"delivery_id": delivery_id, "claim_token_digest": token_digest},
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    return WebhookDeliveryMaterial(
        organization_id=row["organization_id"],
        project_id=row["project_id"],
        destination_id=row["destination_id"],
        event_id=row["event_id"],
        endpoint_url=row["endpoint_url"],
        event_type=row["event_type"],
        event_occurred_at=row["event_occurred_at"],
        event_payload=dict(row["event_payload"]),
        signing_secret_id=row["signing_secret_id"],
        secret_name=row["secret_name"],
        secret_version=row["secret_version"],
        encrypted_value=bytes(row["encrypted_value"]),
        value_nonce=bytes(row["value_nonce"]),
        wrapped_data_key=bytes(row["wrapped_data_key"]),
        key_nonce=bytes(row["key_nonce"]),
        encryption_algorithm=row["encryption_algorithm"],
        master_key_version=row["master_key_version"],
    )


async def complete_webhook_delivery_canary(
    session: AsyncSession,
    *,
    delivery_id: UUID,
    claim_token: str,
    outcome: str,
    http_status: int | None,
    now: datetime,
) -> CompletedWebhookDeliveryCanary:
    token_digest = _claim_digest(claim_token)
    if token_digest is None:
        row = None
    else:
        row = (
            (
                await session.execute(
                    text(
                        "SELECT * FROM control.complete_webhook_delivery_canary("
                        ":delivery_id, :claim_token_digest, :outcome, :http_status, :now)"
                    ),
                    {
                        "delivery_id": delivery_id,
                        "claim_token_digest": token_digest,
                        "outcome": outcome,
                        "http_status": http_status,
                        "now": now,
                    },
                )
            )
            .mappings()
            .one_or_none()
        )
    if row is None:
        raise ApiError(
            status_code=409,
            code="WEBHOOK_CLAIM_FENCED",
            message="The webhook delivery claim is stale.",
        )
    return CompletedWebhookDeliveryCanary(
        id=row["delivery_id"],
        status=row["status"],
        outcome=row["outcome"],
        retry_scheduled=row["retry_scheduled"],
        available_at=row["available_at"],
    )
