from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.errors import ApiError
from ..core.security import canonical_fingerprint
from ..models import (
    EgressCredentialCanaryAttempt,
    ProjectSecret,
)
from .identity_tenancy import append_audit_event

settings = get_settings()

CANARY_OUTCOMES: dict[str, tuple[str, bool, bool]] = {
    "SUCCESS": ("SUCCEEDED", True, False),
    "AUTH_REJECTED": ("FAILED", False, False),
    "TARGET_ERROR": ("FAILED", False, True),
    "TIMEOUT": ("FAILED", False, True),
    "TLS_FAILURE": ("FAILED", False, False),
    "DNS_FAILURE": ("FAILED", False, True),
}


@dataclass(frozen=True)
class ClaimedCredentialCanary:
    id: UUID
    organization_id: UUID
    project_id: UUID
    policy_id: UUID
    policy_revision_id: UUID
    credential_secret_id: UUID
    secret_version: int
    target_digest: str
    provider_key: str
    region_key: str
    attempt_count: int
    claim_token: str = field(repr=False)
    claim_expires_at: datetime


@dataclass(frozen=True)
class CompletedCredentialCanary:
    id: UUID
    status: str
    outcome: str
    healthy: bool
    retryable: bool
    completed_at: datetime
    version: int


def configured_target_digest() -> str:
    return canonical_fingerprint(
        {
            "schema_version": "rdc.egress-credential-canary-target/v1",
            "url": settings.egress_credential_canary_target_url,
            "provider_key": settings.egress_route_provider_key,
            "region_key": settings.egress_route_region_key,
        }
    )


async def enqueue_credential_rotation_canaries(
    session: AsyncSession,
    *,
    secret: ProjectSecret,
    request_id: str,
) -> int:
    """Transactionally schedule one idempotent attempt per active bound revision."""
    if not settings.egress_credential_canary_enabled:
        return 0
    target_digest = configured_target_digest()
    rows = (
        await session.execute(
            text(
                "SELECT * FROM control.enqueue_egress_credential_canaries_for_secret("
                ":secret_id, :target_digest, :provider_key, :region_key)"
            ),
            {
                "secret_id": secret.id,
                "target_digest": target_digest,
                "provider_key": settings.egress_route_provider_key,
                "region_key": settings.egress_route_region_key,
            },
        )
    ).mappings().all()
    for row in rows:
        await append_audit_event(
            session,
            organization_id=secret.organization_id,
            project_id=secret.project_id,
            actor_type="system",
            actor_id="egress-credential-canary",
            action="egress.credential_canary.enqueued",
            resource_type="egress_credential_canary",
            resource_id=str(row["attempt_id"]),
            request_id=request_id,
            details={
                "policy_id": str(row["policy_id"]),
                "policy_revision_id": str(row["policy_revision_id"]),
                "provider_key": settings.egress_route_provider_key,
                "region_key": settings.egress_route_region_key,
            },
        )
    return len(rows)


async def claim_credential_rotation_canaries(
    session: AsyncSession,
    *,
    now: datetime,
    batch_size: int,
) -> list[ClaimedCredentialCanary]:
    """Reclaim expired work and claim a bounded batch with row-level fencing."""
    if not 1 <= batch_size <= settings.egress_credential_canary_batch_size:
        raise ValueError("Credential canary batch size is outside the configured bound")
    rows = (
        await session.execute(
            text(
                "SELECT * FROM control.claim_egress_credential_canaries("
                ":now, :batch_size, :claim_seconds, :max_attempts)"
            ),
            {
                "now": now,
                "batch_size": batch_size,
                "claim_seconds": settings.egress_credential_canary_claim_seconds,
                "max_attempts": settings.egress_credential_canary_max_attempts,
            },
        )
    ).mappings().all()
    return [
        ClaimedCredentialCanary(
            id=row["attempt_id"],
            organization_id=row["organization_id"],
            project_id=row["project_id"],
            policy_id=row["policy_id"],
            policy_revision_id=row["policy_revision_id"],
            credential_secret_id=row["credential_secret_id"],
            secret_version=row["secret_version"],
            target_digest=row["target_digest"],
            provider_key=row["provider_key"],
            region_key=row["region_key"],
            attempt_count=row["attempt_count"],
            claim_token=row["claim_token"],
            claim_expires_at=row["claim_expires_at"],
        )
        for row in rows
    ]


async def complete_credential_rotation_canary(
    session: AsyncSession,
    *,
    attempt_id: UUID,
    claim_token: str,
    outcome: str,
    now: datetime,
) -> CompletedCredentialCanary:
    """Persist a bounded terminal result for an exact unexpired claim."""
    classification = CANARY_OUTCOMES.get(outcome)
    if classification is None:
        raise ApiError(
            status_code=422,
            code="EGRESS_CREDENTIAL_CANARY_OUTCOME_INVALID",
            message="The credential canary outcome is invalid.",
        )
    token_digest = hashlib.sha256(claim_token.encode("ascii")).hexdigest()
    row = (
        await session.execute(
            text(
                "SELECT * FROM control.complete_egress_credential_canary("
                ":attempt_id, :claim_token_digest, :outcome, :target_digest, :now)"
            ),
            {
                "attempt_id": attempt_id,
                "claim_token_digest": token_digest,
                "outcome": outcome,
                "target_digest": configured_target_digest(),
                "now": now,
            },
        )
    ).mappings().one_or_none()
    if row is None:
        raise ApiError(
            status_code=409,
            code="EGRESS_CREDENTIAL_CANARY_CLAIM_STALE",
            message="The credential canary claim is stale.",
        )
    return CompletedCredentialCanary(
        id=row["attempt_id"],
        status=row["status"],
        outcome=row["outcome"],
        healthy=row["healthy"],
        retryable=row["retryable"],
        completed_at=row["completed_at"],
        version=row["version"],
    )


async def list_credential_rotation_canaries(
    session: AsyncSession,
    *,
    project_id: UUID,
    limit: int,
) -> list[dict[str, object]]:
    if not 1 <= limit <= 100:
        raise ValueError("Credential canary list limit must be between 1 and 100")
    attempts = list(
        (
            await session.scalars(
                select(EgressCredentialCanaryAttempt)
                .where(EgressCredentialCanaryAttempt.project_id == project_id)
                .order_by(
                    EgressCredentialCanaryAttempt.scheduled_at.desc(),
                    EgressCredentialCanaryAttempt.id.desc(),
                )
                .limit(limit)
            )
        ).all()
    )
    return [
        {
            "id": str(attempt.id),
            "policy_id": str(attempt.policy_id),
            "policy_revision_id": str(attempt.policy_revision_id),
            "provider_key": attempt.provider_key,
            "region_key": attempt.region_key,
            "status": attempt.status,
            "attempt_count": attempt.attempt_count,
            "outcome": attempt.outcome,
            "healthy": attempt.healthy,
            "retryable": attempt.retryable,
            "scheduled_at": attempt.scheduled_at.isoformat(),
            "completed_at": (
                attempt.completed_at.isoformat() if attempt.completed_at is not None else None
            ),
        }
        for attempt in attempts
    ]
