from __future__ import annotations

from datetime import datetime, timedelta
from uuid import UUID, uuid4

from sqlalchemy import select, text
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.errors import ApiError
from ..core.security import canonical_fingerprint
from ..models import (
    EgressCredentialCanaryAttempt,
    EgressPolicy,
    EgressPolicyRevision,
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


async def _enable_scheduler_context(session: AsyncSession) -> None:
    await session.execute(text("SELECT set_config('rdc.egress_canary_scheduler', '1', true)"))


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
    await _enable_scheduler_context(session)
    revisions = list(
        (
            await session.scalars(
                select(EgressPolicyRevision)
                .join(EgressPolicy, EgressPolicy.id == EgressPolicyRevision.policy_id)
                .where(
                    EgressPolicy.organization_id == secret.organization_id,
                    EgressPolicy.project_id == secret.project_id,
                    EgressPolicy.status == "ACTIVE",
                    EgressPolicy.active_revision_id == EgressPolicyRevision.id,
                    EgressPolicyRevision.credential_secret_id == secret.id,
                )
                .order_by(EgressPolicyRevision.id)
            )
        ).all()
    )
    target_digest = configured_target_digest()
    created = 0
    for revision in revisions:
        attempt_id = await session.scalar(
            pg_insert(EgressCredentialCanaryAttempt)
            .values(
                id=uuid4(),
                organization_id=secret.organization_id,
                project_id=secret.project_id,
                policy_id=revision.policy_id,
                policy_revision_id=revision.id,
                credential_secret_id=secret.id,
                secret_version=secret.version,
                target_digest=target_digest,
                provider_key=settings.egress_route_provider_key,
                region_key=settings.egress_route_region_key,
                status="PENDING",
                attempt_count=0,
                version=1,
            )
            .on_conflict_do_nothing(
                index_elements=[
                    "policy_revision_id",
                    "secret_version",
                    "target_digest",
                ]
            )
            .returning(EgressCredentialCanaryAttempt.id)
        )
        if attempt_id is None:
            continue
        created += 1
        await append_audit_event(
            session,
            organization_id=secret.organization_id,
            project_id=secret.project_id,
            actor_type="system",
            actor_id="egress-credential-canary",
            action="egress.credential_canary.enqueued",
            resource_type="egress_credential_canary",
            resource_id=str(attempt_id),
            request_id=request_id,
            details={
                "policy_id": str(revision.policy_id),
                "policy_revision_id": str(revision.id),
                "provider_key": settings.egress_route_provider_key,
                "region_key": settings.egress_route_region_key,
            },
        )
    return created


async def claim_credential_rotation_canaries(
    session: AsyncSession,
    *,
    now: datetime,
    batch_size: int,
) -> list[EgressCredentialCanaryAttempt]:
    """Reclaim expired work and claim a bounded batch with row-level fencing."""
    if not 1 <= batch_size <= settings.egress_credential_canary_batch_size:
        raise ValueError("Credential canary batch size is outside the configured bound")
    await _enable_scheduler_context(session)
    expired = list(
        (
            await session.scalars(
                select(EgressCredentialCanaryAttempt)
                .where(
                    EgressCredentialCanaryAttempt.status == "CLAIMED",
                    EgressCredentialCanaryAttempt.claim_expires_at <= now,
                )
                .order_by(EgressCredentialCanaryAttempt.claim_expires_at)
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            )
        ).all()
    )
    for attempt in expired:
        if attempt.attempt_count >= settings.egress_credential_canary_max_attempts:
            attempt.status = "FAILED"
            attempt.completed_at = now
            attempt.outcome = "MAX_ATTEMPTS_EXCEEDED"
            attempt.healthy = False
            attempt.retryable = False
        else:
            attempt.status = "PENDING"
            attempt.claim_token = None
            attempt.claim_expires_at = None
            attempt.claimed_at = None
        attempt.version += 1
    await session.flush()

    pending = list(
        (
            await session.scalars(
                select(EgressCredentialCanaryAttempt)
                .where(EgressCredentialCanaryAttempt.status == "PENDING")
                .order_by(
                    EgressCredentialCanaryAttempt.scheduled_at,
                    EgressCredentialCanaryAttempt.id,
                )
                .limit(batch_size)
                .with_for_update(skip_locked=True)
            )
        ).all()
    )
    claimed: list[EgressCredentialCanaryAttempt] = []
    for attempt in pending:
        attempt.status = "CLAIMED"
        attempt.attempt_count += 1
        attempt.claim_token = uuid4()
        attempt.claimed_at = now
        attempt.claim_expires_at = now + timedelta(
            seconds=settings.egress_credential_canary_claim_seconds
        )
        attempt.version += 1
        claimed.append(attempt)
    await session.flush()
    return claimed


async def complete_credential_rotation_canary(
    session: AsyncSession,
    *,
    attempt_id: UUID,
    claim_token: UUID,
    outcome: str,
    now: datetime,
) -> EgressCredentialCanaryAttempt:
    """Persist a bounded terminal result for an exact unexpired claim."""
    classification = CANARY_OUTCOMES.get(outcome)
    if classification is None:
        raise ApiError(
            status_code=422,
            code="EGRESS_CREDENTIAL_CANARY_OUTCOME_INVALID",
            message="The credential canary outcome is invalid.",
        )
    await _enable_scheduler_context(session)
    attempt = await session.scalar(
        select(EgressCredentialCanaryAttempt)
        .where(EgressCredentialCanaryAttempt.id == attempt_id)
        .with_for_update()
    )
    if (
        attempt is None
        or attempt.status != "CLAIMED"
        or attempt.claim_token != claim_token
        or attempt.claim_expires_at is None
        or attempt.claim_expires_at <= now
    ):
        raise ApiError(
            status_code=409,
            code="EGRESS_CREDENTIAL_CANARY_CLAIM_STALE",
            message="The credential canary claim is stale.",
        )
    current_version = await session.scalar(
        select(ProjectSecret.version).where(
            ProjectSecret.id == attempt.credential_secret_id,
            ProjectSecret.organization_id == attempt.organization_id,
            ProjectSecret.project_id == attempt.project_id,
        )
    )
    if attempt.target_digest != configured_target_digest():
        status, normalized_outcome, healthy, retryable = (
            "FAILED",
            "CONFIGURATION_ERROR",
            False,
            False,
        )
    elif current_version != attempt.secret_version:
        status, normalized_outcome, healthy, retryable = (
            "SUPERSEDED",
            "SECRET_VERSION_SUPERSEDED",
            False,
            False,
        )
    else:
        status, healthy, retryable = classification
        normalized_outcome = outcome
    attempt.status = status
    attempt.completed_at = now
    attempt.outcome = normalized_outcome
    attempt.healthy = healthy
    attempt.retryable = retryable
    attempt.version += 1
    await session.flush()
    return attempt


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
