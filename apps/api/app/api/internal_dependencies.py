import hmac
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Header, Path
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.config import get_settings
from ..core.database import get_db, set_worker_context
from ..core.errors import ApiError
from ..core.security import secret_digest
from ..models import ExecutionLease, WorkerIdentity

settings = get_settings()
WORKER_TOKEN_PATTERN = re.compile(r"^rdc_worker_([a-z2-7]{8})_(.+)$")


@dataclass(frozen=True)
class WorkerContext:
    worker: WorkerIdentity


@dataclass(frozen=True)
class LeaseAccess:
    context: WorkerContext
    lease: ExecutionLease


async def require_worker_bootstrap(
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> None:
    if authorization is None:
        raise ApiError(
            status_code=401,
            code="INTERNAL_AUTH_REQUIRED",
            message="Internal worker authentication is required.",
        )
    scheme, _, token = authorization.partition(" ")
    if scheme.casefold() != "bearer" or not token:
        raise ApiError(
            status_code=401,
            code="INTERNAL_AUTH_REQUIRED",
            message="Internal worker authentication is required.",
        )
    supplied = secret_digest(token, settings.worker_token_pepper)
    expected = secret_digest(
        settings.worker_bootstrap_token,
        settings.worker_token_pepper,
    )
    if not hmac.compare_digest(supplied, expected):
        raise ApiError(
            status_code=401,
            code="INTERNAL_CREDENTIAL_INVALID",
            message="The internal credential is invalid.",
        )
    await db.execute(
        text(
            "SELECT set_config("
            "'rdc.worker_bootstrap_authenticated', 'true', true"
            ")"
        )
    )


async def resolve_worker_context(
    db: Annotated[AsyncSession, Depends(get_db)],
    authorization: Annotated[str | None, Header()] = None,
) -> WorkerContext:
    if authorization is None:
        raise ApiError(
            status_code=401,
            code="INTERNAL_AUTH_REQUIRED",
            message="Internal worker authentication is required.",
        )
    scheme, _, token = authorization.partition(" ")
    match = WORKER_TOKEN_PATTERN.fullmatch(token)
    if scheme.casefold() != "bearer" or match is None:
        raise ApiError(
            status_code=401,
            code="INTERNAL_CREDENTIAL_INVALID",
            message="The internal credential is invalid.",
        )
    public_prefix = match.group(1)
    record = await db.scalar(
        select(WorkerIdentity).where(
            WorkerIdentity.public_prefix == public_prefix
        )
    )
    now = datetime.now(UTC)
    if (
        record is None
        or record.status not in {"ACTIVE", "DRAINING"}
        or record.revoked_at is not None
        or (record.expires_at is not None and record.expires_at <= now)
    ):
        raise ApiError(
            status_code=401,
            code="INTERNAL_CREDENTIAL_INVALID",
            message="The internal credential is invalid.",
        )
    supplied_digest = secret_digest(token, settings.worker_token_pepper)
    if not hmac.compare_digest(record.token_digest, supplied_digest):
        raise ApiError(
            status_code=401,
            code="INTERNAL_CREDENTIAL_INVALID",
            message="The internal credential is invalid.",
        )
    await set_worker_context(db, record.id)
    record.last_seen_at = now
    return WorkerContext(worker=record)


async def require_lease_access(
    lease_id: Annotated[UUID, Path()],
    lease_token: Annotated[str | None, Header(alias="X-RDC-Lease-Token")],
    context: Annotated[WorkerContext, Depends(resolve_worker_context)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> LeaseAccess:
    if not lease_token:
        raise ApiError(
            status_code=401,
            code="LEASE_CREDENTIAL_INVALID",
            message="The lease credential is invalid.",
        )
    lease = await db.scalar(
        select(ExecutionLease)
        .where(
            ExecutionLease.id == lease_id,
            ExecutionLease.worker_id == context.worker.id,
        )
        .with_for_update()
    )
    now = datetime.now(UTC)
    supplied = secret_digest(lease_token, settings.lease_token_pepper)
    if (
        lease is None
        or lease.status != "ACTIVE"
        or lease.expires_at <= now
        or lease.deadline_at <= now
        or not hmac.compare_digest(lease.lease_token_digest, supplied)
    ):
        raise ApiError(
            status_code=401,
            code="LEASE_CREDENTIAL_INVALID",
            message="The lease credential is invalid or expired.",
        )
    return LeaseAccess(context=context, lease=lease)
