import asyncio
import json
import time
from collections.abc import AsyncIterator
from datetime import UTC, datetime
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Header, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.config import get_settings
from ...core.database import get_db, session_factory, set_tenant_context
from ...core.errors import ApiError, request_id, success_payload
from ...core.pagination import decode_cursor, encode_cursor, normalize_limit
from ...core.permissions import role_has_permission
from ...core.security import is_expired
from ...models import ApiKey, OrganizationMembership, Run, Session
from ...run_schemas import CreateRunRequest, RunStatus, RunSummary
from ...services.runs import (
    RUN_TERMINAL_STATUSES,
    cancel_run,
    create_run,
    list_project_runs,
    list_run_events,
    minimum_run_event_sequence,
    run_metadata,
)
from ..agent_dependencies import (
    AgentVersionAccess,
    ProjectAccess,
    RunAccess,
    require_agent_version_permission,
    require_project_permission,
    require_run_permission,
)
from ..dependencies import AuthContext, require_csrf

router = APIRouter()
settings = get_settings()
run_stream_slots = asyncio.Semaphore(settings.run_sse_max_connections)


def collection_payload(
    request: Request,
    data: list[dict[str, object]],
    *,
    next_cursor: str | None,
) -> dict[str, object]:
    return {
        "data": data,
        "meta": {
            "request_id": request_id(request),
            "page": {
                "next_cursor": next_cursor,
                "has_more": next_cursor is not None,
            },
        },
    }


def _parse_last_event_id(value: str | None) -> int:
    if value is None or not value.strip():
        return 0
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="Last-Event-ID must be a non-negative integer.",
        ) from exc
    if parsed < 0:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="Last-Event-ID must be a non-negative integer.",
        )
    return parsed


def _event_envelope(
    *,
    event_type: str,
    run_id: UUID,
    sequence: int,
    timestamp: datetime,
    payload: dict[str, object],
) -> dict[str, object]:
    return {
        "schema_version": "1",
        "event_type": event_type,
        "run_id": str(run_id),
        "sequence": sequence,
        "timestamp": timestamp.isoformat().replace("+00:00", "Z"),
        "payload": payload,
    }


def _sse_frame(
    *,
    event_type: str,
    envelope: dict[str, object],
    event_id: int | None = None,
) -> str:
    lines: list[str] = []
    if event_id is not None:
        lines.append(f"id: {event_id:016d}")
    lines.append(f"event: {event_type}")
    lines.append(
        "data: "
        + json.dumps(
            envelope,
            allow_nan=False,
            separators=(",", ":"),
        )
    )
    return "\n".join(lines) + "\n\n"


async def _stream_authorized(
    db: AsyncSession,
    *,
    context: AuthContext,
    organization_id: UUID,
) -> bool:
    now = datetime.now(UTC)
    if context.principal.auth_type == "session":
        session_id = context.principal.session_id
        if session_id is None:
            return False
        record = await db.scalar(
            select(Session).where(Session.id == session_id)
        )
        if (
            record is None
            or record.revoked_at is not None
            or record.idle_expires_at <= now
            or record.absolute_expires_at <= now
        ):
            return False
        membership = await db.scalar(
            select(OrganizationMembership).where(
                OrganizationMembership.organization_id == organization_id,
                OrganizationMembership.user_id == context.user.id,
                OrganizationMembership.status == "ACTIVE",
            )
        )
        return (
            membership is not None
            and role_has_permission(membership.role, "run.read")
        )

    api_key_id = context.principal.api_key_id
    if api_key_id is None:
        return False
    api_key = await db.scalar(
        select(ApiKey).where(
            ApiKey.id == api_key_id,
            ApiKey.organization_id == organization_id,
        )
    )
    return (
        api_key is not None
        and api_key.revoked_at is None
        and not is_expired(api_key.expires_at, now=now)
        and "run.read" in api_key.scopes
    )


async def _run_event_stream(
    request: Request,
    *,
    access: RunAccess,
    last_event_id: int,
) -> AsyncIterator[str]:
    run_id = access.run.id
    organization_id = access.run.organization_id
    user_id = access.context.user.id
    cursor = last_event_id
    last_heartbeat = time.monotonic()

    try:
        yield _sse_frame(
            event_type="run.connected",
            envelope=_event_envelope(
                event_type="run.connected",
                run_id=run_id,
                sequence=cursor,
                timestamp=datetime.now(UTC),
                payload={"status": access.run.status},
            ),
        )

        replay_checked = False
        while True:
            if await request.is_disconnected():
                break

            async with session_factory() as db:
                await set_tenant_context(
                    db,
                    user_id=user_id,
                    organization_id=organization_id,
                )
                if not await _stream_authorized(
                    db,
                    context=access.context,
                    organization_id=organization_id,
                ):
                    break
                if not replay_checked and cursor > 0:
                    minimum = await minimum_run_event_sequence(
                        db,
                        run_id=run_id,
                    )
                    if minimum is not None and cursor < minimum - 1:
                        cursor = minimum - 1
                        yield _sse_frame(
                            event_type="run.replay_reset",
                            envelope=_event_envelope(
                                event_type="run.replay_reset",
                                run_id=run_id,
                                sequence=cursor,
                                timestamp=datetime.now(UTC),
                                payload={
                                    "reason": "replay_window_unavailable"
                                },
                            ),
                        )
                    replay_checked = True

                events = await list_run_events(
                    db,
                    run_id=run_id,
                    after_sequence=cursor,
                    limit=settings.run_sse_replay_limit,
                )
                current = await db.scalar(
                    select(Run).where(
                        Run.id == run_id,
                        Run.organization_id == organization_id,
                    )
                )

            for event in events:
                cursor = event.sequence
                yield _sse_frame(
                    event_type=event.event_type,
                    event_id=event.sequence,
                    envelope=_event_envelope(
                        event_type=event.event_type,
                        run_id=event.run_id,
                        sequence=event.sequence,
                        timestamp=event.created_at,
                        payload=event.payload,
                    ),
                )

            if (
                current is None
                or (
                    current.status in RUN_TERMINAL_STATUSES
                    and not events
                )
            ):
                break

            now_monotonic = time.monotonic()
            if (
                now_monotonic - last_heartbeat
                >= settings.run_sse_heartbeat_seconds
            ):
                last_heartbeat = now_monotonic
                yield _sse_frame(
                    event_type="run.heartbeat",
                    envelope=_event_envelope(
                        event_type="run.heartbeat",
                        run_id=run_id,
                        sequence=cursor,
                        timestamp=datetime.now(UTC),
                        payload={},
                    ),
                )

            await asyncio.sleep(settings.run_sse_poll_interval_seconds)
    finally:
        run_stream_slots.release()


@router.post(
    "/agent-versions/{version_id}/runs",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["runs"],
)
async def create_run_route(
    payload: CreateRunRequest,
    request: Request,
    context: Annotated[AuthContext, Depends(require_csrf)],
    access: Annotated[
        AgentVersionAccess,
        Depends(require_agent_version_permission("run.create")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    idempotency_key: Annotated[
        str | None,
        Header(alias="Idempotency-Key"),
    ] = None,
) -> dict[str, object]:
    if idempotency_key is None:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="Idempotency-Key is required.",
        )
    result = await create_run(
        db,
        version=access.agent_version,
        user_id=context.user.id,
        idempotency_key=idempotency_key,
        payload=payload,
        request_id=request_id(request),
    )
    data = RunSummary.model_validate(result)
    return success_payload(request, data.model_dump(mode="json"))


@router.get("/runs/{run_id}", tags=["runs"])
async def get_run_route(
    request: Request,
    access: Annotated[
        RunAccess,
        Depends(require_run_permission("run.read")),
    ],
) -> dict[str, object]:
    data = RunSummary.model_validate(run_metadata(access.run))
    return success_payload(request, data.model_dump(mode="json"))


@router.post(
    "/runs/{run_id}/cancel",
    status_code=status.HTTP_202_ACCEPTED,
    tags=["runs"],
)
async def cancel_run_route(
    request: Request,
    context: Annotated[AuthContext, Depends(require_csrf)],
    access: Annotated[
        RunAccess,
        Depends(require_run_permission("run.cancel")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    idempotency_key: Annotated[
        str | None,
        Header(alias="Idempotency-Key"),
    ] = None,
) -> dict[str, object]:
    if idempotency_key is None:
        raise ApiError(
            status_code=400,
            code="INVALID_REQUEST",
            message="Idempotency-Key is required.",
        )
    result = await cancel_run(
        db,
        record=access.run,
        user_id=context.user.id,
        idempotency_key=idempotency_key,
        request_id=request_id(request),
    )
    data = RunSummary.model_validate(result)
    return success_payload(request, data.model_dump(mode="json"))


@router.get("/projects/{project_id}/runs", tags=["runs"])
async def list_project_runs_route(
    request: Request,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("run.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
    run_status: Annotated[RunStatus | None, Query(alias="status")] = None,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_cursor(cursor)
    records, has_more = await list_project_runs(
        db,
        project_id=access.project.id,
        cursor=position,
        limit=normalized,
        status=run_status,
    )
    next_cursor = None
    if has_more and records:
        last = records[-1]
        next_cursor = encode_cursor(
            created_at=last.queued_at,
            resource_id=last.id,
        )
    data = [
        RunSummary.model_validate(run_metadata(item)).model_dump(mode="json")
        for item in records
    ]
    return collection_payload(request, data, next_cursor=next_cursor)


@router.get("/runs/{run_id}/events", tags=["runs"])
async def stream_run_events_route(
    request: Request,
    access: Annotated[
        RunAccess,
        Depends(require_run_permission("run.read")),
    ],
    last_event_id_header: Annotated[
        str | None,
        Header(alias="Last-Event-ID"),
    ] = None,
    last_event_id_query: Annotated[
        str | None,
        Query(alias="last_event_id"),
    ] = None,
) -> StreamingResponse:
    last_event_id = _parse_last_event_id(
        last_event_id_header or last_event_id_query
    )
    try:
        await asyncio.wait_for(run_stream_slots.acquire(), timeout=0.01)
    except TimeoutError as exc:
        raise ApiError(
            status_code=429,
            code="RATE_LIMITED",
            message="Too many Run event streams are currently open.",
        ) from exc

    return StreamingResponse(
        _run_event_stream(
            request,
            access=access,
            last_event_id=last_event_id,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
