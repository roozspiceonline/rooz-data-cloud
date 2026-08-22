from typing import Annotated

from fastapi import APIRouter, Depends, Header, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import request_id, success_payload
from ...core.pagination import (
    decode_schedule_list_cursor,
    decode_schedule_trigger_cursor,
    encode_schedule_list_cursor,
    encode_schedule_trigger_cursor,
    normalize_limit,
)
from ...schedule_schemas import CreateScheduleRequest, ScheduleTriggerSummary
from ...services.schedules import (
    create_schedule,
    list_schedule_triggers,
    list_schedules,
    schedule_summary,
    set_schedule_paused,
)
from ..agent_dependencies import (
    AgentVersionAccess,
    ProjectAccess,
    ScheduleAccess,
    require_agent_version_permission,
    require_project_permission,
    require_schedule_permission,
)
from ..dependencies import AuthContext, require_csrf

router = APIRouter(tags=["schedules"])


def _actor(context: AuthContext) -> tuple[str, str]:
    if context.principal.auth_type == "api_key":
        if context.principal.api_key_id is None:
            raise RuntimeError("API-key context is missing an API-key ID")
        return "api_key", str(context.principal.api_key_id)
    return "user", str(context.user.id)


@router.post(
    "/agent-versions/{version_id}/schedules",
    status_code=status.HTTP_201_CREATED,
)
async def create_agent_schedule(
    payload: CreateScheduleRequest,
    request: Request,
    access: Annotated[
        AgentVersionAccess,
        Depends(require_agent_version_permission("schedule.create")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
    idempotency_key: Annotated[str, Header(alias="Idempotency-Key")],
) -> dict[str, object]:
    actor_type, actor_id = _actor(access.context)
    snapshot = await create_schedule(
        db,
        version=access.agent_version,
        user_id=access.context.user.id,
        actor_type=actor_type,
        actor_id=actor_id,
        idempotency_key=idempotency_key,
        request_id=request_id(request),
        payload=payload,
    )
    return success_payload(request, snapshot)


@router.get("/projects/{project_id}/schedules")
async def list_project_schedules(
    request: Request,
    access: Annotated[
        ProjectAccess, Depends(require_project_permission("schedule.read"))
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
    schedule_status: Annotated[
        str | None,
        Query(alias="status", pattern="^(ACTIVE|PAUSED|COMPLETED)$"),
    ] = None,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_schedule_list_cursor(
        cursor,
        project_id=access.project.id,
        status=schedule_status,
    )
    rows, has_more = await list_schedules(
        db,
        project_id=access.project.id,
        status=schedule_status,
        cursor=position,
        limit=normalized,
    )
    next_cursor = None
    if has_more and rows:
        final = rows[-1]
        next_cursor = encode_schedule_list_cursor(
            project_id=access.project.id,
            status=schedule_status,
            created_at=final.created_at,
            resource_id=final.id,
        )
    return {
        "data": [schedule_summary(row) for row in rows],
        "meta": {
            "request_id": request_id(request),
            "page": {
                "next_cursor": next_cursor,
                "has_more": next_cursor is not None,
            },
        },
    }


@router.get("/schedules/{schedule_id}")
async def get_schedule(
    request: Request,
    access: Annotated[
        ScheduleAccess, Depends(require_schedule_permission("schedule.read"))
    ],
) -> dict[str, object]:
    return success_payload(request, schedule_summary(access.schedule))


async def _change_pause_state(
    *,
    paused: bool,
    request: Request,
    access: ScheduleAccess,
    db: AsyncSession,
) -> dict[str, object]:
    actor_type, actor_id = _actor(access.context)
    record = await set_schedule_paused(
        db,
        schedule_id=access.schedule.id,
        paused=paused,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
    )
    return success_payload(request, schedule_summary(record))


@router.post("/schedules/{schedule_id}/pause")
async def pause_schedule(
    request: Request,
    access: Annotated[
        ScheduleAccess, Depends(require_schedule_permission("schedule.update"))
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    return await _change_pause_state(
        paused=True, request=request, access=access, db=db
    )


@router.post("/schedules/{schedule_id}/resume")
async def resume_schedule(
    request: Request,
    access: Annotated[
        ScheduleAccess, Depends(require_schedule_permission("schedule.update"))
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    return await _change_pause_state(
        paused=False, request=request, access=access, db=db
    )


@router.get("/schedules/{schedule_id}/triggers")
async def list_triggers(
    request: Request,
    access: Annotated[
        ScheduleAccess, Depends(require_schedule_permission("schedule.read"))
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
    outcome: Annotated[
        str | None, Query(pattern="^(FIRED|SKIPPED|FAILED)$")
    ] = None,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_schedule_trigger_cursor(
        cursor,
        schedule_id=access.schedule.id,
        outcome=outcome,
    )
    rows, has_more = await list_schedule_triggers(
        db,
        schedule_id=access.schedule.id,
        outcome=outcome,
        cursor=position,
        limit=normalized,
    )
    next_cursor = None
    if has_more and rows:
        final = rows[-1]
        next_cursor = encode_schedule_trigger_cursor(
            schedule_id=access.schedule.id,
            outcome=outcome,
            created_at=final.created_at,
            resource_id=final.id,
        )
    return {
        "data": [
            ScheduleTriggerSummary.model_validate(row).model_dump(mode="json")
            for row in rows
        ],
        "meta": {
            "request_id": request_id(request),
            "page": {
                "next_cursor": next_cursor,
                "has_more": next_cursor is not None,
            },
        },
    }
