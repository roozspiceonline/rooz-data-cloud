from typing import Annotated

from fastapi import APIRouter, Body, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import request_id, success_payload
from ...core.pagination import decode_cursor, encode_cursor, normalize_limit
from ...kv_schemas import CreateKeyValueStoreRequest
from ...services.key_value_stores import (
    create_project_key_value_store,
    create_run_key_value_store,
    key_value_mutation_receipt_summary,
    key_value_store_summary,
    list_key_value_stores,
    mutate_key_value_record,
)
from ..agent_dependencies import (
    KeyValueStoreAccess,
    ProjectAccess,
    RunAccess,
    require_key_value_store_permission,
    require_project_permission,
    require_run_permission,
)
from ..dependencies import AuthContext, require_csrf

router = APIRouter(tags=["key-value-stores"])


def actor(context: AuthContext) -> tuple[str, str]:
    if context.principal.auth_type == "api_key":
        if context.principal.api_key_id is None:
            raise RuntimeError("API-key context is missing an API-key ID")
        return "api_key", str(context.principal.api_key_id)
    return "user", str(context.user.id)


@router.post(
    "/projects/{project_id}/key-value-stores",
    status_code=status.HTTP_201_CREATED,
)
async def create_project_key_value_store_route(
    payload: CreateKeyValueStoreRequest,
    request: Request,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("kv.create")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    record = await create_project_key_value_store(
        db,
        project=access.project,
        user_id=access.context.user.id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
        payload=payload,
    )
    return success_payload(
        request,
        key_value_store_summary(record).model_dump(mode="json"),
    )


@router.post(
    "/runs/{run_id}/key-value-stores",
    status_code=status.HTTP_201_CREATED,
)
async def create_run_key_value_store_route(
    payload: CreateKeyValueStoreRequest,
    request: Request,
    access: Annotated[
        RunAccess,
        Depends(require_run_permission("kv.create")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    record = await create_run_key_value_store(
        db,
        run=access.run,
        user_id=access.context.user.id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
        payload=payload,
    )
    return success_payload(
        request,
        key_value_store_summary(record).model_dump(mode="json"),
    )


@router.get("/projects/{project_id}/key-value-stores")
async def list_key_value_stores_route(
    request: Request,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("kv.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_cursor(cursor)
    records, has_more = await list_key_value_stores(
        db,
        project_id=access.project.id,
        cursor=position,
        limit=normalized,
    )
    next_cursor = None
    if has_more and records:
        final = records[-1]
        next_cursor = encode_cursor(
            created_at=final.created_at,
            resource_id=final.id,
        )
    return {
        "data": [
            key_value_store_summary(record).model_dump(mode="json")
            for record in records
        ],
        "meta": {
            "request_id": request_id(request),
            "page": {
                "next_cursor": next_cursor,
                "has_more": next_cursor is not None,
            },
        },
    }


@router.get("/key-value-stores/{store_id}")
async def get_key_value_store_route(
    request: Request,
    access: Annotated[
        KeyValueStoreAccess,
        Depends(require_key_value_store_permission("kv.read")),
    ],
) -> dict[str, object]:
    return success_payload(
        request,
        key_value_store_summary(access.store).model_dump(mode="json"),
    )


@router.put("/key-value-stores/{store_id}/records")
async def set_key_value_record_route(
    payload: Annotated[object, Body()],
    request: Request,
    access: Annotated[
        KeyValueStoreAccess,
        Depends(require_key_value_store_permission("kv.write")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    outcome = await mutate_key_value_record(
        db,
        store=access.store,
        user_id=access.context.user.id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
        payload=payload,
        required_operation="set",
    )
    return success_payload(
        request,
        key_value_mutation_receipt_summary(outcome).model_dump(mode="json"),
    )


@router.delete("/key-value-stores/{store_id}/records")
async def delete_key_value_record_route(
    payload: Annotated[object, Body()],
    request: Request,
    access: Annotated[
        KeyValueStoreAccess,
        Depends(require_key_value_store_permission("kv.delete")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    outcome = await mutate_key_value_record(
        db,
        store=access.store,
        user_id=access.context.user.id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
        payload=payload,
        required_operation="delete",
    )
    return success_payload(
        request,
        key_value_mutation_receipt_summary(outcome).model_dump(mode="json"),
    )
