from typing import Annotated

from fastapi import APIRouter, Depends, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import request_id, success_payload
from ...core.pagination import decode_cursor, encode_cursor, normalize_limit
from ...dataset_schemas import (
    CreateDatasetRequest,
    DatasetAppendRequest,
    DatasetAppendResult,
)
from ...services.datasets import (
    append_dataset_items,
    create_dataset,
    dataset_append_receipt_summary,
    dataset_summary,
    list_datasets,
)
from ..agent_dependencies import (
    DatasetAccess,
    ProjectAccess,
    RunAccess,
    require_dataset_permission,
    require_project_permission,
    require_run_permission,
)
from ..dependencies import AuthContext, require_csrf

router = APIRouter(tags=["datasets"])


def actor(context: AuthContext) -> tuple[str, str]:
    if context.principal.auth_type == "api_key":
        if context.principal.api_key_id is None:
            raise RuntimeError("API-key context is missing an API-key ID")
        return "api_key", str(context.principal.api_key_id)
    return "user", str(context.user.id)


@router.post(
    "/runs/{run_id}/datasets",
    status_code=status.HTTP_201_CREATED,
)
async def create_dataset_route(
    payload: CreateDatasetRequest,
    request: Request,
    access: Annotated[
        RunAccess,
        Depends(require_run_permission("dataset.create")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    record = await create_dataset(
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
        dataset_summary(record).model_dump(mode="json"),
    )


@router.post(
    "/datasets/{dataset_id}/items",
    status_code=status.HTTP_201_CREATED,
)
async def append_dataset_items_route(
    payload: DatasetAppendRequest,
    request: Request,
    response: Response,
    access: Annotated[
        DatasetAccess,
        Depends(require_dataset_permission("dataset.write")),
    ],
    _: Annotated[AuthContext, Depends(require_csrf)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    actor_type, actor_id = actor(access.context)
    outcome = await append_dataset_items(
        db,
        dataset=access.dataset,
        user_id=access.context.user.id,
        actor_type=actor_type,
        actor_id=actor_id,
        request_id=request_id(request),
        payload=payload.model_dump(mode="python"),
    )
    response.status_code = (
        status.HTTP_200_OK
        if outcome.replayed
        else status.HTTP_201_CREATED
    )
    result = DatasetAppendResult(
        receipt=dataset_append_receipt_summary(outcome.receipt),
        replayed=outcome.replayed,
    )
    return success_payload(
        request,
        result.model_dump(mode="json"),
    )


@router.get("/projects/{project_id}/datasets")
async def list_datasets_route(
    request: Request,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("dataset.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
    cursor: Annotated[str | None, Query()] = None,
    limit: Annotated[int, Query()] = 50,
) -> dict[str, object]:
    normalized = normalize_limit(limit)
    position = decode_cursor(cursor)
    records, has_more = await list_datasets(
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
            dataset_summary(record).model_dump(mode="json")
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


@router.get("/datasets/{dataset_id}")
async def get_dataset_route(
    request: Request,
    access: Annotated[
        DatasetAccess,
        Depends(require_dataset_permission("dataset.read")),
    ],
) -> dict[str, object]:
    return success_payload(
        request,
        dataset_summary(access.dataset).model_dump(mode="json"),
    )
