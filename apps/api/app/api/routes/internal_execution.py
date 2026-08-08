from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import request_id, success_payload
from ...dataset_schemas import DatasetAppendRequest, DatasetAppendResult
from ...execution_schemas import (
    AppendWorkerEventsRequest,
    ArtifactUploadRequest,
    ClaimWorkRequest,
    CompleteLeaseRequest,
    LeaseStatusUpdateRequest,
    RegisterWorkerRequest,
    RenewLeaseRequest,
    SecretEnvelopeRequest,
    WorkerHeartbeatRequest,
)
from ...services.datasets import dataset_append_receipt_summary
from ...services.execution_plane import (
    append_worker_dataset_items,
    append_worker_events,
    claim_work,
    complete_lease,
    heartbeat_worker,
    issue_artifact_upload_grant,
    issue_run_artifact_download_grant,
    issue_secret_envelope,
    register_worker,
    renew_lease,
    update_lease_status,
    worker_summary,
)
from ...services.storage_delivery import issue_build_source_download_grant
from ..internal_dependencies import (
    LeaseAccess,
    WorkerContext,
    require_lease_access,
    require_worker_bootstrap,
    resolve_worker_context,
)

router = APIRouter(
    prefix="/internal/v1",
    tags=["internal-execution"],
    include_in_schema=False,
)


@router.post(
    "/workers/register",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_worker_bootstrap)],
)
async def register_worker_route(
    payload: RegisterWorkerRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    result = await register_worker(
        db,
        payload=payload,
        request_id=request_id(request),
    )
    return success_payload(request, result.model_dump(mode="json"))


@router.get("/workers/me")
async def get_worker_route(
    request: Request,
    context: Annotated[WorkerContext, Depends(resolve_worker_context)],
) -> dict[str, object]:
    return success_payload(
        request,
        worker_summary(context.worker).model_dump(mode="json"),
    )


@router.post("/workers/me/heartbeat")
async def heartbeat_worker_route(
    payload: WorkerHeartbeatRequest,
    request: Request,
    context: Annotated[WorkerContext, Depends(resolve_worker_context)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    result = await heartbeat_worker(
        db,
        worker=context.worker,
        payload=payload,
        request_id=request_id(request),
    )
    return success_payload(request, result.model_dump(mode="json"))


@router.post("/leases/claim")
async def claim_work_route(
    payload: ClaimWorkRequest,
    request: Request,
    response: Response,
    context: Annotated[WorkerContext, Depends(resolve_worker_context)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object] | None:
    result = await claim_work(
        db,
        worker=context.worker,
        payload=payload,
        request_id=request_id(request),
    )
    if result is None:
        response.status_code = status.HTTP_204_NO_CONTENT
        return None
    return success_payload(request, result.model_dump(mode="json"))


@router.post("/leases/{lease_id}/renew")
async def renew_lease_route(
    payload: RenewLeaseRequest,
    request: Request,
    access: Annotated[LeaseAccess, Depends(require_lease_access)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    result = await renew_lease(
        db,
        lease=access.lease,
        worker=access.context.worker,
        payload=payload,
        request_id=request_id(request),
    )
    return success_payload(request, result.model_dump(mode="json"))


@router.post("/leases/{lease_id}/status")
async def update_lease_status_route(
    payload: LeaseStatusUpdateRequest,
    request: Request,
    access: Annotated[LeaseAccess, Depends(require_lease_access)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    result = await update_lease_status(
        db,
        lease=access.lease,
        worker=access.context.worker,
        payload=payload,
        request_id=request_id(request),
    )
    return success_payload(request, result.model_dump(mode="json"))


@router.post("/leases/{lease_id}/events")
async def append_worker_events_route(
    payload: AppendWorkerEventsRequest,
    request: Request,
    access: Annotated[LeaseAccess, Depends(require_lease_access)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    count = await append_worker_events(
        db,
        lease=access.lease,
        worker=access.context.worker,
        payload=payload,
        request_id=request_id(request),
    )
    return success_payload(request, {"accepted": count})


@router.post("/leases/{lease_id}/secret-envelope")
async def issue_secret_envelope_route(
    payload: SecretEnvelopeRequest,
    request: Request,
    access: Annotated[LeaseAccess, Depends(require_lease_access)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    result = await issue_secret_envelope(
        db,
        lease=access.lease,
        worker=access.context.worker,
        payload=payload,
        request_id=request_id(request),
    )
    return success_payload(request, result.model_dump(mode="json"))


@router.post(
    "/leases/{lease_id}/dataset-append",
    status_code=status.HTTP_201_CREATED,
)
async def append_worker_dataset_items_route(
    payload: DatasetAppendRequest,
    request: Request,
    response: Response,
    access: Annotated[LeaseAccess, Depends(require_lease_access)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    outcome = await append_worker_dataset_items(
        db,
        lease=access.lease,
        worker=access.context.worker,
        payload=payload.model_dump(mode="python"),
        request_id=request_id(request),
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
    return success_payload(request, result.model_dump(mode="json"))


@router.post("/leases/{lease_id}/complete")
async def complete_lease_route(
    payload: CompleteLeaseRequest,
    request: Request,
    access: Annotated[LeaseAccess, Depends(require_lease_access)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    result = await complete_lease(
        db,
        lease=access.lease,
        worker=access.context.worker,
        payload=payload,
        request_id=request_id(request),
    )
    return success_payload(request, result.model_dump(mode="json"))


@router.post("/leases/{lease_id}/source-download")
async def issue_source_download_route(
    request: Request,
    access: Annotated[LeaseAccess, Depends(require_lease_access)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    result = await issue_build_source_download_grant(
        db,
        lease=access.lease,
        worker_id=access.context.worker.id,
        request_id=request_id(request),
    )
    return success_payload(request, result.model_dump(mode="json"))

@router.post("/leases/{lease_id}/artifact-upload")
async def issue_artifact_upload_route(
    payload: ArtifactUploadRequest,
    request: Request,
    access: Annotated[LeaseAccess, Depends(require_lease_access)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    result = await issue_artifact_upload_grant(
        db,
        lease=access.lease,
        worker=access.context.worker,
        payload=payload,
        request_id=request_id(request),
    )
    return success_payload(request, result.model_dump(mode="json"))


@router.post("/leases/{lease_id}/artifact-download")
async def issue_artifact_download_route(
    request: Request,
    access: Annotated[LeaseAccess, Depends(require_lease_access)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    result = await issue_run_artifact_download_grant(
        db,
        lease=access.lease,
        worker=access.context.worker,
        request_id=request_id(request),
    )
    return success_payload(request, result.model_dump(mode="json"))

