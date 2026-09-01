from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from ...core.database import get_db
from ...core.errors import success_payload
from ...services.project_diagnostics import (
    ProjectDiagnostics,
    read_project_diagnostics,
)
from ..agent_dependencies import ProjectAccess, require_project_permission

router = APIRouter(tags=["diagnostics"])


def project_diagnostics_payload(diagnostics: ProjectDiagnostics) -> dict[str, object]:
    return {
        "observed_at": diagnostics.observed_at.isoformat(),
        "execution": {
            "active_leases": diagnostics.active_execution_leases,
            "build_dispatch_ready": diagnostics.build_dispatch_ready,
            "run_commands_ready": diagnostics.run_commands_ready,
        },
        "schedules": {"due": diagnostics.schedules_due},
        "request_queues": {
            "ready": diagnostics.request_queue_ready,
            "claimed": diagnostics.request_queue_claimed,
            "failed": diagnostics.request_queue_failed,
        },
        "credential_canaries": {
            "ready": diagnostics.credential_canaries_ready,
            "claimed": diagnostics.credential_canaries_claimed,
            "failed": diagnostics.credential_canaries_failed,
        },
        "webhook_deliveries": {
            "ready": diagnostics.webhook_deliveries_ready,
            "claimed": diagnostics.webhook_deliveries_claimed,
            "dead_lettered": diagnostics.webhook_deliveries_dead_lettered,
        },
    }


@router.get("/projects/{project_id}/diagnostics")
async def get_project_diagnostics(
    request: Request,
    access: Annotated[
        ProjectAccess,
        Depends(require_project_permission("diagnostic.read")),
    ],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> dict[str, object]:
    diagnostics = await read_project_diagnostics(
        db,
        project_id=access.project.id,
    )
    return success_payload(request, project_diagnostics_payload(diagnostics))
