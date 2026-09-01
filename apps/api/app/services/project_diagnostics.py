from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from ..core.database import set_project_context

PROJECT_DIAGNOSTICS_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class ProjectDiagnostics:
    observed_at: datetime
    active_execution_leases: int
    build_dispatch_ready: int
    run_commands_ready: int
    schedules_due: int
    request_queue_ready: int
    request_queue_claimed: int
    request_queue_failed: int
    credential_canaries_ready: int
    credential_canaries_claimed: int
    credential_canaries_failed: int
    webhook_deliveries_ready: int
    webhook_deliveries_claimed: int
    webhook_deliveries_dead_lettered: int


async def read_project_diagnostics(
    session: AsyncSession,
    *,
    project_id: UUID,
) -> ProjectDiagnostics:
    async with asyncio.timeout(PROJECT_DIAGNOSTICS_TIMEOUT_SECONDS):
        await set_project_context(session, project_id)
        row = (
            await session.execute(
                text(
                    """
                SELECT
                  CURRENT_TIMESTAMP AS observed_at,
                  (
                    SELECT count(*)
                    FROM control.execution_leases lease
                    WHERE lease.project_id = :project_id
                      AND lease.status = 'ACTIVE'
                      AND lease.expires_at > CURRENT_TIMESTAMP
                      AND lease.deadline_at > CURRENT_TIMESTAMP
                  ) AS active_execution_leases,
                  (
                    SELECT count(*)
                    FROM control.build_dispatch_outbox item
                    WHERE item.project_id = :project_id
                      AND item.status = 'PENDING'
                      AND item.available_at <= CURRENT_TIMESTAMP
                  ) AS build_dispatch_ready,
                  (
                    SELECT count(*)
                    FROM control.run_command_outbox item
                    WHERE item.project_id = :project_id
                      AND item.status = 'PENDING'
                      AND item.available_at <= CURRENT_TIMESTAMP
                  ) AS run_commands_ready,
                  (
                    SELECT count(*)
                    FROM control.schedules schedule
                    WHERE schedule.project_id = :project_id
                      AND schedule.status = 'ACTIVE'
                      AND schedule.next_fire_at <= CURRENT_TIMESTAMP
                  ) AS schedules_due,
                  (
                    SELECT count(*)
                    FROM control.request_queue_requests request
                    WHERE request.project_id = :project_id
                      AND (
                        (
                          request.status = 'PENDING'
                          AND request.available_at <= CURRENT_TIMESTAMP
                        ) OR (
                          request.status = 'CLAIMED'
                          AND request.claim_expires_at <= CURRENT_TIMESTAMP
                        )
                      )
                  ) AS request_queue_ready,
                  (
                    SELECT count(*)
                    FROM control.request_queue_requests request
                    WHERE request.project_id = :project_id
                      AND request.status = 'CLAIMED'
                      AND request.claim_expires_at > CURRENT_TIMESTAMP
                  ) AS request_queue_claimed,
                  (
                    SELECT count(*)
                    FROM control.request_queue_requests request
                    WHERE request.project_id = :project_id
                      AND request.status = 'FAILED'
                  ) AS request_queue_failed,
                  (
                    SELECT count(*)
                    FROM control.egress_credential_canary_attempts attempt
                    WHERE attempt.project_id = :project_id
                      AND (
                        attempt.status = 'PENDING'
                        OR (
                          attempt.status = 'CLAIMED'
                          AND attempt.claim_expires_at <= CURRENT_TIMESTAMP
                        )
                      )
                  ) AS credential_canaries_ready,
                  (
                    SELECT count(*)
                    FROM control.egress_credential_canary_attempts attempt
                    WHERE attempt.project_id = :project_id
                      AND attempt.status = 'CLAIMED'
                      AND attempt.claim_expires_at > CURRENT_TIMESTAMP
                  ) AS credential_canaries_claimed,
                  (
                    SELECT count(*)
                    FROM control.egress_credential_canary_attempts attempt
                    WHERE attempt.project_id = :project_id
                      AND attempt.status = 'FAILED'
                  ) AS credential_canaries_failed,
                  (
                    SELECT count(*)
                    FROM control.webhook_delivery_attempts delivery
                    JOIN control.webhook_destinations destination
                      ON destination.id = delivery.destination_id
                    WHERE delivery.project_id = :project_id
                      AND (
                        (
                          delivery.status IN ('PENDING', 'RETRY_WAIT')
                          AND delivery.available_at <= CURRENT_TIMESTAMP
                          AND destination.status IN (
                            'PENDING_VERIFICATION', 'ACTIVE'
                          )
                        ) OR (
                          delivery.status = 'CLAIMED'
                          AND delivery.claim_expires_at <= CURRENT_TIMESTAMP
                        )
                      )
                  ) AS webhook_deliveries_ready,
                  (
                    SELECT count(*)
                    FROM control.webhook_delivery_attempts delivery
                    WHERE delivery.project_id = :project_id
                      AND delivery.status = 'CLAIMED'
                      AND delivery.claim_expires_at > CURRENT_TIMESTAMP
                  ) AS webhook_deliveries_claimed,
                  (
                    SELECT count(*)
                    FROM control.webhook_delivery_attempts delivery
                    WHERE delivery.project_id = :project_id
                      AND delivery.status = 'DEAD_LETTERED'
                  ) AS webhook_deliveries_dead_lettered
                    """
                ),
                {"project_id": project_id},
            )
        ).one()
    return ProjectDiagnostics(
        observed_at=row.observed_at,
        active_execution_leases=int(row.active_execution_leases),
        build_dispatch_ready=int(row.build_dispatch_ready),
        run_commands_ready=int(row.run_commands_ready),
        schedules_due=int(row.schedules_due),
        request_queue_ready=int(row.request_queue_ready),
        request_queue_claimed=int(row.request_queue_claimed),
        request_queue_failed=int(row.request_queue_failed),
        credential_canaries_ready=int(row.credential_canaries_ready),
        credential_canaries_claimed=int(row.credential_canaries_claimed),
        credential_canaries_failed=int(row.credential_canaries_failed),
        webhook_deliveries_ready=int(row.webhook_deliveries_ready),
        webhook_deliveries_claimed=int(row.webhook_deliveries_claimed),
        webhook_deliveries_dead_lettered=int(
            row.webhook_deliveries_dead_lettered
        ),
    )
