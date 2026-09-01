from __future__ import annotations

import asyncio
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

RUNTIME_METRICS_QUERY_TIMEOUT_SECONDS = 2.0


@dataclass(frozen=True)
class RuntimeMetrics:
    active_execution_leases: int
    active_workers: int
    build_dispatch_ready: int
    run_commands_ready: int
    schedules_due: int
    request_queue_ready: int
    credential_canaries_ready: int
    credential_canaries_claimed: int
    webhook_deliveries_ready: int
    webhook_deliveries_claimed: int


async def read_runtime_metrics(
    session: AsyncSession,
    *,
    worker_fresh_after_seconds: int,
) -> RuntimeMetrics:
    if not 15 <= worker_fresh_after_seconds <= 300:
        raise ValueError("Worker freshness must be between 15 and 300 seconds.")
    async with asyncio.timeout(RUNTIME_METRICS_QUERY_TIMEOUT_SECONDS):
        row = (
            await session.execute(
                text(
                    """
                SELECT
                  (
                    SELECT count(*)
                    FROM control.execution_leases lease
                    WHERE lease.status = 'ACTIVE'
                      AND lease.expires_at > CURRENT_TIMESTAMP
                      AND lease.deadline_at > CURRENT_TIMESTAMP
                  ) AS active_execution_leases,
                  (
                    SELECT count(*)
                    FROM security.worker_identities worker
                    WHERE worker.status = 'ACTIVE'
                      AND worker.revoked_at IS NULL
                      AND (
                        worker.expires_at IS NULL
                        OR worker.expires_at > CURRENT_TIMESTAMP
                      )
                      AND worker.last_seen_at > CURRENT_TIMESTAMP - make_interval(
                        secs => :worker_fresh_after_seconds
                      )
                      AND (
                        worker.last_lost_at IS NULL
                        OR worker.last_recovered_at >= worker.last_lost_at
                      )
                  ) AS active_workers,
                  (
                    SELECT count(*)
                    FROM control.build_dispatch_outbox item
                    WHERE item.status = 'PENDING'
                      AND item.available_at <= CURRENT_TIMESTAMP
                  ) AS build_dispatch_ready,
                  (
                    SELECT count(*)
                    FROM control.run_command_outbox item
                    WHERE item.status = 'PENDING'
                      AND item.available_at <= CURRENT_TIMESTAMP
                  ) AS run_commands_ready,
                  (
                    SELECT count(*)
                    FROM control.schedules schedule
                    WHERE schedule.status = 'ACTIVE'
                      AND schedule.next_fire_at <= CURRENT_TIMESTAMP
                  ) AS schedules_due,
                  (
                    SELECT count(*)
                    FROM control.request_queue_requests request
                    WHERE (
                      request.status = 'PENDING'
                      AND request.available_at <= CURRENT_TIMESTAMP
                    ) OR (
                      request.status = 'CLAIMED'
                      AND request.claim_expires_at <= CURRENT_TIMESTAMP
                    )
                  ) AS request_queue_ready,
                  (
                    SELECT count(*)
                    FROM control.egress_credential_canary_attempts attempt
                    WHERE attempt.status = 'PENDING'
                       OR (
                         attempt.status = 'CLAIMED'
                         AND attempt.claim_expires_at <= CURRENT_TIMESTAMP
                       )
                  ) AS credential_canaries_ready,
                  (
                    SELECT count(*)
                    FROM control.egress_credential_canary_attempts attempt
                    WHERE attempt.status = 'CLAIMED'
                      AND attempt.claim_expires_at > CURRENT_TIMESTAMP
                  ) AS credential_canaries_claimed,
                  (
                    SELECT count(*)
                    FROM control.webhook_delivery_attempts delivery
                    JOIN control.webhook_destinations destination
                      ON destination.id = delivery.destination_id
                    WHERE (
                      delivery.status IN ('PENDING', 'RETRY_WAIT')
                      AND delivery.available_at <= CURRENT_TIMESTAMP
                      AND destination.status IN ('PENDING_VERIFICATION', 'ACTIVE')
                    ) OR (
                      delivery.status = 'CLAIMED'
                      AND delivery.claim_expires_at <= CURRENT_TIMESTAMP
                    )
                  ) AS webhook_deliveries_ready,
                  (
                    SELECT count(*)
                    FROM control.webhook_delivery_attempts delivery
                    WHERE delivery.status = 'CLAIMED'
                      AND delivery.claim_expires_at > CURRENT_TIMESTAMP
                  ) AS webhook_deliveries_claimed
                    """
                ),
                {"worker_fresh_after_seconds": worker_fresh_after_seconds},
            )
        ).one()
    return RuntimeMetrics(
        active_execution_leases=int(row.active_execution_leases),
        active_workers=int(row.active_workers),
        build_dispatch_ready=int(row.build_dispatch_ready),
        run_commands_ready=int(row.run_commands_ready),
        schedules_due=int(row.schedules_due),
        request_queue_ready=int(row.request_queue_ready),
        credential_canaries_ready=int(row.credential_canaries_ready),
        credential_canaries_claimed=int(row.credential_canaries_claimed),
        webhook_deliveries_ready=int(row.webhook_deliveries_ready),
        webhook_deliveries_claimed=int(row.webhook_deliveries_claimed),
    )
