"""False-by-default trusted runner for claim-fenced webhook deliveries."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime

from .core.config import get_settings
from .core.database import engine, session_factory
from .core.envelope_encryption import decrypt_project_secret
from .core.errors import ApiError
from .core.observability import configure_structured_logging, log_event
from .egress_canary_network_policy import CanaryNetworkLimits
from .services.webhook_delivery_canary import (
    ClaimedWebhookDeliveryCanary,
    claim_webhook_delivery_canaries,
    complete_webhook_delivery_canary,
    load_webhook_delivery_material,
)
from .webhook_delivery_security import sign_webhook_request
from .webhook_delivery_transport import run_webhook_delivery_transport

logger = logging.getLogger("rdc.webhook_delivery_runner")


@dataclass(frozen=True)
class WebhookBatchResult:
    claimed: int
    completed: int
    stale: int
    deferred: int


def _network_limits() -> CanaryNetworkLimits:
    settings = get_settings()
    return CanaryNetworkLimits(
        connect_timeout_seconds=settings.webhook_delivery_connect_timeout_seconds,
        total_timeout_seconds=settings.webhook_delivery_total_timeout_seconds,
        max_response_bytes=settings.webhook_delivery_max_response_bytes,
        max_redirects=0,
        max_retries=0,
    )


async def _complete_claim(
    claim: ClaimedWebhookDeliveryCanary,
    outcome: str,
    http_status: int | None = None,
) -> str:
    try:
        async with session_factory() as session:
            await complete_webhook_delivery_canary(
                session,
                delivery_id=claim.id,
                claim_token=claim.claim_token,
                outcome=outcome,
                http_status=http_status,
                now=datetime.now(UTC),
            )
            await session.commit()
        return "completed"
    except ApiError as exc:
        if exc.code == "WEBHOOK_CLAIM_FENCED":
            return "stale"
        return "deferred"
    except Exception:
        return "deferred"


async def execute_claim(claim: ClaimedWebhookDeliveryCanary) -> str:
    """Execute one delivery without logging its target, payload, claim, or secret."""
    settings = get_settings()
    async with session_factory() as session:
        material = await load_webhook_delivery_material(
            session, delivery_id=claim.id, claim_token=claim.claim_token
        )
    if material is None:
        return await _complete_claim(claim, "CONFIGURATION_ERROR")
    if (
        material.organization_id != claim.organization_id
        or material.project_id != claim.project_id
        or material.destination_id != claim.destination_id
        or material.event_id != claim.event_id
        or material.encryption_algorithm != "AES-256-GCM"
        or material.master_key_version != settings.project_secret_master_key_version
    ):
        return await _complete_claim(claim, "CONFIGURATION_ERROR")
    try:
        plaintext = bytearray(
            decrypt_project_secret(
                ciphertext=material.encrypted_value,
                value_nonce=material.value_nonce,
                wrapped_data_key=material.wrapped_data_key,
                key_nonce=material.key_nonce,
                organization_id=material.organization_id,
                project_id=material.project_id,
                secret_id=material.signing_secret_id,
                name=material.secret_name,
                version=material.secret_version,
            )
        )
    except Exception:
        return await _complete_claim(claim, "CONFIGURATION_ERROR")
    try:
        signed = sign_webhook_request(
            secret=plaintext,
            delivery_id=claim.id,
            event_id=material.event_id,
            event_type=material.event_type,
            occurred_at=material.event_occurred_at,
            payload=material.event_payload,
            timestamp=datetime.now(UTC),
        )
        result = await run_webhook_delivery_transport(
            target_url=material.endpoint_url,
            body=signed.body,
            headers=signed.headers,
            limits=_network_limits(),
        )
    except Exception:
        return await _complete_claim(claim, "CONFIGURATION_ERROR")
    finally:
        for index in range(len(plaintext)):
            plaintext[index] = 0
    return await _complete_claim(claim, result.outcome, result.status_code)


async def run_one_batch() -> WebhookBatchResult:
    settings = get_settings()
    async with session_factory() as session:
        claims = await claim_webhook_delivery_canaries(
            session,
            now=datetime.now(UTC),
            batch_size=settings.webhook_delivery_max_concurrency,
            claim_seconds=settings.webhook_delivery_claim_seconds,
            worker_id=f"webhook-canary-{os.getpid()}",
        )
        await session.commit()
    if not claims:
        return WebhookBatchResult(0, 0, 0, 0)
    semaphore = asyncio.Semaphore(settings.webhook_delivery_max_concurrency)

    async def guarded(claim: ClaimedWebhookDeliveryCanary) -> str:
        async with semaphore:
            try:
                return await execute_claim(claim)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log_event(
                    logger,
                    logging.ERROR,
                    "webhook_delivery.claim.deferred",
                    error_type=type(exc).__name__,
                )
                return "deferred"

    outcomes = await asyncio.gather(*(guarded(claim) for claim in claims))
    return WebhookBatchResult(
        claimed=len(claims),
        completed=outcomes.count("completed"),
        stale=outcomes.count("stale"),
        deferred=outcomes.count("deferred"),
    )


async def run_loop(*, stop: asyncio.Event) -> None:
    settings = get_settings()
    while not stop.is_set():
        started = time.monotonic()
        try:
            result = await run_one_batch()
            if result.claimed:
                log_event(
                    logger,
                    logging.INFO,
                    "webhook_delivery.batch.completed",
                    claimed=result.claimed,
                    completed=result.completed,
                    stale=result.stale,
                    deferred=result.deferred,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log_event(
                logger,
                logging.ERROR,
                "webhook_delivery.batch.failed",
                error_type=type(exc).__name__,
            )
        elapsed = time.monotonic() - started
        wait_seconds = max(0.0, settings.webhook_delivery_poll_interval_seconds - elapsed)
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=wait_seconds)


async def healthcheck() -> int:
    if not get_settings().webhook_delivery_canary_enabled:
        return 0
    try:
        async with engine.connect() as connection:
            await connection.exec_driver_sql("SELECT 1")
        return 0
    except Exception:
        return 1
    finally:
        await engine.dispose()


async def serve() -> None:
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    try:
        if get_settings().webhook_delivery_canary_enabled:
            await run_loop(stop=stop)
        else:
            log_event(
                logger,
                logging.INFO,
                "webhook_delivery.canary.disabled",
            )
            await stop.wait()
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--healthcheck", action="store_true")
    arguments = parser.parse_args()
    settings = get_settings()
    configure_structured_logging(
        service="webhook_delivery",
        environment=settings.env,
        deployment_id=settings.deployment_id,
    )
    if arguments.healthcheck:
        raise SystemExit(asyncio.run(healthcheck()))
    asyncio.run(serve())


if __name__ == "__main__":
    main()
