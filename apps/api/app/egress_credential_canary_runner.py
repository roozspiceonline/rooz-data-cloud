"""Trusted live executor for persisted credential-rotation canary claims."""

from __future__ import annotations

import argparse
import asyncio
import logging
import signal
import time
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime

from .core.config import get_settings
from .core.database import engine, session_factory
from .core.envelope_encryption import decrypt_project_secret
from .core.errors import ApiError
from .egress_canary_network_policy import CanaryNetworkLimits
from .egress_credential_canary_transport import run_credential_canary_transport
from .services.egress_credential_canaries import (
    ClaimedCredentialCanary,
    claim_credential_rotation_canaries,
    complete_credential_rotation_canary,
    configured_target_digest,
    load_credential_rotation_canary_secret,
)

logger = logging.getLogger("rdc.egress_credential_canary_runner")


@dataclass(frozen=True)
class CanaryBatchResult:
    claimed: int
    completed: int
    stale: int
    deferred: int


def _network_limits() -> CanaryNetworkLimits:
    settings = get_settings()
    return CanaryNetworkLimits(
        connect_timeout_seconds=settings.egress_credential_canary_connect_timeout_seconds,
        total_timeout_seconds=settings.egress_credential_canary_total_timeout_seconds,
        max_response_bytes=settings.egress_credential_canary_max_response_bytes,
        max_redirects=0,
        max_retries=settings.egress_credential_canary_max_retries,
    )


async def _complete_claim(claim: ClaimedCredentialCanary, outcome: str) -> str:
    try:
        async with session_factory() as session:
            await complete_credential_rotation_canary(
                session,
                attempt_id=claim.id,
                claim_token=claim.claim_token,
                outcome=outcome,
                now=datetime.now(UTC),
            )
            await session.commit()
        return "completed"
    except ApiError as exc:
        if exc.code == "EGRESS_CREDENTIAL_CANARY_CLAIM_STALE":
            return "stale"
        return "deferred"
    except Exception:
        return "deferred"


async def execute_claim(claim: ClaimedCredentialCanary) -> str:
    """Execute one claim without putting credential or target data in logs/results."""
    settings = get_settings()
    if claim.target_digest != configured_target_digest():
        return await _complete_claim(claim, "TARGET_ERROR")

    async with session_factory() as session:
        material = await load_credential_rotation_canary_secret(
            session,
            attempt_id=claim.id,
            claim_token=claim.claim_token,
        )

    if material is None:
        # Completion owns the authoritative superseded/configuration/stale decision.
        return await _complete_claim(claim, "TARGET_ERROR")
    if (
        material.organization_id != claim.organization_id
        or material.project_id != claim.project_id
        or material.credential_secret_id != claim.credential_secret_id
        or material.secret_version != claim.secret_version
        or material.target_digest != claim.target_digest
        or material.encryption_algorithm != "AES-256-GCM"
        or material.master_key_version != settings.project_secret_master_key_version
    ):
        return "deferred"

    try:
        plaintext = bytearray(
            decrypt_project_secret(
                ciphertext=material.encrypted_value,
                value_nonce=material.value_nonce,
                wrapped_data_key=material.wrapped_data_key,
                key_nonce=material.key_nonce,
                organization_id=material.organization_id,
                project_id=material.project_id,
                secret_id=material.credential_secret_id,
                name=material.secret_name,
                version=material.secret_version,
            )
        )
    except Exception:
        return "deferred"

    authorization = ""
    try:
        try:
            authorization = plaintext.decode("utf-8")
        except UnicodeDecodeError:
            return "deferred"
        transport = await run_credential_canary_transport(
            target_url=settings.egress_credential_canary_target_url,
            authorization=authorization,
            limits=_network_limits(),
        )
    finally:
        authorization = ""
        for index in range(len(plaintext)):
            plaintext[index] = 0

    return await _complete_claim(claim, transport.outcome)


async def run_one_batch() -> CanaryBatchResult:
    settings = get_settings()
    claim_count = min(
        settings.egress_credential_canary_batch_size,
        settings.egress_credential_canary_max_concurrency,
    )
    async with session_factory() as session:
        claims = await claim_credential_rotation_canaries(
            session,
            now=datetime.now(UTC),
            batch_size=claim_count,
        )
        await session.commit()
    if not claims:
        return CanaryBatchResult(0, 0, 0, 0)

    semaphore = asyncio.Semaphore(settings.egress_credential_canary_max_concurrency)

    async def guarded(claim: ClaimedCredentialCanary) -> str:
        async with semaphore:
            try:
                return await execute_claim(claim)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    "credential canary claim deferred code=%s",
                    type(exc).__name__,
                )
                return "deferred"

    outcomes = await asyncio.gather(*(guarded(claim) for claim in claims))
    return CanaryBatchResult(
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
                logger.info(
                    "credential canary batch claimed=%d completed=%d stale=%d deferred=%d",
                    result.claimed,
                    result.completed,
                    result.stale,
                    result.deferred,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.error(
                "credential canary runner batch failed code=%s",
                type(exc).__name__,
            )
        elapsed = time.monotonic() - started
        wait_seconds = max(
            0.0,
            settings.egress_credential_canary_poll_interval_seconds - elapsed,
        )
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=wait_seconds)


async def healthcheck() -> int:
    settings = get_settings()
    if not settings.egress_credential_canary_live_executor_enabled:
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
    settings = get_settings()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    try:
        if settings.egress_credential_canary_live_executor_enabled:
            await run_loop(stop=stop)
        else:
            logger.info("credential canary live executor is disabled")
            await stop.wait()
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--healthcheck", action="store_true")
    arguments = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    if arguments.healthcheck:
        raise SystemExit(asyncio.run(healthcheck()))
    asyncio.run(serve())


if __name__ == "__main__":
    main()
