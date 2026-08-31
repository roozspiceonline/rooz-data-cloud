from __future__ import annotations

import argparse
import asyncio
import logging
import os
import signal
import socket
import time
from contextlib import suppress
from datetime import UTC, datetime
from uuid import uuid4

from .core.config import get_settings
from .core.database import engine, session_factory
from .core.observability import configure_structured_logging, log_event
from .services.execution_recovery_sweeper import (
    execution_recovery_is_fresh,
    read_execution_recovery_health,
    record_execution_recovery_failure,
    run_execution_recovery_sweep,
)

logger = logging.getLogger("rdc.execution_recovery")


def recovery_owner_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{uuid4().hex}"


async def run_sweep_loop(*, stop: asyncio.Event, owner_id: str) -> None:
    settings = get_settings()
    while not stop.is_set():
        started = time.monotonic()
        attempt_started_at = datetime.now(UTC)
        try:
            async with session_factory() as session:
                result = await run_execution_recovery_sweep(
                    session,
                    now=attempt_started_at,
                    owner_id=owner_id,
                    batch_size=settings.execution_recovery_sweep_batch_size,
                    request_id=f"recovery_{uuid4().hex}",
                )
                await session.commit()
            if result.acquired:
                log_event(
                    logger,
                    logging.INFO,
                    "execution_recovery.sweep.completed",
                    leases_reaped=result.leases_reaped,
                    cancellations_converged=result.cancellations_converged,
                    workers_lost=result.workers_lost,
                    worker_leases_fenced=result.worker_leases_fenced,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error_code = type(exc).__name__
            log_event(
                logger,
                logging.ERROR,
                "execution_recovery.sweep.failed",
                error_type=error_code,
            )
            try:
                async with session_factory() as failure_session:
                    await record_execution_recovery_failure(
                        failure_session,
                        now=datetime.now(UTC),
                        failed_started_at=attempt_started_at,
                        owner_id=owner_id,
                        error_code=error_code,
                    )
                    await failure_session.commit()
            except Exception:
                log_event(
                    logger,
                    logging.ERROR,
                    "execution_recovery.failure_telemetry.unavailable",
                )
        elapsed = time.monotonic() - started
        wait_seconds = max(
            0.0,
            settings.execution_recovery_sweep_interval_seconds - elapsed,
        )
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=wait_seconds)


async def healthcheck() -> int:
    settings = get_settings()
    if not settings.execution_recovery_sweep_enabled:
        return 0
    try:
        async with session_factory() as session:
            health = await read_execution_recovery_health(session)
        return 0 if execution_recovery_is_fresh(
            health,
            now=datetime.now(UTC),
            stale_after_seconds=settings.execution_recovery_stale_after_seconds,
        ) else 1
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
        if settings.execution_recovery_sweep_enabled:
            await run_sweep_loop(stop=stop, owner_id=recovery_owner_id())
        else:
            log_event(
                logger,
                logging.INFO,
                "execution_recovery.scheduler.disabled",
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
        service="execution_recovery",
        environment=settings.env,
        deployment_id=settings.deployment_id,
    )
    if arguments.healthcheck:
        raise SystemExit(asyncio.run(healthcheck()))
    asyncio.run(serve())


if __name__ == "__main__":
    main()
