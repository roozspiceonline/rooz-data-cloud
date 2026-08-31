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
from .services.egress_health_maintenance import (
    egress_health_maintenance_is_fresh,
    read_egress_health_maintenance_health,
    record_egress_health_maintenance_failure,
    run_egress_health_maintenance,
)

logger = logging.getLogger("rdc.egress_health_maintenance")


def maintenance_owner_id() -> str:
    return f"{socket.gethostname()}:{os.getpid()}:{uuid4().hex}"


async def run_maintenance_loop(*, stop: asyncio.Event, owner_id: str) -> None:
    settings = get_settings()
    while not stop.is_set():
        started = time.monotonic()
        attempt_started_at = datetime.now(UTC)
        try:
            async with session_factory() as session:
                result = await run_egress_health_maintenance(
                    session,
                    now=attempt_started_at,
                    owner_id=owner_id,
                    rollup_batch_size=settings.egress_health_rollup_batch_size,
                    purge_batch_size=settings.egress_health_purge_batch_size,
                    raw_retention_hours=settings.egress_health_raw_retention_hours,
                    rollup_retention_days=settings.egress_health_rollup_retention_days,
                    request_id=f"egress_health_maintenance_{uuid4().hex}",
                )
                await session.commit()
            if result.acquired:
                logger.info(
                    "egress health maintenance completed buckets=%d "
                    "raw_purged=%d rollups_purged=%d",
                    result.buckets_rolled,
                    result.raw_rows_purged,
                    result.rollup_rows_purged,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            error_code = type(exc).__name__
            logger.error("egress health maintenance failed code=%s", error_code)
            try:
                async with session_factory() as failure_session:
                    await record_egress_health_maintenance_failure(
                        failure_session,
                        now=datetime.now(UTC),
                        failed_started_at=attempt_started_at,
                        owner_id=owner_id,
                        error_code=error_code,
                    )
                    await failure_session.commit()
            except Exception:
                logger.error("egress health maintenance failure telemetry unavailable")
        wait_seconds = max(
            0.0,
            settings.egress_health_maintenance_interval_seconds
            - (time.monotonic() - started),
        )
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=wait_seconds)


async def healthcheck() -> int:
    settings = get_settings()
    if not settings.egress_health_maintenance_enabled:
        return 0
    try:
        async with session_factory() as session:
            health = await read_egress_health_maintenance_health(session)
        return 0 if egress_health_maintenance_is_fresh(
            health,
            now=datetime.now(UTC),
            stale_after_seconds=settings.egress_health_maintenance_stale_after_seconds,
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
        if settings.egress_health_maintenance_enabled:
            await run_maintenance_loop(stop=stop, owner_id=maintenance_owner_id())
        else:
            logger.info("egress health maintenance is disabled")
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
