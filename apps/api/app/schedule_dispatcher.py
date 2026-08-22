from __future__ import annotations

import asyncio
import logging
import signal
import time
from contextlib import suppress
from datetime import UTC, datetime
from uuid import uuid4

from .core.config import get_settings
from .core.database import engine, session_factory
from .services.schedules import dispatch_due_schedules

logger = logging.getLogger(__name__)


async def run_dispatch_loop(*, stop: asyncio.Event) -> None:
    settings = get_settings()
    while not stop.is_set():
        started = time.monotonic()
        try:
            async with session_factory() as session:
                result = await dispatch_due_schedules(
                    session,
                    now=datetime.now(UTC),
                    batch_size=settings.schedule_dispatch_batch_size,
                    request_id=f"schedule-dispatch-{uuid4().hex}",
                )
                await session.commit()
            if result.acquired and result.examined:
                logger.info(
                    "schedule dispatch complete examined=%d fired=%d skipped=%d failed=%d",
                    result.examined,
                    result.fired,
                    result.skipped,
                    result.failed,
                )
        except Exception:
            logger.exception("schedule dispatch failed")
        elapsed = time.monotonic() - started
        wait_seconds = max(
            0.0, settings.schedule_dispatch_interval_seconds - elapsed
        )
        with suppress(TimeoutError):
            await asyncio.wait_for(stop.wait(), timeout=wait_seconds)


async def serve() -> None:
    settings = get_settings()
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop.set)
    try:
        if settings.schedule_dispatch_enabled:
            await run_dispatch_loop(stop=stop)
        else:
            logger.info("schedule dispatcher is disabled")
            await stop.wait()
    finally:
        await engine.dispose()


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    asyncio.run(serve())


if __name__ == "__main__":
    main()
