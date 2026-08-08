"""Server-owned retry policy for execution recovery."""

from datetime import datetime, timedelta


def retry_delay_seconds(
    *,
    attempt: int,
    base_seconds: int,
    max_seconds: int,
) -> int:
    if attempt < 1:
        raise ValueError("Execution attempts start at one.")
    if base_seconds < 1 or max_seconds < base_seconds:
        raise ValueError("Execution retry bounds are invalid.")
    delay = base_seconds << (attempt - 1)
    return min(max_seconds, delay)


def retry_available_at(
    *,
    now: datetime,
    attempt: int,
    base_seconds: int,
    max_seconds: int,
) -> datetime:
    return now + timedelta(
        seconds=retry_delay_seconds(
            attempt=attempt,
            base_seconds=base_seconds,
            max_seconds=max_seconds,
        )
    )


def execution_retry_allowed(
    *,
    requested: bool,
    outcome: str,
    attempt: int,
    max_attempts: int,
    source_available: bool,
) -> bool:
    return (
        requested
        and source_available
        and outcome in {"FAILED", "TIMED_OUT"}
        and 1 <= attempt < max_attempts
    )
