"""Server-owned retry policy for execution recovery."""

from datetime import datetime, timedelta


def execution_deadline_at(*, claimed_at: datetime, timeout_seconds: int) -> datetime:
    if timeout_seconds < 1:
        raise ValueError("Execution timeout must be positive.")
    return claimed_at + timedelta(seconds=timeout_seconds)


def clamp_lease_expiry(
    *,
    proposed: datetime,
    claimed_at: datetime,
    max_lifetime_seconds: int,
    deadline_at: datetime,
) -> datetime:
    if max_lifetime_seconds < 1:
        raise ValueError("Lease maximum lifetime must be positive.")
    if deadline_at <= claimed_at:
        raise ValueError("Execution deadline must follow lease claim time.")
    hard_limit = claimed_at + timedelta(seconds=max_lifetime_seconds)
    return min(proposed, hard_limit, deadline_at)


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
