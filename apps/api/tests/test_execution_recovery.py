from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.execution_recovery import (
    clamp_lease_expiry,
    execution_deadline_at,
    execution_retry_allowed,
    retry_available_at,
    retry_delay_seconds,
)


def test_execution_deadline_is_server_derived() -> None:
    claimed_at = datetime(2026, 8, 9, tzinfo=UTC)
    assert execution_deadline_at(
        claimed_at=claimed_at,
        timeout_seconds=90,
    ) == claimed_at + timedelta(seconds=90)
    with pytest.raises(ValueError):
        execution_deadline_at(claimed_at=claimed_at, timeout_seconds=0)


def test_lease_expiry_is_clamped_to_execution_deadline() -> None:
    claimed_at = datetime(2026, 8, 9, tzinfo=UTC)
    deadline_at = claimed_at + timedelta(seconds=45)
    assert clamp_lease_expiry(
        proposed=claimed_at + timedelta(seconds=60),
        claimed_at=claimed_at,
        max_lifetime_seconds=300,
        deadline_at=deadline_at,
    ) == deadline_at


def test_lease_expiry_is_clamped_to_maximum_lifetime() -> None:
    claimed_at = datetime(2026, 8, 9, tzinfo=UTC)
    assert clamp_lease_expiry(
        proposed=claimed_at + timedelta(seconds=600),
        claimed_at=claimed_at,
        max_lifetime_seconds=300,
        deadline_at=claimed_at + timedelta(seconds=900),
    ) == claimed_at + timedelta(seconds=300)


def test_retry_backoff_is_exponential_and_bounded() -> None:
    assert retry_delay_seconds(attempt=1, base_seconds=2, max_seconds=300) == 2
    assert retry_delay_seconds(attempt=5, base_seconds=2, max_seconds=300) == 32
    assert retry_delay_seconds(attempt=20, base_seconds=2, max_seconds=300) == 300


def test_retry_backoff_rejects_invalid_bounds() -> None:
    with pytest.raises(ValueError):
        retry_delay_seconds(attempt=0, base_seconds=2, max_seconds=300)
    with pytest.raises(ValueError):
        retry_delay_seconds(attempt=1, base_seconds=10, max_seconds=5)


def test_retry_time_is_server_derived() -> None:
    now = datetime(2026, 8, 9, tzinfo=UTC)
    assert retry_available_at(
        now=now, attempt=3, base_seconds=2, max_seconds=300
    ) == now + timedelta(seconds=8)


@pytest.mark.parametrize(
    ("requested", "outcome", "attempt", "source_available", "expected"),
    [
        (True, "FAILED", 1, True, True),
        (True, "TIMED_OUT", 4, True, True),
        (False, "FAILED", 1, True, False),
        (True, "SUCCEEDED", 1, True, False),
        (True, "FAILED", 5, True, False),
        (True, "FAILED", 1, False, False),
    ],
)
def test_retry_requires_server_eligible_failure_and_durable_source(
    requested: bool,
    outcome: str,
    attempt: int,
    source_available: bool,
    expected: bool,
) -> None:
    assert execution_retry_allowed(
        requested=requested,
        outcome=outcome,
        attempt=attempt,
        max_attempts=5,
        source_available=source_available,
    ) is expected


def test_execution_plane_uses_shared_policy_and_audits_schedule() -> None:
    source = (
        Path(__file__).parents[1] / "app/services/execution_plane.py"
    ).read_text()
    assert source.count("execution_retry_allowed(") == 3
    assert source.count("retry_available_at(") == 3
    assert '"next_attempt_at"' in source
    assert '"retry_scheduled"' in source
    assert "min(300, 2**lease.attempt)" not in source
