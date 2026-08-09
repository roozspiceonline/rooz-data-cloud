from __future__ import annotations

from pathlib import Path

API_ROOT = Path(__file__).parents[1]


def test_execution_deadline_migration_is_immutable_and_bounded() -> None:
    source = (
        API_ROOT
        / "migrations/versions/20260809_0016_execution_deadlines.py"
    ).read_text()
    for required in (
        '"deadline_at"',
        "deadline_at > claimed_at AND expires_at <= deadline_at",
        "execution_lease_deadline_immutable",
        "Execution deadline is immutable",
        "lease.deadline_at > now()",
        "execution_leases_reaper_select",
        "status IN ('EXPIRED', 'FAILED')",
    ):
        assert required in source


def test_execution_plane_derives_clamps_and_terminally_reaps_deadlines() -> None:
    source = (API_ROOT / "app/services/execution_plane.py").read_text()
    for required in (
        "_execution_timeout_seconds",
        "execution_deadline_at(",
        "clamp_lease_expiry(",
        "ExecutionLease.deadline_at <= current",
        '"WORKLOAD_DEADLINE_EXCEEDED"',
        '"execution.lease.deadline_exceeded"',
        '"TIMED_OUT" if deadline_exceeded',
        "requested=not deadline_exceeded",
    ):
        assert required in source


def test_worker_lease_access_rejects_overdue_deadlines() -> None:
    source = (API_ROOT / "app/api/internal_dependencies.py").read_text()
    assert "lease.deadline_at <= now" in source


def test_claim_contract_exposes_server_deadline() -> None:
    schema = (API_ROOT / "app/execution_schemas.py").read_text()
    assert schema.count("deadline_at: datetime") == 2
