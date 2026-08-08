#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def need(path: str, *markers: str) -> None:
    source = (ROOT / path).read_text(encoding="utf-8")
    missing = [marker for marker in markers if marker not in source]
    if missing:
        raise SystemExit(f"{path} missing: {', '.join(missing)}")


need(
    "apps/api/app/execution_recovery.py",
    "execution_retry_allowed",
    "retry_delay_seconds",
    "retry_available_at",
    "execution_deadline_at",
    "clamp_lease_expiry",
    "source_available",
)
need(
    "apps/api/app/services/execution_plane.py",
    "execution_retry_allowed",
    "retry_available_at",
    '"retry_scheduled"',
    '"next_attempt_at"',
    '"WORKLOAD_DEADLINE_EXCEEDED"',
    '"execution.lease.deadline_exceeded"',
    "ExecutionLease.deadline_at <= current",
)
need(
    "apps/api/migrations/versions/20260809_0016_execution_deadlines.py",
    "deadline_at > claimed_at AND expires_at <= deadline_at",
    "execution_lease_deadline_immutable",
    "Execution deadline is immutable",
    "lease.deadline_at > now()",
)
need(
    "apps/api/app/api/internal_dependencies.py",
    "lease.deadline_at <= now",
)
need(
    "packages/agent-protocol/schemas/worker-lease-claim.schema.json",
    '"deadline_at"',
)
need(
    "apps/api/app/core/config.py",
    "worker_retry_base_seconds",
    "worker_retry_max_seconds",
)
need(".env.example", "RDC_WORKER_RETRY_BASE_SECONDS", "RDC_WORKER_RETRY_MAX_SECONDS")
need("docker-compose.yml", "RDC_WORKER_RETRY_BASE_SECONDS", "RDC_WORKER_RETRY_MAX_SECONDS")
need(
    "apps/api/tests/test_execution_recovery.py",
    "exponential_and_bounded",
    "durable_source",
    "audits_schedule",
    "clamped_to_execution_deadline",
)
need(
    "apps/api/tests/test_execution_deadline_postgres.py",
    "Execution deadline is immutable",
    "terminally_timed_out",
    "WORKLOAD_DEADLINE_EXCEEDED",
)
need(
    "docs/execution-recovery/THREAT_MODEL.md",
    "server",
    "outbox",
    "immutable lease deadline",
)
need(
    "docs/execution-recovery/RUNBOOK.md",
    "next_attempt_at",
    "SKIP LOCKED",
    "20260809_0016",
    "execution.lease.deadline_exceeded",
)
print("Execution recovery increment 2 verification passed")
