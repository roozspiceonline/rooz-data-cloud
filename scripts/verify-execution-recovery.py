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
    "reap_overdue_cancellations",
    '"run.cancellation_converged"',
    '"RUN_CANCELLATION_PENDING"',
    '"WORKER_RECOVERY_REQUIRED"',
    '"execution.lease.worker_lost"',
    '"worker.recovered"',
)
need(
    "apps/api/migrations/versions/20260809_0017_run_cancellation_convergence.py",
    "cancel_deadline_at > cancel_requested_at",
    "run_cancellation_immutable",
    "Run cancellation deadline is immutable",
)
need(
    "apps/api/app/services/runs.py",
    "_ensure_cancel_command",
    "populate_existing=True",
    "worker_cancel_convergence_seconds",
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
    "worker_cancel_convergence_seconds",
    "execution_recovery_sweep_interval_seconds",
    "execution_recovery_sweep_batch_size",
    "execution_recovery_stale_after_seconds",
    "worker_registration_max_concurrency",
    "execution_project_default_max_active_leases",
    "worker_lost_after_seconds",
)
need(
    ".env.example",
    "RDC_WORKER_RETRY_BASE_SECONDS",
    "RDC_WORKER_RETRY_MAX_SECONDS",
    "RDC_WORKER_CANCEL_CONVERGENCE_SECONDS",
    "RDC_EXECUTION_RECOVERY_SWEEP_INTERVAL_SECONDS",
    "RDC_EXECUTION_RECOVERY_SWEEP_BATCH_SIZE",
    "RDC_EXECUTION_RECOVERY_STALE_AFTER_SECONDS",
    "RDC_WORKER_REGISTRATION_MAX_CONCURRENCY",
    "RDC_EXECUTION_PROJECT_DEFAULT_MAX_ACTIVE_LEASES",
    "RDC_WORKER_LOST_AFTER_SECONDS",
    "RDC_WORKER_HEARTBEAT_SECONDS",
    "RDC_WORKER_LEASE_RENEW_SECONDS",
)
need(
    "docker-compose.yml",
    "RDC_WORKER_RETRY_BASE_SECONDS",
    "RDC_WORKER_RETRY_MAX_SECONDS",
    "RDC_WORKER_CANCEL_CONVERGENCE_SECONDS",
    "execution-recovery:",
    "app.recovery_scheduler",
    "--healthcheck",
)
need(
    "apps/api/app/recovery_scheduler.py",
    "run_sweep_loop",
    "record_execution_recovery_failure",
    "execution_recovery_sweep_interval_seconds",
)
need(
    "apps/api/app/services/execution_recovery_sweeper.py",
    "pg_try_advisory_xact_lock",
    "run_execution_recovery_sweep",
    "execution.recovery.sweep_completed",
    "read_execution_recovery_health",
    "read_execution_admission_health",
    "saturated_projects",
    "saturated_workers",
    "detect_lost_workers",
    "WORKER_LOST",
    "worker.lost",
    "recovery_pending_workers",
)
need(
    "apps/api/migrations/versions/20260809_0019_execution_concurrency_admission.py",
    "max_active_leases BETWEEN 1 AND 1000",
    "max_concurrency BETWEEN 1 AND 16",
    "ix_execution_leases_active_project_admission",
    "ix_execution_leases_active_worker_admission",
)
need(
    "apps/api/migrations/versions/20260809_0018_execution_recovery_sweeps.py",
    "execution_recovery_state",
    "ck_execution_recovery_state_singleton",
    "last_heartbeat_at",
    "total_sweeps",
    "total_failures",
)
need(
    "apps/api/migrations/versions/20260809_0020_worker_loss_recovery.py",
    "last_lost_at",
    "last_recovered_at",
    "cleanup_generation",
    "ix_worker_identities_loss_detection",
    "total_worker_leases_fenced",
    "worker.last_recovered_at >= worker.last_lost_at",
)
need(
    "apps/api/app/execution_schemas.py",
    "WorkerRecoveryReport",
    'Literal["rdc.worker-recovery/v1"]',
    "forced_cleanup_completed: Literal[True]",
)
need(
    "packages/agent-protocol/schemas/worker-heartbeat.schema.json",
    '"rdc.worker-recovery/v1"',
    '"forced_cleanup_completed"',
    '"managed_containers_removed"',
    '"workspace_directories_removed"',
)
need(
    "workers/sandbox-runtime/worker_recovery.py",
    'MANAGED_LABEL = "io.rooz.rdc.managed=true"',
    "MAX_CLEANUP_TARGETS = 256",
    "force_startup_cleanup",
    "class LeaseWatchdog",
    "cleanup_managed_containers",
)
need(
    "workers/sandbox-runtime/worker.py",
    "raise WorkerShutdown",
    "LeaseWatchdog",
    "draining=True",
    "recovery=final_cleanup.as_protocol()",
)
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
    "concurrent_cancel_dispatch_is_idempotent",
    "lost_run_lease_converges_pending_cancellation",
    "late_run_completion_cannot_override_cancellation",
    "recovery_sweep_is_singleton_and_restart_safe",
    "recovery_sweep_enforces_bounded_batches",
    "concurrent_cancellation_reapers_are_single_winner",
    "project_admission_is_single_winner_and_releases",
    "worker_admission_is_single_winner",
    "run_cancel_bypasses_saturated_project_admission",
    "admission_limits_are_database_bounded",
    "admission_health_reports_aggregate_saturation",
    "worker_registration_is_server_capped",
    "lost_worker_is_fenced_and_requires_cleanup_recovery",
)
need(
    "apps/api/tests/test_execution_worker_loss_contracts.py",
    "startup_cleanup_is_label_scoped_validated_and_bounded",
    "lease_watchdog_renews_until_work_completes",
    "lease_watchdog_fails_closed_and_forces_runtime_cleanup",
)
need(
    "docs/execution-recovery/THREAT_MODEL.md",
    "server",
    "outbox",
    "immutable lease deadline",
    "Concurrency admission is server-owned",
    "WORKER_LOST",
    "forced cleanup",
)
need(
    "docs/execution-recovery/RUNBOOK.md",
    "next_attempt_at",
    "SKIP LOCKED",
    "20260809_0016",
    "execution.lease.deadline_exceeded",
    "20260809_0017",
    "run.cancellation_converged",
    "20260809_0018",
    "pg_try_advisory_xact_lock",
    "/health/recovery",
    "20260809_0019",
    "RUN_CANCEL",
    "20260809_0020",
    "WORKER_RECOVERY_REQUIRED",
    "io.rooz.rdc.managed=true",
)
print("Execution recovery increment 6 verification passed")
