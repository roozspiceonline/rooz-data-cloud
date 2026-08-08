# Production Execution Lifecycle / Recovery

This RDC v1 workstream is active after Phase 1P. The implemented foundation
makes execution retry timing a server-owned policy shared by stale-lease
recovery and worker-reported retryable failure handling. It also persists an
immutable, server-derived deadline on every execution lease.

The policy uses validated bounded exponential backoff, allows retries only for
failed or timed-out attempts below the configured maximum, and refuses to
requeue work whose durable dispatch outbox row is missing. Immutable execution
audit events include whether a retry was scheduled and its server-derived
`next_attempt_at`; workers cannot choose that timestamp.

Build deadlines come from the immutable Agent manifest timeout captured in the
durable dispatch outbox. Run deadlines come from the server-validated effective
runtime timeout. Cancellation leases use the server lease maximum. Initial and
renewed lease expiry is clamped to both the lease lifetime ceiling and the
deadline. A deadline-exceeded Build or Run is terminally `TIMED_OUT`, its outbox
source becomes `FAILED`, no retry is scheduled, outstanding secret grants are
expired, and immutable audit lineage records
`execution.lease.deadline_exceeded`.

Remaining increments cover cancellation convergence, an independently
scheduled stale-lease sweep, bounded project and worker admission,
crash/restart integration tests, and production operations.

See the [threat model](THREAT_MODEL.md) and [runbook](RUNBOOK.md).
