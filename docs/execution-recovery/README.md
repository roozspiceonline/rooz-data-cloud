# Production Execution Lifecycle / Recovery

This RDC v1 workstream is active after Phase 1P. Its first increment makes
execution retry timing a server-owned policy shared by stale-lease recovery and
worker-reported retryable failure handling.

The policy uses validated bounded exponential backoff, allows retries only for
failed or timed-out attempts below the configured maximum, and refuses to
requeue work whose durable dispatch outbox row is missing. Immutable execution
audit events include whether a retry was scheduled and its server-derived
`next_attempt_at`; workers cannot choose that timestamp.

Remaining increments cover workload deadline enforcement, cancellation
convergence, an independently scheduled stale-lease sweep, bounded project and
worker admission, crash/restart integration tests, and production operations.

See the [threat model](THREAT_MODEL.md) and [runbook](RUNBOOK.md).
