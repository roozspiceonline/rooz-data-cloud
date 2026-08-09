# Execution recovery threat model

Workers report outcomes but do not own retry timing or retry limits. The API
combines the worker request with server configuration, the persisted lease
attempt, and the existence of the durable dispatch outbox row. Missing lineage
fails terminally instead of creating untraceable duplicate work.

Backoff is exponential and capped. Attempt counts remain database-backed and
bounded by the execution lease constraint. Stale lease and worker-failure paths
use the same policy so a caller cannot obtain a weaker recovery path. Audit
lineage records the attempt, retry decision, and next eligible time without
including lease tokens, secrets, Run input, or failure details beyond existing
bounded codes.

The server derives the immutable lease deadline from persisted Build or Run
configuration, never from a worker renewal request. PostgreSQL rejects deadline
mutation and any expiry beyond the deadline. Worker credential resolution
rejects overdue leases, and deadline-aware RLS prevents overdue Run leases from
retaining Request Queue access. Row locking and `SKIP LOCKED` make concurrent
reapers single-winner; a deadline path is terminal and cannot be converted into
a retry by a worker-supplied `retryable` flag.

Cancellation ownership remains server-side. The API row-locks the Run and
reuses its unique `(run_id, command)` outbox identity, so callers cannot create
duplicate cancel work by racing idempotency keys. PostgreSQL makes the first
cancellation request/deadline immutable. A late start worker cannot move an
`ABORTING` Run back to `RUNNING` or complete it successfully. Convergence fences
all active Run leases before terminalization, which removes worker API and RLS
authority and revokes issued secret grants even if the underlying process is
slow to exit.

Recovery is now independent of worker traffic. The dedicated process uses a
transaction advisory lock, so horizontally duplicated schedulers cannot both
own a batch. Candidate rows remain bounded and use `SKIP LOCKED`; a slow batch
cannot expand into an unbounded transaction. If the process crashes, PostgreSQL
rolls back lease, outbox, Run, grant, audit, and health mutations together and
releases the singleton lock. Restarting safely retries durable candidates.

Scheduler health is global operational metadata, not a tenant resource. The
public health response excludes owner identity, tenant IDs, payloads, exception
text, tokens, and secrets. Failures persist only a bounded exception class name
and generic summary. Readiness reports an enabled scheduler as stale when no
recent successful heartbeat exists, preventing silent recovery loss.

This increment does not yet claim full production recovery. Concurrency
admission must still be enforced across workers and projects, and broader
process/container termination scenarios remain part of the workstream gate.
