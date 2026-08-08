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

This increment does not yet claim full production recovery. A process that can
renew leases must still be bounded by the workload deadline; cancellation must
converge after worker loss; recovery sweeps must run without relying on worker
traffic; and concurrency admission must be enforced across workers and projects.
