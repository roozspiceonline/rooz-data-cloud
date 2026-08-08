# Phase 1P threat model

Queue ownership is derived from the server-resolved project and queue. Queue
requests, receipts, and immutable transition records carry matching organization
and project identifiers and are guarded by PostgreSQL RLS and tenancy triggers.

Enqueue accepts only canonical HTTPS envelopes. It rejects credentials, IP
literals, fragments, unsafe keys, and non-JSON user data. DNS and egress checks
remain a worker responsibility.

Idempotency is serialized by a queue-row lock. A reused key with different bytes
fails closed. Equivalent request identities are unique per queue.

Worker claim and completion require an ACTIVE unexpired lease plus a dedicated
false-by-default canary gate. Queue tenancy is derived from the lease, and each
completion is bound to both the claiming worker and an unguessable claim token.
The gate additionally pins the configured canary worker, immutable Agent
version, worker capability, and manifest `requestQueue` declaration. Expired
claims cannot complete even if reclaim has not yet run.
