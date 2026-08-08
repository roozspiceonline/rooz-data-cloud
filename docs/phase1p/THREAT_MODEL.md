# Phase 1P threat model

Queue ownership is derived from the server-resolved project and queue. Queue
requests, receipts, and immutable transition records carry matching organization
and project identifiers and are guarded by PostgreSQL RLS and tenancy triggers.

Enqueue accepts only canonical HTTPS envelopes. It rejects credentials, IP
literals, fragments, unsafe keys, and non-JSON user data. DNS and egress checks
remain a worker responsibility.

Idempotency is serialized by a queue-row lock. A reused key with different bytes
fails closed. Equivalent request identities are unique per queue.

Each new enqueue and every successful claim, reclaim, handled, or failed state
transition appends an organization- and project-bound immutable audit event in
the same database transaction. Audit records contain lineage identifiers,
digests, attempts, and bounded failure codes; they never contain request URLs,
user data, claim tokens, or failure summaries. PostgreSQL rejects audit events
whose project does not belong to the recorded organization, and rejects audit
event updates and deletes.

Project Queue listings, Queue request listings, and immutable transition
history use bounded keyset pagination with filter-bound signed cursors. Cursor
kinds cannot cross collection boundaries. Queue-list cursors are bound to the
server-resolved project; request cursors are bound to Queue and state filter;
transition cursors are bound to Queue and optional request filter. Invalid,
non-canonical, tampered, or replayed cursors fail closed.

Worker claim and completion require an ACTIVE unexpired lease plus a dedicated
false-by-default canary gate. Queue tenancy is derived from the lease, and each
completion is bound to both the claiming worker and an unguessable claim token.
The gate additionally pins the configured canary worker, immutable Agent
version, worker capability, and manifest `requestQueue` declaration. Expired
claims cannot complete even if reclaim has not yet run.
