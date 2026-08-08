# Phase 1P threat model

Queue ownership is derived from the server-resolved project and queue. Queue
requests, receipts, and immutable transition records carry matching organization
and project identifiers and are guarded by PostgreSQL RLS and tenancy triggers.

Enqueue accepts only canonical HTTPS envelopes. It rejects credentials, IP
literals, fragments, unsafe keys, and non-JSON user data. DNS and egress checks
remain a worker responsibility; no worker route is exposed in this increment.

Idempotency is serialized by a queue-row lock. A reused key with different bytes
fails closed. Equivalent request identities are unique per queue.
