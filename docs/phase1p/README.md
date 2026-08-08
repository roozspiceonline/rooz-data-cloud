# Phase 1P — Tenant-scoped Request Queue

Phase 1P is the roadmap successor to the Key-Value Store primitive. Its design
starts with a protocol and security audit before queue persistence or worker
dequeue is enabled.

The implementation must retain server-derived tenancy, PostgreSQL RLS, bounded
idempotent request transitions, immutable history, signed pagination, audit
lineage, and a false-by-default lease-scoped worker capability. Agent and
Chromium workloads must never receive PostgreSQL or object-storage credentials,
and queue work must not weaken existing browser, egress, Dataset or KV controls.

Tracking: #55.

## Increment 1 — protocol foundation

`rdc.queue-enqueue/v1` accepts only strict envelopes with an idempotency key,
HTTPS hostname URL, optional safe unique key and bounded JSON user data. URLs
cannot use credentials, IP literals, fragments, unbounded envelopes or unsafe
JSON. The validator removes fragments and produces deterministic request and
request-identity SHA-256 digests. It has no persistence, worker or network side
effects.
