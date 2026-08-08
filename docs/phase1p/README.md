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
