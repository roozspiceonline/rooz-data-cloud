# Rooz Data Cloud

Rooz Data Cloud is a tenant-isolated scraping and automation control plane.
The merged baseline includes identity and authorization, Projects, immutable
Agent versions, source/build and Run lifecycle, isolated worker execution,
controlled web and browser canaries, durable Dataset results, and versioned
Key-Value Store state under PostgreSQL RLS.

All untrusted Agent and browser execution remains release-blocked. PostgreSQL,
object-storage, worker and lease credentials never enter Agent or Chromium
containers; worker capabilities are false-by-default and lease-scoped.

Phase 1P, tenant-scoped Request Queues, is active. It will add bounded,
idempotent queue lifecycle controls without weakening existing tenancy, egress,
Dataset or KV protections. See [the RDC v1 roadmap](docs/roadmap/RDC_V1_ROADMAP.md)
for implemented capabilities, remaining work, and release gates.
