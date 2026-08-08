# Phase 1N — Tenant-scoped Dataset Protocol & Durable Result Storage

Phase 1N starts from the merged Phase 1M baseline and adds the first durable
structured data primitive required for an Apify-class scraping platform.

The Phase 1N target is an append-only Dataset abstraction for Run results.

## Increment 1 — protocol foundation

Increment 1 defines the request contract only. It does **not** enable Dataset
persistence, Dataset APIs, or worker Dataset writes.

Contract:

- `rdc.dataset-append/v1`
- strict top-level fields
- one idempotency key per append batch
- 1–100 JSON-object items per batch
- maximum encoded item size: 65,536 bytes
- maximum encoded batch size: 262,144 bytes
- maximum JSON nesting depth: 32
- NaN and Infinity rejected
- non-JSON values rejected
- canonical JSON SHA-256 request digest
- append-only semantics

The request carries no organization, project, Run, Agent or user ownership
fields. Ownership and lineage will be derived exclusively from authenticated
server-side resources when persistence is introduced.

Dataset item content is application data only. Keys inside an item never grant
security authority, even if a record happens to contain names such as
`organization_id`, `project_id`, or `run_id`.

## Current capability boundary

```text
Dataset request contract       available
Dataset persistence            disabled
Dataset API                     disabled
worker Dataset writes          disabled
Agent direct Postgres access   prohibited
Dataset item mutation          unsupported
KV Store                        out of scope (Phase 1O)
Request Queue                   out of scope (Phase 1P)
```

## Planned increments

1. Protocol foundation and CI/security verifier.
2. PostgreSQL Dataset/DatasetItem model, migration, RLS and authenticated API.
3. Idempotent append transaction, quotas, monotonic item sequence numbers and
   immutable Run lineage.
4. Controlled worker append path with no Agent database credentials.
5. Paginated reads, bounded export, audit events and final hardening.

PR governance remains the same as previous RDC phases: the Phase 1N
implementation PR remains DRAFT until the full phase is exact-head green.
