# Phase 1N — Tenant-scoped Dataset Protocol & Durable Result Storage

Phase 1N starts from the merged Phase 1M baseline and adds the first durable
structured data primitive required for an Apify-class scraping platform.

The Phase 1N target is an append-only Dataset abstraction for Run results.

## Increment 1 — protocol foundation

Increment 1 established:

- `rdc.dataset-append/v1`
- strict top-level fields
- one idempotency key per append batch
- 1–100 JSON-object items per batch
- maximum encoded item size: 65,536 bytes
- maximum encoded batch size: 262,144 bytes
- maximum JSON nesting depth: 32
- NaN and Infinity rejection
- canonical JSON SHA-256 request digest

## Increment 2 — Dataset metadata persistence + RLS

Increment 2 adds the persistence boundary without enabling item append:

- `control.datasets`
- `control.dataset_items`
- Dataset lineage bound to organization, project, Run, Agent and AgentVersion
- organization/project ownership derived from the authorized Run
- unique Dataset name per Run
- Dataset item sequence uniqueness per Dataset
- server-side tenancy triggers
- PostgreSQL RLS for both Dataset tables
- `security.rdc_dataset_org(uuid)` hidden-resource resolver
- authenticated Dataset metadata create/list/get API
- `dataset.create` and `dataset.read` permission scopes
- audit event on Dataset creation

The client may provide only the Dataset name when creating metadata. It cannot
provide organization, project, Run, Agent or AgentVersion ownership fields.

## Current capability boundary

```text
Dataset request contract       available
Dataset metadata persistence   available
Dataset metadata API           available
DatasetItem persistence table  available + RLS protected
Dataset item append API        disabled
worker Dataset writes          disabled
Agent direct Postgres access   prohibited
Dataset item mutation          unsupported
KV Store                        out of scope (Phase 1O)
Request Queue                   out of scope (Phase 1P)
```

`DatasetItem` exists now so tenancy/RLS can be proven before writes are
activated. No public or worker path inserts Dataset items in Increment 2.

## Planned increments

1. Protocol foundation and CI/security verifier.
2. PostgreSQL Dataset/DatasetItem model, migration, RLS and authenticated
   metadata API.
3. Idempotent append transaction, quotas, monotonic item sequence numbers and
   immutable request-digest lineage.
4. Controlled worker append path with no Agent database credentials.
5. Paginated item reads, bounded export, audit expansion and final hardening.

PR governance remains unchanged: the Phase 1N implementation PR remains DRAFT
until the full phase is exact-head green.
