# Phase 1N Threat Model

Phase 1N introduces durable structured Run output. Hostile scraped content and
hostile Agent-provided records must be assumed.

## Primary threats

1. Cross-tenant Dataset writes or reads.
2. Caller-supplied ownership identifiers overriding authenticated lineage.
3. Duplicate records caused by retries.
4. Oversized records or batches causing memory/database pressure.
5. Deeply nested JSON causing parser/serializer exhaustion.
6. NaN/Infinity or non-JSON values creating non-portable records.
7. Mutable item APIs destroying scrape-result provenance.
8. Agent containers receiving direct PostgreSQL credentials.
9. Dataset records being mistaken for trusted authorization metadata.
10. Unbounded export/read operations.

## Increment 1 mitigations

- strict `rdc.dataset-append/v1`
- bounded JSON-object batches
- canonical SHA-256 request digest
- required idempotency key
- finite JSON values only

## Increment 2 mitigations

- Dataset ownership is derived from the authenticated Run
- Dataset request body carries no tenant or lineage identifiers
- `control.datasets` and `control.dataset_items` use PostgreSQL RLS
- Dataset tenancy trigger binds Run, Agent and AgentVersion lineage
- DatasetItem tenancy trigger binds Dataset, Run, project and organization
- hidden-resource lookup uses `security.rdc_dataset_org(uuid)`
- Dataset metadata API requires `dataset.create` / `dataset.read`
- Dataset creation writes an audit event
- no DatasetItem append route exists
- no worker Dataset RLS policy exists
- Agent/Chromium containers receive no database credentials

## Mandatory before DatasetItem append activation

- Dataset-scoped unique idempotency receipt
- request digest stored and replay-checked
- monotonic sequence allocation in the same transaction as inserts
- record-count quota enforced before commit
- total-byte quota enforced before commit
- batch/item protocol limits revalidated server-side
- exact replay returns the original receipt without duplicate rows
- mismatched replay under the same idempotency key fails closed
- append audit event
- no arbitrary UPDATE of Dataset items
- no direct Agent/Chromium database network path
