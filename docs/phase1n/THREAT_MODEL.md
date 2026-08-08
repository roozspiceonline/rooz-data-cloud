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

- strict `rdc.dataset-append/v1` top-level contract
- no caller-controlled ownership fields
- idempotency key required
- canonical request digest
- 100-item batch ceiling
- 65,536-byte item ceiling
- 262,144-byte batch ceiling
- JSON nesting depth ceiling
- finite JSON numbers only
- JSON-object items only
- no persistence or worker write activation yet

## Mandatory before persistence activation

- Dataset and DatasetItem tenant columns derived server-side
- PostgreSQL RLS policies for organization/project scope
- unique idempotency constraint scoped to the Dataset
- monotonic append sequence allocated transactionally
- record-count and total-byte quotas enforced before commit
- immutable Run/AgentVersion lineage
- authenticated read permissions
- bounded cursor pagination
- no arbitrary UPDATE of Dataset items
- audit event for Dataset creation and append
- no direct Agent/Chromium database network path
