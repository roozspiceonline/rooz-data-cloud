# Phase 1N Threat Model

Phase 1N treats scraped content and Agent-provided Dataset records as hostile
application data.

## Primary threats

1. Cross-tenant Dataset access.
2. Caller-supplied ownership overriding authenticated lineage.
3. Duplicate records caused by retries.
4. Idempotency-key reuse with a different payload.
5. Concurrent append sequence collisions.
6. Dataset resource exhaustion.
7. Mutable item history destroying provenance.
8. Agent containers receiving database credentials.
9. Dataset content being mistaken for authorization metadata.
10. Unbounded reads or exports.

## Increment 1 mitigations

- strict `rdc.dataset-append/v1`
- bounded JSON objects
- canonical digest
- required idempotency key

## Increment 2 mitigations

- server-derived Run/Agent/AgentVersion lineage
- Dataset/DatasetItem RLS
- tenant triggers
- hidden-resource Dataset resolver
- authenticated metadata routes
- no worker write policy

## Increment 3 mitigations

- Dataset-scoped immutable append receipts
- unique `(dataset_id, idempotency_key)`
- canonical request digest stored on every receipt
- Dataset row locked before replay/quota/sequence decisions
- exact replay returns the existing receipt
- mismatched replay fails closed
- transactional monotonic sequence allocation
- Dataset item count quota: 100,000
- Dataset encoded item-byte quota: 268,435,456
- per-append protocol limits revalidated server-side
- DatasetItem rows bind to the exact append receipt
- database triggers block item/receipt UPDATE and DELETE
- append audit event excludes hostile item content
- worker Dataset writes remain disabled
- no worker Dataset RLS policy
- Agent/Chromium receive no Postgres credentials

## Mandatory before worker append activation

- worker identity authenticated through the private execution plane
- exact active Run/lease lineage
- exact Dataset/Run/AgentVersion match
- worker capability receipt limiting Dataset append
- no direct Agent or browser database/network path
- the worker must submit through a bounded control-plane protocol
- control plane must reuse the same idempotency/quota/sequence transaction
