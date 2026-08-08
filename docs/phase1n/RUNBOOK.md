# Phase 1N Operator Runbook

## Increment 3 state

Authenticated control-plane Dataset item append is now available. Worker
Dataset writes remain disabled.

Expected state:

```text
rdc.dataset-append/v1             available
control.datasets                  present + RLS
control.dataset_items             present + RLS
control.dataset_append_receipts   present + RLS
Dataset metadata routes           available
Dataset item append route         authenticated control-plane only
worker Dataset append             absent
worker Dataset RLS policy         absent
Agent database credentials        absent
direct Agent Postgres access      absent
```

## Append route

`POST /api/v1/datasets/{dataset_id}/items`

Requires `dataset.write` plus the normal authentication/CSRF controls.

Each request must contain:

- `schema_version = rdc.dataset-append/v1`
- idempotency key
- 1–100 JSON-object items

The service revalidates the protocol after Pydantic parsing.

## Idempotency

The Dataset row is locked before replay, quota and sequence decisions.

`(dataset_id, idempotency_key)` is unique.

- same key + same request digest => return original receipt, no new items
- same key + different request digest => fail closed
- first request => create receipt and items in the same transaction

## Quotas

Protocol:

- items per append <= 100
- encoded item <= 65,536 bytes
- append envelope <= 262,144 bytes
- JSON nesting depth <= 32

Dataset:

- item count <= 100,000
- encoded item bytes <= 268,435,456

Database checks mirror the Dataset-level quotas and enforce
`next_sequence = item_count + 1`.

## Append-only guarantees

`DatasetItem` rows bind to `append_receipt_id`.

Database triggers reject UPDATE or DELETE of:

- Dataset items
- Dataset append receipts

No item content is emitted into the append audit event.

## Stop conditions

Stop Phase 1N work if an implementation:

- bypasses `rdc.dataset-append/v1` server validation
- allocates sequences outside the Dataset row-lock transaction
- changes item counters before quota checks
- accepts idempotency replay with a different request digest
- adds arbitrary DatasetItem update/delete APIs
- adds worker Dataset RLS before Increment 4 capability design
- gives Agent or browser containers database credentials
- weakens Phase 1M network isolation

## Next increment

Add a controlled worker-to-control-plane Dataset append capability. The worker
must authenticate through the existing private execution-plane identity and
must never give the Agent or Chromium direct Postgres access.
