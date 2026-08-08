# Phase 1N Operator Runbook

## Increment 1 state

The Dataset protocol exists for validation and contract development only.

Do not enable or advertise Dataset persistence from this increment.

Expected state:

```text
rdc.dataset-append/v1           available
database Dataset tables         absent
Dataset REST routes             absent
worker Dataset append           absent
Agent database credentials      absent
direct Agent Postgres access    absent
```

## Safe request limits

- items per append: 1–100
- encoded item bytes: <= 65,536
- encoded batch bytes: <= 262,144
- JSON nesting depth: <= 32
- idempotency key: 1–128 characters, restricted safe alphabet

## Stop conditions

Stop Phase 1N work if an implementation:

- accepts organization/project/Run ownership from the append payload
- gives Agent or browser containers direct PostgreSQL credentials
- permits cross-project Dataset access
- permits arbitrary item mutation
- accepts unbounded batches or items
- permits retry duplication under the same Dataset/idempotency key
- activates Dataset worker writes before RLS/idempotency/quota guarantees exist

## Next increment

Add the PostgreSQL Dataset/DatasetItem model, migration, mandatory RLS policies,
authenticated control-plane API, and tests. Persistence must remain
control-plane mediated.
