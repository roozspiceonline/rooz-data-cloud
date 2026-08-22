# Scheduler runbook

## Configuration

- `RDC_SCHEDULE_DISPATCH_ENABLED` enables the trusted dispatcher.
- `RDC_SCHEDULE_DISPATCH_INTERVAL_SECONDS` is bounded to 1–300 seconds.
- `RDC_SCHEDULE_DISPATCH_BATCH_SIZE` is bounded to 1–500 schedules.

Run one or more `python -m app.schedule_dispatcher` replicas. PostgreSQL
advisory transaction locking elects one active sweep; other replicas return
without dispatching. A process crash rolls back schedule advancement, Run,
outbox, trigger, idempotency and audit writes together.

## Investigation

1. Confirm migration `20260822_0021` is current and the dispatcher process is
   running with the trusted control-plane database identity.
2. Inspect only aggregate process logs (`examined`, `fired`, `skipped`,
   `failed`). Logs intentionally exclude tenant IDs, Run input and error text.
3. For an authorized tenant investigation, read the schedule and immutable
   trigger history through the API. `FAILED` contains a bounded code, never an
   exception message or Run input.
4. A repeated `BUILD_NOT_READY`, capability-policy or invalid-template failure
   advances the due instant and leaves durable failure history; it cannot poison
   every subsequent sweep.
5. Pausing a schedule is idempotent. Resuming preserves the next scheduled
   instant, so the configured missed-run policy is applied on the next sweep.

## Recovery

- Restarting the dispatcher is safe; the unique trigger constraint and
  deterministic Run idempotency key prevent duplicate work.
- Do not manually delete or update trigger history. Database triggers reject
  both operations.
- Do not modify schedule ownership, cadence or Run template in place. Create a
  new schedule after pausing the old schedule.
- Before rollback, pause dispatch, apply Alembic downgrade only after confirming
  that removal of schedule/history data is acceptable, and retain a backup.
