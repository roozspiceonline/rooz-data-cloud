# Scheduler

The Scheduler persists tenant-scoped one-time and fixed-interval Run schedules.
Every schedule is bound by the server to the authenticated immutable Agent
version, its Project and organization, and one successful Build. The caller
cannot submit ownership fields.

## Implemented contract

- `ONCE` and bounded `INTERVAL` cadences (60 seconds through 365 days).
- `SKIP` and `FIRE_ONCE` missed-run policies with a bounded misfire grace.
- An immutable validated `CreateRunRequest` template; every fire reuses the
  ordinary Run creation validation, outbox, event, idempotency and audit path.
- `ACTIVE`, `PAUSED` and terminal `COMPLETED` schedule states.
- Immutable `FIRED`, `SKIPPED` and `FAILED` trigger history.
- Unique `(schedule_id, scheduled_for)` persistence and deterministic Run
  idempotency keys, so a scheduled instant cannot produce duplicate Runs.
- A transaction-scoped PostgreSQL singleton lock plus ordered
  `FOR UPDATE SKIP LOCKED` selection.
- Backlog collapse: a sweep produces at most one Run per schedule, then advances
  an interval schedule beyond the sweep time instead of creating a burst.
- Tenant RLS, security-definer tenant lookup, lineage triggers, signed
  resource/filter-bound pagination and least-privilege permissions.

Migration `0021` owns `control.schedules` and
`control.schedule_triggers`. The trusted `schedule-dispatcher` service is the
only process that activates transaction-local cross-tenant schedule selection;
before creating a Run it switches to the exact schedule organization and
creator context. Agent and browser workloads never receive database authority.

The scheduler is an implemented foundation workstream. Broader calendar/cron
syntax, user-facing Console support and platform-wide operations remain in the
RDC v1 roadmap.
