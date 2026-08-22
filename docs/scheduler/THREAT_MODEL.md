# Scheduler threat model

## Protected assets

Tenant ownership, immutable Agent/Build lineage, Run templates, scheduled
instants, generated Runs, trigger history, idempotency records and audit events.

## Trust boundaries and controls

| Threat | Control |
| --- | --- |
| Caller selects another tenant | Create path derives organization, Project and Agent from the authorized Agent version; RLS and lineage triggers reject mismatches. |
| Cross-tenant schedule/history read | Membership-aware security-definer resolver, permission checks and tenant RLS return opaque not-found results. |
| Duplicate Run after race/restart | Advisory transaction lock, row locks, unique scheduled-instant constraint, deterministic Run idempotency and atomic commit. |
| Missed interval causes a workload burst | `SKIP` or one bounded `FIRE_ONCE`; next interval advances strictly beyond sweep time. |
| Schedule definition is rewritten | Database trigger makes ownership, cadence, policy and Run template immutable. |
| History is erased or rewritten | Database trigger rejects trigger update/delete; audit events remain immutable. |
| Malformed stored template poisons dispatcher | Validation failure becomes a bounded `FAILED` trigger and the schedule advances. |
| Untrusted Agent gains scheduler/database authority | Scheduler runs in the trusted control plane; Agent/Chromium containers receive neither PostgreSQL credentials nor the dispatcher GUC. |
| Sensitive input leaks through operations | Process logs are aggregate-only; history stores codes and identifiers, not exception strings or Run input. |

## Residual risks

The dispatcher shares the trusted control-plane database identity in the local
Compose profile. Production must isolate its environment credentials and deny
database access to Agent/browser containers. Calendar/cron expressions and
time-zone rule changes are intentionally absent from this fixed-instant/fixed-
interval foundation.
