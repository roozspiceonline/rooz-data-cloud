# Events foundation runbook

Apply migrations through `20260829_0029`, then confirm `control.events` has RLS
enabled, the two project-bound policies exist, and the envelope/immutability
triggers are active. Verify the public API exposes only the Project history GET
route and `/api/v1/system/foundation` does not claim webhook delivery support.

For an event incident, preserve the immutable row, correlate by the bounded
request ID and subject, and inspect the originating Run/Build transaction. Do
not copy payloads into logs. Treat an invalid reference, replay conflict,
credential-key rejection, or RLS denial as a security signal; never bypass the
trigger or relax the allowlist.

Rollback rehearsal is `alembic downgrade 20260829_0028` followed by `alembic
upgrade head` on an isolated database. Downgrade deletes the event foundation,
so production rollback requires an approved evidence-retention decision and
backup. No outbound delivery must occur because this increment has no delivery
code.

For migration `20260830_0030`, confirm destination rows never reach an ACTIVE
state and that the foundation status reports both delivery and activation as
false. Secret values must never be queried for diagnosis; use only destination
ID, version and signing-secret version metadata. Disable a suspicious
destination and rotate its signing secret before any future re-verification.
