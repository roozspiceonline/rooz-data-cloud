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

For migration `20260830_0031`, diagnose lifecycle stalls using status,
attempt-count, available-at, claim expiry and immutable transition sequence.
Never manually reuse a claim token. A stale claim may be reclaimed only through
the fenced service path. `DEAD_LETTERED` rows require an explicit future replay
workflow; direct row edits and transition deletion are prohibited.

For migration `20260831_0032`, keep
`RDC_WEBHOOK_DELIVERY_CANARY_ENABLED=false` until the isolated adversarial test
matrix is reviewed for the deployment network. Validate a private or special
DNS answer is rejected, a connected peer outside the validated DNS set is
rejected, TLS hostname validation is active, redirects are never followed, and
timeout/response/concurrency bounds match the claim lifetime. The runner must
have only database access and the Project-secret master key.

Diagnose only with delivery ID, status, attempt count, outcome taxonomy, HTTP
status, claim expiry, and transition sequence. Never log or query the endpoint,
event body, raw claim token, encrypted material, or plaintext signing secret.
`CONFIGURATION_ERROR` means the immutable snapshot no longer matches an enabled
destination and exact secret version; rotate/recreate rather than editing the
attempt. Stop the runner by restoring the false gate before database repair.

Rollback rehearsal is `alembic downgrade 20260830_0031` followed by `alembic
upgrade head` on an isolated database. Downgrade converges live claims to
`RETRY_WAIT` and removes only the canary capabilities and snapshots; never run
it merely to retry a delivery.

For migration `20260901_0033`, use the delivery history API and immutable
transition sequence to diagnose failures. Replay only `DEAD_LETTERED` rows with
the current version and a new retained idempotency key. Do not replay after an
operator disable or configuration change. Automatic disablement after the
bounded consecutive terminal-failure threshold blocks both claims and new
enqueues; a successful active delivery resets the counter. Secret rotation
returns the destination to pending verification.

Rehearse `alembic downgrade -1` and `alembic upgrade head` on an isolated,
data-bearing database only after claims converge. The downgrade converts active
destinations back to pending verification and removes replay metadata; preserve
immutable transition evidence and take an approved backup before production
rollback.
