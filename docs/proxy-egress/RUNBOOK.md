# Proxy/Egress Policy Runbook

## Safe rollout

1. Apply migrations through `20260828_0024`. Confirm the policy tables and
   `control.egress_health_observations` have RLS enabled, and confirm the health
   table has tenant-select, worker-select/insert, exact-lease guard and
   immutable update/delete triggers. Confirm the route columns reject invalid
   slugs and the Project/route/time index exists.
2. Keep existing Queue HTTP/browser canary allowlists unchanged. Confirm
   `/api/v1/system/foundation` reports `egress_policy_live_binding_enabled=true`
   and binding receipt `rdc.run-egress-policy-receipt/v1`.
3. Create a DRAFT policy with a unique `Idempotency-Key`; inspect only metadata
   and the canonical digest. If authentication is required, reference a
   same-Project write-only secret whose value is the complete safe
   `Authorization` header value (for example, `Bearer ...`).
4. Activate the intended revision using the latest policy version. A 409 means
   the operator must reload and review the new lineage before retrying.
5. Create an eligible Run using only the policy ID. Confirm Run lineage,
   activation and any Queue v6 capability carry the same binding digest. A
   policy that exceeds the static canary ceiling must remain rejected.
6. Rotate by creating a revision, reviewing its normalized hosts and digest,
   then explicitly activating it. Never edit a revision or replace secret
   material through a policy endpoint.
7. For credential-bound web fetches, confirm only the internal lease endpoint
   issues `execution.egress_credential_envelope.issued`, expiry is at most 60
   seconds, and neither Run events nor Agent output contains a secret name,
   reference, ciphertext or plaintext. Chromium use must remain denied.
8. Submit a bounded health observation from an active egress-enabled Run lease.
   Confirm an exact observation-ID replay returns HTTP 200 with `replayed=true`,
   altered evidence returns `EGRESS_HEALTH_REPLAY_CONFLICT`, and the Project
   summary exposes counts only for a requested 1–24 hour window.
9. Set `RDC_EGRESS_ROUTE_PROVIDER_KEY` and `RDC_EGRESS_ROUTE_REGION_KEY` to
   non-secret lowercase opaque slugs for the deployment route. Set
   `RDC_EGRESS_HEALTH_MIN_ROUTE_SAMPLES` between 5 and 1000. Confirm the route
   endpoint suppresses smaller cohorts, rejects excessive cardinality and does
   not expose raw observation or execution lineage.

## Incident response

Disable the policy with the current version, preserve policy/revision/audit
rows, and rotate or delete the Project secret through the secret API. Disable
the existing static canary egress gate or remove its host allowlist for
immediate containment of already queued immutable snapshots. Do not log
request bodies, secret UUIDs, ciphertext, credential values or external
response bodies.

Investigate `egress_policy.created`, `egress_policy.revision_created`,
`egress_policy.activated` and `egress_policy.disabled` audit actions by policy
and request ID. Version conflicts and cross-tenant 404s are expected defensive
outcomes, not reasons to relax authorization or RLS.

Investigate `egress_health.observed` by observation, Run, lease and request ID.
Do not log or add target URLs, response content, headers, provider credentials or
raw external data. A spike in `HTTP_429`, `TIMEOUT` or `PROXY_FAILURE` is evidence
for operator investigation only; it does not authorize an automatic retry or
route change.

Queued bound Runs are rechecked at admission. After disable or revision
rotation, confirm affected pending Runs become `FAILED` with
`EGRESS_POLICY_BINDING_REVOKED`, their START outboxes become `FAILED`, the audit
action is `run.egress_policy_binding_revoked`, and no execution lease exists.
Runs admitted before the policy transition serialize ahead of that transition;
use the static canary kill switch for immediate in-flight containment.

Treat `EGRESS_POLICY_ACTIVE_REVISION_INVALID`,
`EGRESS_POLICY_EXCEEDS_CANARY_CEILING`, `EGRESS_CREDENTIAL_BINDING_INVALID`,
worker binding-digest mismatches and Queue v6 receipt mismatches as security
events. Do not bypass the static ceiling. Rotate the Project secret and disable
the policy/static canary for immediate containment; database grant revocation
cannot retract a value already decrypted by an active trusted worker.

## Verification and rollback

Run `python scripts/verify-proxy-egress.py`, the PostgreSQL egress tests and the
provider-neutral `python scripts/verify-egress-health.py` protocol verifier, the
full repository gates. A rollback rehearsal is `alembic downgrade
20260828_0023` followed by `alembic upgrade head` on an isolated database.
Downgrade removes route attribution but preserves immutable observations;
production rollback still requires an approved evidence-preservation decision.
