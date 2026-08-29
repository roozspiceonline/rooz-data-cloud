# Proxy/Egress Policy Runbook

## Safe rollout

1. Apply migrations through `20260829_0027`. Confirm the policy tables and
   `control.egress_health_observations` have RLS enabled, and confirm the health
   table has tenant-select, worker-select/insert, exact-lease guard and
   immutable update/delete triggers. Confirm the route columns reject invalid
   slugs and the Project/route/time index exists. Confirm new observation rows
   have `evidence IS NULL`, compact fields are bounded, and only replay,
    Project/time and Project/route/time indexes remain.
   Confirm the canary table has `claim_token_digest` but no `claim_token`
   column; the three `control.*_egress_credential_canar*` capability functions
   are `SECURITY DEFINER` with fixed search paths and no `PUBLIC` execution;
   and no scheduler select/insert/update policy remains. Setting the retired
   `rdc.egress_canary_scheduler` GUC must grant no table access.
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
10. Keep `RDC_EGRESS_CREDENTIAL_CANARY_ENABLED=false` until a reviewed live
    runner exists. To validate persistence in an isolated environment, set one
    credential-free HTTPS target with no query/user-info/fragment and bounded
    claim/batch/attempt values. Rotate a secret bound to an ACTIVE revision and
    confirm one replay-safe PENDING attempt plus immutable ENQUEUED history.
    Confirm the public list omits secret version, target digest and claim token.
11. Confirm `/api/v1/system/foundation` reports canary persistence/history true,
    live executor false and adaptive routing false. Do not interpret a stored
    SUCCEEDED result as authority to retry a Run or select a route.
12. Before Issue #97 is enabled, require evidence that the live transport uses
    the validated DNS set and revalidates the actual connected peer; disables
    redirects and proxy-environment inheritance; requires hostname-verified
    TLS; and enforces connect/total timeout, response-byte, retry and claim
    concurrency bounds. Unit policy tests alone are not live-runner evidence.

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

Investigate immutable health observations by Project/time and their stored
Run/lease/worker lineage. Normal samples are operational telemetry and do not
emit duplicate `egress_health.observed` audit rows. Do not log or add target
URLs, response content, headers, provider credentials or raw external data. A
spike in `HTTP_429`, `TIMEOUT` or `PROXY_FAILURE` is evidence for operator
investigation only; it does not authorize an automatic retry or route change.

For canary incidents, disable `RDC_EGRESS_CREDENTIAL_CANARY_ENABLED`, preserve
attempt/transition rows and rotate the affected Project secret. Treat stale
claims, `CONFIGURATION_ERROR`, `AUTH_REJECTED`, `SECRET_VERSION_SUPERSEDED` and
unexpected claim churn as security or operator events. Never add target URLs,
secret identifiers, authorization values or response bodies to results/logs.

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
provider-neutral `python scripts/verify-egress-health.py` protocol verifier, and the
full repository gates. A rollback rehearsal is `alembic downgrade
20260829_0026` followed by `alembic upgrade head` on an isolated database.
Downgrading `0027` preserves attempts/history but replaces digests with new raw
UUID tokens, invalidating any in-flight claim; drain or expire claims first.
Downgrading below `0026` deletes canary attempts/history and therefore requires
an approved backup and evidence-preservation decision.
