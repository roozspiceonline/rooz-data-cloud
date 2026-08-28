# Proxy/Egress Policy Runbook

## Safe rollout

1. Apply migration `20260822_0022` and confirm both tables have RLS enabled,
   tenant policies, owner/reference triggers and immutable revision trigger.
2. Keep existing Queue HTTP/browser canary allowlists unchanged. Confirm
   `/api/v1/system/foundation` reports `egress_policy_live_binding_enabled=true`
   and binding receipt `rdc.run-egress-policy-receipt/v1`.
3. Create a DRAFT policy with a unique `Idempotency-Key`; inspect only metadata
   and the canonical digest. If authentication is required, reference a
   same-Project write-only secret.
4. Activate the intended revision using the latest policy version. A 409 means
   the operator must reload and review the new lineage before retrying.
5. Create an eligible Run using only the policy ID. Confirm Run lineage,
   activation and any Queue v6 capability carry the same binding digest. A
   policy that exceeds the static canary ceiling must remain rejected.
6. Rotate by creating a revision, reviewing its normalized hosts and digest,
   then explicitly activating it. Never edit a revision or replace secret
   material through a policy endpoint.

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

Queued bound Runs are rechecked at admission. After disable or revision
rotation, confirm affected pending Runs become `FAILED` with
`EGRESS_POLICY_BINDING_REVOKED`, their START outboxes become `FAILED`, the audit
action is `run.egress_policy_binding_revoked`, and no execution lease exists.
Runs admitted before the policy transition serialize ahead of that transition;
use the static canary kill switch for immediate in-flight containment.

Treat `EGRESS_POLICY_ACTIVE_REVISION_INVALID`,
`EGRESS_POLICY_EXCEEDS_CANARY_CEILING`, worker binding-digest mismatches and
Queue v6 receipt mismatches as security events. Do not bypass the static
ceiling or re-enable credential-bound Runs during incident repair.

## Verification and rollback

Run `python scripts/verify-proxy-egress.py`, the PostgreSQL egress tests and the
full repository gates. A rollback rehearsal is `alembic downgrade
20260822_0021` followed by `alembic upgrade head` on an isolated database.
Downgrade deletes policy metadata, so production rollback requires an approved
backup and evidence-preservation decision.
