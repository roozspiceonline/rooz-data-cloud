# Proxy/Egress Policy Runbook

## Safe rollout

1. Apply migration `20260822_0022` and confirm both tables have RLS enabled,
   tenant policies, owner/reference triggers and immutable revision trigger.
2. Keep existing Queue HTTP/browser canary allowlists unchanged. Confirm
   `/api/v1/system/foundation` reports `egress_policy_live_binding_enabled=false`.
3. Create a DRAFT policy with a unique `Idempotency-Key`; inspect only metadata
   and the canonical digest. If authentication is required, reference a
   same-Project write-only secret.
4. Activate the intended revision using the latest policy version. A 409 means
   the operator must reload and review the new lineage before retrying.
5. Rotate by creating a revision, reviewing its normalized hosts and digest,
   then explicitly activating it. Never edit a revision or replace secret
   material through a policy endpoint.

## Incident response

Disable the policy with the current version, preserve policy/revision/audit
rows, and rotate or delete the Project secret through the secret API. Because
live binding is not yet wired, also disable the existing static canary egress
gate or remove its host allowlist when containment is required. Do not log
request bodies, secret UUIDs, ciphertext, credential values or external
response bodies.

Investigate `egress_policy.created`, `egress_policy.revision_created`,
`egress_policy.activated` and `egress_policy.disabled` audit actions by policy
and request ID. Version conflicts and cross-tenant 404s are expected defensive
outcomes, not reasons to relax authorization or RLS.

## Verification and rollback

Run `python scripts/verify-proxy-egress.py`, the PostgreSQL egress tests and the
full repository gates. A rollback rehearsal is `alembic downgrade
20260822_0021` followed by `alembic upgrade head` on an isolated database.
Downgrade deletes policy metadata, so production rollback requires an approved
backup and evidence-preservation decision.
