# Proxy/Egress Threat Model

## Assets and boundaries

Protected assets are tenant policy metadata, immutable policy lineage, Project
secret references, write-only credential material, and the existing trusted
egress broker boundary. API callers, Agent code, Chromium, hostnames, future
proxy responses and all external network data are untrusted.

## Primary threats and controls

- Cross-tenant policy or secret reference: authorization resolves ownership
  through `security.rdc_egress_policy_org`; service queries require exact
  organization/Project matches; RLS and security-definer tenancy triggers
  independently reject mismatches.
- SSRF-policy ambiguity: inputs admit exact normalized DNS hostnames only.
  Wildcards, URL/user-info/path syntax, IP literals, single-label and special-use
  names fail closed. Future live resolution must still reject non-public DNS and
  revalidate every redirect/address.
- Unbounded fetches: immutable revisions cap request count, per-response and
  aggregate bytes, redirects, connect timeout and request timeout.
- Privilege or race escalation: permissions separate read from mutation;
  activation/disable/revision creation lock the policy row and require the exact
  version. The active-revision trigger requires same policy and tenancy.
- History rewriting: revision update/delete is rejected by PostgreSQL. Rotation
  appends a revision and requires explicit activation.
- Credential disclosure: policies store only a Project-secret UUID; metadata and
  audit output emits only a boolean. Agent/Chromium receive no database,
  object-storage or policy credential.
- Idempotency abuse: creation locks a tenant/principal/endpoint/key digest and
  conflicts when the same key has a different canonical request fingerprint.
- Premature activation: persisted `ACTIVE` currently represents operator policy
  selection only. Foundation status explicitly reports live binding disabled;
  no worker or broker consumes these rows yet.

## Residual work before live enforcement

Bind an exact active revision and digest into Run/lease receipts; validate it in
the worker and broker; resolve public addresses with redirect revalidation;
deliver credentials only as short-lived worker-bound envelopes; define
revocation/rotation convergence; and add live adversarial SSRF and proxy tests.
