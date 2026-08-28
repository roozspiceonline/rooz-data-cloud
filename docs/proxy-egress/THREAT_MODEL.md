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
- Caller-authored or stale binding: Run input accepts a strict policy resource
  reference only. The server row-locks an exact same-tenant/same-Project ACTIVE
  policy and resolves its current revision; DRAFT, DISABLED, missing,
  cross-tenant and cross-Project references return the same not-found outcome.
- Snapshot tampering: the receipt binds policy ID, revision ID and number,
  canonical revision digest, runtime digest and credential absence. Activation,
  Queue v6 capabilities and the trusted worker compare the same binding digest;
  any missing, extra or changed field fails closed.
- Canary widening: both control plane and worker require exact hosts and methods
  to be subsets of their static canary and require every numeric budget to be no
  greater. Runtime policy selection cannot expand general egress.
- Method escalation: the broker and browser gateway enforce the revision's
  GET/HEAD subset; a GET-only revision cannot issue HEAD.

## Residual work before live enforcement

Deliver credentials only as short-lived worker/broker-bound envelopes; define
revocation/rotation convergence for already queued immutable snapshots; and add
production proxy-provider health, rotation and live adversarial canaries.
