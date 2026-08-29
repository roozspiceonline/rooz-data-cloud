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
- Credential disclosure: policies store only a Project-secret UUID; metadata,
  Run lineage and audit output emit only a boolean or policy binding digest.
  Plaintext is decrypted server-side only long enough to create a short-lived
  worker-key-encrypted envelope and is injected solely into trusted broker
  request headers. Agent/Chromium receive no database, object-storage or policy
  credential; credential-bound browser paths fail closed.
- Idempotency abuse: creation locks a tenant/principal/endpoint/key digest and
  conflicts when the same key has a different canonical request fingerprint.
- Caller-authored or stale binding: Run input accepts a strict policy resource
  reference only. The server row-locks an exact same-tenant/same-Project ACTIVE
  policy and resolves its current revision; DRAFT, DISABLED, missing,
  cross-tenant and cross-Project references return the same not-found outcome.
- Snapshot tampering: the receipt binds policy ID, revision ID and number,
  canonical revision digest, runtime digest and credential presence. Activation,
  Queue v6 capabilities and the trusted worker compare the same binding digest;
  any missing, extra or changed field fails closed.
- Canary widening: both control plane and worker require exact hosts and methods
  to be subsets of their static canary and require every numeric budget to be no
  greater. Runtime policy selection cannot expand general egress.
- Method escalation: the broker and browser gateway enforce the revision's
  GET/HEAD subset; a GET-only revision cannot issue HEAD.
- Queued-work revocation race: `RUN_START` admission holds the Run, outbox and
  policy row locks in one transaction and rechecks ACTIVE plus the exact
  selected revision before creating a lease. Disable/rotate and claim therefore
  serialize; stale work terminally fails without a capability receipt.
- Credential rotation race: issuance locks policy and secret rows, binds the
  encrypted grant to secret version plus worker/lease/Run/policy digest, and
  replacement revokes outstanding grants. Previously decrypted values are
  bounded by the shorter of lease expiry and the 60-second envelope TTL.
- Forged or replayed health evidence: only an authenticated active `RUN_START`
  lease owned by an active `EVENT_INGEST` worker with an egress activation may
  append. Ownership is derived from that lease and independently checked by a
  PostgreSQL trigger and worker RLS. The server and database deterministically
  derive outcome flags. Each immutable observation is replay-keyed within its
  lease; exact replay is harmless and changed evidence conflicts.
- Health telemetry exfiltration: the strict evidence object cannot contain a
  target, body, headers, credential, provider identity or arbitrary extension.
  Stored values and audit details are bounded classifications only. Tenant users
  receive a bounded 1–24 hour Project aggregate, not raw observation lineage.
- Telemetry growth and audit amplification: accepted evidence is normalized to
  compact typed bounded columns and JSONB is cleared. The immutable observation
  itself retains exact lease/Run/worker/digest lineage under RLS, so routine
  samples do not duplicate that operational event in the security audit table.
  Policy, credential, lifecycle and administrative actions remain audited.
- Route-dimension spoofing or cardinality abuse: provider and region keys are
  validated lowercase operator configuration stamped by the API, never worker
  or tenant input. The public aggregate is tenant-authorized, window-bounded,
  capped at 32 dimensions and applies a configured minimum sample threshold.
  Low-volume dimensions are suppressed rather than exposing sparse route data.
- Rotation-canary substitution or replay: enqueue is server-owned and
  transactionally follows secret replacement. PostgreSQL derives exact tenant,
  active revision, secret and current version lineage; the unique
  revision/version/target-digest key makes replay harmless. Migration `0027`
  removes the transaction-wide scheduler GUC and all scheduler RLS policies.
  Three fixed-search-path `SECURITY DEFINER` operations now provide only exact
  secret enqueue, bounded global claim/reclaim, and exact token-fenced
  completion; execution is revoked from `PUBLIC`. They do not accept caller
  organization, Project, policy, revision or secret-version lineage.
- Canary claim capability theft: claim generates 256 random bits, returns the
  raw hexadecimal bearer token only in the trusted claim result, and persists
  only its SHA-256 digest. Completion hashes the submitted token before the
  database call. Tokens and digests are absent from tenant APIs, audit details,
  transition history, metrics and errors. Reclaim replaces the token and makes
  the prior token unusable; expiry and terminal state reject completion.
- Rotation/completion race: completion resolves immutable attempt lineage, then
  locks the exact `ProjectSecret` before locking the attempt. Rotation already
  locks that same secret before enqueue, establishing the global lock order
  `ProjectSecret -> canary attempt`. If rotation commits first, completion sees
  the higher version and records `SUPERSEDED`; if completion owns the secret
  lock first, version N may complete before rotation proceeds.
- Canary history rewriting or disclosure: terminal attempts cannot transition,
  attempt lineage cannot change, deletes fail, and an append-only transition
  table records every enqueue, claim, reclaim and result. Tenant reads are RLS
  protected and the bounded API omits secret/target/claim identifiers. Canary
  results cannot grant retry or routing authority.

## Tenancy conclusion

RDC's canonical database tenant boundary is the organization. Project-bound
tables use organization membership RLS, while API routes independently resolve
the authenticated Project and require the resource permission before passing
`access.project.id` to services. Canary attempts follow the same model: RLS
prevents cross-organization reads, the public route is Project-filtered and
permission-checked, and database lineage triggers/functions derive exact
same-Project policy, revision and secret relationships. A tenant database role
cannot execute scheduler capabilities or update another tenant's attempt.

## Live-runner boundary

The checked-in live runner rejects IP literals, single-label and special-use
hostnames and rejects any DNS set containing non-global, multicast, reserved,
unspecified, private, link-local or IPv4-mapped-private addresses. The transport
connects to an exact validated address, retains the original hostname for TLS
certificate verification and SNI, and checks the actual connected peer against
the validated DNS set before sending credentials. It uses direct asyncio TLS
sockets rather than a proxy-aware HTTP client, rejects redirects, and bounds
connect/total timeouts, response bytes, retries and claim concurrency. Only the
existing bounded outcome taxonomy is persisted. Plaintext credentials remain
inside that trusted runner and must never enter Agent/Chromium input, response
bodies, logs, traces, audit JSON, metrics labels or database rows.

## Residual work before adaptive enforcement

The live credential-canary runner now exists but remains false by default. Its
claim-fenced secret loader releases encrypted material only for an exact live
claim; the runner decrypts it locally, uses a direct peer-pinned TLS connection,
validates the connected peer against the prevalidated DNS set, rejects redirects
and bounds timeout/response/retry/concurrency use. Plaintext is not persisted or
returned. A real live adversarial canary is still required before operators may
treat this runner as production-validated, and adaptive routing remains explicitly
disabled.

The provider-health evidence is untrusted even when reported by an authenticated
worker because status codes and challenge signals originate externally. The
classification protocol accepts only bounded numeric/boolean evidence, rejects
target URLs and arbitrary content, and cannot widen policy, select a route or
authorize a retry. Immutable observation persistence does not confer routing or
retry authority.
