# RDC v1 Roadmap

Machine-readable current status and database head are canonicalized in
[`rdc-status.json`](rdc-status.json) and validated against the migration graph.
This roadmap owns dependency order and acceptance criteria; dated audits are
historical evidence rather than an independent status source.

## Status

This roadmap is the durable delivery plan for RDC v1. It records implemented
behavior only; a capability is not complete until its documented security and
test gates pass on the exact merged commit.

## Completed baseline

| Capability | Status | Evidence |
| --- | --- | --- |
| Identity, sessions, API keys, tenancy and authorization | Complete | migrations `0001`–`0002`, API tests and RLS controls |
| Agents, immutable versions, builds, Runs and worker leases | Complete baseline | migrations `0003`–`0008`, execution verifiers |
| Controlled web/browser canaries and egress boundaries | Complete baseline | Phase 1J–1M threat models and verifiers |
| Tenant-scoped Datasets | Complete | Phase 1N, append receipts, RLS, signed pagination/export |
| Tenant-scoped Key-Value Stores | Complete | Phase 1O, version history, RLS, controlled worker capability |
| Tenant-scoped Request Queues | Complete | Phase 1P, PR #56, migration `0015`, RDC CI #189 |
| Production Execution Lifecycle / Recovery | Complete | PR #57, migrations `0016`–`0020`, RDC CI #198 |
| Scheduler | Complete | PR #66, migration `0021`, RDC CI #206 |
| Scraping runtime | Complete baseline | PR #76, RDC CI #220 and main CI #221; Queue-bound offline/HTTP/browser acquisition with Dataset/KV composition |

## Active work

| Workstream | Status | Dependency |
| --- | --- | --- |
| Proxy/egress | Immutable binding, credential envelopes, lease observations and privacy-preserving route aggregates implemented | Scraping runtime and write-only Project secrets |
| Platform efficiency | Compact telemetry, canonical status, verifier orchestration and Docker context controls implemented | Egress health persistence |

The merged recovery workstream centralizes server-owned retry eligibility and
bounded exponential backoff, refuses to retry when the durable outbox source is
missing, and records the scheduled retry time in immutable execution audit
lineage. The second increment persists server-derived immutable Build/Run
deadlines, clamps renewals, and terminally times out overdue workloads under
race-safe recovery. The third increment makes cancellation dispatch idempotent,
persists an immutable convergence deadline, fences late/lost worker leases, and
terminally aborts cancelled Runs. The fourth increment adds an independently
scheduled recovery process with transaction-scoped singleton ownership, bounded
`SKIP LOCKED` batches, crash-safe rollback/restart behavior, and durable health
telemetry. The fifth increment persists bounded server-owned project and worker
limits and enforces them atomically at claim time with recovery-derived release;
RUN_CANCEL remains available when project execution capacity is saturated.
The sixth increment detects stale workers from server-observed activity, fences
and retries their leases, renews healthy in-flight work, performs bounded
label-scoped runtime cleanup on failure/restart/signal, and requires persisted
cleanup recovery evidence before claims and RLS authority resume.
The seventh increment adds hardened service supervision, environment identity
separation, PostgreSQL backup/restore and migration rollback rehearsal,
versioned-object recovery canaries, aggregate recovery metrics, and SLO alerts.
The merged Scheduler foundation adds persistent one-time and fixed-interval
schedules, bounded missed-run behavior, duplicate-safe Run creation, immutable
trigger history, tenant RLS and a singleton-safe dispatch service.

The first scraping-runtime increment binds a Run to one server-verified tenant
Queue, issues an exact lease-scoped capability, independently validates the
claim in the worker, withholds claim tokens from Agent input, and completes one
request per Run. It remains false-by-default. The second increment
derives one Queue-claimed GET through the existing bounded
HTTPS egress broker, binds its policy digest into v2 Run/lease receipts, rejects
caller web-intent injection, and keeps Agent networking disabled. The third
increment adds gated v3 Queue/browser receipts and exact worker capabilities,
derives one bounded navigation from the validated Queue claim, runs Chromium
behind the Unix egress gateway, withholds the claim token, and then executes the
Agent with networking disabled. The fourth increment composes the existing
idempotent Dataset append boundary with every Queue acquisition mode and
requires Dataset persistence before Queue HANDLED completion. The fifth
increment composes KV reads and idempotent mutations with all Queue acquisition
modes and requires KV persistence before Queue HANDLED completion.

The first proxy/egress increment persists server-owned Project policy metadata
and immutable revisions containing exact normalized HTTPS hosts, GET/HEAD
methods and bounded request/byte/redirect/timeout budgets. Optimistic,
row-locked activation and disable transitions select an exact revision;
credential material remains in write-only Project secrets and API responses
expose only whether a reference is configured. PostgreSQL RLS and reference
triggers independently enforce organization, Project, revision and secret
tenancy. The second increment accepts only a policy resource reference on
eligible Run creation, row-locks and resolves the current ACTIVE immutable
revision, and persists canonical revision/runtime digests. The same binding
digest reaches activation and Queue v6 worker capabilities; the trusted worker
independently reconstructs it and the broker enforces its host, method and
budget subset. The static canary remains an additional maximum ceiling.
Credential-bound policies remain fail-closed and no secret material reaches
Agent or Chromium. The third increment revalidates the bound policy under row
lock at `RUN_START` admission and terminally fails stale, disabled, rotated,
cross-tenant or tampered snapshots before any lease is issued.
The fourth increment resolves credential references only inside the trusted
lease service, encrypts the complete Authorization value to an ephemeral worker
key with lease/Run/policy AAD, injects it only in the broker, denies Chromium,
and serializes secret replacement with grant issuance and revocation.
The fifth increment begins provider health with a strict deterministic outcome
taxonomy over bounded status/latency/size/boolean evidence. It deliberately
does not persist targets, select routes, authorize retries or widen egress.
The sixth increment persists those classifications as immutable, replay-safe
observations bound to an authenticated active Run lease. PostgreSQL RLS and an
exact-reference trigger independently enforce tenant/Project/Run/worker
lineage; a bounded Project aggregate exposes no target or raw evidence and does
not grant retry or routing authority.
The seventh increment stamps validated server-configured provider/region keys
and exposes a 1–24 hour Project route aggregate with minimum-sample suppression
and a 32-dimension cap. Sparse groups, raw evidence and execution lineage remain
hidden; the aggregate cannot select a route or authorize retry.
The first platform-efficiency increment normalizes health evidence into compact
typed columns, removes routine telemetry audit duplication and four unused
indexes while retaining immutable RLS/lease/replay lineage. It also adds a
machine-readable migration/workstream status validator, one complete verifier
runner with backward-compatible phase entrypoints, and Docker ignore controls.
The eighth increment transactionally schedules credential-rotation canaries
against exact active revision, secret version and operator target-digest
lineage. Enqueue is idempotent, claims are race-safe and expiring, completion
is token-fenced, PostgreSQL RLS protects both attempts and immutable transition
history, and the tenant summary is credential/target-free. Live execution and
adaptive routing remain disabled.
The ninth increment removes the broad canary scheduler GUC/RLS privilege,
introduces operation-scoped database capabilities, persists only claim-token
digests, serializes secret rotation with completion, and adds adversarial RLS,
claim-fencing, race and future-runner network-policy gates. Live credential use
still belongs to Issue #97 and remains false by default.
The tenth increment adds the false-by-default live credential-canary runner as a
separate trusted service. A claim-fenced `SECURITY DEFINER` loader releases only
the exact encrypted Project-secret version for one unexpired claim; plaintext is
decrypted only in the runner, used only as the complete Authorization value,
zeroed/released after the request, and never persisted or logged. The transport
resolves and validates every DNS address, connects to an exact validated IP with
hostname-verified TLS/SNI, rechecks the actual connected peer, ignores ambient
proxy configuration by using direct sockets, rejects redirects, and bounds
timeouts, response bytes, retries and claim concurrency. Adaptive routing remains
disabled pending a real live adversarial canary.

The first Events/Webhooks increment adds `rdc.event/v1` lifecycle-event
persistence under project-bound PostgreSQL RLS. Event ownership is derived from
the exact Project, Run/Build subjects are revalidated below the service layer,
payloads use a small allowlisted schema with recursive credential-key and byte
bounds, and UPDATE/DELETE is rejected by an immutable database trigger. Run and
Build creation transactionally emit representative replay-safe events. The
authenticated project history API uses deterministic `(occurred_at, id)` order
and a signed cursor bound to both Project and event-type filter. No destination,
signing secret, delivery attempt, retry worker, or outbound webhook request is
present in this increment.

## Remaining RDC v1 workstreams

1. Proxy/egress: run and review the live adversarial credential canary against
   the isolated runner, including DNS/peer/TLS/redirect/timeout/response-limit
   failure cases; keep adaptive routing disabled until that gate passes.
2. Platform efficiency: add PostgreSQL time-bucket rollups, bounded raw/rollup
   retention and advisory changed-path CI while preserving required full gates.
3. Events/webhooks: add trusted SSRF-safe signed delivery execution, replay
   tooling and failure disablement on top of the merged event, destination and
   claim-fenced delivery-lifecycle foundations.
4. Observability: structured run/worker logs, diagnostics, metrics and safe
   correlation identifiers.
5. Usage controls: quotas, rate limits, concurrency and auditable failures.
6. SDK/CLI and Console: API-backed operations for all major resources.
7. Platform-wide production operations: release automation, registry/SBOM,
   capacity, disaster recovery, and environment promotion for all workstreams.
8. End-to-end acceptance and final release/security audit.

## Dependency order

`execution recovery → scheduler/runtime integration → egress and
webhooks → observability/usage controls → SDK/CLI/Console → production
operations → end-to-end release audit`.

## Permanent security gates

- PostgreSQL RLS and server-derived ownership for tenant data.
- No Agent/Chromium PostgreSQL or object-storage credentials.
- False-by-default worker capabilities bound to ACTIVE unexpired leases.
- No anonymous Dataset, KV or Queue access; signed resource/filter-bound cursors.
- Egress, browser isolation, path/object-key safety, quotas and auditability
  must not regress.

## Test and merge gates

Every workstream requires clean diff review, migrations, targeted adversarial
tests, `ruff`, `mypy`, `pytest`, frontend lint/typecheck/tests/build, verifier
scripts, Compose validation, and exact-head GitHub CI success. A PR is merged
only after a final security review, verified mergeability and no blocking review
threads; its feature branch is preserved.

## Definition of done

RDC v1 is complete only when every listed workstream is implemented and
documented; API, worker and console paths are coherent; migrations/RLS/security
invariants pass; the authenticated end-to-end flow (Agent → Queue → Run →
controlled worker → Dataset/KV → logs/results) passes, including cross-tenant
denial tests; production recovery docs exist; and final-main CI plus the final
security audit are green.
