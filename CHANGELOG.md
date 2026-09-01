# Changelog

## Unreleased

- Added a dedicated tenant-authorized project diagnostics snapshot over
  existing execution, Scheduler, Queue, credential-canary and webhook state.
- Added a hidden fixed-series Prometheus snapshot of durable runtime queue and
  in-flight work across scheduler, execution, scraping and trusted runners.
- Added lease-derived sandbox-worker/API request correlation and bounded
  structured worker lifecycle events without copying Agent logs or credentials.
- Corrected credential-bound egress resolution so encrypted authorization is
  loaded and consumed only by the trusted Run path, never the Build path.
- Added secret-safe `rdc.log/v1` JSON events, validated request correlation and
  structured API/trusted-runner completion and failure telemetry.
- Added conservative changed-path classification and focused advisory CI while
  retaining unconditional full exact-head and merged-main required gates.
- Added tenant-isolated hourly egress-health rollups with exact raw-edge
  fallback, preserving the existing 1–24 hour summary response contracts.
- Added singleton, restart-safe telemetry maintenance with bounded 48–168 hour
  raw retention, 7–90 day rollup retention, immutable aggregate purge audit
  events, database-backed health and hardened Compose/systemd services.
- Added a false-by-default trusted webhook delivery canary with digest-only
  claim fencing, immutable endpoint/secret snapshots, claim-scoped encrypted
  material loading and completion, canonical timestamped HMAC-SHA256 signing,
  and a direct peer-pinned TLS transport with no proxies, redirects, retries,
  or address failover.
- Added bounded retry/dead-letter convergence, generic failure outcomes, a
  least-credentialed separate runner, and adversarial PostgreSQL/network tests.
- Added tenant-scoped webhook destination metadata with strict HTTPS admission,
  Project RLS, idempotent creation and write-only encrypted signing-secret
  rotation while keeping activation and outbound delivery disabled.
- Added immutable `rdc.event/v1` Run/Build lifecycle events with server-derived
  tenant and subject lineage, Project-bound PostgreSQL RLS, credential-safe
  bounded payloads and replay-safe uniqueness.
- Added permission-checked Project event history with deterministic ordering and
  signed Project/filter-bound cursors.
- Kept general destination activation, operator replay, and automatic failure
  disablement outside this increment; the trusted runner remains false by
  default and limited to pending-verification destinations.

## 0.14.0-phase1n — 2026-08-08

- Added tenant-scoped `control.datasets`, `control.dataset_items` and immutable
  append receipts under PostgreSQL RLS.
- Added strict `rdc.dataset-append/v1`, canonical SHA-256 request digests,
  Dataset-scoped idempotency, row-locked sequence allocation and item/byte
  quotas.
- Added authenticated Dataset metadata and append APIs.
- Added false-by-default lease-scoped worker Dataset append using explicit
  `DATASET_APPEND` capability and `rdc.dataset-worker-capability/v1`.
- Kept Agent and Chromium containers without worker, lease or PostgreSQL
  credentials.
- Added signed Dataset-bound item pagination with a maximum page size of 200.
- Added separately scoped, CSRF-protected canonical JSONL export limited to
  10,000 items and 16 MiB with SHA-256 response metadata and audit events.
- Kept Dataset items append-only with no item UPDATE/PATCH/DELETE surface.
- Kept public Dataset export disabled and general untrusted execution
  release-blocked.

## 0.13.0-phase1m — 2026-08-08

- Added strict `rdc.browser/v2` controlled navigation/extraction.
- Added exact HTTPS allowlists, global DNS, validated-address pinning, TLS
  hostname verification, redirect/subresource revalidation and bounded budgets.
- Added Unix-domain-socket browser gateway transport while Chromium remains
  `--network none`.
- Added plan-bound browser navigation results and artifact provenance.
- Added independent false-by-default
  `RDC_SANDBOX_CANARY_BROWSER_LIVE_NAVIGATION_ENABLED`.
- Bound live navigation to exact AgentVersion, exact worker, no secrets,
  concurrency 1 and hard canary resource ceilings.
- Preserved DRAFT/no-START behavior when the live canary is inactive.
- Kept general untrusted browser execution release-blocked.

## 0.12.0-phase1l — 2026-08-08

- Added the strict `rdc.browser/v1` snapshot intent contract and
  `rdc.browser-policy/v1` operator-owned policy receipts.
- Added `controlled-browser` activation receipts with egress-policy and
  browser-policy digest binding.
- Added independent worker-side browser policy and Run-plan validation.
- Added a Playwright `1.61.0` dedicated browser runtime boundary with an
  immutable local image digest requirement.
- Added a Chromium-compatible browser seccomp profile and an isolated
  `about:blank` self-test bridge.
- Added forced browser-container cleanup, bounded runtime timeout validation and
  isolated stdout JSON handling.
- Kept Agent containers and the browser self-test runtime on `--network none`.
- Kept public Chromium navigation, project secrets, persistence, downloads,
  uploads, remote CDP and general untrusted browser execution blocked.

## Phase 1I — Controlled Sandbox Activation & End-to-End Execution

- Added a second activation gate that defaults to `disabled`.
- Bound canary execution to one immutable AgentVersion and one exact
  single-concurrency worker.
- Rejected secrets, network/browser/storage capabilities, and broader resource
  requests from the canary path.
- Added digest-bound activation receipts to lease snapshots and artifacts.
- Added server-side source/image lineage verification for Build and Run
  artifacts.
- Added a deterministic offline canary Agent, source-ZIP builder, runbook,
  tests, protocol schema, console messaging, and CI verifier.

## Phase 1H — Sandboxed Build & Runtime Foundation

- Added strict sandbox worker attestation and an opt-in execution gate.
- Added rootless BuildKit/containerd worker code with no host Docker socket.
- Added non-root, read-only, capability-dropped runtime policy with seccomp/AppArmor and cgroup limits.
- Added short-lived execution artifact upload/download grants and server-side SHA-256 verification.
- Added OCI scanning, SBOM/provenance generation, cancellation, cleanup, tests, docs, and CI verification.
- Kept the global execution gate disabled by default and blocked web-egress/browser Agents in Phase 1H.

## Phase 1G — Secure Source Ingestion and Artifact Delivery

- Added S3-compatible direct Agent source uploads with exact presigned constraints.
- Added SHA-256 verification and safe ZIP inspection without extraction.
- Bound verified source objects to immutable Agent versions and Builds.
- Added tenant and worker short-lived source-download grants.
- Added storage RLS, tenancy guards, audit records, APIs, console UI, tests, and CI verification.
- Kept BuildKit, containers, and untrusted Agent execution disabled.

## Phase 1F — Isolated Execution-Plane Foundation

- Added the private `/internal/v1` worker protocol.
- Added worker registration, heartbeat, draining, capabilities, and concurrency.
- Added durable Build and Run command leasing with bounded renewal and retries.
- Added worker Run-event ingestion and completion state transitions.
- Added digest-addressed artifact metadata, scan status, and provenance.
- Added lease-scoped X25519/HKDF/AES-GCM secret envelopes.
- Added execution-plane RLS, tenancy triggers, audit policy, schemas, tests, and console visibility.
- Kept untrusted Agent execution and container invocation disabled.

## 0.5.0-phase1e — 2026-08-06

- Added idempotent Run creation from successful immutable-version Build artifacts.
- Added bounded inline input and immutable-manifest resource enforcement.
- Added Run reads, project Run history, and idempotent cancellation.
- Added durable START and CANCEL command outbox records.
- Added append-only, sequence-ordered Run events.
- Added replayable SSE monitoring with Last-Event-ID, replay reset, heartbeats, stream authorization revalidation, and connection limits.
- Added ANSI sanitization, event size limits, and sensitive-key redaction.
- Added Run RLS, tenant resolvers, tenancy triggers, audit events, console workflows, and Phase 1E verification.

## 0.4.0-phase1d — 2026-08-06

- Added envelope-encrypted, write-only project secrets.
- Added secret metadata create, list, replace, and delete APIs.
- Added ETag concurrency and idempotent secret replacement.
- Added Build create, read, and Agent Build-history APIs.
- Added a transactional Build dispatch outbox without execution inside the API.
- Added RLS, tenant resolvers, tenancy triggers, and audit events.
- Added Secrets and Builds console workflows and Phase 1D CI verification.

## 0.3.0-phase1c — 2026-08-06

- Added tenant-scoped Agent metadata and immutable Agent versions.
- Added manifest validation, canonical digests, cursor pagination, and ETags.

## 0.2.0-phase1b — 2026-08-06

- Added identity, sessions, organizations, projects, API keys, audit, idempotency, and RLS.

## 0.1.0-phase1a — 2026-08-06

- Established the runnable monorepo, control-plane API shell, console shell, Compose topology, and CI.
