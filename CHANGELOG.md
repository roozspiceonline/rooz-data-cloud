# Changelog

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
