# Changelog

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
