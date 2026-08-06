# Rooz Data Cloud — Phase 1F

Phase 1F extends the merged identity, tenancy, Agent, project-secret, Build, and Run foundations with a separate authenticated execution-plane protocol.

## Included

- Write-only worker registration tokens and worker heartbeats
- Worker draining state and bounded concurrency
- Durable Build, Run-start, and Run-cancel command leasing
- PostgreSQL `FOR UPDATE SKIP LOCKED` claims and active-source uniqueness
- Short-lived lease tokens, renewal limits, expiry reaping, and bounded retries
- Worker status reporting and sanitized Run-event ingestion
- Digest-addressed artifact metadata, scan state, and provenance
- Lease-scoped X25519 project-secret envelopes
- PostgreSQL RLS, worker context, tenancy guards, and audit events
- Public project lease and artifact metadata APIs
- Execution-plane visibility in the project console
- Protocol schemas, reference worker client, migration, tests, and CI

## Execution boundary

The public API still does not execute Agent code. The internal protocol is excluded from the public OpenAPI document and accepts only worker and lease credentials. Every claim advertises `execution_enabled: false`. Docker, Kubernetes, BuildKit, shells, subprocesses, and untrusted Agent execution remain disabled until a later sandbox-runtime phase proves the isolation boundary.

## Start the phase

The generated `start-phase1f.py` reads the repository-scoped GitHub token from:

```text
~/Downloads/rdc-team-bridge/.env
```

The Bridge web server does not need to be running. The installer creates one Phase 1F issue, creates `feat/phase-1f-execution-plane-foundation`, uploads the implementation, and opens a draft pull request. It does not merge or delete branches.
