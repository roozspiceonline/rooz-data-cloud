# Rooz Data Cloud — Phase 1E

Phase 1E extends the merged identity, tenancy, Agent, project-secret, and Build foundations with the Run control plane and replayable Server-Sent Events monitoring.

## Included

- Idempotent Run creation from a successful immutable-version Build artifact
- Inline JSON input with a 64 KiB limit
- Runtime resource overrides bounded by immutable Agent-manifest limits
- Run read and project Run-history APIs
- Idempotent Run cancellation with explicit state transitions
- Durable `START` and `CANCEL` command outbox records
- Append-only Run events with monotonically increasing per-Run sequences
- SSE replay, `Last-Event-ID`, replay-reset, heartbeat, reconnect, and terminal-stream behavior
- Event ANSI sanitization, size limits, and sensitive-key redaction
- Revalidated stream authorization and concurrent-stream limits
- PostgreSQL RLS, explicit tenant predicates, resolver functions, tenancy guards, and audit events
- Runs console for queueing, cancellation, history, and live event monitoring
- Alembic, backend, frontend, scaffold, protocol, and Compose verification

## Execution boundary

The public API stores and queues metadata only. It does not execute Agent code, start containers, invoke Docker/Kubernetes, decrypt project secrets, or expose an execution-worker endpoint. A future isolated execution plane will consume Run command records and append validated events.

## Start the phase

The generated `start-phase1e.py` reads the existing repository-scoped GitHub token from:

```text
~/Downloads/rdc-team-bridge/.env
```

The Bridge web server does not need to be running. The script creates one Phase 1E GitHub issue, creates `feat/phase-1e-run-control-plane-sse`, uploads the implementation, and opens a draft pull request. It does not merge automatically.
