# RDC Phase 1E — Run Control Plane and SSE Monitoring

Phase 1E adds tenant-scoped Run metadata, durable Run commands, cancellation, persisted events, and replayable Server-Sent Events. It deliberately does not execute Agent code inside the public API.

## Run creation

- `POST /api/v1/agent-versions/{version_id}/runs`
- Requires `Idempotency-Key`
- Requires a successful Build artifact for the same immutable Agent version
- Accepts inline JSON object input up to 64 KiB
- Allows resource overrides only within immutable manifest limits
- Returns `202 Accepted`
- Writes a `START` command to `control.run_command_outbox`
- Persists the initial `run.status` event

Large object-storage inputs remain deferred.

## Run reads and listing

- `GET /api/v1/runs/{run_id}`
- `GET /api/v1/projects/{project_id}/runs`
- Cursor pagination by queued time and opaque resource ID
- Optional status filtering
- Explicit organization and project predicates plus PostgreSQL RLS

## Cancellation

- `POST /api/v1/runs/{run_id}/cancel`
- Requires `Idempotency-Key`
- Queued Runs are aborted before dispatch and their pending `START` command is cancelled
- Active Runs enter `ABORTING` and receive a durable `CANCEL` command
- Terminal Runs return their existing terminal state idempotently
- Cancellation is audited and never deletes a Run record

## Persisted Run events

`control.run_events` stores append-only tenant-scoped events with a monotonically increasing per-Run sequence. Sequence allocation uses a transaction-scoped PostgreSQL advisory lock.

Persisted event types:

- `run.status`
- `run.log`
- `run.metric`
- `run.warning`
- `run.completed`
- `run.failed`

Event payloads are JSON-limited, ANSI-sanitized, length-limited, and recursively redact keys associated with credentials, secrets, authorization, cookies, passwords, and tokens.

## SSE monitoring

- `GET /api/v1/runs/{run_id}/events`
- Authenticated and tenant-authorized before streaming
- Supports `Last-Event-ID` and a query fallback for browser `EventSource`
- Replays persisted events after the supplied sequence
- Emits `run.replay_reset` when the requested replay window is unavailable
- Emits heartbeats at a configured interval
- Revalidates session/API-key and permission state during polling
- Caps concurrent streams with an in-process semaphore
- Terminates after the Run reaches a terminal state and buffered events are flushed

The SSE stream emits padded sequence IDs and clients must tolerate duplicate delivery.

## Console

The Runs console supports:

- Agent, immutable version, and successful Build selection
- JSON input and bounded resource overrides
- Run queueing and cancellation
- Project Run history
- Live/replayable event monitoring
- Loading, empty, validation, reconnecting, terminal, and error states
- Keyboard and screen-reader accessible controls and announcements

## Execution boundary

Phase 1E records metadata, commands, and events only. It does not:

- Execute Agent code
- Start containers or subprocesses
- Invoke Docker, Kubernetes, or BuildKit
- Decrypt or inject project secrets
- Provide an internal execution-worker API
- Store large input objects or external log blobs
- Implement datasets, exports, connectors, billing, or marketplace features

A future isolated execution-plane worker will consume the durable Run command outbox and append validated events through a separately authenticated internal path.
