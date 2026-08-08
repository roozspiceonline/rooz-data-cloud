# Phase 1P — Tenant-scoped Request Queue

Phase 1P implements the durable Request Queue primitive tracked by #55. The
increment is complete in the feature branch and remains release-blocked until
its exact-head CI, security review, and merge gates pass.

## Implemented increments

1. **Strict enqueue protocol.** `rdc.queue-enqueue/v1` accepts a bounded HTTPS
   request envelope, rejects credentials, IP literals, fragments, unsafe keys,
   and non-JSON data, and produces deterministic request and identity digests.
2. **Tenant-scoped persistence.** Migration `20260809_0015` creates Queue,
   request, enqueue-receipt, and transition tables. Organization and project
   ownership is server-derived and reinforced by foreign keys, tenancy
   triggers, and command-specific PostgreSQL RLS policies.
3. **Idempotent enqueue.** A queue-row lock serializes enqueue decisions. The
   same idempotency key and canonical digest returns the original request;
   conflicting reuse fails closed. Request identity is unique within a Queue,
   and enqueue receipts are immutable.
4. **Race-safe lifecycle.** Requests transition through `PENDING`, `CLAIMED`,
   and terminal `HANDLED` or `FAILED` states. Claims use `FOR UPDATE SKIP
   LOCKED`, an unguessable claim token, an expiry, attempt counters, bounded
   retry metadata, and atomic Queue counter updates. Expired claims are
   reclaimed or failed after retry exhaustion.
5. **Lease-scoped worker access.** Worker Queue operations are false by default
   and require sandbox canary activation, the pinned worker and Agent version,
   `REQUEST_QUEUE_ACCESS`, manifest `requestQueue: true`, and an ACTIVE,
   unexpired `RUN_START` lease for the same organization and project. Worker
   RLS is limited to the Queue/request lifecycle and transition inserts;
   receipts remain outside worker authority.
6. **Immutable lineage and safe reads.** Every enqueue, claim, reclaim, handled,
   and failed transition writes tenant-bound transition and audit lineage in
   the same transaction. Request identity, receipts, transitions, and audit
   events are database-enforced immutable. Authenticated Queue, request, and
   transition reads use bounded keyset pagination with signed cursors bound to
   the server-resolved project, Queue, state, and request filters.

## Security and verification

Agent and Chromium workloads never receive PostgreSQL, object-storage, worker,
or lease credentials. Queue access does not broaden browser, egress, Dataset,
or Key-Value Store authority. Adversarial tests cover cross-tenant resolution,
RLS visibility and mutation denial, cross-project trigger rejection,
idempotency conflicts, simultaneous claims, stale tokens, expiry/retry
recovery, immutable history, audit redaction, and cursor tampering/replay.

Operational controls are documented in the [threat model](THREAT_MODEL.md) and
[runbook](RUNBOOK.md). The repository gate is `python scripts/verify-phase1p.py`
plus the full migration, backend, frontend, Compose, and exact-head CI suite.
