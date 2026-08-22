# Scraping Runtime Runbook

## Enable one Queue-bound canary

1. Confirm the Queue, immutable Agent version, successful Build, and worker are
   in the same server-derived Project lineage.
2. Configure the Agent version with `browser=false`, `dataset=false`,
   `keyValueStore=false`, and `requestQueue=true`. Use `network=none` for the
   offline mode or `network=web-egress` for brokered Queue HTTP.
3. Register the exact worker with `RUN_START` and `REQUEST_QUEUE_ACCESS` and
   keep `max_concurrency=1`.
4. Enable the sandbox master gate, canary activation, and
   `RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED=true` in both API and worker
   environments.
5. Create a Run with `request_queue.schema_version=rdc.run-queue/v1` and the
   Queue ID. Do not put `_rdc_queue`, `_rdc_queue_http`, or legacy web request
   keys in caller input.

For Queue HTTP, also enable the API and worker
`RDC_SANDBOX_CANARY_REQUEST_QUEUE_HTTP_ENABLED=true`, the existing web-egress
gate, and an exact hostname allowlist. Confirm the persisted v2 binding receipt
has `acquisition_mode=brokered-http`, the current egress-policy digest,
`dispatch_enabled=true`, and `agent_container_network=none`. A disabled Queue
HTTP gate produces a DRAFT receipt-only Run rather than dispatching work.

The Run succeeds without starting Agent code when the Queue is empty. A claimed
request becomes `HANDLED` on exit code zero and `FAILED` with the generic
`AGENT_EXIT_NONZERO` code otherwise. A denied or failed Queue HTTP acquisition
uses `QUEUE_HTTP_FETCH_FAILED`. Worker/process loss leaves the request claim to
the existing bounded expiry/reclaim lifecycle.

## Incident response

Disable `RDC_SANDBOX_CANARY_REQUEST_QUEUE_HTTP_ENABLED` first for an acquisition
incident, or `RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED` to stop all Queue work.
Drain or stop the worker, inspect immutable Queue transitions, Run events,
execution leases, and audit events by safe identifiers, then allow expired
claims to reclaim. Reduce or rotate the exact allowlist before re-enabling.
Never copy claim tokens, request user data, URLs, response bodies, response
headers, or Agent output into operational logs.

Do not enable Queue access for a new Agent version or worker until the receipt,
scope-denial, stale-token, cross-tenant, egress-policy tampering, and unsafe-URL
tests pass. Do not widen the allowlist as an operational workaround.
