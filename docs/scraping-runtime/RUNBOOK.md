# Scraping Runtime Runbook

## Enable one Queue-bound canary

1. Confirm the Queue, immutable Agent version, successful Build, and worker are
   in the same server-derived Project lineage.
2. Configure the canary Agent version with `network=none`, `browser=false`,
   `dataset=false`, `keyValueStore=false`, and `requestQueue=true`.
3. Register the exact worker with `RUN_START` and `REQUEST_QUEUE_ACCESS` and
   keep `max_concurrency=1`.
4. Enable the sandbox master gate, canary activation, and
   `RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED=true` in both API and worker
   environments.
5. Create a Run with `request_queue.schema_version=rdc.run-queue/v1` and the
   Queue ID. Do not put `_rdc_queue` in caller input.

The Run succeeds without starting Agent code when the Queue is empty. A claimed
request becomes `HANDLED` on exit code zero and `FAILED` with the generic
`AGENT_EXIT_NONZERO` code otherwise. Worker/process loss leaves the request
claim to the existing bounded expiry/reclaim lifecycle.

## Incident response

Disable `RDC_SANDBOX_CANARY_REQUEST_QUEUE_ENABLED` first. Drain or stop the
worker, inspect immutable Queue transitions, Run events, execution leases, and
audit events by safe identifiers, then allow expired claims to reclaim. Never
copy claim tokens, request user data, or URLs into operational logs.

Do not enable Queue access for a new Agent version or worker until the receipt,
scope-denial, stale-token, and cross-tenant tests pass. Do not add network to a
Queue-bound Run as an operational workaround.
