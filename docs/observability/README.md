# Observability

The first observability increment defines `rdc.log/v1`, a process-local JSON
logging contract for the API and trusted control-plane runners. It does not add
a tenant log database, change Run artifact retention, or expose a new API.

Every structured line contains a UTC timestamp, severity, service,
environment, event name and optional deployment identifier. API completion
events add the validated `X-Request-ID`, HTTP method, matched route template,
status and bounded duration. They never inspect the raw URL, query string,
headers, body, client address or user agent.

Event and field names are validated. Values must be null or bounded scalar
types; nested values and control characters are rejected. Field-name classes
covering authorization, cookies, credentials, headers, hosts, passwords,
payloads, query strings, secrets, tokens and URLs are prohibited. Error events
record only a Python exception class name, not exception text or traceback.

The same formatter is configured by the execution-recovery, schedule,
egress-health maintenance, credential-canary and webhook-delivery processes.
Their event fields are aggregate counts, bounded state labels and exception
types. Secret material, destinations, payloads and claim tokens remain absent.

Existing Agent stdout/stderr remains a tenant-authorized `LOG_BUNDLE` object
artifact with the established size, digest, lease and object-storage controls.
It is not copied into service logs.

The second increment extends the same schema to the isolated sandbox worker.
Lease-scoped internal API calls use a deterministic `lease_<uuidhex>` request
identifier derived only from the public lease UUID; heartbeat and claim calls
use random `worker_<uuidhex>` identifiers. `worker.started`,
`worker.lease.claimed`, `worker.lease.completed`, `worker.failed` and
`worker.stopped` contain only worker/lease/Run IDs, work kind, bounded outcome
and exception type. Lease tokens, claims, inputs, exception text and Agent
stdout/stderr are never included.

Remaining observability work is intentionally separate: bounded multi-process
runtime metrics and tenant-authorized diagnostics over existing resources.
