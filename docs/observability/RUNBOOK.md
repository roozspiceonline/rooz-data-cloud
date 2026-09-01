# Structured logging runbook

Ingest each stdout/stderr line from RDC services as one `rdc.log/v1` JSON
object. Index `timestamp`, `severity`, `service`, `environment`, `event`,
`deployment_id` and the four permitted correlation identifiers only. Reject or
quarantine lines that are not valid JSON or do not match the schema version.

Use `request_id` to correlate an API response with `http.request.completed`.
For worker operations, join `lease_<uuidhex>` across sandbox-worker and API
events; do not attempt to decode or attach the lease token. Non-lease worker
calls intentionally receive unrelated random correlation IDs.
Use event names and aggregate fields for dashboards and alerts. Do not enrich
logs with request URLs, query strings, headers, bodies, target hosts, payloads,
credentials or secret values at the collector.

Access to centralized service logs is an operator privilege, not a tenant API.
Preserve environment separation and configure retention in the external log
collector. RDC does not treat centralized logs as an audit ledger; immutable
database audit/events and Run artifact lineage remain authoritative.

If formatting rejects a new field, rename or redesign the event around a safe
bounded scalar. Do not weaken the forbidden-field set. When diagnosing an
exception, use the emitted exception class, request ID and immutable database
lineage; never add exception text if it can contain caller or secret material.

Scrape `/metrics/runtime` only from the operator monitoring network. Load
`infrastructure/monitoring/rdc-runtime.rules.yml` and alert when scrape health
is zero or absent, execution work has no fresh worker, or the global webhook
backlog crosses the reviewed threshold. The endpoint is a current PostgreSQL snapshot,
not a billing ledger. Do not add labels or export tenant/resource identifiers;
use tenant-authorized resource APIs for investigation.

For tenant investigations, grant the narrow `diagnostic.read` scope and call
`GET /api/v1/projects/{project_id}/diagnostics`. Start with nonzero ready or
terminal-failure counts, then inspect the corresponding permission-protected
resource history. The snapshot is current aggregate state, not a log export or
audit ledger. Do not copy centralized service logs into the response and do not
broaden it with identifiers, targets, payloads, tokens, credentials or errors.
