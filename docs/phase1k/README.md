# Phase 1K — Generalized Web-Fetch Runtime Contract

Phase 1J proved a secure brokered HTTPS canary while keeping Agent containers
fully network-isolated. Phase 1K converts that prototype input/output shape into
a versioned contract suitable for reusable web-fetch Agents.

## Foundation-only boundary

This foundation does **not** activate or broaden runtime web access.

The Agent container remains:

```text
--network none
```

The Phase 1J worker broker remains the only component permitted to perform
outbound HTTPS.

## `rdc.web-fetch/v1`

The new envelope contains only request intent:

- schema version
- bounded request list
- unique request IDs
- GET / HEAD
- HTTPS URL

It intentionally does **not** contain host allowlists, arbitrary headers,
cookies, credentials, proxies, redirect policy, byte ceilings or timeouts.
Those remain operator-owned policy.

The initial adapter converts `rdc.web-fetch/v1` requests into the existing
internal Phase 1J `_rdc_web_requests` transport shape.

## Release boundary

Phase 1K does not authorize multiple AgentVersions or general untrusted
execution. Browser automation remains a later phase.

## Run integration

Phase 1K Run creation now accepts an optional top-level `web_fetch` object
alongside arbitrary Agent `input`. Keeping web fetch outside `input` avoids
collisions with Agent-defined input schemas.

The control plane stores the versioned intent separately in the Run input
reference. The sandbox worker independently validates it, adapts it to the
existing Phase 1J broker, and injects only `_rdc_web_fetch_result` into the
Agent input before execution.

The result envelope includes:

- `rdc.web-fetch-result/v1`
- request-envelope SHA-256 binding
- final validated URL and HTTP status
- bounded safe response headers
- text/base64/none body representation
- body size and SHA-256 lineage
- aggregate broker request/byte budget evidence

Phase 1J legacy compatibility remains supported for the dedicated canary:
`_rdc_web_requests` continues to work when the versioned Run-level
`web_fetch` field is absent. The two modes cannot be mixed.

Agent containers remain `--network none`; this integration does not broaden
activation beyond the existing Phase 1J single canary.

