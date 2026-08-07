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
