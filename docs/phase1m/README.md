# Phase 1M — Controlled Browser Navigation & Extraction Protocol

Phase 1M builds on the merged Phase 1L controlled-browser foundation.

Phase 1L remains authoritative for `rdc.browser/v1`, controlled-browser
activation receipts, the immutable browser image boundary and the isolated
`about:blank` Chromium self-test.

## Increment 1 — v2 protocol foundation

`rdc.browser/v2` defines only:

- `goto`
- `wait_for_selector`
- `extract_text`
- `extract_html`
- viewport-only `screenshot`

The protocol remains bounded by exact fields, action/page limits, selector
limits, wait limits and extraction limits. URLs must use lowercase HTTPS and
must match the exact operator hostname allowlist.

## Increment 2 — receipt-only Run intent

The Run API now accepts a `browser_navigation` v2 intent, but this does **not**
make live navigation executable.

A v2 intent is stored with:

- the normalized `rdc.browser/v2` request
- the existing immutable `rdc.browser-policy/v1` payload
- the browser-policy SHA-256 digest
- `rdc.browser-navigation-receipt/v1`
- a deterministic request digest
- `execution_enabled=false`
- `dispatch_enabled=false`
- `browser_network=none`
- `browser_egress_gateway_required=true`

A v2 Run is created in `DRAFT` and receives **no START outbox command**. The
control plane explicitly refuses v2 sandbox activation. The worker contains an
independent v2 receipt validator and still fails closed with navigation
execution disabled.

## Execution boundary

Chromium remains offline.

```text
Agent container                 browser runtime
--network none                  --network none
      |                               |
      +---------- no live URL --------+
```

No Phase 1M code currently sends `browser_navigation` URLs to Chromium.

## Required before live navigation

A dedicated RDC-controlled browser-egress gateway must be implemented before a
v2 Run can leave receipt-only state. That gateway must mediate top-level
navigation, redirects and subresources while preserving global-DNS and SSRF
protections.

## Explicitly blocked

- direct Chromium Internet access
- arbitrary JavaScript / evaluate
- clicks, typing and forms
- arbitrary cookies or auth headers
- project secrets
- uploads and downloads
- persistent profiles
- raw CDP / browser server
- arbitrary proxies
- WebRTC
- general untrusted browser execution
