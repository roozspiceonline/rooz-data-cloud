# Phase 1M — Controlled Browser Navigation & Extraction Protocol

Phase 1M builds on the merged Phase 1L controlled-browser foundation.

Phase 1L remains authoritative for the existing `rdc.browser/v1` snapshot
contract, activation receipts, immutable image requirement, offline Chromium
self-test and false-by-default browser gate.

## Foundation increment

This first Phase 1M increment introduces `rdc.browser/v2` as a protocol and pure
policy-validation surface only. It does **not** expose v2 through the Run API and
does **not** send public URLs to Chromium.

The v2 step set is intentionally narrow:

- `goto`
- `wait_for_selector`
- `extract_text`
- `extract_html`
- viewport-only `screenshot`

The first step must be `goto`. Every navigation URL must use lowercase HTTPS
and resolve to an exact operator-allowlisted hostname at policy-validation time.
IP literals remain prohibited by the inherited Phase 1L hostname policy.

Selectors are bounded to 512 characters. Waits, text extraction, HTML
extraction, page count and action count are all bounded.

## Execution boundary

Chromium remains offline in this increment.

```text
Agent container                 browser runtime
--network none                  --network none
      |                               |
      +---------- no live URL --------+
```

`rdc.browser/v2` is not API-executable yet. A later Phase 1M increment must add
an RDC-controlled browser-egress gateway before any public Chromium navigation
is possible.

The browser-egress gateway must mediate top-level requests, redirects and
subresources and retain the existing SSRF prohibitions. Chromium must never
receive unrestricted host networking.

## Explicitly blocked

- arbitrary JavaScript / evaluate
- clicks, typing and forms
- arbitrary cookies or auth headers
- project secrets
- uploads and downloads
- persistent profiles
- raw CDP / browser server
- arbitrary proxies
- WebRTC
- unrestricted browser internet access
- general untrusted browser execution
