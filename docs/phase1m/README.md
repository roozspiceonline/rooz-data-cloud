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

## Increment 2 — receipt-only Run intent

The API accepts `browser_navigation` but stores it as a receipt-only `DRAFT`
Run. No START outbox is created and control-plane activation remains denied.

The immutable `rdc.browser-navigation-receipt/v1` binds:

- request digest
- `rdc.browser-policy/v1` digest
- `rdc.browser-egress-policy/v1` digest
- `execution_enabled=false`
- `dispatch_enabled=false`
- `browser_network=none`

## Increment 3 — browser-egress gateway policy

`rdc.browser-egress-policy/v1` now defines the security contract that a future
gateway transport must obey.

It reuses the Phase 1J egress limits and allowlist, and requires:

- HTTPS only
- GET/HEAD only
- exact operator allowlist
- IP literals denied
- global DNS only
- validated address pinning
- redirect revalidation
- subresource revalidation
- bounded request/resource/total-byte budgets
- bounded connect/request timeouts
- authorization/cookie/proxy-authorization request headers stripped
- Set-Cookie response headers stripped
- service workers disabled
- WebSockets disabled
- WebRTC disabled
- arbitrary proxy override disabled
- persistent cookies disabled

Allowed network resource classes are intentionally narrow:

- document
- stylesheet
- script
- image
- font
- xhr
- fetch

Unknown resource classes fail closed.

## Execution boundary

Chromium remains offline.

```text
Agent container                 browser runtime
--network none                  --network none
      |                               |
      +---------- no live URL --------+
```

The gateway **transport is not wired**. The policy contract can validate a
resource or redirect and returns the already-validated global IP addresses that
a later TLS transport must pin. No Phase 1M code sends browser traffic to those
addresses yet.

## Still blocked

- direct Chromium Internet access
- arbitrary JavaScript / evaluate
- clicks, typing and forms
- project secrets
- uploads/downloads
- persistent profiles
- raw CDP / browser server
- arbitrary proxies
- WebSockets / service workers / WebRTC
- general untrusted browser execution
