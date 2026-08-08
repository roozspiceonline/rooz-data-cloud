# Phase 1M — Controlled Browser Navigation & Extraction Protocol

Phase 1M builds on the merged Phase 1L controlled-browser foundation.

Phase 1L remains authoritative for `rdc.browser/v1` and the isolated
`about:blank` Chromium self-test.

## Increment 1 — v2 protocol foundation

`rdc.browser/v2` permits only bounded `goto`, `wait_for_selector`,
`extract_text`, `extract_html`, and viewport-only `screenshot`.

## Increment 2 — receipt-only Run intent

Browser-navigation Runs remain `DRAFT`, create no START outbox command, and
cannot receive control-plane v2 activation.

## Increment 3 — browser-egress gateway policy

`rdc.browser-egress-policy/v1` defines exact HTTPS allowlists, global DNS,
validated-address pinning, redirect/subresource revalidation, budgets and
browser-specific denial surfaces. Its digest is bound into the immutable Run
receipt.

## Increment 4 — isolated Unix gateway transport

The browser→gateway transport uses a per-Run Unix-domain socket while the
browser container remains `--network none`.

## Increment 5 — bounded forwarding and extraction contracts

The live forwarding implementation now exists behind the fail-closed Run
boundary, but normal v2 Run dispatch is still disabled.

New contracts:

- `rdc.browser-gateway-request/v1`
- `rdc.browser-gateway-response/v1`
- `rdc.browser-gateway-error/v1`
- `rdc.browser-navigation-result/v1`

The browser runtime can intercept HTTPS requests with Playwright routing and
send only these fields to the worker-side gateway:

- request id
- immutable gateway-policy digest
- resource type
- method
- URL

Browser request headers, cookies, authorization data and request bodies are
never forwarded.

The worker-side gateway reuses the Phase 1J pinned HTTPS primitive. Every
document and subresource is validated against `rdc.browser-egress-policy/v1`
before the gateway connects. The connection is made only to a DNS-validated
global address while TLS hostname/SNI validation remains bound to the
allowlisted hostname.

Redirects are not trusted. A redirect Location is normalized and independently
revalidated before it is returned to Chromium. Chromium then issues the target
request through the same Unix gateway, causing validation again before the next
connection.

Gateway budgets cover total requests, total response bytes, redirects,
per-resource bytes, connect timeout and request timeout.

Playwright fulfills network requests from gateway responses. Unsupported
resource types or gateway denials are aborted. The runtime never uses
`route.continue_()` for external requests.

Extraction results are bounded:

- text by `max_chars`
- HTML by `max_bytes`
- screenshot by browser policy
- screenshot is viewport-only PNG with size and SHA-256 verification

Chromium itself must remain network-none.

## Current activation boundary

Increment 5 does **not** make receipt-only v2 Runs executable.

```text
v2 Run state                  DRAFT
START dispatch                blocked
control-plane v2 activation   denied
browser live forwarding       disabled for normal Runs
Chromium network              none
```

The live path is code-available for independent contract verification only.
The worker does not call it in this increment.

## Still blocked

- normal v2 Run execution
- public browser activation
- arbitrary JavaScript/evaluate input
- clicks/forms/type
- project secrets
- uploads/downloads
- persistent profiles/cookies
- CDP/browser server
- arbitrary proxies
- WebSockets/service workers/WebRTC
