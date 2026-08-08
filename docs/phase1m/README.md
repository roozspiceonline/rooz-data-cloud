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

The browser→gateway transport self-test uses a per-Run Unix-domain socket:

`/rdc-ipc/gateway.sock`

The browser container still runs with:

`--network none`

Only the private per-Run IPC directory is bind-mounted read-only into the
browser runtime. No CNI bridge, host network, published port, Docker socket or
containerd socket is exposed.

The runtime sends `rdc.browser-gateway-ping/v1` carrying the exact
browser-egress policy digest. The worker-side self-test server returns
`rdc.browser-gateway-pong/v1` only when the digest and bounded nonce are valid.

`rdc.browser-gateway-transport-self-test/v1` proves that Chromium remains on
`about:blank`, browser networking is `none`, the gateway makes no external
request, and live forwarding is false.

The self-test transport contains no DNS, HTTP or TLS forwarding code.

## Next boundary

Live navigation will later use Playwright request interception: Chromium's
network requests will be intercepted and sent over the Unix socket to the
worker-side RDC gateway. Only that gateway may perform policy-validated,
address-pinned HTTPS requests.

Chromium itself must remain network-none.

## Still blocked

- live gateway forwarding
- public Chromium navigation
- arbitrary JavaScript/evaluate
- clicks/forms/type
- project secrets
- uploads/downloads
- persistent profiles/cookies
- CDP/browser server
- arbitrary proxies
- WebSockets/service workers/WebRTC
