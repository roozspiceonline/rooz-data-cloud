# Phase 1M — Controlled Browser Navigation & Extraction Protocol

Phase 1M adds controlled `rdc.browser/v2` navigation/extraction on the Phase 1L
browser boundary. Chromium remains `--network none` and reaches approved HTTPS
resources only through a per-Run Unix socket to the worker-side RDC gateway.

The gateway enforces exact host allowlists, global DNS, validated-address
pinning, TLS hostname/SNI verification, redirect/subresource revalidation,
GET/HEAD-only requests and request/redirect/byte/time budgets. Browser headers,
cookies, Authorization and request bodies are not forwarded.

The action set remains: `goto`, `wait_for_selector`, `extract_text`,
`extract_html`, and viewport-only `screenshot`. Results are bound to exact step
ids/order/types/limits and request/browser/egress policy digests.

Live navigation requires the independent false-by-default gate
`RDC_SANDBOX_CANARY_BROWSER_LIVE_NAVIGATION_ENABLED`. Without the full exact
canary configuration, a new v2 Run remains DRAFT and has no START command.
General untrusted browser execution remains release-blocked.
