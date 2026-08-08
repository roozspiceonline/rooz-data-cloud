# Rooz Data Cloud — Phase 1M merge candidate

Rooz Data Cloud Phase 1M implements controlled browser navigation and bounded
extraction on top of the merged Phase 1L browser foundation.

Live navigation has its own false-by-default gate:
`RDC_SANDBOX_CANARY_BROWSER_LIVE_NAVIGATION_ENABLED=false`.

The capability includes strict `rdc.browser/v2`, exact HTTPS hostname allowlists,
global-DNS validation, validated-address pinning, TLS hostname/SNI verification,
redirect/subresource revalidation, per-Run Unix gateway transport, plan-bound
results and bounded text/HTML/viewport screenshot extraction.

Agent containers and Chromium remain `--network none`. Browser cookies,
Authorization headers and request bodies never cross the gateway. General
untrusted browser execution remains release-blocked.

Without the full exact canary configuration, new v2 Runs remain DRAFT with no
START command. PR #50 remains draft and unmerged until exact-head CI is green
and the Product Owner explicitly approves the Phase 1M merge.
