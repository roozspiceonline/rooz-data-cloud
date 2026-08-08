# Phase 1M Operator Runbook

## Current status

Phase 1M increment 5 provides the bounded live gateway and extraction
implementation, but v2 Runs remain receipt-only and non-executable.

```text
Agent network                  none
Browser runtime network        none
Browser→gateway transport      Unix domain socket
Gateway request contract       rdc.browser-gateway-request/v1
Gateway response contract      rdc.browser-gateway-response/v1
Navigation result contract     rdc.browser-navigation-result/v1
Normal v2 START dispatch       blocked
Normal v2 activation           denied
```

## Forwarding contract

The browser runtime sends no browser-provided headers or request body to the
gateway. Only request id, gateway-policy digest, resource type, method and URL
cross the Unix socket.

The worker-side gateway:

1. verifies the exact immutable gateway-policy digest
2. enforces GET/HEAD only
3. enforces permitted browser resource types
4. validates the exact allowlisted HTTPS hostname
5. resolves only global addresses
6. uses the Phase 1J pinned HTTPS connection primitive
7. strips Set-Cookie and other unsafe response headers
8. revalidates redirects before returning Location to Chromium
9. enforces request, redirect and byte budgets

## Runtime interception

The browser runtime uses Playwright `context.route("**/*", ...)` and fulfills
approved responses from the Unix gateway. It never uses `route.continue_()`.

Unsupported resources and policy failures are aborted.

Chromium remains `--network none`, so a request that bypasses interception has
no direct Internet path.

## Result contract

`rdc.browser-navigation-result/v1` binds:

- navigation request digest
- browser-policy digest
- browser-egress-policy digest
- `browser_network=none`
- `gateway_transport=unix`
- final HTTPS URL
- bounded per-step extraction results
- gateway egress-budget usage

Screenshot results are base64 PNG with byte length and SHA-256.

## Stop conditions

Stop immediately if any change:

- enables normal v2 START dispatch in this increment
- grants v2 control-plane activation
- changes Chromium away from `--network none`
- forwards browser headers, cookies, authorization or request bodies
- uses `route.continue_()` for external requests
- connects before DNS/global-address policy validation
- stops pinning the outbound connection to a validated address
- returns an unvalidated redirect Location to Chromium
- removes request/redirect/byte budgets
- enables CDP, uploads/downloads, persistent profiles or arbitrary proxies

## Next increment

Final Phase 1M hardening will wire the already-bounded live path into the
controlled canary only after independent exact-head CI, add worker artifact
validation/provenance, and decide the narrow activation transition. PR #50
must remain DRAFT until that final increment is green.
