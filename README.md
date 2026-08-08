# Rooz Data Cloud — Phase 1M in progress

Rooz Data Cloud has completed and merged Phase 1L: the controlled-browser
execution foundation.

The authoritative merged browser baseline provides:

- strict `rdc.browser/v1` intent
- operator-owned browser policy receipts and SHA-256 binding
- controlled-browser activation receipts
- independent worker verification
- immutable local browser-runtime image references
- dedicated Chromium-compatible seccomp
- isolated `about:blank` Playwright/Chromium self-test
- forced browser-container cleanup
- false-by-default browser gate
- Agent and browser self-test runtime on `--network none`

Phase 1M is now building the controlled navigation and extraction protocol.

## Phase 1M safety boundary

The first Phase 1M increment introduces `rdc.browser/v2` protocol validation
only. Public Chromium navigation is still disabled.

No Phase 1M change may grant unrestricted Internet access to Agent containers
or Chromium. Live browser navigation requires a dedicated RDC-controlled
browser-egress gateway with SSRF, redirect, DNS and subresource enforcement.

General untrusted browser execution remains release-blocked.
