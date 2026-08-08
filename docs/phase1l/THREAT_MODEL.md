# Phase 1L Browser Threat Model

## Principal threats

### SSRF and browser-generated network traffic

A browser can generate redirects, subresource requests, frames, scripts and
service-worker traffic. Future runtime integration must revalidate every
network destination against exact operator policy and globally routable
addresses.

### Browser escape / host compromise

Chromium is a large attack surface. The future browser worker must be non-root,
use Linux sandboxing, dropped capabilities, seccomp/AppArmor and bounded
resources. It must use no host Docker socket and must never use `--no-sandbox`.

### Credential/state leakage

There are no persistent browser profiles, project secrets, authentication
passthrough, saved passwords, browser sync or cross-Run cookies in Phase 1L.

### File and remote-control abuse

Downloads/uploads are disabled. Phase 1L does not expose an externally reachable
CDP endpoint and does not accept arbitrary JavaScript or CDP commands.

## Residual risk

No live browser runtime is activated by this foundation. Chromium/Playwright
supply-chain, renderer, sandbox, service-worker and subresource risks must be
addressed before runtime rollout.
