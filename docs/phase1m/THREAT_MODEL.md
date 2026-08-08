# Phase 1M Threat Model

## New transport threat

Increment 4 adds a browser→gateway IPC path. The risks include cross-Run socket
reuse, malformed messages, gateway-policy substitution and turning the IPC
self-test into a hidden network bypass.

## Mitigations

- per-Run Unix-domain socket
- fixed in-container socket path
- private worker workspace
- read-only IPC mount
- browser remains `--network none`
- no host/CNI/bridge networking
- no published ports
- no Docker/containerd socket mount
- exact gateway-policy SHA-256 digest required
- 32-hex-character nonce
- strict message fields
- 4096-byte message maximum
- gateway self-test server has no DNS/HTTP/TLS forwarding implementation
- external request is false
- live forwarding is false
- Chromium remains on `about:blank`

## Residual risk

The next increment will add real gateway request messages. Before external
forwarding is enabled, every top-level request, redirect and subresource must be
revalidated against `rdc.browser-egress-policy/v1`, connected only to validated
global addresses, and bounded by immutable Run budgets.

Chromium must remain without an Internet-capable interface.
