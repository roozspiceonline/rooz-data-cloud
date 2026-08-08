# Phase 1M Threat Model

## Assets

- tenant isolation
- AgentVersion immutability
- browser/navigation/gateway policy digests
- worker identity
- internal network confidentiality
- cloud metadata credentials
- project secrets
- browser extraction outputs

## Browser network threats

1. SSRF through top-level navigation
2. redirect-to-private-address attacks
3. subresource requests to private or metadata networks
4. DNS rebinding between validation and connection
5. direct IP-literal bypass
6. credential leakage through Authorization/Cookie headers
7. persistence through Set-Cookie/service workers/profiles
8. WebSocket or WebRTC side channels
9. proxy override bypass
10. request/byte amplification from subresource fan-out
11. arbitrary JavaScript/CDP escalation
12. bypassing RDC mediation with direct Chromium networking

## Current mitigations

`rdc.browser-egress-policy/v1` requires:

- HTTPS only
- exact allowlisted hostnames
- global-only DNS
- IP literals rejected
- validated address pinning
- redirects revalidated
- every network subresource independently revalidated
- request/resource/total-byte budgets
- request/connect timeouts
- Authorization/Cookie/Proxy-Authorization stripping
- Set-Cookie stripping
- WebSocket/service-worker/WebRTC denial
- arbitrary proxy denial
- persistent cookies disabled

The policy is immutable per Run: its SHA-256 digest is bound into
`rdc.browser-navigation-receipt/v1` and independently reconstructed by the
worker from the Phase 1J egress policy.

## Residual risk

No live browser networking exists yet. The next increment must preserve the
policy while implementing an isolated browser-to-gateway transport. Chromium
must not receive unrestricted host networking, and the transport must connect
only to already validated/pinned global addresses while preserving TLS
hostname verification.
