# Phase 1M Operator Runbook

## Current status

`rdc.browser/v2` is a receipt-only Run intent. The browser-egress gateway policy
contract now exists, but gateway transport is **not wired**.

Phase 1L controls remain authoritative:

```text
RDC_SANDBOX_CANARY_BROWSER_ENABLED=false
Agent container network=none
Browser self-test network=none
```

## Receipt-only behavior

For a valid v2 navigation Run:

1. immutable AgentVersion requires `browser=true`
2. immutable AgentVersion requires `network=web-egress`
3. navigation is checked against `rdc.browser-policy/v1`
4. API creates `rdc.browser-egress-policy/v1`
5. gateway-policy SHA-256 digest is bound into the navigation receipt
6. Run remains `DRAFT`
7. no START command is created
8. control-plane v2 activation remains denied
9. worker reconstructs the gateway policy from its Phase 1J egress policy
10. worker verifies payload + digest independently
11. worker still terminates fail-closed because live navigation is disabled

## Gateway policy invariants

Every future browser network request must be mediated as either a permitted
top-level document or permitted subresource.

The gateway must:

- validate every URL as HTTPS/443
- resolve only global/public addresses
- pin the connection to the validated address
- preserve TLS SNI/certificate validation for the allowlisted hostname
- repeat validation on redirects
- repeat validation on every subresource
- enforce request, redirect, resource-byte and total-byte budgets
- strip Authorization, Cookie and Proxy-Authorization
- strip Set-Cookie
- reject WebSocket/service-worker/WebRTC/proxy override surfaces

## Stop conditions

Stop Phase 1M immediately if any change:

- wires gateway transport before the policy receipt is independently verified
- queues START for a receipt-only v2 Run
- grants v2 sandbox activation
- removes `--network none` from the current browser runtime
- permits HTTP, IP literals, non-global DNS or non-allowlisted hosts
- permits redirects/subresources without revalidation
- permits WebSocket, service worker, WebRTC or arbitrary proxying
- enables project secrets, persistent cookies or browser profiles
- sets `transport_wired=true`
- sets receipt execution/dispatch true

## Next increment

Implement an isolated browser-to-gateway transport namespace without granting
Chromium unrestricted host networking.
