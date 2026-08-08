# Phase 1M Threat Model

## Assets

- tenant isolation
- AgentVersion immutability
- browser policy and activation digests
- worker identity
- internal network confidentiality
- cloud metadata credentials
- project secrets
- browser extraction outputs

## New threat surface

`rdc.browser/v2` introduces declarative public navigation intent. The protocol
itself must not imply that Chromium is allowed to reach the public Internet.

Key threats:

1. SSRF through top-level navigation
2. redirect-to-private-address attacks
3. subresource requests to private or metadata networks
4. DNS rebinding between validation and connection
5. abusive selectors or waits consuming browser resources
6. oversized DOM/text/screenshot output
7. protocol smuggling through unknown fields or action types
8. arbitrary JavaScript escalation
9. session/cookie persistence across Runs
10. bypassing the RDC egress broker with direct browser networking

## Foundation mitigations

- strict `additionalProperties=false` JSON schema
- exact action fields
- exact HTTPS hostname allowlist
- IP literals prohibited
- policy-bounded page/action counts
- bounded selector length
- bounded waits and extraction sizes
- viewport screenshot only
- no click/type/evaluate/CDP actions
- v2 remains unavailable to Run execution
- Agent and browser runtime remain `--network none`

## Required before live navigation

A dedicated browser-egress gateway must enforce:

- HTTPS-only destinations
- exact operator hostname allowlist
- global DNS resolution only
- rejection of private, loopback, link-local, multicast, reserved and metadata
  addresses
- DNS validation followed by connection pinning
- redirect revalidation
- subresource revalidation
- request, byte and time budgets
- no user-provided proxy bypass
- no browser authentication material
