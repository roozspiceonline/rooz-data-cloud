# Phase 1J Operator Runbook

## Current status

The initial Phase 1J commit is a **non-activating security foundation**.
Do not enable any egress capability from this commit alone.

## Planned operator-owned configuration

The completed Phase 1J implementation will introduce configuration equivalent
to:

```text
RDC_SANDBOX_CANARY_WEB_EGRESS_ENABLED=false
RDC_SANDBOX_CANARY_WEB_EGRESS_ALLOWED_HOSTS=[]
RDC_SANDBOX_CANARY_WEB_EGRESS_MAX_REQUESTS=8
RDC_SANDBOX_CANARY_WEB_EGRESS_MAX_RESPONSE_BYTES=1048576
RDC_SANDBOX_CANARY_WEB_EGRESS_MAX_TOTAL_BYTES=4194304
RDC_SANDBOX_CANARY_WEB_EGRESS_MAX_REDIRECTS=3
RDC_SANDBOX_CANARY_WEB_EGRESS_CONNECT_TIMEOUT_SECONDS=5
RDC_SANDBOX_CANARY_WEB_EGRESS_REQUEST_TIMEOUT_SECONDS=15
```

The final values remain operator policy, never Agent-authored policy.

## Host allowlist rules

- exact hostnames only
- IDNA-normalized lowercase names
- no `*` wildcards
- no IP literals
- no single-label internal hostnames
- no `.local` destinations
- no URL credentials
- HTTPS only
- explicit port may only be 443

DNS answers must all be globally routable. Any private, loopback, link-local,
multicast, reserved, unspecified or otherwise non-global answer denies the
request.

## Redirects

Every redirect is treated as a brand-new destination and passes the complete
URL + DNS validation again. The original allowlisted URL never grants trust to
a redirect destination.

## Container boundary

The Agent container stays:

```text
--network none
```

Brokered responses are data, not a networking capability granted to the
container.

## Stop conditions

Stop Phase 1J activation immediately if any of these occur:

- egress-policy digest mismatch
- redirect validation mismatch
- DNS returns a non-global address
- request/byte/time budget exceeded
- unexpected browser or secret capability
- worker identity or AgentVersion mismatch

General untrusted Agent execution must remain disabled.
