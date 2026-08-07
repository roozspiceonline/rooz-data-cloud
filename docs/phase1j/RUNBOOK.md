# Phase 1J Operator Runbook

## Safe default

Phase 1J web egress is implemented behind a separate default-disabled gate:

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

Do not enable the egress gate until the exact Phase 1J canary AgentVersion,
worker identity and destination allowlist have been reviewed.

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

The API and worker must use the same allowlist and limits. Their canonical
`rdc.egress/v1` policy digests must match or the worker rejects the claim.

## DNS and connection handling

DNS answers must all be globally routable. The worker pins a validated public
address into the outbound TCP connection. TLS certificate validation and SNI
continue to use the allowlisted hostname.

## Redirects

Every redirect is treated as a new destination and passes complete URL and DNS
validation again. Redirects consume the request budget.

## Broker request contract

The Run input may contain `_rdc_web_requests`, a list of objects with `id`,
`method` (`GET` or `HEAD`) and an allowlisted HTTPS `url`.

The worker removes `_rdc_web_requests` and injects `_rdc_web_results` plus
`_rdc_web_budget` before the Agent starts.

Agent-authored request headers, cookies, Authorization credentials, custom
ports, POST/PUT/PATCH/DELETE and compressed responses are not supported.

## Container boundary

The Agent container always stays:

```text
--network none
```

Brokered responses are input data, not a networking capability granted to the
container.

## Stop conditions

Stop Phase 1J activation immediately if any of these occur:

- egress-policy digest mismatch
- worker/API allowlist mismatch
- redirect validation mismatch
- DNS returns a non-global address
- request/byte/time budget exceeded
- unexpected browser or secret capability
- worker identity or AgentVersion mismatch
- Agent container network policy differs from `none`

General untrusted Agent execution must remain disabled.
