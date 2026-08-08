# Phase 1M Threat Model

Assume hostile page content. Threats include top-level/subresource SSRF,
redirect-to-private/metadata targets, DNS rebinding, direct browser networking,
credential/header/body leakage, POST/form effects, WebSocket/WebRTC side
channels, resource amplification, output tampering, policy substitution,
cross-Run IPC reuse and accidental activation after upgrading Phase 1L.

Mitigations: independent live-navigation gate default false; exact AgentVersion
and worker; concurrency 1; no secrets; Agent and Chromium `--network none`;
per-Run Unix gateway; GET/HEAD only; no browser headers/cookies/auth/body;
exact HTTPS allowlist; IP-literal rejection; global DNS; validated-address
pinning; TLS hostname/SNI validation; redirect and subresource revalidation;
request/redirect/byte/time budgets; service workers blocked; no
`route.continue_()`; bounded viewport screenshots; immutable request/policy
digests; and plan-bound result validation before artifact upload.

`RDC_SANDBOX_CANARY_BROWSER_ENABLED=true` alone is insufficient. The separate
`RDC_SANDBOX_CANARY_BROWSER_LIVE_NAVIGATION_ENABLED=true` opt-in is required.
Clicks, typing, forms, arbitrary evaluate, secrets, downloads/uploads,
persistent profiles, raw CDP and unrestricted Internet remain out of scope.
