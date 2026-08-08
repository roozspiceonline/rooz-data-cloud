# Phase 1M Operator Runbook

Safe default: `RDC_SANDBOX_CANARY_BROWSER_LIVE_NAVIGATION_ENABLED=false`.

A live v2 canary requires sandbox execution, canary mode, exact AgentVersion,
exact worker, concurrency 1, web egress, exact hostname allowlist, browser gate,
live-navigation gate, `network=web-egress`, `browser=true`, no secrets and no
Dataset/KV/Request Queue capabilities. Live limits must remain no broader than
256 MiB, 500m CPU, 64 PIDs, 256 MiB ephemeral disk and 120 seconds.

Without all gates, new v2 Runs are DRAFT/no-START. Existing DRAFT Runs do not
become executable after config changes; create a new Run after deliberate
activation.

The worker independently revalidates both policies and the receipt, runs the
per-Run Unix gateway, launches Chromium with `--network none`, and validates
`rdc.browser-navigation-result/v1` against the immutable plan before artifact
registration. Provenance records runtime image ref, request/browser/egress
digests, network none, gateway unix and direct browser Internet false.

Disable the live gate immediately on any network bypass, policy/digest mismatch,
private/metadata reachability, result validation failure, or appearance of
secrets/uploads/downloads/persistence/CDP. PR #50 remains DRAFT until exact-head
CI is green and explicit Phase 1M merge approval is given.
