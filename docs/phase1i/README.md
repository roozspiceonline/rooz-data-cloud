# Phase 1I — Controlled Sandbox Activation & End-to-End Execution

Phase 1I turns the Phase 1H sandbox into a deliberately narrow canary path.
It does **not** enable general untrusted Agent execution.

## Activation invariant

An execution claim can set `execution_enabled: true` only when all of these
conditions hold:

1. `RDC_SANDBOX_EXECUTION_ENABLED=true`.
2. `RDC_SANDBOX_ACTIVATION_MODE=canary`.
3. `RDC_SANDBOX_CANARY_AGENT_VERSION_ID` exactly matches the immutable
   AgentVersion in the Build or Run claim.
4. `RDC_SANDBOX_CANARY_WORKER_NAME` exactly matches the authenticated worker.
5. The worker advertises `max_concurrency=1`.
6. The strict `rdc.sandbox/v1` attestation passes.
7. The Agent declares no secrets.
8. Network, browser, dataset, key-value-store, and request-queue capabilities
   are all disabled.
9. Resource limits fit inside the smaller Phase 1I canary ceilings.

A global switch alone therefore cannot activate arbitrary Agents.

## Evidence and lineage

The control plane writes a digest-bound `activation` object into the immutable
lease payload snapshot. The worker independently validates that activation
against its authenticated worker identity, the AgentVersion ID, and the
sandbox-policy digest.

Every Build artifact carries activation, immutable AgentVersion ID, and source
SHA-256 lineage. Every Run output/log artifact carries activation, Run ID, and
the exact container-image digest. The API rejects artifact registration when
that lineage does not match the lease snapshot.

## Reference canary

`examples/canary-agent` is an offline deterministic Agent that reads inline
JSON input and writes one JSON output file. It has no secrets or external
capabilities.

## Release boundary

Phase 1I proves one controlled offline Agent path:

source upload → immutable AgentVersion → Build → scan/SBOM/provenance →
container artifact → sandbox Run → output/log artifacts → cleanup.

Web egress, browser automation, arbitrary Agent activation, multiple canary
versions, Kubernetes scheduling, autoscaling, billing, and marketplace
execution remain out of scope.
