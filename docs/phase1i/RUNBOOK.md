# Phase 1I canary execution runbook

Use this only after Phase 1I is merged and deployed to a dedicated sandbox
worker host.

## 1. Create the source archive

```bash
python3 scripts/build-phase1i-canary-source.py
```

Create an Agent with slug `rdc-canary`, upload the generated ZIP, complete
source verification, and create an immutable AgentVersion.

## 2. Pin one exact version and one exact worker

Keep the master switch off while preparing configuration:

```text
RDC_SANDBOX_EXECUTION_ENABLED=false
RDC_SANDBOX_ACTIVATION_MODE=disabled
RDC_SANDBOX_CANARY_AGENT_VERSION_ID=<immutable-version-uuid>
RDC_SANDBOX_CANARY_WORKER_NAME=<authenticated-worker-name>
```

The worker must be registered with `max_concurrency=1`.

## 3. Activate only the canary

After the API and worker configuration are verified:

```text
RDC_SANDBOX_EXECUTION_ENABLED=true
RDC_SANDBOX_ACTIVATION_MODE=canary
```

No other AgentVersion or worker is eligible.

## 4. Prove the chain

Queue one Build. Require:

- Build `SUCCEEDED`
- `CONTAINER_IMAGE` available and scan `PASSED`
- SBOM and provenance artifacts present
- artifact provenance includes the canary activation, source SHA-256, and
  immutable AgentVersion ID

Then queue one Run with:

```json
{"message":"phase1i","values":[1,2,3,4]}
```

Require:

```json
{"canary":"rdc-phase1i","count":4,"echo":"phase1i","sum":10}
```

Also require a `LOG_BUNDLE`, terminal Run status, and Run artifact provenance
bound to the exact container-image digest.

## 5. Return to safe default

After the first proof, return the master switch to false until the next
explicit rollout decision:

```text
RDC_SANDBOX_EXECUTION_ENABLED=false
RDC_SANDBOX_ACTIVATION_MODE=disabled
```

General untrusted Agent execution remains prohibited throughout Phase 1I.
