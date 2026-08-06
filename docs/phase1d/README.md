# RDC Phase 1D — Project Secrets and Build Control Plane

Phase 1D adds write-only project secrets and the metadata-only Build control plane.

## Project secrets

- Metadata list, create, replace, and delete APIs
- No reveal endpoint
- Secret values accepted only during create or replacement
- Per-secret random AES-256-GCM data keys
- Data keys wrapped with a configured 256-bit master key
- Tenant-bound authenticated encryption context
- ETag concurrency for replacement
- Idempotent replacement commands
- RLS, explicit tenant predicates, tenancy triggers, and audit events

The control plane stores ciphertext, nonces, and wrapped data keys. It does not expose a public decryption path. Future execution-plane injection must use a separate internal service identity and may receive only explicitly authorized secrets.

## Build control plane

- Create Build from an immutable Agent version
- Idempotency-protected Build creation
- Read one Build and list Builds for an Agent
- Durable transactional dispatch outbox
- Tenant-scoped Build and outbox records
- RLS, tenancy triggers, and audit events

The public API records and queues Build metadata only. It does not run BuildKit, invoke Docker, execute Agent code, or inject project secrets. A future isolated execution-plane worker will consume the outbox through a separately authenticated internal interface.

## Deferred

- Build worker and BuildKit execution
- Source uploads and build contexts
- Artifact registry integration
- Secret decryption or runtime injection
- Runs, cancellation, SSE, logs, and metrics
- Datasets, exports, connectors, billing, and marketplace
