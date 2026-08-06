# Phase 1G — Secure Source Ingestion and Artifact Delivery

## Purpose

Phase 1G adds the first real object-delivery boundary to Rooz Data Cloud. Users upload Agent source ZIPs directly to S3-compatible object storage through short-lived, exact-size presigned forms. The control plane verifies the uploaded object and safely inspects its archive before an immutable Agent version can reference it.

This phase does **not** build images or execute Agent code. Every worker claim continues to set `execution_enabled: false`.

## Source upload lifecycle

1. `POST /api/v1/agents/{agent_id}/source-uploads` creates a pending storage object and a short-lived presigned POST.
2. The browser uploads the exact declared byte length directly to object storage.
3. `POST /api/v1/storage-objects/{storage_object_id}/complete` verifies provider metadata, content type, size, SHA-256, and safe-ZIP policy.
4. A passed archive becomes `AVAILABLE` with `scan_status=PASSED`.
5. An immutable Agent version must reference that exact storage object and a manifest whose canonical digest matches the inspected root `agent.json`.
6. Every Build snapshots the immutable source object ID.

## Archive policy

The control plane reads a bounded archive into memory but never extracts it. It rejects:

- absolute, drive-qualified, backslash, NUL, empty, current, or parent paths;
- duplicate normalized paths;
- symlinks, devices, sockets, FIFOs, and encrypted entries;
- nested archives;
- excessive file count, depth, per-file size, expanded size, or compression ratio;
- missing root `agent.json`;
- invalid Rooz Agent manifests;
- manifest names that do not match the target Agent slug;
- missing schema files referenced by the manifest.

Rejected objects are marked `REJECTED`, assigned a stable rejection code, audited, and deleted from object storage on a best-effort basis.

## Delivery grants

Tenant users with `storage.download` can request a short-lived presigned download URL for an available object. Active BUILD leases can request the same source through:

`POST /internal/v1/leases/{lease_id}/source-download`

The internal route remains outside public OpenAPI. Worker grants are bound to the active worker and lease. The database stores only a SHA-256 capability digest, not the presigned URL.

## Storage model

- `control.storage_objects` stores immutable expected and verified metadata.
- `security.storage_grants` records upload/download capability issuance without retaining capability URLs.
- `control.agent_versions.source_object_id` binds a verified source archive to an immutable version.
- `control.builds.source_object_id` snapshots the same archive for the Build.

The Phase 1G migration uses a nullable database rollout for the new references so an existing deployment can upgrade safely. Application paths require the references for all newly created versions and Builds.

## Tenant and worker security

- Tenant APIs use explicit permission checks and PostgreSQL RLS.
- Storage-object relationships are protected by tenancy triggers.
- Worker reads require an active BUILD lease that targets a Build linked to the object.
- Object keys are tenant/project/Agent scoped.
- Upload grants enforce exact content length, media type, object ID metadata, and declared digest metadata.
- Capability URLs, worker credentials, lease tokens, and source bytes are not written to audit logs.

## Console

The Agent screen uploads and verifies source before creating a version. The project Storage page lists verified objects and creates short-lived download grants. URLs are used immediately and are not stored in browser persistence.

## Deferred

- source archive extraction inside disposable worker workspaces;
- rootless BuildKit and image registry integration;
- container image signing and transparency logs;
- sandboxed Run execution;
- runtime egress policy and proxying;
- worker autoscaling and scheduling pools.
