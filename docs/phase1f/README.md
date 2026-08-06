# Phase 1F — Isolated Execution-Plane Foundation

## Purpose

Phase 1F establishes a separate, authenticated execution-plane protocol. The
public API still does not execute Agent code. Internal workers can register,
heartbeat, claim durable Build or Run commands, renew bounded leases, report
state, append sanitized Run events, register immutable artifact metadata, and
receive lease-scoped secret envelopes.

## Security boundary

The internal API is rooted at `/internal/v1`, is excluded from the public
OpenAPI document, and never accepts browser sessions, CSRF credentials, API
keys, or personal access tokens. Worker credentials and lease credentials are
separate, write-only values with independent HMAC digests.

Phase 1F does not:

- start containers or virtual machines;
- invoke Docker, Kubernetes, BuildKit, shell commands, `eval`, or `exec`;
- expose control-plane database credentials to workers;
- return project-secret plaintext from a public endpoint;
- enable untrusted Agent execution.

Every lease claim includes `execution_enabled: false`. A later phase must prove
the sandbox and artifact-delivery implementation before changing that flag.

## Internal protocol

### Worker lifecycle

- `POST /internal/v1/workers/register`
- `GET /internal/v1/workers/me`
- `POST /internal/v1/workers/me/heartbeat`

Registration requires the deployment bootstrap credential. The worker token is
shown once. Workers can report `ACTIVE` or `DRAINING`; draining workers cannot
claim new work.

### Lease lifecycle

- `POST /internal/v1/leases/claim`
- `POST /internal/v1/leases/{lease_id}/renew`
- `POST /internal/v1/leases/{lease_id}/status`
- `POST /internal/v1/leases/{lease_id}/events`
- `POST /internal/v1/leases/{lease_id}/secret-envelope`
- `POST /internal/v1/leases/{lease_id}/complete`

Claims use PostgreSQL row locks with `SKIP LOCKED`, an active-source unique
index, and a worker-scoped advisory lock. Leases are short-lived, have a hard
maximum lifetime, and are retried with bounded exponential backoff. Expired
leases return their source command to `PENDING` until the maximum attempt count
is reached.

### Work kinds

- `BUILD`
- `RUN_START`
- `RUN_CANCEL`

Build claims are metadata-only and identify the immutable Agent manifest. Run
claims identify the immutable Agent version, successful Build, input reference,
runtime bounds, and verified artifact metadata when available.

## Secret injection

Agent manifests may declare up to 64 uppercase secret names. A `RUN_START`
lease may request only declared names from the matching project and
environment. The control plane decrypts each stored project secret only inside
the bounded injection path, immediately encrypts one JSON payload to an
ephemeral X25519 worker key, clears its mutable plaintext buffer, and returns a
short-lived envelope.

Algorithm:

`X25519-HKDF-SHA256-AES-256-GCM`

The associated data binds the envelope to the lease, worker, and Run. Grants
expire no later than the lease and are revoked when the lease completes.

## Artifact metadata

Workers may register digest-addressed metadata for:

- container images;
- SBOMs;
- provenance attestations;
- Run outputs;
- log bundles.

A successful Build requires an available container-image artifact with a passed
scan. Artifact bytes remain in object storage; the control plane stores only
validated metadata, digest, object key, media type, size, scan state, and
provenance.

## Tenant controls

- public execution metadata uses `execution.read`;
- explicit project predicates remain mandatory;
- PostgreSQL RLS protects leases and artifacts;
- worker policies are bound to the current worker identity and active leases;
- tenancy triggers validate every lease, artifact, and secret grant;
- worker actions create audit records without credential or secret values.

## Console

The project console adds an **Execution plane** page showing lease and artifact
metadata only. Worker credentials, lease tokens, secret grants, and decrypted
values never enter the browser.

## Deferred

The following remain deferred:

- sandboxed Agent execution;
- Build context upload and BuildKit integration;
- artifact object-store upload/download credentials;
- container registry integration;
- worker autoscaling and scheduling pools;
- Kubernetes or microVM runtime adapters;
- production worker revocation and rotation UI.
