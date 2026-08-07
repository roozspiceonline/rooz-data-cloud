# Rooz Data Cloud — Phase 1G

Phase 1G extends the merged control plane and authenticated execution-plane protocol with secure Agent source ingestion and short-lived object delivery.

## Included

- Direct S3-compatible source ZIP uploads through exact-size presigned POSTs
- SHA-256, media-type, provider-metadata, and byte-length verification
- Safe ZIP inspection without extraction
- Immutable source-object binding for Agent versions and Builds
- Lease-bound source-download grants for Build workers
- Tenant storage metadata APIs and a functional project Storage console
- PostgreSQL RLS, tenancy guards, audit events, schemas, tests, and CI verification

## Execution boundary

The API does not extract or execute Agent code. BuildKit, Docker, Kubernetes, containers, subprocesses, and sandboxed Runs remain disabled. Every worker claim still advertises `execution_enabled: false`.

## Start the phase

The generated `start-phase1g.py` reads the repository-scoped GitHub token from:

```text
~/Downloads/rdc-team-bridge/.env
```

The Bridge web server does not need to be running. The installer creates one Phase 1G issue, creates `feat/phase-1g-secure-source-artifact-delivery`, uploads the implementation, and opens a draft pull request. It does not merge or delete branches.
