# Rooz Data Cloud — Phase 1D

Phase 1D extends the merged identity, tenancy, and Agent registry foundation with write-only project secrets and the metadata-only Build control plane.

## Included

- Envelope-encrypted project-secret storage
- Secret metadata list, create, replace, and delete APIs
- No secret reveal or plaintext-return endpoint
- ETag concurrency and idempotent secret replacement
- Build creation from immutable Agent versions
- Build read and Agent Build-history APIs
- Transactional Build dispatch outbox
- PostgreSQL RLS, explicit tenant predicates, resource resolvers, and tenancy guards
- Security audit events
- Secrets and Builds console flows
- Alembic, backend, frontend, scaffold, and Compose CI

## Execution boundary

The public API stores and queues metadata only. It does not decrypt secrets for users, invoke BuildKit, call Docker, execute Agent code, start Runs, or inject runtime secrets. Build execution remains delegated to a future isolated execution-plane worker.

## Start the phase

Keep RDC Team Bridge running, then execute:

```bash
cd ~/Downloads
unzip -o RDC-P1D-SECRETS-BUILDS.zip
cd RDC-P1D-SECRETS-BUILDS
python3 start-phase1d.py
```

The script creates Phase 1D Bridge tasks and GitHub Issues, uploads the implementation to `feat/phase-1d-secrets-build-control-plane`, opens a draft pull request, and dispatches the UX/accessibility review to Gemini. It never merges automatically.
