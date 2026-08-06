# Rooz Data Cloud — Phase 1A Engineering Foundation

Phase 1A converts the approved Phase 0 contracts into a runnable engineering baseline.

## Included

- pnpm/Turborepo monorepo
- Next.js console shell
- FastAPI control-plane API shell
- PostgreSQL, Redis, and local S3-compatible storage
- Docker Compose development topology
- Shared UI, shared types, and API client packages
- Alembic migration foundation
- Liveness and dependency-aware readiness endpoints
- GitHub Actions CI
- Automated RDC Team Bridge and GitHub kickoff

## Explicitly excluded

- Production authentication and session issuance
- Organization/project persistence APIs
- Agent, Build, and Run domain operations
- Build workers or runtime workers
- Billing, marketplace, pipelines, datasets, or connectors
- Secret reveal behavior or arbitrary code execution

## Start the module

Keep RDC Team Bridge running, then execute:

```bash
cd ~/Downloads
unzip -o RDC-P1A-ENGINEERING-FOUNDATION.zip
cd RDC-P1A-ENGINEERING-FOUNDATION
python3 start-phase1a.py
```

The script opens a draft pull request and never merges automatically.

## Local stack after merge

```bash
cp .env.example .env
docker compose up -d --build
docker compose ps
```

Open:

- Console: http://localhost:3000
- API docs: http://localhost:8000/api/docs
- API liveness: http://localhost:8000/health/live
- API readiness: http://localhost:8000/health/ready
- MinIO console: http://localhost:9001
