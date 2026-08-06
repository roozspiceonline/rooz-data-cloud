# Phase 1A Engineering Foundation

Phase 1A establishes the runnable monorepo, API and console composition roots, local data services,
shared packages, migration foundation, and CI. Product domains remain separate follow-on modules.

## Acceptance gate

- Console build and type checking pass.
- API lint, type checking, and tests pass.
- Docker Compose configuration validates.
- PostgreSQL and Redis health checks gate API startup.
- API liveness and readiness are independently observable.
- No credentials are committed.
- No arbitrary Agent or Build code runs in the public API process.
- The approved `/api/v1` and Organization → Project route contracts remain intact.
