# RDC Phase 1C — Agent Registry and Immutable Versions

Phase 1C adds the first product-domain module on top of the Phase 1B identity and tenancy foundation.

## Included

- Tenant-scoped Agent metadata
- Immutable Agent versions
- `rooz.agent/v1` manifest validation
- SHA-256 canonical manifest digests
- Cursor pagination with HMAC integrity protection
- ETag and `If-Match` optimistic concurrency for Agent metadata
- Explicit organization and project predicates
- PostgreSQL Row-Level Security
- Database tenancy guards
- Database trigger preventing Agent-version update or deletion
- Audit events for Agent creation, update, and version creation
- Agent list, creation, detail, update, version history, and manifest screens

## Security boundaries

Phase 1C stores and validates metadata only.

It does **not**:

- Build containers
- Execute Agent code
- Start Runs
- Stream Run logs
- Inject project secrets
- Create datasets or exports
- Connect to external providers

Arbitrary Agent code remains prohibited inside the public API process.

## API inventory

- `GET /api/v1/projects/{project_id}/agents`
- `POST /api/v1/projects/{project_id}/agents`
- `GET /api/v1/agents/{agent_id}`
- `PATCH /api/v1/agents/{agent_id}`
- `GET /api/v1/agents/{agent_id}/versions`
- `POST /api/v1/agents/{agent_id}/versions`
- `GET /api/v1/agent-versions/{version_id}`

## Verification

```bash
python3 scripts/verify-phase1c.py
cd apps/api && pytest
cd ../.. && pnpm test && pnpm build
```
