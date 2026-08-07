# Rooz Data Cloud Security and Quality Merge Gates

**Document ID:** RDC-SEC-GATE-001  
**Task:** RDC-P0-CHAT-001  
**Status:** Phase 0 baseline  
**Applies to:** all pull requests targeting protected integration and release branches

---

## 1. Purpose

These gates convert architecture and security requirements into automated and reviewable merge controls.

A pull request MUST NOT merge when a required gate fails.

---

## 2. Branch protection baseline

Protected branches:

```text
main
release/*
```

Required settings:

- Pull request required
- Direct pushes disabled
- Force pushes disabled
- Branch deletion disabled
- Required status checks
- Conversation resolution required
- Stale approvals dismissed after new commits
- Administrators follow protection rules
- Signed commits or verified CI provenance SHOULD be enabled
- Merge queue MAY be enabled after CI stabilizes

At least one technical review is required. Bablu approval is additionally required for product scope, commercial behavior, data deletion, or externally visible policy changes.

---

## 3. Required CI jobs

## 3.1 `contract-integrity`

Checks:

- Required source-of-truth files exist
- Markdown links resolve where practical
- JSON and YAML parse
- Agent manifests validate against schemas
- API contract version is present
- Architecture decision references are valid
- No task silently changes an approved phase boundary

Failure: merge blocked.

## 3.2 `python-quality`

Planned commands:

```bash
ruff check .
ruff format --check .
mypy apps services packages
pytest tests/unit tests/integration
```

Rules:

- No syntax failures
- No lint errors in changed production code
- Type-checking passes for enforced packages
- Unit and integration tests pass
- Test warnings are reviewed and bounded

## 3.3 `frontend-quality`

Planned commands:

```bash
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

Additional:

- Accessibility component checks
- Route smoke tests
- Bundle-budget checks once baselines exist
- No browser secret/token storage

## 3.4 `secret-scan`

Tool:

```text
gitleaks
```

Checks:

- Repository history in PR range
- Changed files
- Generated task packets where stored
- `.env` files excluded

Any credible credential finding blocks merge.

False positives require a documented allowlist entry with justification and expiry where appropriate.

## 3.5 `dependency-review`

Checks:

- Python dependency vulnerabilities with `pip-audit`
- JavaScript dependency review
- Lockfile consistency
- License policy
- New package justification
- No unpinned production GitHub Action references

Critical vulnerabilities block merge. High vulnerabilities require a fix or dated exception.

## 3.6 `sast`

Tools MAY include:

```text
Semgrep
Bandit
CodeQL
```

Mandatory rule categories:

- SQL injection
- Command injection
- Path traversal
- Unsafe archive extraction
- Insecure random
- Weak cryptography
- Debug mode
- Credential logging
- Unsafe deserialization
- SSRF-prone request construction
- Shell invocation with user input

Critical/high confirmed findings block merge.

## 3.7 `tenant-isolation`

Required tests for every tenant-owned resource:

- Same-tenant read/write succeeds
- Cross-tenant read returns safe denial
- Cross-tenant write/delete fails
- Relationship assignment across tenants fails
- Background job requires tenant context
- PostgreSQL RLS blocks access using runtime role
- Runtime role has no `BYPASSRLS`
- Runtime role does not own tenant tables

Any failure blocks merge.

## 3.8 `auth-security`

Checks:

- Argon2id password hashing
- Raw passwords never logged/stored
- Session cookie flags
- Session rotation
- Revocation
- CSRF enforcement
- Generic recovery behavior
- API keys stored as digests
- Revoked credentials fail
- Sensitive headers redacted

Any failure blocks merge.

## 3.9 `api-contract`

Checks:

- OpenAPI validates
- Generated client types are current
- Standard error envelope is used
- Endpoint permission metadata exists
- Tenant and audit requirements are documented
- Breaking changes are detected with an OpenAPI diff tool such as `oasdiff`

Unapproved breaking changes block merge.

## 3.10 `migration-safety`

Checks:

- Alembic heads are singular unless intentional
- Upgrade from baseline succeeds
- Downgrade or irreversibility documentation exists
- Empty-database migration succeeds
- Existing-fixture upgrade succeeds
- RLS policies and grants are included
- No unbounded destructive operation
- New non-null columns have safe rollout strategy

Failure blocks merge.

## 3.11 `container-security`

When Dockerfiles or images are affected:

- Dockerfile lint
- Image build
- Trivy vulnerability scan
- Non-root user check
- No embedded secrets
- No prohibited capabilities
- Health check where applicable
- SBOM generation
- Approved base image policy

Critical image findings block merge. High findings require remediation or a time-bounded exception.

## 3.12 `execution-isolation`

When build/runtime code is affected:

- No API-container execution of user code
- No host Docker socket mount
- Rootless build policy
- Resource limits
- Read-only root filesystem where applicable
- Capability drop
- Network policy
- Timeout and cancellation cleanup
- Short-lived scoped credentials

Violation blocks merge.

## 3.13 `export-safety`

When CSV/XLSX export is affected:

- Formula-injection corpus neutralized
- No macros
- Correct encoding
- Output-size limits
- Tenant authorization
- Streaming behavior for large exports
- Audit event emitted

Failure blocks merge.

## 3.14 `audit-integrity`

Checks:

- Required mutations emit audit events
- Sensitive fields are excluded
- Runtime role cannot update/delete audit events
- Request ID and actor information present
- Failure outcomes are recorded where required

Failure blocks merge.

---

## 4. Pull-request risk classification

Every PR receives one risk class.

### Low

Examples:

- Documentation typo
- Non-functional UI copy
- Test-only refactor

Approvals:

- One technical review

### Medium

Examples:

- Ordinary endpoint
- UI workflow
- Non-sensitive database index
- Internal refactor

Approvals:

- One technical review
- Required CI

### High

Examples:

- Authentication
- Authorization
- RLS
- Secrets
- Build/runtime isolation
- Uploads
- Billing
- Data deletion
- External webhook or proxy behavior

Approvals:

- ChatGPT security/architecture approval
- Gemini review when browser or UX contracts are affected
- Bablu approval when product behavior or user data policy changes
- Full relevant security gates

---

## 5. Manual review checklist

Reviewer confirms:

- [ ] Scope matches the assigned task
- [ ] Phase boundary is respected
- [ ] No hidden contract change
- [ ] Tenant ownership is explicit
- [ ] Authentication and permissions are server-enforced
- [ ] Sensitive values are not logged or returned
- [ ] Errors use stable codes
- [ ] Idempotency is defined for side-effecting retries
- [ ] Audit events are present
- [ ] New dependencies are justified
- [ ] Tests cover negative and abuse cases
- [ ] Documentation is updated
- [ ] Rollback or safe deployment path exists

---

## 6. Security exception process

An exception request must include:

```text
Finding:
Affected component:
Reason remediation cannot occur before merge:
Compensating controls:
Residual risk:
Owner:
Expiration date:
Tracking issue:
```

Rules:

- No permanent exceptions.
- Critical tenant-isolation or plaintext-secret failures cannot be excepted.
- Expired exceptions fail CI or release review.
- Exception approval does not remove the underlying finding from tracking.

---

## 7. Recommended GitHub Actions layout

```text
.github/workflows/
├── contracts.yml
├── backend.yml
├── frontend.yml
├── security.yml
├── migrations.yml
├── containers.yml
└── release.yml
```

Conceptual security workflow:

```yaml
name: Security gates

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  secret-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-commit>
        with:
          fetch-depth: 0
      - name: Scan secrets
        run: gitleaks detect --source . --redact

  python-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<pinned-commit>
      - name: Dependency audit
        run: pip-audit
      - name: Static analysis
        run: bandit -r apps services packages
      - name: Semgrep
        run: semgrep --config p/security-audit

  tenant-isolation:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:<pinned-version>
    steps:
      - uses: actions/checkout@<pinned-commit>
      - name: Run tenant security tests
        run: pytest tests/security/tenant_isolation -q
```

Actual action commit SHAs and dependency versions are chosen during CI implementation.

---

## 8. Release gates

Before a release:

- All required PR gates pass
- No unresolved critical vulnerability
- High-risk exceptions are unexpired
- Database migration rehearsal passes
- Backup and restore verification is current
- Container images are scanned
- SBOMs are retained
- Configuration and secret references are validated
- Smoke tests pass
- Rollback plan exists
- Audit logging works
- Bablu approves user-facing scope

---

## 9. Gate ownership

| Area | Owner |
|---|---|
| Architecture and backend security | ChatGPT |
| Frontend, accessibility, and browser behavior | Gemini |
| Product scope and user-facing policy | Bablu |
| Automated execution | GitHub Actions |
| Source of truth | Repository documentation and approved ADRs |

---

## 10. Phase 0 implementation order

1. Add source-of-truth documentation
2. Add contract/schema validators
3. Add secret scanning
4. Add backend and frontend quality jobs
5. Add dependency and SAST jobs
6. Add database service for migration/RLS tests
7. Add container scanning when images exist
8. Protect `main`
9. Require status checks
10. Test the exception workflow


## Phase 1F merge gates

- Internal routes are excluded from public OpenAPI.
- Worker and lease credentials use different prefixes, peppers, and digests.
- Worker bootstrap, token, and lease settings reject weak production defaults.
- Claims use row locking, active-source uniqueness, bounded attempts, and expiry.
- Worker concurrency is serialized per worker.
- Lease status and completion transitions are target-specific.
- Run events pass the Phase 1E sanitizer and payload limit.
- Secret names are declared by the immutable Agent manifest.
- Secret envelopes are X25519/HKDF/AES-256-GCM and expire with the lease.
- Artifact success requires a passed, available container image for Builds.
- Execution tables have RLS and tenancy triggers.
- The console exposes metadata only.
- No untrusted execution primitive exists in the API or reference client.
- Alembic online migration, Ruff, strict mypy, pytest, frontend lint/typecheck/tests/build, all phase verifiers, and Compose validation pass.


## Phase 1G merge gates

- Upload intent binds exact byte length, content type, object ID metadata, and declared SHA-256.
- Completion recomputes SHA-256 and validates provider metadata before availability.
- ZIP inspection rejects traversal, special files, encrypted entries, nested archives, and decompression abuse.
- Root `agent.json` and referenced schemas are mandatory.
- Immutable versions and Builds bind the verified source object.
- Storage grants are short-lived and only capability digests are stored.
- Tenant and worker storage access is protected by explicit predicates, RLS, and tenancy triggers.
- Worker download requires an active BUILD lease.
- No extraction, BuildKit, Docker, Kubernetes, container, shell, subprocess, or Agent execution is introduced.
- Alembic, Ruff, strict mypy, pytest, frontend checks, all phase verifiers, and Compose validation pass.

## Phase 1H sandbox merge gate

A Phase 1H merge is blocked unless: the global execution setting defaults to false; the API contains no subprocess/container-runtime primitive; the worker preflight rejects root, visible Docker sockets, and non-rootless runtime sockets; claim execution requires strict sandbox attestation; Phase 1H networking is deny-all; artifact uploads are recomputed with SHA-256 by the control plane; runtime argv contains non-root, read-only, all-capabilities-dropped, no-new-privileges, PID/CPU/memory/time limits; and all Phase 1A–1H CI checks pass.



## Phase 1I controlled-activation merge gate

A Phase 1I merge is blocked unless:

- `RDC_SANDBOX_EXECUTION_ENABLED` still defaults to false.
- `RDC_SANDBOX_ACTIVATION_MODE` defaults to `disabled`.
- canary mode requires one valid immutable AgentVersion UUID.
- canary mode requires one exact authenticated worker name.
- the eligible worker has `max_concurrency=1`.
- the canary manifest declares no secrets.
- network, browser, dataset, key-value-store, and request-queue capabilities
  are all disabled.
- canary resource ceilings do not exceed Phase 1H sandbox ceilings.
- execution requires both a valid sandbox policy and a valid canary
  activation.
- the worker recomputes and checks the sandbox-policy digest.
- every Build artifact is bound to activation, AgentVersion, and source digest.
- every Run artifact is bound to activation, Run ID, and container-image
  digest.
- the API rejects mismatched activation or lineage provenance.
- the API still contains no container-runtime or subprocess primitive.
- the reference canary uses no network or secrets.
- all previous phase verifiers, the Phase 1I verifier, backend checks,
  frontend checks, and Compose validation pass.
