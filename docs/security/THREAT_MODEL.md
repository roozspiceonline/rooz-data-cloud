# Rooz Data Cloud Threat Model

**Document ID:** RDC-SEC-TM-001  
**Task:** RDC-P0-CHAT-001  
**Status:** Phase 0 baseline  
**Method:** asset and trust-boundary analysis with STRIDE-informed threat categories  
**Owner:** ChatGPT — Security and Architecture

---

## 1. Scope

This threat model covers the planned RDC foundation and its future control/execution boundary:

- Browser console
- Public API
- Authentication and authorization
- PostgreSQL
- Redis or queue infrastructure
- Object storage
- Source uploads
- Build workers and BuildKit
- Runtime manager
- Agent containers
- Proxy and outbound network path
- Logs and exports
- Project secrets
- GitHub and dependency supply chain
- Webhooks as a later-phase boundary

It does not authorize implementation of later phases.

---

## 2. Security objectives

RDC MUST preserve:

1. **Tenant confidentiality:** one organization cannot access another organization’s data.
2. **Tenant integrity:** one organization cannot alter another organization’s resources.
3. **Control-plane integrity:** user Agent code cannot execute inside the public API process.
4. **Execution isolation:** malicious builds and Runs are contained.
5. **Credential confidentiality:** passwords, sessions, API keys, service tokens, and project secrets do not leak.
6. **Audit integrity:** security-relevant activity remains attributable and tamper-resistant.
7. **Availability:** one user or Agent cannot exhaust shared infrastructure without bounded impact.
8. **Responsible use:** prohibited automation is blocked or reviewed where technically and legally required.

---

## 3. Trust boundaries

```text
Untrusted browser
      |
      | HTTPS + session/CSRF
      v
Public edge / reverse proxy
      |
      v
Control-plane API
      | \
      |  \---- PostgreSQL
      |   \--- Redis / queues
      |    \-- Object storage
      |
      | signed, scoped internal job
      v
Execution-plane queue
      |
      +--> Isolated build worker --> rootless BuildKit --> image registry
      |
      +--> Runtime manager --> isolated Agent container --> controlled egress
```

Additional boundaries:

- GitHub and package registries are external supply-chain dependencies.
- AI providers are future external processors.
- Proxy providers are external network intermediaries.
- Webhook targets are untrusted destinations.

---

## 4. Assets

Critical assets:

- User identities and password hashes
- Browser sessions and CSRF state
- API keys and personal access tokens
- Organization memberships and permissions
- Project and Agent metadata
- Agent source archives
- Built container images
- Build and Run control messages
- Project secrets
- Datasets and stored artifacts
- Logs and screenshots
- Billing and usage records in later phases
- Audit events
- Registry, database, object-store, and provider credentials

---

## 5. Threat actors

- Unauthenticated internet attacker
- Malicious registered user
- Malicious organization member
- Compromised user account
- Malicious Agent developer
- Compromised dependency or base image
- Compromised external provider
- Insider with operational access
- Automated abuse or resource-exhaustion actor
- Accidental developer error causing cross-tenant exposure

---

## 6. Security invariants

The following are release-blocking invariants:

- Arbitrary Agent code never executes in the API container.
- Tenant-owned reads and writes are scoped explicitly and protected by RLS.
- Runtime database roles cannot bypass RLS.
- Secret plaintext is never returned after creation.
- Raw session tokens and API keys are never stored.
- Sensitive headers and values are redacted from logs.
- Build and Run workers receive only short-lived, scoped credentials.
- Outbound network access is policy-controlled.
- Uploaded archives are size-limited and safely extracted.
- Every privileged mutation is audited.
- Security checks cannot be bypassed through frontend behavior.

---

## 7. Threat register

Likelihood and impact use: Low, Medium, High, Critical.

### T-01 Credential stuffing and brute force

- **Scenario:** attacker tests stolen credentials against login.
- **Components:** auth API, sessions.
- **Likelihood:** High
- **Impact:** High
- **Preventive controls:** Argon2id, per-account and per-IP throttling, breached-password screening policy, generic errors, optional future MFA, secure recovery.
- **Detective controls:** failed-login metrics, anomaly alerts, audit events.
- **Required tests:** repeated failures trigger controls; account enumeration is not possible; lockout does not enable denial-of-service against arbitrary accounts.
- **Residual risk:** Medium.

### T-02 Session theft or fixation

- **Scenario:** attacker steals or fixes a browser session.
- **Components:** browser, auth API, session store.
- **Likelihood:** Medium
- **Impact:** High
- **Preventive controls:** Secure HttpOnly SameSite cookies, rotation after login and privilege changes, TLS, CSP, short idle expiry, server revocation.
- **Detective controls:** unusual session metadata, concurrent-location signals, audit records.
- **Tests:** cookie attributes, rotation, revocation, old-token invalidation.
- **Residual risk:** Medium.

### T-03 CSRF

- **Scenario:** malicious site causes a logged-in browser to mutate RDC state.
- **Components:** browser/API.
- **Likelihood:** Medium
- **Impact:** High
- **Controls:** session-bound CSRF token, Origin validation, SameSite cookies, explicit CORS, no unsafe GET mutations.
- **Tests:** missing/invalid token, foreign Origin, preflight behavior.
- **Residual risk:** Low.

### T-04 API-key or PAT theft

- **Scenario:** credential leaks through source code, logs, browser storage, or error output.
- **Components:** API, GitHub, logs.
- **Likelihood:** High
- **Impact:** High
- **Controls:** show once, digest at rest, scopes, expiry, revocation, secret scanning, header redaction, no query-string auth.
- **Tests:** stored record lacks plaintext; log tests; revoked key fails.
- **Residual risk:** Medium.

### T-05 Cross-tenant data exposure

- **Scenario:** missing filter or unsafe relationship allows one organization to access another.
- **Components:** API, repositories, PostgreSQL.
- **Likelihood:** Medium
- **Impact:** Critical
- **Controls:** explicit tenant predicates, RLS, non-owner runtime DB role, composite tenant relationships, permission checks, safe 404 behavior.
- **Tests:** cross-tenant CRUD matrix for every resource; RLS tests using runtime role; background-job context tests.
- **Residual risk:** Low to Medium.

### T-06 Privilege escalation

- **Scenario:** member changes role or accesses owner-only operation.
- **Components:** membership API, DB.
- **Likelihood:** Medium
- **Impact:** Critical
- **Controls:** permission-based authorization, reauthentication for ownership transfer, final-owner invariant, optimistic locking, audit.
- **Tests:** role matrix, owner-removal race, stale update, forged organization ID.
- **Residual risk:** Low.

### T-07 SQL injection or unsafe query construction

- **Scenario:** attacker injects query syntax through filters or search.
- **Components:** API/database.
- **Likelihood:** Medium
- **Impact:** Critical
- **Controls:** parameterized SQL/ORM, allowlisted sorts and filters, no arbitrary SQL expressions, static analysis.
- **Tests:** injection payload suite; search and sort validation.
- **Residual risk:** Low.

### T-08 SSRF

- **Scenario:** Agent or webhook URL reaches metadata services, loopback, private networks, or internal services.
- **Components:** HTTP worker, proxy gateway, webhook service.
- **Likelihood:** High
- **Impact:** Critical
- **Controls:** scheme and port allowlists, DNS resolution validation, private/reserved IPv4 and IPv6 blocking, redirect revalidation, egress proxy, metadata endpoint blocking, destination logging.
- **Tests:** loopback, RFC1918, link-local, IPv6 local, encoded IPs, DNS rebinding simulation, redirect-to-private.
- **Residual risk:** Medium.

### T-09 Malicious or oversized upload

- **Scenario:** source ZIP consumes disk/memory or contains malware.
- **Components:** upload API, object storage, build worker.
- **Likelihood:** High
- **Impact:** High
- **Controls:** body limits, streaming upload, content digest, malware scan, quarantine, accepted-type validation.
- **Tests:** oversized body, MIME mismatch, partial upload, malware test signature.
- **Residual risk:** Medium.

### T-10 Zip bomb and path traversal

- **Scenario:** archive expands excessively or writes outside workspace.
- **Components:** build worker.
- **Likelihood:** High
- **Impact:** Critical
- **Controls:** compressed and expanded size quotas, file-count limit, depth limit, normalized paths, reject absolute paths, `..`, devices, hardlinks, and unsafe symlinks; extract into disposable workspace.
- **Tests:** classic zip bomb, nested archive, traversal paths, symlink escape.
- **Residual risk:** Low to Medium.

### T-11 Build-system escape

- **Scenario:** malicious Dockerfile escapes worker or reads host/registry credentials.
- **Components:** build worker, BuildKit, registry.
- **Likelihood:** Medium
- **Impact:** Critical
- **Controls:** execution-plane separation, rootless BuildKit, no host Docker socket, restricted entitlements, approved base images for MVP, network policy, resource limits, short-lived registry credentials, image scanning.
- **Tests:** privileged directive rejection, host mount denial, network denial, credential non-availability, timeout and cleanup.
- **Residual risk:** Medium.

### T-12 Runtime container escape

- **Scenario:** malicious Agent attacks kernel, sibling containers, or control plane.
- **Components:** runtime manager, worker host.
- **Likelihood:** Medium
- **Impact:** Critical
- **Controls:** non-root container, dropped capabilities, seccomp/AppArmor, read-only root where practical, PID/CPU/memory limits, isolated network, no control-plane credentials, patched host.
- **Tests:** capability checks, mount checks, cgroup enforcement, metadata access denial.
- **Residual risk:** Medium.

### T-13 Secret leakage

- **Scenario:** secret appears in logs, errors, environment dump, dataset, image layer, or build argument.
- **Components:** secret store, runtime, logs, build system.
- **Likelihood:** High
- **Impact:** Critical
- **Controls:** write-only API, envelope encryption, allowlisted injection, redaction, no build-arg secrets, short-lived service credentials, secret-value scanning.
- **Tests:** canary secret through stdout/stderr/error/dataset; API reveal attempts; image history scan.
- **Residual risk:** Medium.

### T-14 Log injection and terminal escape

- **Scenario:** Agent emits forged structured entries, newlines, ANSI escape sequences, or huge messages.
- **Components:** log collector and console.
- **Likelihood:** High
- **Impact:** Medium
- **Controls:** structured envelopes, size/rate limits, JSON encoding, ANSI sanitization, immutable source metadata, safe rendering.
- **Tests:** newline forging, terminal escape, huge line, invalid UTF-8.
- **Residual risk:** Low.

### T-15 Dependency or supply-chain compromise

- **Scenario:** malicious package, compromised action, base image, or registry artifact.
- **Components:** repository, CI, build.
- **Likelihood:** Medium
- **Impact:** Critical
- **Controls:** lockfiles, pinned GitHub Actions by commit, dependency review, SBOM, vulnerability scan, signed images later, approved registries and base images.
- **Tests:** lockfile consistency, known-vulnerability fixtures, unapproved registry rejection.
- **Residual risk:** Medium.

### T-16 GitHub credential compromise

- **Scenario:** repository token leaks or has excessive scope.
- **Components:** Team Bridge, CI, GitHub.
- **Likelihood:** Medium
- **Impact:** Critical
- **Controls:** fine-grained token, least privilege, local `.env`, secret scanning, branch protection, rotation, separate deployment credentials.
- **Tests:** `.env` ignored; token absent from logs and task packets; protected branch rejects direct push.
- **Residual risk:** Medium.

### T-17 Resource exhaustion and noisy neighbor

- **Scenario:** user creates many builds, Runs, streams, records, or large logs.
- **Components:** API, queue, workers, storage.
- **Likelihood:** High
- **Impact:** High
- **Controls:** quotas, concurrency caps, cgroups, timeouts, queue fairness, output limits, stream limits, backpressure, circuit breakers.
- **Tests:** load and soak tests; quota races; Run timeout; log truncation.
- **Residual risk:** Medium.

### T-18 Idempotency race

- **Scenario:** retries create duplicate builds, Runs, invitations, or charges.
- **Components:** API/database/queue.
- **Likelihood:** High
- **Impact:** High
- **Controls:** scoped idempotency record, unique constraint, request fingerprint, atomic command acceptance.
- **Tests:** concurrent identical requests; same key/different body; retry after network failure.
- **Residual risk:** Low.

### T-19 Audit tampering

- **Scenario:** attacker or insider deletes or alters evidence.
- **Components:** PostgreSQL, operations.
- **Likelihood:** Medium
- **Impact:** High
- **Controls:** append-only privileges, separate operations role, integrity hashes or archival later, backup, access audit.
- **Tests:** runtime role cannot UPDATE/DELETE; metadata redaction.
- **Residual risk:** Medium.

### T-20 Spreadsheet formula injection

- **Scenario:** exported value beginning with `=`, `+`, `-`, or `@` executes in spreadsheet software.
- **Components:** export worker.
- **Likelihood:** High
- **Impact:** Medium
- **Controls:** neutralize dangerous leading characters, plain-text cells, no macros, export warning and tests.
- **Tests:** formula payload corpus.
- **Residual risk:** Low.

### T-21 Cross-site scripting through datasets or logs

- **Scenario:** collected HTML/script is rendered as trusted markup.
- **Components:** console, dataset/log viewer.
- **Likelihood:** High
- **Impact:** High
- **Controls:** render as text, React escaping, CSP, sanitization only when rich content is explicitly required, no unsafe HTML.
- **Tests:** stored XSS payload suite.
- **Residual risk:** Low.

### T-22 Webhook abuse

- **Scenario:** later webhook endpoint targets internal network, receives forged delivery, or causes replay.
- **Components:** webhook service.
- **Current control:** migration `20260829_0029` adds only credential-free,
  immutable Project event persistence. It adds no destination, signing secret,
  delivery worker or outbound request. Project-bound RLS, exact subject
  validation, signed cursors and recursive payload bounds protect the event
  foundation while the network delivery boundary remains absent.
- **Current control update:** migrations `20260830_0030` through
  `20260901_0033` add HTTPS destination admission, immutable delivery and
  secret-version snapshots, digest-only claim fencing, a claim-scoped encrypted
  secret loader, timestamped HMAC-SHA256, and a separate false-by-default
  direct-TLS canary. It validates the complete public DNS set and connected
  peer, uses hostname-verified TLS/SNI, follows no redirect, ignores ambient
  proxies, and bounds time, bytes, concurrency, claims, and attempts.
  Successful claim-fenced verification is the only activation path; history
  omits secrets and request material, replay is explicit and idempotently
  version-fenced, and bounded consecutive terminal failures automatically
  disable the destination.
- **Likelihood:** Medium
- **Impact:** High
- **Controls:** SSRF defenses, HMAC signatures, timestamp and replay window, retries with limits, delivery audit, endpoint verification.
- **Tests:** private destination, signature mismatch, replay, redirect.
- **Residual risk:** Medium.
- **Phase:** Events/Webhooks control plane complete; network execution remains
  an environment-specific false-by-default gate.

### T-23 Insecure error handling

- **Scenario:** stack traces or headers leak credentials or implementation details.
- **Components:** all services.
- **Likelihood:** Medium
- **Impact:** High
- **Controls:** stable error envelope, allowlisted details, centralized exception handler, production debug disabled.
- **Tests:** injected failure confirms no secret/header/path/SQL leakage.
- **Residual risk:** Low.

### T-24 Insecure operational access

- **Scenario:** support or developer bypasses tenant protections.
- **Components:** database, admin tools, logs.
- **Likelihood:** Medium
- **Impact:** Critical
- **Controls:** separate roles, just-in-time access, reason and ticket requirement, full audit, no shared accounts, read-only by default.
- **Tests:** privilege review and access simulation.
- **Residual risk:** Medium.

---

## 8. Data-flow security requirements

### Browser to API

- HTTPS
- Secure session cookie
- Session-bound CSRF
- Strict origin allowlist
- CSP and output escaping
- Body and rate limits

### API to PostgreSQL

- Least-privilege role
- TLS where networked
- Explicit tenant context
- RLS
- Parameterized queries
- Transaction timeouts

### API to queue

- Signed or authenticated messages
- Schema validation
- Tenant context
- Idempotent consumption
- No raw user credentials

### Queue to worker

- Short-lived job claim
- Resource policy
- Artifact digests
- Bounded retries
- Dead-letter handling

### Worker to object storage/registry

- Short-lived scoped credentials
- Tenant/object prefix constraints
- TLS
- Content digests
- No listing beyond needed scope

---

## 9. Security testing strategy

Required categories:

- Authentication and session tests
- CSRF tests
- Permission matrix tests
- Cross-tenant isolation tests
- PostgreSQL RLS tests
- API-key and secret-redaction tests
- SSRF payload tests
- Archive extraction tests
- Container policy tests
- Dependency and image scans
- Export-injection tests
- XSS tests
- Rate-limit and resource-exhaustion tests
- Audit immutability tests

Security tests are merge-blocking where applicable.

---

## 10. Incident signals

Alerts or investigations are triggered by:

- Cross-tenant authorization denial spikes
- Repeated RLS violations
- Secret-redaction matches
- Unusual API-key usage
- High failed-login volume
- Build or runtime escape indicators
- Metadata endpoint access attempts
- Excessive egress or log volume
- Audit-table modification attempts
- Dependency or image critical vulnerability
- GitHub token misuse or unexpected repository mutation

---

## 11. Risk acceptance

- Critical residual risk requires explicit ChatGPT security approval and Bablu product-owner acknowledgment.
- High residual risk requires a dated remediation plan.
- No accepted exception may weaken tenant isolation, credential confidentiality, or API/execution separation without a new architecture decision.
- Exceptions expire and must be re-reviewed.


## Phase 1F execution-plane threats and controls

| Threat | Control |
|---|---|
| Stolen worker token | Write-only high-entropy token, HMAC digest at rest, revocation/expiry fields, separate internal route group |
| Stolen lease token | Separate short-lived credential, worker binding, HMAC digest, hard maximum lifetime, row lock on access |
| Duplicate work | `SKIP LOCKED`, active-source unique index, worker advisory lock, source attempt counter |
| Worker abandonment | Expiry reaping, bounded exponential retry, terminal failure after maximum attempts |
| Cross-tenant worker access | Worker context, active-lease RLS, explicit service predicates, tenancy triggers |
| Secret overreach | Immutable manifest declaration, project/environment match, active `RUN_START` lease, short-lived X25519 envelope |
| Secret leakage | No public reveal route, no browser exposure, no audit/log values, mutable plaintext buffer cleared after encryption |
| Artifact substitution | SHA-256 digest, target/lease tenancy trigger, scan status, provenance, successful Build requires passed image metadata |
| Internal API discovery | Internal routes excluded from public OpenAPI; separate authentication contract |
| Premature code execution | Claim payload fixed to `execution_enabled: false`; no Docker, Kubernetes, BuildKit, shell, subprocess, `eval`, or `exec` primitive |

The reference worker client is protocol-only. Production sandboxing, image execution, object-store credentials, network policy, kernel isolation, and runtime attestation remain separate merge gates.

## Phase 1H control mapping

Phase 1H implements the first executable controls for T-11 and T-12: rootless BuildKit, no host Docker socket, no insecure entitlements, approved base images, digest-verified source and artifacts, non-root containerd runtime, all capabilities dropped, no-new-privileges, read-only root filesystem, seccomp/AppArmor, cgroup/time limits, disposable workspaces, and deny-all networking. The control plane itself still contains no container-runtime invocation primitive.

The `RDC_SANDBOX_EXECUTION_ENABLED` switch defaults to false. A second gate requires a strict worker attestation before `execution_enabled` can become true. Phase 1H does not authorize web-egress or browser Agents; those remain blocked until a later egress-proxy/SSRF-control phase.



### T-17 Sandbox activation bypass

- **Scenario:** an operator or compromised configuration enables sandbox
  execution and unintentionally authorizes arbitrary Agents or workers.
- **Components:** API settings, execution claim policy, sandbox worker.
- **Likelihood:** Medium
- **Impact:** Critical
- **Controls:** independent master switch and activation mode, exact immutable
  AgentVersion pin, exact worker-name pin, single concurrency, strict
  attestation, offline-minimal capability profile, no secrets, narrower
  resource ceilings.
- **Tests:** master-switch-only denial, wrong-version denial, wrong-worker
  denial, concurrency denial, capability denial, secret denial, resource
  denial.
- **Residual risk:** Low to Medium.

### T-18 Execution artifact lineage spoofing

- **Scenario:** a compromised or faulty worker uploads an artifact whose digest
  is valid but whose provenance is unrelated to the approved canary source or
  image.
- **Components:** sandbox worker, object storage, execution artifact registry.
- **Likelihood:** Medium
- **Impact:** High
- **Controls:** lease-bound object keys and metadata, server-side SHA-256
  recomputation, immutable activation receipt in lease snapshot, Build
  source-digest binding, Run image-digest binding.
- **Tests:** altered activation, source digest, AgentVersion, Run ID, and image
  digest are rejected.
- **Residual risk:** Low to Medium.
