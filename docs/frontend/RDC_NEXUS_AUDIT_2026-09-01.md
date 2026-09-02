# RDC NEXUS Console audit and implementation plan

Date: 2026-09-01

Scope: Console information architecture and UI foundation

Tracking: GitHub issue #124 (UI-1A); usage visibility remains tracked by #123

## Evidence and limitations

This audit combines direct source inspection, Console route contracts, the running API's OpenAPI surface, existing tests, and visual captures of the current pre-auth and organization-loading states at 1440 × 900 and 430 × 900. An authenticated workspace was not available without introducing credentials or fabricated application state, so authenticated visual findings are source-backed and must be rechecked against a real tenant in staging.

## Current capability matrix

| Domain                         | Backend capability                                         | Console state before UI-1A                       | UI-1A treatment                                                          |
| ------------------------------ | ---------------------------------------------------------- | ------------------------------------------------ | ------------------------------------------------------------------------ |
| Authentication                 | Session, registration, login, logout                       | Functional login and cookie-based session        | Refined pre-auth presentation; security statement retained               |
| Organizations and projects     | Organization, project, membership, API-key APIs            | Organization selection and first-project routing | Project context exposed in shell; unsupported management remains planned |
| Agents and versions            | CRUD, immutable versions, source upload                    | Functional                                       | Operational navigation                                                   |
| Builds                         | Build requests and artifact lineage                        | Functional                                       | Operational navigation                                                   |
| Runs                           | Lifecycle, SSE events, cancellation                        | Functional                                       | Operational navigation                                                   |
| Execution                      | Leases and artifacts; worker APIs are internal             | Functional lease/artifact view                   | Execution Plane is operational; Workers remains planned                  |
| Schedules                      | Schedule APIs                                              | No Console route                                 | Planned, disabled                                                        |
| Datasets                       | Dataset and item APIs                                      | Foundation placeholder                           | Foundation route, explicitly labeled                                     |
| KV stores                      | Store and record APIs                                      | No Console route                                 | Planned, disabled                                                        |
| Queues                         | Queue/request APIs and internal claim capability           | No Console route                                 | Planned, disabled                                                        |
| Storage                        | Object metadata and short-lived downloads                  | Functional                                       | Operational navigation                                                   |
| Egress                         | Policies, health, canaries                                 | No Console route                                 | Planned, disabled                                                        |
| Events and webhooks            | Events, destinations, deliveries, replay                   | No Console route                                 | Planned, disabled                                                        |
| Diagnostics                    | Project diagnostics plus internal runtime/recovery metrics | No Console route                                 | Planned; no internal metric surface exposed                              |
| Usage and costs                | Resource-specific quotas only; no canonical aggregate      | No Console route                                 | Planned; no fabricated usage or pricing                                  |
| Secrets                        | Write-only value lifecycle and metadata                    | Functional                                       | Operational navigation                                                   |
| Audit                          | Immutable records exist; reader is incomplete              | Placeholder                                      | Foundation route, explicitly labeled                                     |
| Settings                       | Partial project controls                                   | Placeholder                                      | Foundation route, explicitly labeled                                     |
| Pipelines, connectors, Copilot | No production capability                                   | Placeholders for pipelines/connectors            | Planned, disabled; no route or fake interaction                          |

## Information architecture

The project workspace is organized around operator intent:

1. Overview
2. Build
3. Execute
4. Data
5. Network
6. Automate
7. Observe
8. Usage
9. Security
10. Developer
11. Project

The shell preserves organization and project scope in every authenticated route. Existing destinations are links. Foundation routes are links with an explicit status. Planned capabilities are discoverable descriptions without hrefs or enabled actions.

## UI system

UI-1A introduces dark-first semantic tokens with a system light theme:

- Canvas, surface, raised, overlay, muted, and three border levels.
- Primary, secondary, muted, and disabled text.
- Accent, focus, information, success, warning, and danger.
- Queued, running, succeeded, failed, cancelled, retrying, paused, unhealthy, disabled, and degraded states.
- Compact radii, spacing, elevation, typography, tabular numerics, and reduced-motion behavior.

The reusable shell provides desktop collapse, a mobile drawer, active-route context, responsive breadcrumbs, and a Cmd/Ctrl+K navigation palette. Lucide is the sole added UI dependency because a consistent operational icon vocabulary improves dense navigation scanning without adding runtime services or application state.

## Security invariants

- Session credentials remain in server-issued HttpOnly cookies.
- No browser credential storage was added.
- Tenant scope remains derived from the existing organization/project route hierarchy.
- Planned capabilities have no href and cannot invoke backend behavior.
- No secret values, internal worker routes, runtime metrics, or privileged diagnostics are surfaced.
- API error and authorization behavior remains authoritative; the shell does not infer permissions.

## Test strategy

UI-1A requires:

- Source contract tests for route truthfulness, planned states, responsive behavior, keyboard access, and token coverage.
- TypeScript validation for the Console and shared UI package.
- A production Console build.
- Repository verifiers and formatting checks.
- Same-viewport before/after browser captures for pre-auth desktop and mobile.
- Authenticated shell, keyboard-only, screen-reader, and real tenant-role acceptance checks in staging.

## Phased delivery

1. **UI-1A — NEXUS shell foundation:** tokens, grouped navigation, responsive shell, breadcrumbs, command palette, and pre-auth alignment.
2. **UI-1B — reusable Console primitives:** page header, tabs, data table, filters, pagination, empty/loading/error states, confirmation patterns.
3. **UI-2 — existing workflow migration:** Agents, Builds, Runs, Execution, Secrets, and Storage onto shared primitives.
4. **UI-3 — backend-backed missing modules:** Schedules, Datasets, KV, Queues, Egress, Events/Webhooks, Diagnostics, Memberships, and API keys.
5. **UI-4 — usage visibility:** implement #123 from authoritative quota/counter contracts.
6. **UI-5 — operational hardening:** role-based staging acceptance, accessibility audit, browser matrix, performance budgets, and production observability.

Each phase must remain independently reviewable and must not manufacture unsupported endpoint behavior or mutate merged migrations.
