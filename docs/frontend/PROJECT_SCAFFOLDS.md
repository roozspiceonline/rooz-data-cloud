# Rooz Data Cloud (RDC) — Frontend Project Scaffolds

**Document ID:** RDC-FE-SCAFFOLD-001  
**Phase:** Phase 0 proposal  
**Status:** Reconciled

## 1. `apps/console`

```text
apps/console/
├── README.md
├── next.config.mjs
├── package.json
├── postcss.config.mjs
├── tailwind.config.ts
├── tsconfig.json
├── public/
│   ├── favicon.ico
│   └── images/
└── src/
    ├── app/
    │   ├── layout.tsx
    │   ├── page.tsx                              # Redirect authenticated users to /console
    │   ├── global-error.tsx
    │   ├── not-found.tsx
    │   ├── (auth)/
    │   │   ├── login/page.tsx                   # /login
    │   │   ├── register/page.tsx
    │   │   ├── forgot-password/page.tsx
    │   │   └── reset-password/page.tsx
    │   └── console/
    │       ├── page.tsx                         # Resolve org or redirect to selector
    │       ├── select-organization/page.tsx
    │       └── organizations/
    │           └── [orgId]/
    │               ├── layout.tsx
    │               ├── page.tsx                 # Redirect to /projects
    │               ├── projects/
    │               │   ├── page.tsx             # Project list/create
    │               │   └── [projectId]/
    │               │       ├── layout.tsx
    │               │       ├── page.tsx         # Redirect to /dashboard
    │               │       ├── dashboard/page.tsx
    │               │       ├── agents/
    │               │       │   ├── page.tsx
    │               │       │   └── [agentId]/
    │               │       │       ├── page.tsx
    │               │       │       └── versions/[versionId]/page.tsx
    │               │       ├── builds/
    │               │       │   ├── page.tsx
    │               │       │   └── [buildId]/page.tsx
    │               │       ├── runs/
    │               │       │   ├── page.tsx
    │               │       │   └── [runId]/page.tsx
    │               │       ├── secrets/page.tsx
    │               │       ├── audit/page.tsx
    │               │       ├── settings/page.tsx
    │               │       ├── pipelines/page.tsx       # future-disabled shell
    │               │       ├── datasets/page.tsx        # future-disabled shell
    │               │       ├── storage/page.tsx         # future-disabled shell
    │               │       └── connectors/page.tsx      # future-disabled shell
    │               ├── members/page.tsx
    │               ├── api-keys/page.tsx                # Organization-scoped
    │               ├── audit/page.tsx
    │               └── settings/page.tsx
    ├── components/
    │   ├── auth/
    │   ├── layout/
    │   ├── agents/
    │   ├── builds/
    │   ├── runs/
    │   ├── logs/
    │   ├── secrets/
    │   └── states/
    ├── hooks/
    │   ├── use-run-events-stream.ts
    │   ├── use-cursor-pagination.ts
    │   ├── use-csrf-token.ts
    │   ├── use-organization-id.ts
    │   └── use-project-id.ts
    ├── lib/
    │   ├── api-client.ts
    │   ├── api-errors.ts
    │   ├── query-client.ts
    │   ├── routes.ts
    │   └── validations/
    ├── providers/
    │   ├── query-provider.tsx
    │   └── theme-provider.tsx
    ├── styles/
    │   └── globals.css
    └── test/
        ├── unit/
        ├── component/
        ├── accessibility/
        └── e2e/
```

## 2. `packages/ui`

```text
packages/ui/
├── README.md
├── package.json
├── postcss.config.mjs
├── tailwind.config.ts
├── tsconfig.json
└── src/
    ├── index.ts
    ├── components/
    │   ├── ui/
    │   │   ├── alert.tsx
    │   │   ├── badge.tsx
    │   │   ├── button.tsx
    │   │   ├── card.tsx
    │   │   ├── dialog.tsx
    │   │   ├── dropdown-menu.tsx
    │   │   ├── form.tsx
    │   │   ├── input.tsx
    │   │   ├── label.tsx
    │   │   ├── select.tsx
    │   │   ├── sheet.tsx
    │   │   ├── skeleton.tsx
    │   │   ├── table.tsx
    │   │   ├── data-table.tsx
    │   │   ├── toast.tsx
    │   │   ├── toaster.tsx
    │   │   ├── tooltip.tsx
    │   │   └── visually-hidden.tsx
    │   └── state/
    │       ├── empty-state.tsx
    │       ├── error-state.tsx
    │       ├── loading-state.tsx
    │       └── permission-state.tsx
    ├── hooks/
    │   ├── use-toast.ts
    │   └── use-media-query.ts
    ├── lib/
    │   └── utils.ts
    └── styles/
        └── globals.css
```

## 3. Scaffold constraints

- Phase 0 creates documentation and an empty scaffold only.
- Future-disabled routes do not fetch data.
- API-key screens are organization-scoped.
- Login remains `/login`; project routes remain under the approved `/console/organizations/[orgId]/projects/[projectId]` root.
- Monaco Editor and React Flow are not dependencies of the initial shell bundle.
- Shared UI primitives are presentational and do not contain tenant authorization logic.
