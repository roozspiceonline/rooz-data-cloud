# Rooz Data Cloud (RDC) - Frontend Testing Strategy

## 1. Testing Strategy & Toolchain Alignment

```text
           / \
          /   \        E2E Tests (Playwright + Axe-core)
         /  E2E \      - Auth flows, tenant routing, SSE stream reconnection
        /---------\
       / Component \   Component & Accessibility Tests (Vitest + RTL + vitest-axe)
      /             \  - Form schemas, state matrices, accessible primitive behavior
     /---------------\
    /   Unit & Util   \ Unit Tests (Vitest)
   /                   \ - Zod validation schemas, data formatters, URL state logic
  -----------------------
```

### Core Tooling Stack
- **Test Runner**: Vitest
- **DOM Rendering Engine**: `@testing-library/react` & `@testing-library/user-event`
- **Component Accessibility Inspection**: `vitest-axe`
- **Browser E2E Execution**: Playwright
- **E2E Accessibility Scanning**: `@axe-core/playwright`
- **Bundle Analysis**: `@next/bundle-analyzer`

---

## 2. Unit & Schema Testing

Unit tests validate isolated functions, client state transformers, cursor pagination calculations, and Zod schemas.

- Directory Location: `src/__tests__/unit` or `*.test.ts`
- Execution Command: `pnpm test:unit`

```ts
// Example Unit Test: Secret Schema Validation
import { describe, it, expect } from 'vitest';
import { secretCreateSchema } from '@/lib/validations/secret';

describe('secretCreateSchema', () => {
  it('accepts valid uppercase secret key and value', () => {
    const valid = secretCreateSchema.safeParse({ name: 'DATABASE_PASSWORD', value: 'secret_value_123' });
    expect(valid.success).toBe(true);
  });

  it('rejects invalid lowercase secret key names', () => {
    const result = secretCreateSchema.safeParse({ name: 'database_password', value: 'secret_value_123' });
    expect(result.success).toBe(false);
  });
});
```

---

## 3. Component & Accessibility Testing (`vitest-axe`)

Component tests verify rendering, user interaction, form validation errors, and localized component accessibility.

> **Testing Policy**: Automated axe scans catch structural ARIA and contrast issues in test DOMs but **do not replace manual keyboard/screen reader verification**.

```tsx
// Example Component & Axe Test
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, it, expect, vi } from 'vitest';
import { axe, toHaveNoViolations } from 'vitest-axe';
import { SecretForm } from '@/components/secrets/secret-form';

expect.extend(toHaveNoViolations);

describe('SecretForm Component', () => {
  it('should have no detectable accessibility violations', async () => {
    const { container } = render(<SecretForm onSubmit={vi.fn()} />);
    const results = await axe(container);
    expect(results).toHaveNoViolations();
  });

  it('renders validation error when submitting empty fields', async () => {
    render(<SecretForm onSubmit={vi.fn()} />);
    const submitBtn = screen.getByRole('button', { name: /save secret/i });
    
    await userEvent.click(submitBtn);
    expect(await screen.findByText(/secret name is required/i)).toBeInTheDocument();
  });
});
```

---

## 4. End-to-End (E2E) Testing (Playwright)

Playwright runs end-to-end integration flows against live Next.js development server builds.

### Key E2E Test Suites
1. **Explicit Route Isolation**: Accessing `/console/organizations/org-1/projects/proj-1/dashboard` verifies tenant headers and navigation context.
2. **SSE Reconnection Resilience**: Simulates network drops during live log streaming, verifies replay from the last event ID, tolerates duplicate delivery, and checks UI connection-state updates.
3. **Write-Only Secrets Flow**: Verifies created secrets render only as masked placeholders with metadata badges.

```ts
// E2E Accessibility Scan Snippet
import { test, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

test.describe('Project Dashboard Accessibility', () => {
  test('dashboard view satisfies WCAG 2.1 AA rules', async ({ page }) => {
    await page.goto('/console/organizations/org-test/projects/proj-test/dashboard');

    const accessibilityScanResults = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();

    expect(accessibilityScanResults.violations).toEqual([]);
  });
});
```

---

## 5. Bundle Size Guardrails

1. **Provisional Route Bundle Target**: Initial route JavaScript target is **< 150 kB gzipped** until real scaffold measurements establish the final baseline.
2. **CI Enforcement**: A reproducible bundle-report command produces PR artifacts. CI fails if heavy libraries (`monaco-editor`, `@xyflow/react`) leak into initial routing chunks; the numerical threshold becomes blocking after the baseline is approved.

---

## 6. Required contract tests

The frontend test suite MUST include:

- `SESSION_EXPIRED` redirect behavior;
- `AUTH_REQUIRED` invalid-session behavior;
- one-time `AUTH_CSRF_INVALID` recovery;
- preservation of `Idempotency-Key` on a permitted retry;
- `PERMISSION_DENIED` UI refresh;
- standard error and field-error binding;
- opaque cursor history and reset behavior;
- SSE duplicate-event tolerance;
- `run.replay_reset` recovery;
- write-only secret metadata rendering;
- organization-scoped API-key navigation;
- prevention of credential persistence in browser storage.

## 7. Manual release checks

Before a production release:

- keyboard-only navigation through primary workflows;
- VoiceOver or NVDA smoke pass;
- zoom and reflow at 200% and 400%;
- reduced-motion verification;
- light/dark high-contrast review;
- mobile sidebar and table operation;
- live log readability without forced auto-scroll.
