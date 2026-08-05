# Rooz Data Cloud (RDC) - Accessibility Standard

## 1. Compliance Mandate & Target Standard

All web user interfaces in `apps/console` and shared UI components in `@rdc/ui` **MUST conform to Web Content Accessibility Guidelines (WCAG) 2.1 Level AA**.

---

## 2. Color Contrast Target & Verification Rules

- **Normal Text (< 18pt / 24px regular)**: Target minimum contrast ratio **4.5:1** against adjacent background tokens.
- **Large Text (>= 18pt / 24px or >= 14pt bold)**: Target minimum contrast ratio **3.0:1**.
- **UI Components & Graphical Elements**: Target minimum contrast ratio **3.0:1**.

> **Verification Rule**: Contrast ratios must be verified through calculated token contrast audits and automated CI axe testing. Claims of contrast compliance are valid only when backed by continuous test execution outputs.

---

## 3. Landmark Architecture & Skip Navigation

Every application layout must expose clear semantic HTML5 landmarks and a skip link:

```tsx
// Root Application Shell Layout Landmark Structure
export function ApplicationShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Accessible Skip Link */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:absolute focus:z-50 focus:p-4 focus:bg-primary focus:text-primary-foreground focus:rounded-md"
      >
        Skip to main content
      </a>

      <header role="banner" className="border-b">
        {/* Global Navigation Header */}
      </header>

      <div className="flex flex-1">
        <aside role="complementary" aria-label="Sidebar Navigation" className="w-64 border-r">
          {/* Sidebar */}
        </aside>

        <main id="main-content" tabIndex={-1} role="main" className="flex-1 p-6 focus:outline-none">
          {children}
        </main>
      </div>
    </div>
  );
}
```

---

## 4. Route-Transition Focus Management

During Next.js client-side route transitions, screen reader focus must be explicitly managed to prevent focus loss:
1. Upon page route completion, focus is directed programmatically to the main `#main-content` heading (`<h1>`).
2. Heading elements receive `tabIndex={-1}` to accept programmatic focus without injecting extra tab stops into standard keyboard sequence navigation.

---

## 5. Keyboard Navigation & Overlay Focus Trapping

1. **Focus Rings**:
   - Standard focus ring class: `focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2 focus-visible:outline-none`.
   - Never remove outline styling (`outline-none`) without providing an active `focus-visible` replacement.
2. **Dialogs & Sheet Modals**:
   - Overlay traps focus within container when active (`Radix UI FocusScope`).
   - On exit/close, keyboard focus **must return automatically** to the trigger element that opened the dialog.
3. **Complex Visualizers Escapes**:
   - Monaco Editor and React Flow canvases must expose explicit key bindings (`Esc`) allowing keyboard users to exit visualizer focus traps and resume document tab order flow.

---

## 6. Dynamic ARIA Live Regions (SSE Stream Events)

Dynamic real-time event updates (e.g., SSE run logs) utilize accessible ARIA live containers:
- **Standard Stream Logs**: `aria-live="polite"` `aria-atomic="false"`.
- **Critical Execution Failures**: Trigger assertive toast alerts using `role="alert"` `aria-live="assertive"`.

---

## 7. Form Accessibility Standards

1. **Explicit Labeling**: Every input, select, and textarea element must pair with an explicit `<label htmlFor="...">` or `aria-labelledby`.
2. **Validation Error Binding**:
   - Inputs with validation errors append `aria-invalid="true"`.
   - Error messages render with unique IDs linked to input via `aria-describedby="[field-id]-error"`.

---

## 8. Accessible Testing Protocol

Compliance requires dual automated and manual verification:
- **Automated Checks**: Vitest component-level axe tests (`vitest-axe`) and Playwright E2E accessibility audits (`@axe-core/playwright`).
- **MANDATORY Manual Verification**:
  - Full keyboard-only workflow pass (tab, shift-tab, enter, space, arrows, escape).
  - Screen reader navigation check using macOS VoiceOver or NVDA.
  - **Automated axe scans DO NOT replace manual verification**; automated tools detect only a subset of accessibility barriers.

---

## 9. Integration decisions

- Browser-based accessibility scans validate rendered styles; jsdom component scans do not prove actual color contrast.
- Token contrast MUST also be checked by a deterministic contrast-audit script.
- Native semantic elements are preferred over redundant ARIA roles.
- Rapid SSE log lines are not individually announced. Live regions announce connection changes, warnings, failures, and terminal Run state.
- Reserved visual canvas features require an equivalent keyboard-accessible configuration path before production release.
