# Rooz Data Cloud (RDC) - Design System Specification

## 1. Design Token Foundations

The RDC Design System is constructed on **Tailwind CSS**, **shadcn/ui** accessible primitives, and CSS custom properties for dual light/dark execution.

### Color Tokens (CSS Variables)

Location: `packages/ui/src/styles/globals.css`

```css
@layer base {
  :root {
    --background: 0 0% 100%;
    --foreground: 222.2 84% 4.9%;

    --card: 0 0% 100%;
    --card-foreground: 222.2 84% 4.9%;

    --popover: 0 0% 100%;
    --popover-foreground: 222.2 84% 4.9%;

    --primary: 221.2 83.2% 53.3%;
    --primary-foreground: 210 40% 98%;

    --secondary: 210 40% 96.1%;
    --secondary-foreground: 222.2 47.4% 11.2%;

    --muted: 210 40% 96.1%;
    --muted-foreground: 215.4 16.3% 46.9%;

    --accent: 210 40% 96.1%;
    --accent-foreground: 222.2 47.4% 11.2%;

    --destructive: 0 84.2% 60.2%;
    --destructive-foreground: 210 40% 98%;

    --border: 214.3 31.8% 91.4%;
    --input: 214.3 31.8% 91.4%;
    --ring: 221.2 83.2% 53.3%;

    --radius: 0.5rem;

    /* Elevation / Shadows */
    --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.05);
    --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1);
    --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);
  }

  .dark {
    --background: 224 71% 4%;
    --foreground: 213 31% 91%;

    --card: 224 71% 4%;
    --card-foreground: 213 31% 91%;

    --popover: 224 71% 4%;
    --popover-foreground: 213 31% 91%;

    --primary: 217.2 91.2% 59.8%;
    --primary-foreground: 222.2 47.4% 11.2%;

    --secondary: 215 27.9% 16.9%;
    --secondary-foreground: 210 40% 98%;

    --muted: 215 27.9% 16.9%;
    --muted-foreground: 217.9 10.6% 64.9%;

    --accent: 215 27.9% 16.9%;
    --accent-foreground: 210 40% 98%;

    --destructive: 0 62.8% 30.6%;
    --destructive-foreground: 210 40% 98%;

    --border: 215 27.9% 16.9%;
    --input: 215 27.9% 16.9%;
    --ring: 216 100% 65%;

    --shadow-sm: 0 1px 2px 0 rgb(0 0 0 / 0.3);
    --shadow-md: 0 4px 6px -1px rgb(0 0 0 / 0.4);
    --shadow-lg: 0 10px 15px -3px rgb(0 0 0 / 0.5);
  }
}
```

---

## 2. Dark / Light Mode Strategy

Theme switching is managed via `next-themes` wrapped in `@rdc/ui/theme-provider`.
- **Default Theme**: System preference with fallback to dark mode.
- **Hydration Mismatch Mitigation**: Theme context consumers render a neutral skeleton layout or defer mounting rendering until client-side hydration completes (`mounted` flag pattern).

---

## 3. Radius, Elevation, Motion, & Reduced Motion

### Radius Scale
- `rounded-sm`: `calc(var(--radius) - 4px)` (2px)
- `rounded-md`: `calc(var(--radius) - 2px)` (6px)
- `rounded-lg`: `var(--radius)` (8px)
- `rounded-full`: `9999px`

### Motion & Spring Scale
- **Transitions**: Animate only the required properties; avoid broad `transition-all` on complex components. Standard duration target: 150–200ms.
- **Modals / Drawers**: Scale-fade spring `transition-transform duration-150 ease-out`.
- **Reduced Motion Compliance**:
  ```css
  @media (prefers-reduced-motion: reduce) {
    *, ::before, ::after {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
      scroll-behavior: auto !important;
    }
  }
  ```

---

## 4. Status Taxonomy & Visual Representation

Statuses must **never** be communicated through color alone. Every status badge pairs an explicit text label with a distinct icon shape:

| Status Code | Label | Color Token | Icon Primitive |
| :--- | :--- | :--- | :--- |
| `active` / `succeeded` | Active / Succeeded | Green (`bg-emerald-500/10 text-emerald-500`) | `CheckCircle2Icon` |
| `pending` / `queued` | Pending / Queued | Amber (`bg-amber-500/10 text-amber-500`) | `ClockIcon` |
| `running` | Running | Blue (`bg-blue-500/10 text-blue-500`) | `Loader2Icon` (Spinning) |
| `failed` | Failed | Red (`bg-rose-500/10 text-rose-500`) | `XCircleIcon` |
| `cancelled` | Cancelled | Gray (`bg-zinc-500/10 text-zinc-500`) | `SlashIcon` |

---

## 5. Destructive Actions UX Standard

Destructive actions (e.g., deleting a project, revoking API keys, resetting storage) require structured confirmation patterns based on impact severity:

1. **Standard Destructive**: Confirmation Dialog with red action button (`variant="destructive"`), explicit explanation of consequence, and mandatory focus on the "Cancel" trigger upon open.
2. **High-Impact Destructive**: Requires user to type the exact target entity name into a verification input before enabling the deletion submit button.

```tsx
// High-Impact Destructive Confirmation Component Example
import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from '@rdc/ui/dialog';
import { Button } from '@rdc/ui/button';
import { Input } from '@rdc/ui/input';

interface DestructiveConfirmModalProps {
  isOpen: boolean;
  resourceName: string;
  onConfirm: () => void;
  onClose: () => void;
}

export function DestructiveConfirmModal({ isOpen, resourceName, onConfirm, onClose }: DestructiveConfirmModalProps) {
  const [inputValue, setInputValue] = useState('');
  const isMatch = inputValue === resourceName;

  return (
    <Dialog open={isOpen} onOpenChange={onClose}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-destructive">Delete Resource</DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          This action cannot be undone. Type <strong className="text-foreground">{resourceName}</strong> to confirm.
        </p>
        <Input
          value={inputValue}
          onChange={(e) => setInputValue(e.target.value)}
          placeholder={resourceName}
          aria-label="Confirm resource name deletion"
        />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="destructive" disabled={!isMatch} onClick={onConfirm}>
            Delete Permanently
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
```

---

## 6. Code & Log Views Architecture

- **Log Viewer Panel**: Monospace font (`font-mono`), line numbers, automated timestamp formatting, and log-level highlighting (`INFO`: slate, `WARN`: amber, `ERROR`: rose).
- **Auto-Scroll Engine**: Attached to bottom by default. If manual upward scroll is detected via scroll container delta, auto-scroll detaches and renders a floating button: `"Scroll to bottom ↓"`.

---

## 7. Responsive Behavior & Breakpoints

- Breakpoints match Tailwind defaults (`sm: 640px`, `md: 768px`, `lg: 1024px`, `xl: 1280px`, `2xl: 1536px`).
- Sidebar: Collapses into an accessible sheet slide-out navigation drawer on screens `< 1024px` (`lg`).
- Data Tables: Horizontal scrolling wrapper (`overflow-x-auto`) with fixed action columns on small viewports.

---

## 8. Integration decisions

- The exact Tailwind and shadcn/ui versions are pinned during the monorepo scaffold task, not in this Phase 0 document.
- Color-token claims require a dedicated calculated contrast audit. Component tests alone are not proof of token contrast.
- Theme selection is a product preference; system theme is the default until Bablu approves a different default.
- The initial route bundle target of 150 kB gzipped is a provisional engineering budget and becomes merge-blocking only after a reproducible measurement command is committed.
- Code and log views MUST sanitize untrusted content and MUST NOT render logs through raw HTML.
