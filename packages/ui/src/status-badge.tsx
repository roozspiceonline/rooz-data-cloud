import type { ReactNode } from "react";

const tones = {
  danger: "var(--danger)",
  info: "var(--info, var(--primary))",
  neutral: "var(--muted-foreground)",
  success: "var(--success)",
  warning: "var(--warning)",
} as const;

export function StatusBadge({ children, tone }: { children: ReactNode; tone: keyof typeof tones }) {
  return (
    <span
      style={{
        alignItems: "center",
        background: "color-mix(in srgb, currentColor 8%, transparent)",
        border: `1px solid ${tones[tone]}`,
        borderRadius: "999px",
        color: tones[tone],
        display: "inline-flex",
        fontSize: "0.78rem",
        fontWeight: 700,
        gap: "0.35rem",
        lineHeight: 1,
        minHeight: 28,
        padding: "0.35rem 0.65rem",
      }}
    >
      <span aria-hidden="true">●</span>
      {children}
    </span>
  );
}
