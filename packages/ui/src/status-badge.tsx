import type { ReactNode } from "react";

const tones = {
  danger: "var(--danger)",
  info: "var(--primary)",
  neutral: "var(--muted-foreground)",
  success: "var(--success)",
  warning: "var(--warning)",
} as const;

interface StatusBadgeProps {
  children: ReactNode;
  tone: keyof typeof tones;
}

export function StatusBadge({ children, tone }: StatusBadgeProps) {
  const color = tones[tone];

  return (
    <span
      style={{
        alignItems: "center",
        background: `color-mix(in srgb, ${color} 14%, transparent)`,
        border: `1px solid ${color}`,
        borderRadius: "999px",
        color,
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
