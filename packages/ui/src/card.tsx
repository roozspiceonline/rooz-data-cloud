import type { CSSProperties, ReactNode } from "react";

export function Card({ children, style }: { children: ReactNode; style?: CSSProperties }) {
  return (
    <section
      style={{
        background: "var(--surface-raised, var(--surface))",
        border: "1px solid var(--border-subtle, var(--border))",
        borderRadius: "var(--radius)",
        boxShadow: "var(--shadow-sm, 0 1px 2px rgb(15 23 42 / 0.08))",
        padding: "var(--space-5, 1.25rem)",
        ...style,
      }}
    >
      {children}
    </section>
  );
}
