import type { CSSProperties, ReactNode } from "react";

export function Card({ children, style }: { children: ReactNode; style?: CSSProperties }) {
  return (
    <section style={{
      background: "var(--surface)",
      border: "1px solid var(--border)",
      borderRadius: "var(--radius)",
      boxShadow: "0 12px 28px rgb(15 23 42 / 0.06)",
      padding: "1.25rem",
      ...style,
    }}>
      {children}
    </section>
  );
}
