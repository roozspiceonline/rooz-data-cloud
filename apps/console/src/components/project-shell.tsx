import Link from "next/link";
import type { ReactNode } from "react";
import { projectNavigation } from "@/lib/navigation";

export function ProjectShell({ children, orgId, projectId }: { children: ReactNode; orgId: string; projectId: string }) {
  const root = `/console/organizations/${orgId}/projects/${projectId}`;
  return (
    <div style={{ minHeight: "100vh" }}>
      <header style={{ alignItems: "center", background: "var(--surface)", borderBottom: "1px solid var(--border)", display: "flex", justifyContent: "space-between", minHeight: 68, padding: "0 1.5rem" }}>
        <div><strong>Rooz Data Cloud</strong><div style={{ color: "var(--muted-foreground)", fontSize: "0.8rem" }}>{orgId} / {projectId}</div></div>
        <Link href="/console/select-org">Switch organization</Link>
      </header>
      <div style={{ display: "grid", gridTemplateColumns: "minmax(13rem, 16rem) minmax(0, 1fr)", minHeight: "calc(100vh - 68px)" }}>
        <aside aria-label="Project navigation" style={{ background: "var(--surface)", borderRight: "1px solid var(--border)", padding: "1.25rem" }}>
          <nav aria-label="Primary">
            <ul style={{ display: "grid", gap: "0.35rem", listStyle: "none", margin: 0, padding: 0 }}>
              {projectNavigation.map((item) => (
                <li key={item.href}>
                  <Link href={`${root}${item.href}`} style={{ borderRadius: "0.5rem", display: "block", minHeight: 44, padding: "0.7rem 0.8rem", textDecoration: "none" }}>
                    {item.label}
                    {item.future ? <span style={{ color: "var(--muted-foreground)", display: "block", fontSize: "0.72rem" }}>Future module</span> : null}
                  </Link>
                </li>
              ))}
            </ul>
          </nav>
        </aside>
        <main id="main-content" tabIndex={-1} style={{ minWidth: 0, padding: "2rem" }}>{children}</main>
      </div>
    </div>
  );
}
