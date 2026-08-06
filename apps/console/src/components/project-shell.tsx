"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

import { projectNavigation } from "@/lib/navigation";

interface ProjectShellProps {
  children: ReactNode;
  orgId: string;
  projectId: string;
}

export function ProjectShell({ children, orgId, projectId }: ProjectShellProps) {
  const pathname = usePathname();
  const root = `/console/organizations/${orgId}/projects/${projectId}`;

  return (
    <div style={{ minHeight: "100vh" }}>
      <header
        style={{
          alignItems: "center",
          background: "var(--surface)",
          borderBottom: "1px solid var(--border)",
          display: "flex",
          flexWrap: "wrap",
          gap: "1rem",
          justifyContent: "space-between",
          minHeight: 68,
          padding: "0.75rem 1.5rem",
        }}
      >
        <div>
          <strong>Rooz Data Cloud</strong>
          <div style={{ color: "var(--muted-foreground)", fontSize: "0.8rem" }}>
            {orgId} / {projectId}
          </div>
        </div>
        <Link
          href="/console/select-org"
          style={{
            color: "var(--primary)",
            fontSize: "0.875rem",
            fontWeight: 600,
            textDecoration: "none",
          }}
        >
          Switch organization
        </Link>
      </header>

      <div className="shell-body">
        <aside
          aria-label="Project navigation"
          className="project-sidebar"
          style={{
            background: "var(--surface)",
            padding: "1.25rem",
          }}
        >
          <nav aria-label="Primary">
            <ul
              style={{
                display: "grid",
                gap: "0.35rem",
                listStyle: "none",
                margin: 0,
                padding: 0,
              }}
            >
              {projectNavigation.map((item) => {
                const itemHref = `${root}${item.href}`;
                const isActive =
                  pathname === itemHref || pathname.startsWith(`${itemHref}/`);

                if (item.future) {
                  return (
                    <li key={item.href}>
                      <span
                        aria-disabled="true"
                        style={{
                          borderRadius: "0.5rem",
                          color: "var(--muted-foreground)",
                          cursor: "not-allowed",
                          display: "block",
                          minHeight: 44,
                          opacity: 0.68,
                          padding: "0.7rem 0.8rem",
                          userSelect: "none",
                        }}
                      >
                        {item.label}
                        <span style={{ display: "block", fontSize: "0.72rem" }}>
                          Future module
                        </span>
                      </span>
                    </li>
                  );
                }

                return (
                  <li key={item.href}>
                    <Link
                      aria-current={isActive ? "page" : undefined}
                      href={itemHref}
                      style={{
                        background: isActive
                          ? "var(--surface-muted)"
                          : "transparent",
                        borderRadius: "0.5rem",
                        color: isActive
                          ? "var(--primary)"
                          : "var(--foreground)",
                        display: "block",
                        fontWeight: isActive ? 700 : 500,
                        minHeight: 44,
                        padding: "0.7rem 0.8rem",
                        textDecoration: "none",
                      }}
                    >
                      {item.label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </nav>
        </aside>

        <main
          id="main-content"
          tabIndex={-1}
          style={{ minWidth: 0, padding: "2rem" }}
        >
          {children}
        </main>
      </div>
    </div>
  );
}
