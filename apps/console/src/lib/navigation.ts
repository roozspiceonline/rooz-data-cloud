export interface ProjectNavigationItem {
  href: string;
  label: string;
  future?: boolean;
}

export const projectNavigation: readonly ProjectNavigationItem[] = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/agents", label: "Agents" },
  { href: "/builds", label: "Builds" },
  { href: "/runs", label: "Runs" },
  { href: "/execution", label: "Execution plane" },
  { href: "/secrets", label: "Secrets" },
  { href: "/audit", label: "Audit" },
  { href: "/settings", label: "Settings" },
  { href: "/pipelines", label: "Pipelines", future: true },
  { href: "/datasets", label: "Datasets", future: true },
  { href: "/storage", label: "Storage" },
  { href: "/connectors", label: "Connectors", future: true }
] as const;
