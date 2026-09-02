import type { LucideIcon } from "lucide-react";
import {
  Activity,
  Archive,
  Blocks,
  Bot,
  Box,
  Braces,
  ChartNoAxesCombined,
  CircleGauge,
  Clock3,
  CloudCog,
  Code2,
  Database,
  FileKey2,
  FileSearch2,
  Gauge,
  GitBranch,
  HardDrive,
  KeyRound,
  ListTree,
  LockKeyhole,
  Network,
  RadioTower,
  ReceiptText,
  Route,
  ScrollText,
  Send,
  Settings2,
  ShieldCheck,
  Sparkles,
  SquareActivity,
  TableProperties,
  TerminalSquare,
  Users,
  Webhook,
  Workflow,
} from "lucide-react";

export type NavigationAvailability = "available" | "foundation" | "planned";

export interface ProjectNavigationItem {
  availability: NavigationAvailability;
  description: string;
  href?: string;
  icon: LucideIcon;
  keywords?: readonly string[];
  label: string;
  shortcut?: string;
}

export interface ProjectNavigationSection {
  items: readonly ProjectNavigationItem[];
  label: string;
}

export const projectNavigationSections: readonly ProjectNavigationSection[] = [
  {
    label: "Overview",
    items: [
      {
        availability: "available",
        description: "Project mission control and platform foundations.",
        href: "/dashboard",
        icon: Gauge,
        keywords: ["home", "mission control"],
        label: "Dashboard",
        shortcut: "G D",
      },
      {
        availability: "planned",
        description: "Project-wide operational and security activity.",
        icon: Activity,
        label: "Activity",
      },
    ],
  },
  {
    label: "Build",
    items: [
      {
        availability: "available",
        description: "Agent registry, immutable versions, and source lineage.",
        href: "/agents",
        icon: Bot,
        keywords: ["versions", "source"],
        label: "Agents",
        shortcut: "G A",
      },
      {
        availability: "available",
        description: "Build requests and immutable artifact lineage.",
        href: "/builds",
        icon: Box,
        label: "Builds",
      },
    ],
  },
  {
    label: "Execute",
    items: [
      {
        availability: "available",
        description: "Run lifecycle, live events, and cancellation.",
        href: "/runs",
        icon: CircleGauge,
        label: "Runs",
        shortcut: "G R",
      },
      {
        availability: "planned",
        description: "One-time and fixed-interval Run schedules.",
        icon: Clock3,
        label: "Scheduler",
      },
      {
        availability: "planned",
        description: "Tenant queues, requests, claims, and transitions.",
        icon: ListTree,
        keywords: ["request queues"],
        label: "Request Queues",
        shortcut: "G Q",
      },
      {
        availability: "available",
        description: "Lease and artifact visibility for isolated execution.",
        href: "/execution",
        icon: Network,
        keywords: ["workers", "leases", "artifacts"],
        label: "Execution Plane",
      },
      {
        availability: "planned",
        description: "Worker capacity and heartbeat visibility.",
        icon: CloudCog,
        label: "Workers",
      },
    ],
  },
  {
    label: "Data",
    items: [
      {
        availability: "foundation",
        description: "Dataset metadata, items, lineage, and bounded exports.",
        href: "/datasets",
        icon: TableProperties,
        label: "Datasets",
      },
      {
        availability: "planned",
        description: "Versioned Key-Value records and mutation lineage.",
        icon: Database,
        keywords: ["kv", "key value"],
        label: "KV Stores",
      },
      {
        availability: "available",
        description: "Verified objects and short-lived download grants.",
        href: "/storage",
        icon: HardDrive,
        label: "Storage",
      },
    ],
  },
  {
    label: "Network",
    items: [
      {
        availability: "planned",
        description: "Exact-host egress policy and revision management.",
        icon: ShieldCheck,
        label: "Egress Policies",
      },
      {
        availability: "planned",
        description: "Provider-neutral route health and canary evidence.",
        icon: Route,
        keywords: ["proxy health", "canary"],
        label: "Route Health",
      },
    ],
  },
  {
    label: "Automate",
    items: [
      {
        availability: "planned",
        description: "Immutable project lifecycle events.",
        icon: RadioTower,
        label: "Events",
      },
      {
        availability: "planned",
        description: "Destinations, delivery history, and bounded replay.",
        icon: Webhook,
        label: "Webhooks",
      },
      {
        availability: "planned",
        description: "Workflow orchestration is not available in RDC v1 yet.",
        icon: Workflow,
        label: "Pipelines",
      },
    ],
  },
  {
    label: "Observe",
    items: [
      {
        availability: "planned",
        description: "Safe project-scoped diagnostics snapshots.",
        icon: FileSearch2,
        label: "Diagnostics",
      },
      {
        availability: "planned",
        description: "Low-cardinality runtime and recovery signals.",
        icon: ChartNoAxesCombined,
        label: "Metrics",
      },
      {
        availability: "planned",
        description: "Structured correlated logs when a public API is available.",
        icon: ScrollText,
        label: "Logs",
      },
    ],
  },
  {
    label: "Usage",
    items: [
      {
        availability: "planned",
        description: "Current project consumption and enforced limits.",
        icon: SquareActivity,
        label: "Usage",
      },
      {
        availability: "planned",
        description: "Pricing and cost data are not available yet.",
        icon: ReceiptText,
        label: "Costs",
      },
    ],
  },
  {
    label: "Security",
    items: [
      {
        availability: "available",
        description: "Write-only project secret metadata and rotation.",
        href: "/secrets",
        icon: LockKeyhole,
        label: "Secrets",
      },
      {
        availability: "foundation",
        description: "Immutable security activity; Console reader pending.",
        href: "/audit",
        icon: FileKey2,
        label: "Audit",
      },
      {
        availability: "planned",
        description: "Organization membership and role management.",
        icon: Users,
        label: "Members",
      },
      {
        availability: "planned",
        description: "Scoped API-key lifecycle and one-time creation values.",
        icon: KeyRound,
        label: "API Keys",
      },
    ],
  },
  {
    label: "Developer",
    items: [
      {
        availability: "planned",
        description: "Contract-backed endpoint catalog and examples.",
        icon: Braces,
        label: "API Explorer",
      },
      {
        availability: "planned",
        description: "Typed SDK onboarding when the SDK is released.",
        icon: Code2,
        label: "SDK",
      },
      {
        availability: "planned",
        description: "Supported command-line workflows when the CLI is released.",
        icon: TerminalSquare,
        label: "CLI",
      },
      {
        availability: "planned",
        description: "Product and operational documentation entry point.",
        icon: Archive,
        label: "Documentation",
      },
    ],
  },
  {
    label: "Project",
    items: [
      {
        availability: "foundation",
        description: "Project controls backed by authoritative permissions.",
        href: "/settings",
        icon: Settings2,
        label: "Settings",
      },
      {
        availability: "planned",
        description: "External integrations are not available yet.",
        icon: Blocks,
        label: "Integrations",
      },
      {
        availability: "planned",
        description: "Outbound notification rules are not available yet.",
        icon: Send,
        label: "Notifications",
      },
      {
        availability: "planned",
        description: "AI operational assistance has no backend capability.",
        icon: Sparkles,
        label: "RDC Copilot",
      },
      {
        availability: "planned",
        description: "Source connectors are not available in RDC v1 yet.",
        icon: GitBranch,
        label: "Connectors",
      },
    ],
  },
] as const;

export const projectNavigation = projectNavigationSections.flatMap((section) => section.items);

export function matchProjectNavigationItem(pathname: string) {
  return projectNavigation
    .filter((item) => item.href)
    .sort((left, right) => (right.href?.length ?? 0) - (left.href?.length ?? 0))
    .find((item) => pathname.endsWith(item.href ?? "") || pathname.includes(`${item.href ?? ""}/`));
}
