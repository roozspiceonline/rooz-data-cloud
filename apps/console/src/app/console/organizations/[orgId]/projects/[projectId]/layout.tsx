import type { ReactNode } from "react";
import { ProjectShell } from "@/components/project-shell";

export default async function ProjectLayout({ children, params }: { children: ReactNode; params: Promise<{ orgId: string; projectId: string }> }) {
  const { orgId, projectId } = await params;
  return <ProjectShell orgId={orgId} projectId={projectId}>{children}</ProjectShell>;
}
