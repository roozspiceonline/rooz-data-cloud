import { AgentRegistry } from "@/components/agent-registry";

export default async function Page({
  params,
}: {
  params: Promise<{ orgId: string; projectId: string }>;
}) {
  const { orgId, projectId } = await params;
  return <AgentRegistry organizationId={orgId} projectId={projectId} />;
}
