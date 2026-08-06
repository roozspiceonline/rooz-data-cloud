import { AgentDetail } from "@/components/agent-detail";

export default async function Page({
  params,
}: {
  params: Promise<{ agentId: string; orgId: string; projectId: string }>;
}) {
  const { agentId, orgId, projectId } = await params;
  return (
    <AgentDetail
      agentId={agentId}
      organizationId={orgId}
      projectId={projectId}
    />
  );
}
