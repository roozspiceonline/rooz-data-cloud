import { AgentVersionDetail } from "@/components/agent-version-detail";

export default async function Page({
  params,
}: {
  params: Promise<{
    agentId: string;
    orgId: string;
    projectId: string;
    versionId: string;
  }>;
}) {
  const { agentId, orgId, projectId, versionId } = await params;
  return (
    <AgentVersionDetail
      agentId={agentId}
      organizationId={orgId}
      projectId={projectId}
      versionId={versionId}
    />
  );
}
