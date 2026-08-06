import { ExecutionPlaneOverview } from "@/components/execution-plane-overview";

export default async function Page({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  return <ExecutionPlaneOverview projectId={projectId} />;
}
