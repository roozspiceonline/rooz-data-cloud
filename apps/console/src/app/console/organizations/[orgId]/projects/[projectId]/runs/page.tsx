import { RunControlPlane } from "@/components/run-control-plane";

export default async function Page({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  return <RunControlPlane projectId={projectId} />;
}
