import { BuildControlPlane } from "@/components/build-control-plane";

export default async function Page({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  return <BuildControlPlane projectId={projectId} />;
}
