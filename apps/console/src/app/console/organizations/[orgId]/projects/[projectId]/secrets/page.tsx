import { ProjectSecretManager } from "@/components/project-secret-manager";

export default async function Page({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  return <ProjectSecretManager projectId={projectId} />;
}
