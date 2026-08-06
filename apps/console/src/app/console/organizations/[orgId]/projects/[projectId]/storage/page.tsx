import { StorageManager } from "@/components/storage-manager";

export default async function Page({
  params,
}: {
  params: Promise<{ projectId: string }>;
}) {
  const { projectId } = await params;
  return <StorageManager projectId={projectId} />;
}
