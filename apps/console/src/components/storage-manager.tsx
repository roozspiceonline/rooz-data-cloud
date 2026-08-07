"use client";

import type { StorageObjectSummary } from "@rdc/shared-types";
import { Card, StatusBadge } from "@rdc/ui";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

export function StorageManager({ projectId }: { projectId: string }) {
  const router = useRouter();
  const [objects, setObjects] = useState<ReadonlyArray<StorageObjectSummary>>([]);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        await rdcApi.session();
        const result = await rdcApi.projectStorageObjects(projectId);
        if (active) setObjects(result.data);
      } catch (error) {
        if (typeof error === "object" && error !== null && "status" in error && error.status === 401) {
          router.replace("/login");
          return;
        }
        if (active) setMessage(error instanceof Error ? error.message : "Storage could not be loaded.");
      }
    }
    void load();
    return () => { active = false; };
  }, [projectId, router]);

  async function download(objectId: string) {
    setMessage(null);
    try {
      const grant = await rdcApi.storageDownloadGrant(objectId);
      window.location.assign(grant.url);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Download grant failed.");
    }
  }

  return (
    <section aria-labelledby="storage-title" style={{ display: "grid", gap: "1rem" }}>
      <header>
        <h1 id="storage-title">Storage</h1>
        <p>Verified source archives and short-lived delivery grants. Capability URLs are never persisted in the browser.</p>
      </header>
      {message ? <p aria-live="polite" role="status">{message}</p> : null}
      {objects.length === 0 ? (
        <Card><p style={{ margin: 0 }}>No source archives have been uploaded for this project.</p></Card>
      ) : (
        <ul style={{ display: "grid", gap: "1rem", listStyle: "none", margin: 0, padding: 0 }}>
          {objects.map((object) => (
            <li key={object.id}>
              <Card>
                <div style={{ alignItems: "center", display: "flex", gap: "0.75rem", justifyContent: "space-between" }}>
                  <div>
                    <h2 style={{ margin: 0 }}>{object.file_name}</h2>
                    <p style={{ marginBottom: 0 }}>{object.size_bytes ?? object.expected_size_bytes} bytes</p>
                  </div>
                  <StatusBadge tone={object.status === "AVAILABLE" ? "success" : object.status === "REJECTED" ? "danger" : "warning"}>
                    {object.status}
                  </StatusBadge>
                </div>
                <p><code style={{ overflowWrap: "anywhere" }}>{object.sha256_digest ?? object.expected_sha256_digest}</code></p>
                <button disabled={object.status !== "AVAILABLE"} onClick={() => void download(object.id)} style={{ minHeight: 44 }} type="button">
                  Create short-lived download
                </button>
              </Card>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
