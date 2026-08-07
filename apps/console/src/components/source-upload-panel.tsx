"use client";

import type { StorageObjectSummary } from "@rdc/shared-types";
import { Card, StatusBadge } from "@rdc/ui";
import type { FormEvent } from "react";
import { useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer), (value) =>
    value.toString(16).padStart(2, "0"),
  ).join("");
}

export function SourceUploadPanel({
  agentId,
  onAvailable,
}: {
  agentId: string;
  onAvailable?: (object: StorageObjectSummary) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [uploading, setUploading] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [record, setRecord] = useState<StorageObjectSummary | null>(null);

  async function upload(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!file) return;
    setUploading(true);
    setMessage(null);
    try {
      const digest = toHex(await crypto.subtle.digest("SHA-256", await file.arrayBuffer()));
      const intent = await rdcApi.createSourceUpload(agentId, {
        file_name: file.name,
        media_type: "application/zip",
        size_bytes: file.size,
        sha256_digest: digest,
      });
      const body = new FormData();
      for (const [key, value] of Object.entries(intent.upload.fields)) {
        body.append(key, value);
      }
      body.append("file", file);
      const response = await fetch(intent.upload.url, { method: "POST", body });
      if (!response.ok) {
        throw new Error(`Object upload failed with HTTP ${response.status}.`);
      }
      const completed = await rdcApi.completeSourceUpload(intent.object.id);
      setRecord(completed);
      setMessage("Source archive passed integrity and safe-ZIP inspection.");
      onAvailable?.(completed);
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Source upload failed.");
    } finally {
      setUploading(false);
    }
  }

  return (
    <Card>
      <h3 style={{ marginTop: 0 }}>Verified source archive</h3>
      <p>
        Upload a ZIP containing a root <code>agent.json</code> and every schema
        referenced by that manifest. The API verifies the declared SHA-256,
        size, paths, expansion limits, and manifest before making it available.
      </p>
      <form onSubmit={upload} style={{ display: "grid", gap: "0.8rem" }}>
        <input
          accept=".zip,application/zip"
          disabled={uploading}
          onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          required
          type="file"
        />
        <button disabled={uploading || !file} style={{ minHeight: 44, width: "fit-content" }} type="submit">
          {uploading ? "Verifying source…" : "Upload and verify source"}
        </button>
      </form>
      {message ? <p aria-live="polite" role="status">{message}</p> : null}
      {record ? (
        <div style={{ display: "grid", gap: "0.35rem" }}>
          <StatusBadge tone={record.status === "AVAILABLE" ? "success" : "warning"}>
            {record.status}
          </StatusBadge>
          <strong>{record.file_name}</strong>
          <code style={{ overflowWrap: "anywhere" }}>{record.sha256_digest}</code>
        </div>
      ) : null}
    </Card>
  );
}
