"use client";

import type { AgentVersionDetail as VersionData } from "@rdc/shared-types";
import { Card, StatusBadge } from "@rdc/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

export function AgentVersionDetail({
  agentId,
  organizationId,
  projectId,
  versionId,
}: {
  agentId: string;
  organizationId: string;
  projectId: string;
  versionId: string;
}) {
  const router = useRouter();
  const [version, setVersion] = useState<VersionData | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const root = `/console/organizations/${organizationId}/projects/${projectId}`;

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        await rdcApi.session();
        const result = await rdcApi.agentVersion(versionId);
        if (!active) return;
        if (result.agent_id !== agentId || result.project_id !== projectId) {
          setMessage("This version does not belong to the selected Agent.");
          return;
        }
        setVersion(result);
      } catch (error) {
        if (
          typeof error === "object" &&
          error !== null &&
          "status" in error &&
          error.status === 401
        ) {
          router.replace("/login");
          return;
        }
        setMessage(error instanceof Error ? error.message : "The version could not be loaded.");
      }
    }
    void load();
    return () => {
      active = false;
    };
  }, [agentId, projectId, router, versionId]);

  if (!version) {
    return <p aria-live="polite" role="status">{message ?? "Loading Agent version…"}</p>;
  }

  return (
    <div style={{ display: "grid", gap: "1.5rem" }}>
      <header>
        <Link href={`${root}/agents/${agentId}`}>← Agent details</Link>
        <div style={{ alignItems: "center", display: "flex", gap: "0.75rem", marginTop: "0.75rem" }}>
          <h1 style={{ margin: 0 }}>Version {version.semantic_version}</h1>
          <StatusBadge tone="success">Immutable</StatusBadge>
        </div>
      </header>
      <Card>
        <dl style={{ display: "grid", gap: "0.75rem", margin: 0 }}>
          <div><dt>Registry revision</dt><dd>{version.version_number}</dd></div>
          <div><dt>Protocol</dt><dd>{version.protocol}</dd></div>
          <div><dt>Created</dt><dd>{new Date(version.created_at).toLocaleString()}</dd></div>
          <div><dt>Manifest digest</dt><dd style={{ fontFamily: "monospace", overflowWrap: "anywhere" }}>{version.manifest_digest}</dd></div>
          <div><dt>Release notes</dt><dd>{version.release_notes ?? "None"}</dd></div>
        </dl>
      </Card>
      <Card>
        <h2 style={{ marginTop: 0 }}>Validated manifest</h2>
        <pre style={{ margin: 0, overflowX: "auto", whiteSpace: "pre-wrap" }}>
          {JSON.stringify(version.manifest, null, 2)}
        </pre>
      </Card>
    </div>
  );
}
