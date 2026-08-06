"use client";

import type { AgentVersionDetail as VersionData } from "@rdc/shared-types";
import { Card, StatusBadge } from "@rdc/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The version could not be loaded.";
}

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
  const [loading, setLoading] = useState(true);
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
        if (!active) return;
        if (
          typeof error === "object" &&
          error !== null &&
          "status" in error &&
          error.status === 401
        ) {
          router.replace("/login");
          return;
        }
        setMessage(errorMessage(error));
      } finally {
        if (active) setLoading(false);
      }
    }
    void load();
    return () => {
      active = false;
    };
  }, [agentId, projectId, router, versionId]);

  if (loading) {
    return <p aria-live="polite" role="status">Loading version details…</p>;
  }

  if (!version) {
    return (
      <Card>
        <h1 style={{ marginTop: 0 }}>Version unavailable</h1>
        <p>{message ?? "The requested version could not be loaded."}</p>
        <Link href={`${root}/agents/${agentId}`}>Back to Agent details</Link>
      </Card>
    );
  }

  const manifestJson = JSON.stringify(version.manifest, null, 2);

  return (
    <div style={{ display: "grid", gap: "1.5rem" }}>
      <header>
        <Link href={`${root}/agents/${agentId}`} aria-label="Back to Agent details">
          ← Agent details
        </Link>
        <div style={{ alignItems: "center", display: "flex", gap: "0.75rem", marginTop: "0.75rem" }}>
          <h1 style={{ margin: 0 }}>Version v{version.semantic_version}</h1>
          <StatusBadge tone="info">Immutable</StatusBadge>
        </div>
        <p style={{ color: "var(--muted-foreground)", margin: 0 }}>
          Registry revision {version.version_number}
        </p>
      </header>

      {message ? (
        <div
          aria-live="polite"
          role="status"
          style={{
            padding: "0.75rem 1rem",
            borderRadius: "0.375rem",
            backgroundColor: "var(--surface-subtle, #f4f4f5)",
            borderLeft: "4px solid var(--border-accent, #0052cc)",
          }}
        >
          <p style={{ margin: 0 }}>{message}</p>
        </div>
      ) : null}

      <Card>
        <h2 style={{ marginTop: 0 }}>Version metadata</h2>
        <dl style={{ display: "grid", gridTemplateColumns: "max-content 1fr", gap: "0.5rem 1rem", margin: 0 }}>
          <dt style={{ fontWeight: "bold" }}>Semantic version:</dt>
          <dd style={{ margin: 0 }}>{version.semantic_version}</dd>
          <dt style={{ fontWeight: "bold" }}>Revision number:</dt>
          <dd style={{ margin: 0 }}>{version.version_number}</dd>
          <dt style={{ fontWeight: "bold" }}>Protocol:</dt>
          <dd style={{ margin: 0 }}>{version.protocol}</dd>
          <dt style={{ fontWeight: "bold" }}>Manifest digest:</dt>
          <dd style={{ margin: 0, fontFamily: "monospace", wordBreak: "break-all" }}>
            {version.manifest_digest}
          </dd>
          <dt style={{ fontWeight: "bold" }}>Created at:</dt>
          <dd style={{ margin: 0 }}>{new Date(version.created_at).toLocaleString()}</dd>
        </dl>
        <div style={{ marginTop: "1rem" }}>
          <h3 style={{ marginBottom: "0.25rem", marginTop: 0 }}>Release notes</h3>
          <p style={{ margin: 0, color: version.release_notes ? "inherit" : "var(--muted-foreground)" }}>
            {version.release_notes || "No release notes provided."}
          </p>
        </div>
      </Card>

      <Card>
        <div style={{ alignItems: "center", display: "flex", justifyContent: "space-between" }}>
          <h2 style={{ margin: 0 }}>Manifest JSON</h2>
          <StatusBadge tone="neutral">Read-only</StatusBadge>
        </div>
        <pre
          aria-label="Agent Manifest JSON"
          tabIndex={0}
          style={{
            backgroundColor: "var(--surface-subtle, #f4f4f5)",
            borderRadius: "0.375rem",
            fontFamily: "monospace",
            fontSize: "0.875rem",
            marginTop: "1rem",
            overflowX: "auto",
            padding: "1rem",
          }}
        >
          <code>{manifestJson}</code>
        </pre>
      </Card>
    </div>
  );
}
