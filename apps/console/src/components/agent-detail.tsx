"use client";

import type {
  AgentManifest,
  AgentSummary,
  AgentVersionSummary,
} from "@rdc/shared-types";
import { Card, StatusBadge } from "@rdc/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
import type { FormEvent } from "react";
import { useEffect, useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The operation failed.";
}

function manifestTemplate(slug: string): AgentManifest {
  return {
    protocol: "rooz.agent/v1",
    name: slug,
    version: "0.1.0",
    runtime: { kind: "container", entrypoint: ["python", "-m", "agent"] },
    schemas: { input: "schemas/input.json", output: "schemas/output.json" },
    capabilities: {
      network: "none",
      browser: false,
      dataset: false,
      keyValueStore: false,
      requestQueue: false,
    },
    resources: {
      memoryMb: 512,
      cpuUnits: 500,
      timeoutSeconds: 300,
      maxProcesses: 16,
      ephemeralDiskMb: 512,
    },
    extensions: {},
  };
}

export function AgentDetail({
  agentId,
  organizationId,
  projectId,
}: {
  agentId: string;
  organizationId: string;
  projectId: string;
}) {
  const router = useRouter();
  const [agent, setAgent] = useState<AgentSummary | null>(null);
  const [etag, setEtag] = useState("");
  const [versions, setVersions] = useState<ReadonlyArray<AgentVersionSummary>>([]);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [publishing, setPublishing] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [description, setDescription] = useState("");
  const [status, setStatus] = useState<"ACTIVE" | "ARCHIVED">("ACTIVE");
  const [manifestText, setManifestText] = useState("");
  const [releaseNotes, setReleaseNotes] = useState("");

  const root = `/console/organizations/${organizationId}/projects/${projectId}`;

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        await rdcApi.session();
        const [resource, versionPage] = await Promise.all([
          rdcApi.agent(agentId),
          rdcApi.agentVersions(agentId),
        ]);
        if (!active) return;
        if (resource.agent.project_id !== projectId) {
          setMessage("This Agent does not belong to the selected project.");
          return;
        }
        setAgent(resource.agent);
        setEtag(resource.etag);
        setVersions(versionPage.data);
        setName(resource.agent.name);
        setSlug(resource.agent.slug);
        setDescription(resource.agent.description ?? "");
        setStatus(resource.agent.status);
        setManifestText(
          JSON.stringify(manifestTemplate(resource.agent.slug), null, 2),
        );
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
        setMessage(errorMessage(error));
      } finally {
        if (active) setLoading(false);
      }
    }
    void load();
    return () => {
      active = false;
    };
  }, [agentId, projectId, router]);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!agent || !etag) return;
    setSaving(true);
    setMessage(null);
    try {
      const resource = await rdcApi.updateAgent(
        agent.id,
        {
          name: name.trim(),
          slug: slug.trim(),
          description: description.trim() || null,
          status,
        },
        etag,
      );
      setAgent(resource.agent);
      setEtag(resource.etag);
      setMessage("Agent metadata was updated.");
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setSaving(false);
    }
  }

  async function publish(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!agent) return;
    setPublishing(true);
    setMessage(null);
    try {
      const parsed = JSON.parse(manifestText) as AgentManifest;
      const version = await rdcApi.createAgentVersion(agent.id, {
        manifest: parsed,
        release_notes: releaseNotes.trim() || null,
      });
      setVersions((current) => [version, ...current]);
      setReleaseNotes("");
      const next = manifestTemplate(agent.slug);
      const parts = version.semantic_version.split(".");
      const patch = Number(parts[2] ?? "0") + 1;
      next.version = `${parts[0] ?? "0"}.${parts[1] ?? "1"}.${patch}`;
      setManifestText(JSON.stringify(next, null, 2));
      setMessage(`Immutable version ${version.semantic_version} was created.`);
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setPublishing(false);
    }
  }

  if (loading) {
    return <p aria-live="polite" role="status">Loading Agent…</p>;
  }
  if (!agent) {
    return (
      <Card>
        <h1>Agent unavailable</h1>
        <p>{message ?? "The requested Agent could not be loaded."}</p>
        <Link href={`${root}/agents`}>Back to Agents</Link>
      </Card>
    );
  }

  return (
    <div style={{ display: "grid", gap: "1.5rem" }}>
      <header>
        <Link href={`${root}/agents`}>← Agents</Link>
        <div style={{ alignItems: "center", display: "flex", gap: "0.75rem", marginTop: "0.75rem" }}>
          <h1 style={{ margin: 0 }}>{agent.name}</h1>
          <StatusBadge tone={agent.status === "ACTIVE" ? "success" : "neutral"}>
            {agent.status}
          </StatusBadge>
        </div>
        <p style={{ color: "var(--muted-foreground)" }}>{agent.slug}</p>
      </header>

      <Card>
        <h2 style={{ marginTop: 0 }}>Agent metadata</h2>
        <form onSubmit={save} style={{ display: "grid", gap: "1rem" }}>
          <label style={{ display: "grid", gap: "0.35rem" }}>
            Name
            <input disabled={saving} maxLength={160} onChange={(event) => setName(event.target.value)} required style={{ minHeight: 44, padding: "0.7rem" }} value={name} />
          </label>
          <label style={{ display: "grid", gap: "0.35rem" }}>
            Slug
            <input disabled={saving} maxLength={80} onChange={(event) => setSlug(event.target.value)} required style={{ minHeight: 44, padding: "0.7rem" }} value={slug} />
          </label>
          <label style={{ display: "grid", gap: "0.35rem" }}>
            Description
            <textarea disabled={saving} maxLength={4000} onChange={(event) => setDescription(event.target.value)} rows={4} style={{ padding: "0.7rem" }} value={description} />
          </label>
          <label style={{ display: "grid", gap: "0.35rem" }}>
            Status
            <select disabled={saving} onChange={(event) => setStatus(event.target.value as "ACTIVE" | "ARCHIVED")} style={{ minHeight: 44, padding: "0.7rem" }} value={status}>
              <option value="ACTIVE">Active</option>
              <option value="ARCHIVED">Archived</option>
            </select>
          </label>
          <button aria-busy={saving} disabled={saving} style={{ minHeight: 44, width: "fit-content" }} type="submit">
            {saving ? "Saving…" : "Save metadata"}
          </button>
        </form>
      </Card>

      <Card>
        <h2 style={{ marginTop: 0 }}>Create immutable version</h2>
        <p>
          The manifest is validated and stored as metadata only. Build and Run
          execution remain disabled in Phase 1C.
        </p>
        <form onSubmit={publish} style={{ display: "grid", gap: "1rem" }}>
          <label style={{ display: "grid", gap: "0.35rem" }}>
            Agent manifest JSON
            <textarea
              aria-describedby="manifest-help"
              disabled={publishing}
              onChange={(event) => setManifestText(event.target.value)}
              required
              rows={24}
              spellCheck={false}
              style={{ fontFamily: "monospace", padding: "0.7rem", resize: "vertical" }}
              value={manifestText}
            />
          </label>
          <p id="manifest-help" style={{ color: "var(--muted-foreground)", margin: 0 }}>
            Manifest name must match the Agent slug. Semantic versions cannot be reused.
          </p>
          <label style={{ display: "grid", gap: "0.35rem" }}>
            Release notes
            <textarea disabled={publishing} maxLength={8000} onChange={(event) => setReleaseNotes(event.target.value)} rows={4} style={{ padding: "0.7rem" }} value={releaseNotes} />
          </label>
          <button aria-busy={publishing} disabled={publishing} style={{ minHeight: 44, width: "fit-content" }} type="submit">
            {publishing ? "Creating version…" : "Create immutable version"}
          </button>
        </form>
      </Card>

      <section aria-labelledby="versions-heading">
        <h2 id="versions-heading">Version history</h2>
        {versions.length === 0 ? (
          <Card><p style={{ margin: 0 }}>No immutable versions exist yet.</p></Card>
        ) : (
          <ul style={{ display: "grid", gap: "1rem", listStyle: "none", margin: 0, padding: 0 }}>
            {versions.map((version) => (
              <li key={version.id}>
                <Card>
                  <h3 style={{ marginTop: 0 }}>v{version.semantic_version}</h3>
                  <p>Registry revision {version.version_number}</p>
                  <p style={{ color: "var(--muted-foreground)", fontFamily: "monospace", overflowWrap: "anywhere" }}>
                    SHA-256 {version.manifest_digest}
                  </p>
                  <Link href={`${root}/agents/${agent.id}/versions/${version.id}`}>
                    View manifest
                  </Link>
                </Card>
              </li>
            ))}
          </ul>
        )}
      </section>

      {message ? <p aria-live="polite" role="status">{message}</p> : null}
    </div>
  );
}
