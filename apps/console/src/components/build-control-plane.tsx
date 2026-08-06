"use client";

import type {
  AgentSummary,
  AgentVersionSummary,
  BuildSummary,
} from "@rdc/shared-types";
import { Card, StatusBadge } from "@rdc/ui";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The Build operation failed.";
}

function newIdempotencyKey(): string {
  return `build-create-${globalThis.crypto.randomUUID()}`;
}

export function BuildControlPlane({ projectId }: { projectId: string }) {
  const router = useRouter();
  const [agents, setAgents] = useState<ReadonlyArray<AgentSummary>>([]);
  const [versions, setVersions] = useState<ReadonlyArray<AgentVersionSummary>>([]);
  const [builds, setBuilds] = useState<ReadonlyArray<BuildSummary>>([]);
  const [agentId, setAgentId] = useState("");
  const [versionId, setVersionId] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingAgent, setLoadingAgent] = useState(false);
  const [queueing, setQueueing] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        await rdcApi.session();
        const result = await rdcApi.agents(projectId);
        if (active) setAgents(result.data);
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
        if (active) setMessage(errorMessage(error));
      } finally {
        if (active) setLoading(false);
      }
    }
    void load();
    return () => {
      active = false;
    };
  }, [projectId, router]);

  async function chooseAgent(selectedAgentId: string) {
    setAgentId(selectedAgentId);
    setVersionId("");
    setVersions([]);
    setBuilds([]);
    setMessage(null);
    if (!selectedAgentId) return;
    setLoadingAgent(true);
    try {
      const [versionPage, buildPage] = await Promise.all([
        rdcApi.agentVersions(selectedAgentId),
        rdcApi.agentBuilds(selectedAgentId),
      ]);
      setVersions(versionPage.data);
      setBuilds(buildPage.data);
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setLoadingAgent(false);
    }
  }

  async function queueBuild() {
    if (!versionId) return;
    setMessage(null);
    setQueueing(true);
    try {
      const created = await rdcApi.createBuild(versionId, newIdempotencyKey());
      setBuilds((current) => [created, ...current]);
      setMessage(
        "Build metadata was accepted into the durable dispatch outbox. " +
          "No user code executes in the public API process.",
      );
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setQueueing(false);
    }
  }

  return (
    <div style={{ display: "grid", gap: "1.5rem" }}>
      <header>
        <div style={{ alignItems: "center", display: "flex", gap: "0.75rem" }}>
          <h1 style={{ margin: 0 }}>Build control plane</h1>
          <StatusBadge tone="info">Metadata only</StatusBadge>
        </div>
        <p style={{ color: "var(--muted-foreground)" }}>
          Build requests are recorded and placed in a durable outbox for a future
          isolated worker. This API never invokes BuildKit or executes Agent code.
        </p>
      </header>

      {message ? (
        <div aria-live="polite" role="status" style={{ border: "1px solid var(--border)", borderRadius: "0.5rem", padding: "0.8rem" }}>
          {message}
        </div>
      ) : null}

      <Card>
        <h2 style={{ marginTop: 0 }}>Queue Build metadata</h2>
        {loading ? (
          <p aria-live="polite" role="status">Loading Agents…</p>
        ) : agents.length === 0 ? (
          <p>Create an Agent and immutable Agent version before queueing a Build.</p>
        ) : (
          <div style={{ display: "grid", gap: "1rem" }}>
            <div style={{ display: "grid", gap: "0.35rem" }}>
              <label htmlFor="select-agent">Agent</label>
              <select
                id="select-agent"
                disabled={queueing}
                onChange={(event) => void chooseAgent(event.target.value)}
                style={{ minHeight: 44, padding: "0.7rem" }}
                value={agentId}
              >
                <option value="">Select an Agent</option>
                {agents.map((agent) => (
                  <option key={agent.id} value={agent.id}>
                    {agent.name}
                  </option>
                ))}
              </select>
            </div>
            {loadingAgent ? (
              <p aria-live="polite" role="status">Loading versions and Builds…</p>
            ) : null}
            {agentId && !loadingAgent ? (
              <div style={{ display: "grid", gap: "0.35rem" }}>
                <label htmlFor="select-agent-version">Immutable Agent version</label>
                <select
                  id="select-agent-version"
                  disabled={queueing || versions.length === 0}
                  onChange={(event) => setVersionId(event.target.value)}
                  style={{ minHeight: 44, padding: "0.7rem" }}
                  value={versionId}
                >
                  <option value="">Select a version</option>
                  {versions.map((version) => (
                    <option key={version.id} value={version.id}>
                      v{version.semantic_version} · revision {version.version_number}
                    </option>
                  ))}
                </select>
              </div>
            ) : null}
            {agentId && !loadingAgent && versions.length === 0 ? (
              <p aria-live="polite" role="status">No immutable versions exist for this Agent.</p>
            ) : null}
            <button
              aria-busy={queueing}
              disabled={!versionId || queueing}
              onClick={() => void queueBuild()}
              style={{ minHeight: 44, width: "fit-content" }}
              type="button"
            >
              {queueing ? "Queueing…" : "Queue Build metadata"}
            </button>
          </div>
        )}
      </Card>

      <section aria-labelledby="build-history-heading">
        <h2 id="build-history-heading">Build history</h2>
        {!agentId ? (
          <Card><p style={{ margin: 0 }}>Select an Agent to view its Build records.</p></Card>
        ) : builds.length === 0 && !loadingAgent ? (
          <Card><p style={{ margin: 0 }}>No Builds exist for the selected Agent.</p></Card>
        ) : (
          <ul style={{ display: "grid", gap: "1rem", listStyle: "none", margin: 0, padding: 0 }}>
            {builds.map((build) => (
              <li key={build.id}>
                <Card>
                  <div style={{ alignItems: "start", display: "flex", gap: "1rem", justifyContent: "space-between" }}>
                    <div>
                      <h3 style={{ marginTop: 0 }}>Build {build.id}</h3>
                      <p>Agent version {build.agent_version_id}</p>
                      <p style={{ color: "var(--muted-foreground)", fontFamily: "monospace", overflowWrap: "anywhere" }}>
                        Manifest SHA-256 {build.manifest_digest}
                      </p>
                      <p>Created {new Date(build.created_at).toLocaleString()}</p>
                    </div>
                    <StatusBadge tone={build.status === "SUCCEEDED" ? "success" : build.status === "FAILED" ? "danger" : "info"}>
                      {build.status}
                    </StatusBadge>
                  </div>
                </Card>
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  );
}
