"use client";

import type { AgentSummary } from "@rdc/shared-types";
import { Card, StatusBadge } from "@rdc/ui";
import Link from "next/link";
import { useRouter } from "next/navigation";
import type { FormEvent } from "react";
import { useEffect, useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

function messageFor(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "The Agent registry could not be loaded.";
}

export function AgentRegistry({
  organizationId,
  projectId,
}: {
  organizationId: string;
  projectId: string;
}) {
  const router = useRouter();
  const [agents, setAgents] = useState<ReadonlyArray<AgentSummary>>([]);
  const [nextCursor, setNextCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [slug, setSlug] = useState("");
  const [description, setDescription] = useState("");

  const root = `/console/organizations/${organizationId}/projects/${projectId}`;

  useEffect(() => {
    let active = true;

    async function load() {
      try {
        await rdcApi.session();
        const result = await rdcApi.agents(projectId);
        if (active) {
          setAgents(result.data);
          setNextCursor(result.page.next_cursor);
        }
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
        setMessage(messageFor(error));
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, [projectId, router]);

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage(null);
    setSubmitting(true);
    try {
      const result = await rdcApi.createAgent(projectId, {
        name: name.trim(),
        slug: slug.trim(),
        description: description.trim() || null,
      });
      setAgents((current) => [result.agent, ...current]);
      setName("");
      setSlug("");
      setDescription("");
      setMessage(`Agent ${result.agent.name} was created.`);
    } catch (error) {
      setMessage(messageFor(error));
    } finally {
      setSubmitting(false);
    }
  }

  async function loadMore() {
    if (!nextCursor) return;
    setLoadingMore(true);
    setMessage(null);
    try {
      const result = await rdcApi.agents(projectId, nextCursor);
      setAgents((current) => [...current, ...result.data]);
      setNextCursor(result.page.next_cursor);
    } catch (error) {
      setMessage(messageFor(error));
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <div style={{ display: "grid", gap: "1.5rem" }}>
      <header>
        <div style={{ alignItems: "center", display: "flex", gap: "0.75rem" }}>
          <h1 style={{ margin: 0 }}>Agents</h1>
          <StatusBadge tone="info">Phase 1C</StatusBadge>
        </div>
        <p style={{ color: "var(--muted-foreground)", marginBottom: 0 }}>
          Manage Agent metadata and publish immutable manifest versions. No code is
          executed from this screen.
        </p>
      </header>

      <Card>
        <h2 style={{ marginTop: 0 }}>Create Agent</h2>
        <form onSubmit={create} style={{ display: "grid", gap: "1rem" }}>
          <label style={{ display: "grid", gap: "0.35rem" }}>
            Name
            <input
              disabled={submitting}
              maxLength={160}
              onChange={(event) => setName(event.target.value)}
              required
              style={{ minHeight: 44, padding: "0.7rem" }}
              value={name}
            />
          </label>
          <label style={{ display: "grid", gap: "0.35rem" }}>
            Slug
            <input
              autoCapitalize="none"
              disabled={submitting}
              maxLength={80}
              onChange={(event) => setSlug(event.target.value)}
              pattern="[a-z0-9](?:[a-z0-9-]{0,78}[a-z0-9])?"
              required
              style={{ minHeight: 44, padding: "0.7rem" }}
              value={slug}
            />
          </label>
          <label style={{ display: "grid", gap: "0.35rem" }}>
            Description
            <textarea
              disabled={submitting}
              maxLength={4000}
              onChange={(event) => setDescription(event.target.value)}
              rows={4}
              style={{ padding: "0.7rem", resize: "vertical" }}
              value={description}
            />
          </label>
          <button
            aria-busy={submitting}
            disabled={submitting}
            style={{ minHeight: 44, width: "fit-content" }}
            type="submit"
          >
            {submitting ? "Creating…" : "Create Agent"}
          </button>
        </form>
      </Card>

      <section aria-labelledby="agent-list-heading">
        <h2 id="agent-list-heading">Project Agents</h2>
        {loading ? (
          <p aria-live="polite" role="status">Loading Agents…</p>
        ) : agents.length === 0 ? (
          <Card>
            <p style={{ margin: 0 }}>
              No Agents exist in this project. Create the first Agent above.
            </p>
          </Card>
        ) : (
          <ul
            style={{
              display: "grid",
              gap: "1rem",
              listStyle: "none",
              margin: 0,
              padding: 0,
            }}
          >
            {agents.map((agent) => (
              <li key={agent.id}>
                <Card>
                  <div
                    style={{
                      alignItems: "start",
                      display: "flex",
                      gap: "1rem",
                      justifyContent: "space-between",
                    }}
                  >
                    <div>
                      <h3 style={{ margin: 0 }}>{agent.name}</h3>
                      <p style={{ color: "var(--muted-foreground)" }}>
                        {agent.slug}
                      </p>
                      <p>{agent.description ?? "No description supplied."}</p>
                    </div>
                    <StatusBadge
                      tone={agent.status === "ACTIVE" ? "success" : "neutral"}
                    >
                      {agent.status}
                    </StatusBadge>
                  </div>
                  <Link href={`${root}/agents/${agent.id}`}>Open Agent</Link>
                </Card>
              </li>
            ))}
          </ul>
        )}
        {nextCursor ? (
          <button
            aria-busy={loadingMore}
            disabled={loadingMore}
            onClick={() => void loadMore()}
            style={{ marginTop: "1rem", minHeight: 44 }}
            type="button"
          >
            {loadingMore ? "Loading…" : "Load more"}
          </button>
        ) : null}
      </section>

      {message ? (
        <p aria-live="polite" role="status" style={{ margin: 0 }}>
          {message}
        </p>
      ) : null}
    </div>
  );
}
