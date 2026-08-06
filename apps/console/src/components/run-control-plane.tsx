"use client";

import type {
  AgentSummary,
  AgentVersionSummary,
  BuildSummary,
  CreateRunInput,
  RunEventEnvelope,
  RunStatus,
  RunSummary,
} from "@rdc/shared-types";
import { Card, StatusBadge } from "@rdc/ui";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useRef, useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

const TERMINAL_STATUSES = new Set<RunStatus>([
  "SUCCEEDED",
  "PARTIALLY_SUCCEEDED",
  "FAILED",
  "TIMED_OUT",
  "ABORTED",
]);
const CANCELLABLE_STATUSES = new Set<RunStatus>([
  "DRAFT",
  "READY",
  "QUEUED",
  "STARTING",
  "RUNNING",
  "PAUSING",
  "PAUSED",
  "TIMING_OUT",
]);
const EVENT_TYPES = [
  "run.connected",
  "run.status",
  "run.log",
  "run.metric",
  "run.warning",
  "run.completed",
  "run.failed",
  "run.heartbeat",
  "run.replay_reset",
] as const;

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : "The Run operation failed.";
}

function newIdempotencyKey(kind: "create" | "cancel"): string {
  return `run-${kind}-${globalThis.crypto.randomUUID()}`;
}

function statusTone(status: RunStatus): "danger" | "info" | "success" {
  if (["FAILED", "TIMED_OUT", "ABORTED"].includes(status)) return "danger";
  if (["SUCCEEDED", "PARTIALLY_SUCCEEDED"].includes(status)) return "success";
  return "info";
}

function parseOptionalPositiveInteger(
  value: string,
  label: string,
): number | undefined {
  if (!value.trim()) return undefined;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) {
    throw new Error(`${label} must be a positive whole number.`);
  }
  return parsed;
}

function replaceRun(
  runs: ReadonlyArray<RunSummary>,
  next: RunSummary,
): ReadonlyArray<RunSummary> {
  return runs.map((item) => (item.id === next.id ? next : item));
}

export function RunControlPlane({ projectId }: { projectId: string }) {
  const router = useRouter();
  const eventSourceRef = useRef<EventSource | null>(null);
  const lastSequenceRef = useRef(0);
  const [agents, setAgents] = useState<ReadonlyArray<AgentSummary>>([]);
  const [versions, setVersions] = useState<ReadonlyArray<AgentVersionSummary>>([]);
  const [builds, setBuilds] = useState<ReadonlyArray<BuildSummary>>([]);
  const [runs, setRuns] = useState<ReadonlyArray<RunSummary>>([]);
  const [events, setEvents] = useState<ReadonlyArray<RunEventEnvelope>>([]);
  const [agentId, setAgentId] = useState("");
  const [versionId, setVersionId] = useState("");
  const [buildId, setBuildId] = useState("");
  const [inputJson, setInputJson] = useState("{}");
  const [memoryMb, setMemoryMb] = useState("");
  const [cpuMillis, setCpuMillis] = useState("");
  const [timeoutSeconds, setTimeoutSeconds] = useState("");
  const [selectedRunId, setSelectedRunId] = useState("");
  const [loading, setLoading] = useState(true);
  const [loadingAgent, setLoadingAgent] = useState(false);
  const [queueing, setQueueing] = useState(false);
  const [cancellingId, setCancellingId] = useState("");
  const [streamState, setStreamState] = useState("Disconnected");
  const [message, setMessage] = useState<string | null>(null);

  const selectedRun = runs.find((item) => item.id === selectedRunId) ?? null;
  const successfulBuilds = useMemo(
    () => builds.filter(
      (build) => build.status === "SUCCEEDED" && build.artifact_digest,
    ),
    [builds],
  );
  const eligibleBuilds = useMemo(
    () => successfulBuilds.filter(
      (build) => !versionId || build.agent_version_id === versionId,
    ),
    [successfulBuilds, versionId],
  );

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        await rdcApi.session();
        const [agentPage, runPage] = await Promise.all([
          rdcApi.agents(projectId),
          rdcApi.projectRuns(projectId),
        ]);
        if (active) {
          setAgents(agentPage.data);
          setRuns(runPage.data);
        }
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

  useEffect(() => {
    eventSourceRef.current?.close();
    eventSourceRef.current = null;
    lastSequenceRef.current = 0;
    setEvents([]);

    if (!selectedRunId) {
      setStreamState("Disconnected");
      return undefined;
    }

    const source = new EventSource(
      rdcApi.runEventsUrl(selectedRunId, lastSequenceRef.current),
      { withCredentials: true },
    );
    eventSourceRef.current = source;
    setStreamState("Connecting");

    const onEvent: EventListener = (rawEvent) => {
      if (!(rawEvent instanceof MessageEvent)) return;
      try {
        const envelope = JSON.parse(String(rawEvent.data)) as RunEventEnvelope;
        if (envelope.sequence > lastSequenceRef.current) {
          lastSequenceRef.current = envelope.sequence;
        }
        if (envelope.event_type !== "run.heartbeat") {
          setEvents((current) => [...current.slice(-199), envelope]);
        }
        if (envelope.event_type === "run.connected") {
          setStreamState("Connected");
        }
        if (envelope.event_type === "run.replay_reset") {
          setMessage(
            "The retained replay window changed. Run state was refreshed.",
          );
          void rdcApi.run(selectedRunId).then((fresh) => {
            setRuns((current) => replaceRun(current, fresh));
          });
        }
        if (envelope.event_type === "run.status") {
          const status = envelope.payload.status;
          if (typeof status === "string") {
            void rdcApi.run(selectedRunId).then((fresh) => {
              setRuns((current) => replaceRun(current, fresh));
            });
          }
        }
        if (
          envelope.event_type === "run.completed" ||
          envelope.event_type === "run.failed"
        ) {
          setStreamState("Terminal");
          source.close();
        }
      } catch {
        setMessage("A malformed Run event was ignored.");
      }
    };

    for (const eventType of EVENT_TYPES) {
      source.addEventListener(eventType, onEvent);
    }
    source.onerror = () => {
      setStreamState("Reconnecting");
    };

    return () => {
      for (const eventType of EVENT_TYPES) {
        source.removeEventListener(eventType, onEvent);
      }
      source.close();
      if (eventSourceRef.current === source) eventSourceRef.current = null;
    };
  }, [selectedRunId]);

  async function chooseAgent(selectedAgentId: string) {
    setAgentId(selectedAgentId);
    setVersionId("");
    setBuildId("");
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

  async function queueRun() {
    if (!versionId || !buildId) return;
    setMessage(null);
    setQueueing(true);
    try {
      const parsed = JSON.parse(inputJson) as unknown;
      if (
        typeof parsed !== "object" ||
        parsed === null ||
        Array.isArray(parsed)
      ) {
        throw new Error("Run input must be a JSON object.");
      }
      const runtime: CreateRunInput["runtime"] = {};
      const parsedMemory = parseOptionalPositiveInteger(memoryMb, "Memory");
      const parsedCpu = parseOptionalPositiveInteger(cpuMillis, "CPU");
      const parsedTimeout = parseOptionalPositiveInteger(
        timeoutSeconds,
        "Timeout",
      );
      if (parsedMemory !== undefined) runtime.memory_mb = parsedMemory;
      if (parsedCpu !== undefined) runtime.cpu_millis = parsedCpu;
      if (parsedTimeout !== undefined) runtime.timeout_seconds = parsedTimeout;

      const created = await rdcApi.createRun(
        versionId,
        {
          build_id: buildId,
          input: parsed as Record<string, unknown>,
          runtime,
        },
        newIdempotencyKey("create"),
      );
      setRuns((current) => [created, ...current]);
      setSelectedRunId(created.id);
      setMessage(
        "Run metadata was accepted into the durable command outbox. " +
          "No Agent code executes in the public API process.",
      );
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setQueueing(false);
    }
  }

  async function cancelSelectedRun(run: RunSummary) {
    setMessage(null);
    setCancellingId(run.id);
    try {
      const updated = await rdcApi.cancelRun(
        run.id,
        newIdempotencyKey("cancel"),
      );
      setRuns((current) => replaceRun(current, updated));
      setMessage(
        updated.status === "ABORTED"
          ? "The queued Run was aborted before dispatch."
          : "Cancellation was recorded for the isolated execution plane.",
      );
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setCancellingId("");
    }
  }

  return (
    <div style={{ display: "grid", gap: "1.5rem" }}>
      <header>
        <div style={{ alignItems: "center", display: "flex", gap: "0.75rem" }}>
          <h1 style={{ margin: 0 }}>Run control plane</h1>
          <StatusBadge tone="info">Execution isolated</StatusBadge>
        </div>
        <p style={{ color: "var(--muted-foreground)" }}>
          Queue metadata-only Run commands, request cancellation, and monitor
          persisted events through replayable Server-Sent Events. The public API
          never executes Agent code or decrypts project secrets.
        </p>
      </header>

      {message ? (
        <div
          aria-live="polite"
          role="status"
          style={{
            border: "1px solid var(--border)",
            borderRadius: "0.5rem",
            padding: "0.8rem",
          }}
        >
          {message}
        </div>
      ) : null}

      <Card>
        <h2 style={{ marginTop: 0 }}>Queue a Run</h2>
        {loading ? (
          <p aria-live="polite" role="status">Loading Run prerequisites…</p>
        ) : agents.length === 0 ? (
          <p>Create an Agent, immutable version, and successful Build first.</p>
        ) : (
          <div style={{ display: "grid", gap: "1rem" }}>
            <label style={{ display: "grid", gap: "0.35rem" }}>
              Agent
              <select
                disabled={queueing}
                onChange={(event) => void chooseAgent(event.target.value)}
                style={{ minHeight: 44, padding: "0.7rem" }}
                value={agentId}
              >
                <option value="">Select an Agent</option>
                {agents.map((agent) => (
                  <option key={agent.id} value={agent.id}>{agent.name}</option>
                ))}
              </select>
            </label>

            {loadingAgent ? (
              <p aria-live="polite" role="status">
                Loading immutable versions and Builds…
              </p>
            ) : null}

            {agentId && !loadingAgent ? (
              <label style={{ display: "grid", gap: "0.35rem" }}>
                Immutable Agent version
                <select
                  disabled={queueing || versions.length === 0}
                  onChange={(event) => {
                    setVersionId(event.target.value);
                    setBuildId("");
                  }}
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
              </label>
            ) : null}

            {versionId ? (
              <label style={{ display: "grid", gap: "0.35rem" }}>
                Successful Build artifact
                <select
                  disabled={queueing || eligibleBuilds.length === 0}
                  onChange={(event) => setBuildId(event.target.value)}
                  style={{ minHeight: 44, padding: "0.7rem" }}
                  value={buildId}
                >
                  <option value="">Select a Build</option>
                  {eligibleBuilds.map((build) => (
                    <option key={build.id} value={build.id}>
                      {build.id} · {build.artifact_digest}
                    </option>
                  ))}
                </select>
              </label>
            ) : null}

            {versionId && eligibleBuilds.length === 0 ? (
              <p>
                This version has no successful Build artifact. Run creation
                remains disabled until an isolated Build worker completes one.
              </p>
            ) : null}

            <label style={{ display: "grid", gap: "0.35rem" }}>
              Input JSON
              <textarea
                aria-describedby="run-input-help"
                onChange={(event) => setInputJson(event.target.value)}
                rows={8}
                spellCheck={false}
                style={{ fontFamily: "monospace", padding: "0.7rem" }}
                value={inputJson}
              />
            </label>
            <p id="run-input-help" style={{ color: "var(--muted-foreground)", margin: 0 }}>
              Inline JSON objects are limited to 64 KiB. Large object-storage
              inputs remain deferred.
            </p>

            <fieldset style={{ border: "1px solid var(--border)", display: "grid", gap: "0.8rem", padding: "1rem" }}>
              <legend>Optional resource overrides</legend>
              <p style={{ color: "var(--muted-foreground)", margin: 0 }}>
                Overrides can reduce, but never exceed, immutable Agent-version limits.
              </p>
              <label style={{ display: "grid", gap: "0.35rem" }}>
                Memory (MiB)
                <input inputMode="numeric" onChange={(event) => setMemoryMb(event.target.value)} value={memoryMb} />
              </label>
              <label style={{ display: "grid", gap: "0.35rem" }}>
                CPU (millicores)
                <input inputMode="numeric" onChange={(event) => setCpuMillis(event.target.value)} value={cpuMillis} />
              </label>
              <label style={{ display: "grid", gap: "0.35rem" }}>
                Timeout (seconds)
                <input inputMode="numeric" onChange={(event) => setTimeoutSeconds(event.target.value)} value={timeoutSeconds} />
              </label>
            </fieldset>

            <button
              aria-busy={queueing}
              disabled={!versionId || !buildId || queueing}
              onClick={() => void queueRun()}
              style={{ minHeight: 44, width: "fit-content" }}
              type="button"
            >
              {queueing ? "Queueing…" : "Queue Run metadata"}
            </button>
          </div>
        )}
      </Card>

      <section aria-labelledby="run-history-heading">
        <h2 id="run-history-heading">Run history</h2>
        {runs.length === 0 && !loading ? (
          <Card><p style={{ margin: 0 }}>No Runs exist in this project.</p></Card>
        ) : (
          <ul style={{ display: "grid", gap: "1rem", listStyle: "none", margin: 0, padding: 0 }}>
            {runs.map((run) => (
              <li key={run.id}>
                <Card>
                  <div style={{ alignItems: "start", display: "flex", gap: "1rem", justifyContent: "space-between" }}>
                    <div>
                      <h3 style={{ marginTop: 0 }}>Run {run.id}</h3>
                      <p>Queued {new Date(run.queued_at).toLocaleString()}</p>
                      <p>
                        {run.memory_mb} MiB · {run.cpu_millis} millicores · {run.timeout_seconds}s timeout
                      </p>
                      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.6rem" }}>
                        <button onClick={() => setSelectedRunId(run.id)} type="button">
                          {selectedRunId === run.id ? "Monitoring" : "Monitor events"}
                        </button>
                        {CANCELLABLE_STATUSES.has(run.status) ? (
                          <button
                            aria-busy={cancellingId === run.id}
                            disabled={cancellingId === run.id}
                            onClick={() => void cancelSelectedRun(run)}
                            type="button"
                          >
                            {cancellingId === run.id ? "Cancelling…" : `Cancel Run ${run.id}`}
                          </button>
                        ) : null}
                      </div>
                    </div>
                    <StatusBadge tone={statusTone(run.status)}>{run.status}</StatusBadge>
                  </div>
                </Card>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="run-events-heading">
        <div style={{ alignItems: "center", display: "flex", gap: "0.75rem" }}>
          <h2 id="run-events-heading">Live Run events</h2>
          <StatusBadge tone={streamState === "Connected" ? "success" : "info"}>
            {streamState}
          </StatusBadge>
        </div>
        {!selectedRun ? (
          <Card><p style={{ margin: 0 }}>Choose a Run to open its replayable event stream.</p></Card>
        ) : (
          <Card>
            <h3 style={{ marginTop: 0 }}>Run {selectedRun.id}</h3>
            <p>
              Current state: <strong>{selectedRun.status}</strong>
              {TERMINAL_STATUSES.has(selectedRun.status) ? " · terminal" : ""}
            </p>
            {events.length === 0 ? (
              <p aria-live="polite">Waiting for persisted Run events…</p>
            ) : (
              <ol
                aria-label={`Events for Run ${selectedRun.id}`}
                style={{ display: "grid", gap: "0.75rem", margin: 0, paddingLeft: "1.5rem" }}
              >
                {events.map((event, index) => (
                  <li key={`${event.sequence}-${event.event_type}-${index}`}>
                    <strong>{event.event_type}</strong>
                    <span> · sequence {event.sequence}</span>
                    <pre style={{ overflowX: "auto", whiteSpace: "pre-wrap" }}>
                      {JSON.stringify(event.payload, null, 2)}
                    </pre>
                  </li>
                ))}
              </ol>
            )}
          </Card>
        )}
      </section>
    </div>
  );
}
