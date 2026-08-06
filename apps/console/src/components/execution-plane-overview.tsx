"use client";

import type {
  ExecutionArtifactSummary,
  ExecutionLeaseStatus,
  ExecutionLeaseSummary,
} from "@rdc/shared-types";
import { Card, StatusBadge } from "@rdc/ui";
import { useRouter } from "next/navigation";
import { useEffect, useMemo, useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "The execution-plane metadata could not be loaded.";
}

function leaseTone(
  status: ExecutionLeaseStatus,
): "danger" | "info" | "success" {
  if (["FAILED", "EXPIRED", "CANCELLED"].includes(status)) {
    return "danger";
  }
  if (status === "COMPLETED") return "success";
  return "info";
}

function artifactTone(
  artifact: ExecutionArtifactSummary,
): "danger" | "info" | "success" {
  if (
    artifact.status === "REJECTED" ||
    artifact.status === "QUARANTINED" ||
    artifact.scan_status === "FAILED"
  ) {
    return "danger";
  }
  if (
    artifact.status === "AVAILABLE" &&
    ["PASSED", "NOT_REQUIRED"].includes(artifact.scan_status)
  ) {
    return "success";
  }
  return "info";
}

function compactId(value: string | null): string {
  if (!value) return "—";
  return value.length > 18 ? `${value.slice(0, 8)}…${value.slice(-6)}` : value;
}

export function ExecutionPlaneOverview({ projectId }: { projectId: string }) {
  const router = useRouter();
  const [leases, setLeases] = useState<ReadonlyArray<ExecutionLeaseSummary>>([]);
  const [artifacts, setArtifacts] = useState<
    ReadonlyArray<ExecutionArtifactSummary>
  >([]);
  const [loading, setLoading] = useState(true);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        await rdcApi.session();
        const [leasePage, artifactPage] = await Promise.all([
          rdcApi.projectExecutionLeases(projectId),
          rdcApi.projectExecutionArtifacts(projectId),
        ]);
        if (active) {
          setLeases(leasePage.data);
          setArtifacts(artifactPage.data);
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

  const activeLeases = useMemo(
    () => leases.filter((lease) => lease.status === "ACTIVE").length,
    [leases],
  );
  const passedArtifacts = useMemo(
    () => artifacts.filter(
      (artifact) =>
        artifact.status === "AVAILABLE" &&
        ["PASSED", "NOT_REQUIRED"].includes(artifact.scan_status),
    ).length,
    [artifacts],
  );

  return (
    <section aria-labelledby="execution-plane-heading">
      <header style={{ marginBottom: "1.5rem" }}>
        <p style={{ color: "var(--muted-foreground)", margin: 0 }}>
          Phase 1F
        </p>
        <h1 id="execution-plane-heading">Isolated execution plane</h1>
        <p style={{ maxWidth: "72ch" }}>
          Inspect worker leases and immutable artifact metadata. The internal
          protocol is active, but untrusted Agent execution remains disabled
          until the isolation runtime is separately approved and verified.
        </p>
      </header>

      {message ? (
        <p role="alert" style={{ color: "var(--danger)" }}>{message}</p>
      ) : null}

      <div
        style={{
          display: "grid",
          gap: "1rem",
          gridTemplateColumns: "repeat(auto-fit, minmax(13rem, 1fr))",
          marginBottom: "1rem",
        }}
      >
        <Card>
          <strong>{loading ? "…" : activeLeases}</strong>
          <div>Active leases</div>
        </Card>
        <Card>
          <strong>{loading ? "…" : artifacts.length}</strong>
          <div>Registered artifacts</div>
        </Card>
        <Card>
          <strong>{loading ? "…" : passedArtifacts}</strong>
          <div>Available and verified</div>
        </Card>
      </div>

      <Card>
        <h2>Execution leases</h2>
        {loading ? <p role="status">Loading execution leases…</p> : null}
        {!loading && leases.length === 0 ? (
          <p>No worker has claimed Build or Run work for this project.</p>
        ) : null}
        {leases.length > 0 ? (
          <div style={{ overflowX: "auto" }}>
            <table style={{ borderCollapse: "collapse", width: "100%" }}>
              <thead>
                <tr>
                  <th scope="col">Kind</th>
                  <th scope="col">Status</th>
                  <th scope="col">Attempt</th>
                  <th scope="col">Target</th>
                  <th scope="col">Claimed</th>
                  <th scope="col">Expires</th>
                </tr>
              </thead>
              <tbody>
                {leases.map((lease) => (
                  <tr key={lease.id}>
                    <td>{lease.work_kind}</td>
                    <td>
                      <StatusBadge tone={leaseTone(lease.status)}>
                        {lease.status}
                      </StatusBadge>
                    </td>
                    <td>{lease.attempt}</td>
                    <td title={lease.build_id ?? lease.run_id ?? ""}>
                      {compactId(lease.build_id ?? lease.run_id)}
                    </td>
                    <td>{new Date(lease.claimed_at).toLocaleString()}</td>
                    <td>{new Date(lease.expires_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Card>

      <div style={{ height: "1rem" }} />

      <Card>
        <h2>Artifact metadata</h2>
        {loading ? <p role="status">Loading artifact metadata…</p> : null}
        {!loading && artifacts.length === 0 ? (
          <p>No execution artifacts are registered for this project.</p>
        ) : null}
        {artifacts.length > 0 ? (
          <div style={{ overflowX: "auto" }}>
            <table style={{ borderCollapse: "collapse", width: "100%" }}>
              <thead>
                <tr>
                  <th scope="col">Kind</th>
                  <th scope="col">Status</th>
                  <th scope="col">Scan</th>
                  <th scope="col">Digest</th>
                  <th scope="col">Size</th>
                  <th scope="col">Created</th>
                </tr>
              </thead>
              <tbody>
                {artifacts.map((artifact) => (
                  <tr key={artifact.id}>
                    <td>{artifact.kind}</td>
                    <td>
                      <StatusBadge tone={artifactTone(artifact)}>
                        {artifact.status}
                      </StatusBadge>
                    </td>
                    <td>{artifact.scan_status}</td>
                    <td title={`${artifact.digest_algorithm}:${artifact.digest}`}>
                      {compactId(artifact.digest)}
                    </td>
                    <td>{artifact.size_bytes.toLocaleString()} bytes</td>
                    <td>{new Date(artifact.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </Card>
    </section>
  );
}
