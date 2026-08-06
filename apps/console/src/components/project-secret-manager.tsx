"use client";

import type {
  ProjectSecretSummary,
  SecretEnvironment,
} from "@rdc/shared-types";
import { Card, StatusBadge } from "@rdc/ui";
import { useRouter } from "next/navigation";
import type { FormEvent } from "react";
import { useEffect, useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

function errorMessage(error: unknown): string {
  return error instanceof Error
    ? error.message
    : "The project-secret operation failed.";
}

function newIdempotencyKey(prefix: string): string {
  return `${prefix}-${globalThis.crypto.randomUUID()}`;
}

export function ProjectSecretManager({
  projectId,
}: {
  projectId: string;
}) {
  const router = useRouter();
  const [secrets, setSecrets] = useState<ReadonlyArray<ProjectSecretSummary>>([]);
  const [loading, setLoading] = useState(true);
  const [submitting, setSubmitting] = useState(false);
  const [replacing, setReplacing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [name, setName] = useState("");
  const [value, setValue] = useState("");
  const [description, setDescription] = useState("");
  const [environment, setEnvironment] = useState<SecretEnvironment>("production");
  const [replacementId, setReplacementId] = useState("");
  const [replacementValue, setReplacementValue] = useState("");
  const [replacementDescription, setReplacementDescription] = useState("");
  const [replacementEnvironment, setReplacementEnvironment] =
    useState<SecretEnvironment>("production");
  const [deleteTargetId, setDeleteTargetId] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        await rdcApi.session();
        const result = await rdcApi.projectSecrets(projectId);
        if (active) setSecrets(result.data);
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

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage(null);
    setSubmitting(true);
    try {
      const created = await rdcApi.createProjectSecret(projectId, {
        name: name.trim(),
        value,
        description: description.trim() || null,
        environment,
      });
      setSecrets((current) => [created, ...current]);
      setName("");
      setValue("");
      setDescription("");
      setMessage(`Secret metadata for ${created.name} was created. The value cannot be revealed.`);
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setSubmitting(false);
    }
  }

  function selectForReplacement(secret: ProjectSecretSummary) {
    setReplacementId(secret.id);
    setReplacementValue("");
    setReplacementDescription(secret.description ?? "");
    setReplacementEnvironment(secret.environment);
    setMessage(`Replacing ${secret.name}. The existing value is not available.`);
  }

  async function replace(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const selected = secrets.find((item) => item.id === replacementId);
    if (!selected) return;
    setMessage(null);
    setReplacing(true);
    try {
      const updated = await rdcApi.replaceProjectSecret(
        selected.id,
        {
          value: replacementValue,
          description: replacementDescription.trim() || null,
          environment: replacementEnvironment,
        },
        selected.etag,
        newIdempotencyKey("secret-replace"),
      );
      setSecrets((current) =>
        current.map((item) => (item.id === updated.id ? updated : item)),
      );
      setReplacementValue("");
      setReplacementId("");
      setMessage(`Secret ${updated.name} was replaced. Its value remains write-only.`);
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setReplacing(false);
    }
  }

  async function remove(secretId: string) {
    setMessage(null);
    setDeleting(true);
    try {
      await rdcApi.deleteProjectSecret(secretId);
      setSecrets((current) => current.filter((item) => item.id !== secretId));
      if (replacementId === secretId) setReplacementId("");
      setDeleteTargetId(null);
      setMessage("Project-secret metadata and encrypted ciphertext were deleted.");
    } catch (error) {
      setMessage(errorMessage(error));
    } finally {
      setDeleting(false);
    }
  }

  const activeReplacementSecret = secrets.find((s) => s.id === replacementId);

  return (
    <div style={{ display: "grid", gap: "1.5rem" }}>
      <header>
        <div style={{ alignItems: "center", display: "flex", gap: "0.75rem" }}>
          <h1 style={{ margin: 0 }}>Project secrets</h1>
          <StatusBadge tone="info">Write-only</StatusBadge>
        </div>
        <p style={{ color: "var(--muted-foreground)" }}>
          Values are encrypted with per-secret data keys. Existing values are never
          returned and there is no reveal action.
        </p>
      </header>

      {message ? (
        <div aria-live="polite" role="status" style={{ border: "1px solid var(--border)", borderRadius: "0.5rem", padding: "0.8rem" }}>
          {message}
        </div>
      ) : null}

      <Card>
        <h2 style={{ marginTop: 0 }}>Create secret</h2>
        <form onSubmit={create} style={{ display: "grid", gap: "1rem" }}>
          <div style={{ display: "grid", gap: "0.35rem" }}>
            <label htmlFor="create-secret-name">Name</label>
            <input
              id="create-secret-name"
              aria-describedby="create-secret-name-hint"
              autoCapitalize="characters"
              autoComplete="off"
              disabled={submitting}
              maxLength={64}
              onChange={(event) => setName(event.target.value.toUpperCase())}
              pattern="[A-Z][A-Z0-9_]{0,63}"
              required
              spellCheck={false}
              style={{ minHeight: 44, padding: "0.7rem" }}
              value={name}
            />
            <span id="create-secret-name-hint" style={{ color: "var(--muted-foreground)", fontSize: "0.85rem" }}>
              Uppercase letters, numbers, and underscores. Must start with a letter (e.g. DATABASE_URL).
            </span>
          </div>
          <div style={{ display: "grid", gap: "0.35rem" }}>
            <label htmlFor="create-secret-value">Secret value</label>
            <input
              id="create-secret-value"
              autoComplete="new-password"
              disabled={submitting}
              maxLength={16384}
              onChange={(event) => setValue(event.target.value)}
              required
              spellCheck={false}
              style={{ minHeight: 44, padding: "0.7rem" }}
              type="password"
              value={value}
            />
          </div>
          <div style={{ display: "grid", gap: "0.35rem" }}>
            <label htmlFor="create-secret-env">Environment</label>
            <select
              id="create-secret-env"
              disabled={submitting}
              onChange={(event) => setEnvironment(event.target.value as SecretEnvironment)}
              style={{ minHeight: 44, padding: "0.7rem" }}
              value={environment}
            >
              <option value="development">Development</option>
              <option value="test">Test</option>
              <option value="staging">Staging</option>
              <option value="production">Production</option>
            </select>
          </div>
          <div style={{ display: "grid", gap: "0.35rem" }}>
            <label htmlFor="create-secret-desc">Description</label>
            <textarea
              id="create-secret-desc"
              disabled={submitting}
              maxLength={1000}
              onChange={(event) => setDescription(event.target.value)}
              rows={3}
              style={{ padding: "0.7rem" }}
              value={description}
            />
          </div>
          <button aria-busy={submitting} disabled={submitting} style={{ minHeight: 44, width: "fit-content" }} type="submit">
            {submitting ? "Encrypting…" : "Create write-only secret"}
          </button>
        </form>
      </Card>

      {replacementId && activeReplacementSecret ? (
        <Card>
          <h2 id="replace-secret-heading" style={{ marginTop: 0 }}>
            Replace value for {activeReplacementSecret.name}
          </h2>
          <form aria-labelledby="replace-secret-heading" onSubmit={replace} style={{ display: "grid", gap: "1rem" }}>
            <div style={{ display: "grid", gap: "0.35rem" }}>
              <label htmlFor="replace-secret-value">New secret value</label>
              <input
                id="replace-secret-value"
                autoComplete="new-password"
                disabled={replacing}
                maxLength={16384}
                onChange={(event) => setReplacementValue(event.target.value)}
                required
                spellCheck={false}
                style={{ minHeight: 44, padding: "0.7rem" }}
                type="password"
                value={replacementValue}
              />
            </div>
            <div style={{ display: "grid", gap: "0.35rem" }}>
              <label htmlFor="replace-secret-env">Environment</label>
              <select
                id="replace-secret-env"
                disabled={replacing}
                onChange={(event) => setReplacementEnvironment(event.target.value as SecretEnvironment)}
                style={{ minHeight: 44, padding: "0.7rem" }}
                value={replacementEnvironment}
              >
                <option value="development">Development</option>
                <option value="test">Test</option>
                <option value="staging">Staging</option>
                <option value="production">Production</option>
              </select>
            </div>
            <div style={{ display: "grid", gap: "0.35rem" }}>
              <label htmlFor="replace-secret-desc">Description</label>
              <textarea
                id="replace-secret-desc"
                disabled={replacing}
                maxLength={1000}
                onChange={(event) => setReplacementDescription(event.target.value)}
                rows={3}
                style={{ padding: "0.7rem" }}
                value={replacementDescription}
              />
            </div>
            <div style={{ display: "flex", gap: "0.75rem" }}>
              <button aria-busy={replacing} disabled={replacing} style={{ minHeight: 44 }} type="submit">
                {replacing ? "Replacing…" : "Replace encrypted value"}
              </button>
              <button
                aria-label={`Cancel replacement for ${activeReplacementSecret.name}`}
                disabled={replacing}
                onClick={() => setReplacementId("")}
                style={{ minHeight: 44 }}
                type="button"
              >
                Cancel
              </button>
            </div>
          </form>
        </Card>
      ) : null}

      <section aria-labelledby="secret-list-heading">
        <h2 id="secret-list-heading">Secret metadata</h2>
        {loading ? (
          <p aria-live="polite" role="status">Loading secret metadata…</p>
        ) : secrets.length === 0 ? (
          <Card><p style={{ margin: 0 }}>No project secrets exist. Values will remain write-only after creation.</p></Card>
        ) : (
          <ul style={{ display: "grid", gap: "1rem", listStyle: "none", margin: 0, padding: 0 }}>
            {secrets.map((secret) => (
              <li key={secret.id}>
                <Card>
                  <div style={{ alignItems: "start", display: "flex", gap: "1rem", justifyContent: "space-between" }}>
                    <div>
                      <h3 style={{ marginTop: 0 }}>{secret.name}</h3>
                      <p>{secret.description ?? "No description supplied."}</p>
                      <p style={{ color: "var(--muted-foreground)" }}>
                        {secret.environment} · encrypted value present · version {secret.version}
                      </p>
                    </div>
                    <StatusBadge tone="success">Encrypted</StatusBadge>
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem" }}>
                    <button
                      aria-label={`Replace value for ${secret.name}`}
                      onClick={() => selectForReplacement(secret)}
                      style={{ minHeight: 44 }}
                      type="button"
                    >
                      Replace value
                    </button>
                    {deleteTargetId === secret.id ? (
                      <>
                        <button
                          aria-busy={deleting}
                          aria-label={`Confirm deletion of ${secret.name}`}
                          disabled={deleting}
                          onClick={() => void remove(secret.id)}
                          style={{ minHeight: 44 }}
                          type="button"
                        >
                          Confirm delete
                        </button>
                        <button
                          aria-label={`Cancel deletion of ${secret.name}`}
                          disabled={deleting}
                          onClick={() => setDeleteTargetId(null)}
                          style={{ minHeight: 44 }}
                          type="button"
                        >
                          Cancel
                        </button>
                      </>
                    ) : (
                      <button
                        aria-label={`Delete ${secret.name}`}
                        onClick={() => setDeleteTargetId(secret.id)}
                        style={{ minHeight: 44 }}
                        type="button"
                      >
                        Delete
                      </button>
                    )}
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
