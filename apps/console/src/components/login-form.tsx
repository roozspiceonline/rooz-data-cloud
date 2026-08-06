"use client";

import { useRouter } from "next/navigation";
import { FormEvent, useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

export function LoginForm() {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);

    const form = new FormData(event.currentTarget);
    const email = String(form.get("email") ?? "").trim();
    const password = String(form.get("password") ?? "");

    try {
      await rdcApi.login(email, password);
      router.replace("/console/select-org");
      router.refresh();
    } catch {
      setError("Invalid email address or password.");
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form noValidate onSubmit={submit} style={{ display: "grid", gap: "1rem" }}>
      <div style={{ display: "grid", gap: "0.4rem" }}>
        <label htmlFor="login-email">Email address</label>
        <input
          aria-describedby={error ? "login-error" : undefined}
          aria-invalid={error ? true : undefined}
          autoComplete="email"
          disabled={submitting}
          id="login-email"
          name="email"
          required
          type="email"
          style={{ minHeight: 44, padding: "0.7rem" }}
        />
      </div>

      <div style={{ display: "grid", gap: "0.4rem" }}>
        <label htmlFor="login-password">Password</label>
        <input
          aria-describedby={error ? "login-error" : undefined}
          aria-invalid={error ? true : undefined}
          autoComplete="current-password"
          disabled={submitting}
          id="login-password"
          name="password"
          required
          type="password"
          style={{ minHeight: 44, padding: "0.7rem" }}
        />
      </div>

      {error ? (
        <p
          aria-live="assertive"
          id="login-error"
          role="alert"
          style={{ color: "var(--danger)", margin: 0 }}
        >
          {error}
        </p>
      ) : null}

      <button
        aria-busy={submitting}
        disabled={submitting}
        style={{ minHeight: 44 }}
        type="submit"
      >
        {submitting ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
