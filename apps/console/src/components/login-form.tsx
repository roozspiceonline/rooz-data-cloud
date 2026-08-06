"use client";

import { RdcApiError } from "@rdc/api-client";
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
    const email = String(form.get("email") ?? "");
    const password = String(form.get("password") ?? "");

    try {
      await rdcApi.login(email, password);
      router.replace("/console/select-org");
      router.refresh();
    } catch (caught) {
      setError(
        caught instanceof RdcApiError
          ? caught.message
          : "Sign in could not be completed.",
      );
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={submit} style={{ display: "grid", gap: "1rem" }}>
      <div style={{ display: "grid", gap: "0.4rem" }}>
        <label htmlFor="email">Email address</label>
        <input
          autoComplete="email"
          id="email"
          name="email"
          required
          type="email"
          style={{ minHeight: 44, padding: "0.7rem" }}
        />
      </div>

      <div style={{ display: "grid", gap: "0.4rem" }}>
        <label htmlFor="password">Password</label>
        <input
          autoComplete="current-password"
          id="password"
          name="password"
          required
          type="password"
          style={{ minHeight: 44, padding: "0.7rem" }}
        />
      </div>

      {error ? (
        <p role="alert" style={{ color: "var(--danger)", margin: 0 }}>
          {error}
        </p>
      ) : null}

      <button
        disabled={submitting}
        style={{ minHeight: 44 }}
        type="submit"
      >
        {submitting ? "Signing in…" : "Sign in"}
      </button>
    </form>
  );
}
