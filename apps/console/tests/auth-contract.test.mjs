import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("auth client stores CSRF only in module memory", async () => {
  const source = await readFile(
    new URL(
      "../../../packages/api-client/src/index.ts",
      import.meta.url,
    ),
    "utf8",
  );
  assert.match(source, /let csrfToken: string \| null = null/);
  assert.match(source, /credentials: "include"/);
  assert.doesNotMatch(source, /localStorage|sessionStorage/);
});

test("login form exposes accessible error behavior", async () => {
  const source = await readFile(
    new URL("../src/components/login-form.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /role="alert"/);
  assert.match(source, /autoComplete="email"/);
  assert.match(source, /autoComplete="current-password"/);
});

test("organization selector uses authorized API results", async () => {
  const source = await readFile(
    new URL(
      "../src/components/organization-selector.tsx",
      import.meta.url,
    ),
    "utf8",
  );
  assert.match(source, /rdcApi\.organizations/);
  assert.match(source, /rdcApi\.projects/);
  assert.doesNotMatch(source, /org_demo|project_demo/);
});
