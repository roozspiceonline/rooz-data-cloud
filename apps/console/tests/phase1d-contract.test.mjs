import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

async function source(path) {
  return readFile(new URL(path, import.meta.url), "utf8");
}

test("secret client exposes metadata-only write operations", async () => {
  const client = await source("../../../packages/api-client/src/index.ts");
  assert.match(client, /projectSecrets/);
  assert.match(client, /replaceProjectSecret/);
  assert.match(client, /Idempotency-Key/);
  assert.match(client, /If-Match/);
  assert.doesNotMatch(client, /revealSecret|getSecretValue/);
  assert.doesNotMatch(client, /localStorage|sessionStorage/);
});

test("secret UI has no reveal action and clears values", async () => {
  const component = await source("../src/components/project-secret-manager.tsx");
  assert.match(component, /type="password"/);
  assert.match(component, /setValue\(""\)/);
  assert.match(component, /setReplacementValue\(""\)/);
  assert.match(component, /there is no reveal action/i);
  assert.doesNotMatch(component, /Show secret|Reveal secret/);
});

test("Build UI preserves isolated execution boundary", async () => {
  const component = await source("../src/components/build-control-plane.tsx");
  assert.match(component, /durable outbox/i);
  assert.match(component, /never invokes BuildKit/i);
  assert.doesNotMatch(component, /child_process|new Function|eval\(/);
});
