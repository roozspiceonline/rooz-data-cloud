import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

async function source(path) {
  return readFile(new URL(path, import.meta.url), "utf8");
}

test("Agent API client uses approved registry endpoints and ETags", async () => {
  const client = await source("../../../packages/api-client/src/index.ts");
  assert.match(client, /\/projects\/\$\{encodeURIComponent\(projectId\)\}\/agents/);
  assert.match(client, /\/agents\/\$\{encodeURIComponent\(agentId\)\}\/versions/);
  assert.match(client, /If-Match/);
  assert.doesNotMatch(client, /localStorage|sessionStorage/);
});

test("Agent registry has accessible loading and empty states", async () => {
  const registry = await source("../src/components/agent-registry.tsx");
  assert.match(registry, /aria-live="polite"/);
  assert.match(registry, /No Agents exist in this project/);
  assert.match(registry, /Create Agent/);
});

test("Agent version UI states that execution remains disabled", async () => {
  const detail = await source("../src/components/agent-detail.tsx");
  assert.match(detail, /immutable version/i);
  assert.match(detail, /Build and Run\s+execution remain disabled/);
  assert.doesNotMatch(detail, /eval\(|new Function|child_process/);
});
