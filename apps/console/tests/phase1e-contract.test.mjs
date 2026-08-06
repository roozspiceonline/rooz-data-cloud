import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

async function source(path) {
  return readFile(new URL(path, import.meta.url), "utf8");
}

test("Run client exposes idempotent commands and SSE URL support", async () => {
  const client = await source("../../../packages/api-client/src/index.ts");
  assert.match(client, /createRun/);
  assert.match(client, /cancelRun/);
  assert.match(client, /Idempotency-Key/);
  assert.match(client, /runEventsUrl/);
  assert.match(client, /last_event_id/);
  assert.doesNotMatch(client, /localStorage|sessionStorage/);
});

test("Run console preserves the isolated execution boundary", async () => {
  const component = await source("../src/components/run-control-plane.tsx");
  assert.match(component, /Run control plane/);
  assert.match(component, /Server-Sent Events/);
  assert.match(component, /EventSource/);
  assert.match(component, /No Agent code executes/);
  assert.match(component, /successful Build artifact/i);
  assert.doesNotMatch(component, /child_process|new Function|eval\(/);
});

test("Run console exposes cancellation and accessible live states", async () => {
  const component = await source("../src/components/run-control-plane.tsx");
  assert.match(component, /Cancel Run/);
  assert.match(component, /aria-live="polite"/);
  assert.match(component, /Reconnecting/);
  assert.match(component, /run\.replay_reset/);
  assert.match(component, /run\.heartbeat/);
});
