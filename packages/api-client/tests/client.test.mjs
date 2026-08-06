import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("client uses cookie credentials and approved CSRF header", async () => {
  const source = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");
  assert.match(source, /credentials: "include"/);
  assert.match(source, /X-RDC-CSRF/);
  assert.doesNotMatch(source, /localStorage|sessionStorage/);
});

test("client exposes Run commands and credentialed SSE URL support", async () => {
  const source = await readFile(new URL("../src/index.ts", import.meta.url), "utf8");
  assert.match(source, /createRun/);
  assert.match(source, /cancelRun/);
  assert.match(source, /Idempotency-Key/);
  assert.match(source, /runEventsUrl/);
  assert.match(source, /last_event_id/);
});
