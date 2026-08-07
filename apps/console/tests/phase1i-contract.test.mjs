import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("Phase 1I console explains exact canary activation", async () => {
  const source = await readFile(
    new URL("../src/components/execution-plane-overview.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /Phase 1I/);
  assert.match(source, /one configured immutable AgentVersion/);
  assert.match(source, /single-concurrency worker/);
  assert.match(source, /master gate and canary mode/);
  assert.match(source, /General untrusted execution remains release-blocked/);
  assert.doesNotMatch(source, /worker token|lease_token|secret-envelope/i);
});
