import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("Phase 1F console exposes metadata-only execution visibility", async () => {
  const source = await readFile(
    new URL("../src/components/execution-plane-overview.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /projectExecutionLeases/);
  assert.match(source, /projectExecutionArtifacts/);
  assert.match(source, /general untrusted execution/i);
  assert.doesNotMatch(source, /worker token|lease_token|secret-envelope/i);
});
