import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("Phase 1H sandbox boundary remains visible in later phases", async () => {
  const source = await readFile(
    new URL("../src/components/execution-plane-overview.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /Phase 1(?:H|I)/);
  assert.match(source, /General untrusted execution remains release-blocked/);
  assert.doesNotMatch(source, /worker token|lease_token|secret-envelope/i);
});
