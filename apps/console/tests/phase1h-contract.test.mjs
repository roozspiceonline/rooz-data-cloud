import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("Phase 1H console explains attested sandbox gating", async () => {
  const source = await readFile(
    new URL("../src/components/execution-plane-overview.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /Phase 1H/);
  assert.match(source, /explicitly attested workers/);
  assert.match(source, /global gate remains off/);
  assert.doesNotMatch(source, /worker token|lease_token|secret-envelope/i);
});
