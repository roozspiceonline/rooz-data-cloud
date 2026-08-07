import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("Phase 1J console explains brokered web-egress boundary", async () => {
  const source = await readFile(
    new URL("../src/components/execution-plane-overview.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /Phase 1J/);
  assert.match(source, /Brokered HTTPS canary/);
  assert.match(source, /Agent container stays --network none/);
  assert.match(source, /operator allowlist/);
  assert.match(source, /GET\/HEAD/);
  assert.match(source, /defaults off/);
  assert.match(source, /General untrusted execution remains release-blocked/);
  assert.doesNotMatch(
    source,
    /worker token|lease_token|secret-envelope|Authorization credential/i,
  );
});
