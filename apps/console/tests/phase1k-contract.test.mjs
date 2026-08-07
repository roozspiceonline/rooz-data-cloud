import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("Phase 1K console exposes versioned web-fetch safety evidence", async () => {
  const source = await readFile(
    new URL("../src/components/execution-plane-overview.tsx", import.meta.url),
    "utf8",
  );

  assert.match(source, /Phase 1K/);
  assert.match(source, /Phase 1J/);
  assert.match(source, /Versioned web fetch/);
  assert.match(source, /top-level web_fetch/);
  assert.match(source, /rdc\.web-fetch\/v1/);
  assert.match(source, /_rdc_web_fetch_result/);
  assert.match(source, /rdc\.web-fetch-result\/v1/);
  assert.match(source, /SHA-256 lineage/);
  assert.match(source, /Agent container stays --network none/);
  assert.match(source, /web-egress gate defaults off/);
  assert.match(source, /General untrusted execution remains release-blocked/);

  assert.doesNotMatch(
    source,
    /Authorization credential|cookie jar|proxy credential|project secret/i,
  );
});
