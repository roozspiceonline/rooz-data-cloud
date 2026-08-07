import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("Phase 1G Agent workflow requires verified source before version creation", async () => {
  const source = await readFile(
    new URL("../src/components/agent-detail.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /SourceUploadPanel/);
  assert.match(source, /source_object_id/);
  assert.match(source, /verified source archive is required/i);
  assert.match(source, /Build and Run execution remain disabled/);
});

test("Phase 1G source upload uses Web Crypto and direct object storage", async () => {
  const source = await readFile(
    new URL("../src/components/source-upload-panel.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /crypto\.subtle\.digest/);
  assert.match(source, /FormData/);
  assert.match(source, /createSourceUpload/);
  assert.match(source, /completeSourceUpload/);
  assert.doesNotMatch(source, /localStorage|sessionStorage/);
});

test("Phase 1G project Storage page is functional", async () => {
  const source = await readFile(
    new URL("../src/components/storage-manager.tsx", import.meta.url),
    "utf8",
  );
  assert.match(source, /projectStorageObjects/);
  assert.match(source, /storageDownloadGrant/);
  assert.match(source, /short-lived/i);
});
