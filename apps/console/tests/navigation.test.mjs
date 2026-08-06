import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

test("approved project navigation is present", async () => {
  const source = await readFile(new URL("../src/lib/navigation.ts", import.meta.url), "utf8");
  assert.match(source, /dashboard/);
  assert.match(source, /agents/);
  assert.match(source, /runs/);
});

test("browser credential storage is not introduced", async () => {
  const source = await readFile(new URL("../../../packages/api-client/src/index.ts", import.meta.url), "utf8");
  assert.doesNotMatch(source, /localStorage|sessionStorage/);
});
