import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

const read = (path) =>
  readFile(new URL(path, import.meta.url), "utf8");

test("approved project navigation is present", async () => {
  const source = await read("../src/lib/navigation.ts");
  assert.match(source, /dashboard/);
  assert.match(source, /agents/);
  assert.match(source, /runs/);
});

test("browser credential storage is not introduced", async () => {
  const source = await read(
    "../../../packages/api-client/src/index.ts",
  );
  assert.doesNotMatch(source, /localStorage|sessionStorage/);
});

test("the global layout owns the single skip link", async () => {
  const rootLayout = await read("../src/app/layout.tsx");
  const projectShell = await read(
    "../src/components/project-shell.tsx",
  );
  assert.match(rootLayout, /className="skip-link"/);
  assert.doesNotMatch(projectShell, /className="skip-link"/);
});

test("project navigation exposes active and disabled states", async () => {
  const source = await read(
    "../src/components/project-shell.tsx",
  );
  assert.match(source, /usePathname/);
  assert.match(source, /aria-current/);
  assert.match(source, /aria-disabled="true"/);
  assert.match(source, /if \(item\.future\)/);
});

test("the shell has a mobile layout boundary", async () => {
  const source = await read("../src/app/globals.css");
  assert.match(source, /\.shell-body/);
  assert.match(source, /@media \(max-width: 768px\)/);
});

test("status badges include a theme-aware background tint", async () => {
  const source = await read(
    "../../../packages/ui/src/status-badge.tsx",
  );
  assert.match(source, /color-mix/);
});
