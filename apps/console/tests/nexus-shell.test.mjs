import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";

const navigationUrl = new URL("../src/lib/navigation.ts", import.meta.url);
const shellUrl = new URL("../src/components/project-shell.tsx", import.meta.url);
const stylesUrl = new URL("../src/app/globals.css", import.meta.url);

test("NEXUS navigation groups operational and planned capabilities", async () => {
  const source = await readFile(navigationUrl, "utf8");

  for (const section of [
    "Overview",
    "Build",
    "Execute",
    "Data",
    "Network",
    "Automate",
    "Observe",
    "Usage",
    "Security",
    "Developer",
    "Project",
  ]) {
    assert.match(source, new RegExp(`label: "${section}"`));
  }

  assert.match(source, /availability: "available"/);
  assert.match(source, /availability: "foundation"/);
  assert.match(source, /availability: "planned"/);
  assert.match(source, /href: "\/dashboard"/);
  assert.match(source, /href: "\/runs"/);
  assert.doesNotMatch(source, /href: "\/pipelines"/);
  assert.doesNotMatch(source, /href: "\/connectors"/);
});

test("NEXUS shell provides responsive and keyboard navigation affordances", async () => {
  const [shell, styles] = await Promise.all([
    readFile(shellUrl, "utf8"),
    readFile(stylesUrl, "utf8"),
  ]);

  assert.match(shell, /Meta\+K Control\+K/);
  assert.match(shell, /aria-label="RDC NEXUS dashboard"/);
  assert.match(shell, /aria-label="Open command navigation"/);
  assert.match(shell, /role="dialog"/);
  assert.match(shell, /role="combobox"/);
  assert.match(shell, /aria-current=/);
  assert.match(shell, /aria-disabled=/);
  assert.match(shell, /Mobile navigation drawer/);
  assert.match(styles, /@media \(max-width: 959px\)/);
  assert.match(styles, /prefers-reduced-motion/);
});

test("NEXUS tokens cover control-plane surfaces and runtime states", async () => {
  const styles = await readFile(stylesUrl, "utf8");

  for (const token of [
    "--canvas",
    "--surface-raised",
    "--border-subtle",
    "--text-secondary",
    "--accent-muted",
    "--queued",
    "--running",
    "--succeeded",
    "--failed",
    "--cancelled",
    "--retrying",
    "--paused",
    "--unhealthy",
    "--disabled",
    "--degraded",
  ]) {
    assert.match(styles, new RegExp(token));
  }
});
