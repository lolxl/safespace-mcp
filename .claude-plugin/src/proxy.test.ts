import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const proxySrc = readFileSync(join(here, "proxy.ts"), "utf8");

// v1.73 — proxy.ts is the thin bootstrap: it builds the server via the
// createMcpServer factory (./server) and dispatches the configured transport.
// (The SERVER_VERSION #115 regression-lock moved to server.test.ts with the
// constant.) These source-text locks defend the two security-critical invariants
// of the bootstrap:

test("proxy.ts builds the server via the createMcpServer factory (./server)", () => {
  expect(proxySrc).toMatch(
    /import\s+\{\s*createMcpServer\s*\}\s+from\s+["']\.\/server["']/,
  );
});

test("stdio is the DEFAULT transport; http is opt-in (Model A byte-identical regression-lock)", () => {
  // The http listener is GUARDED behind transportMode()==="http"; the unguarded
  // default path connects StdioServerTransport. A regression that flipped the
  // default to http (network exposure WITHOUT an explicit opt-in) would break
  // these two assertions — the load-bearing safety property of v1.73 PR-1.
  expect(proxySrc).toMatch(/transportMode\(\)\s*===\s*["']http["']/);
  expect(proxySrc).toMatch(/new StdioServerTransport\(\)/);
});

// v1.74 PR-2b — the http transport is Model B = operator auth is MANDATORY. The
// bootstrap MUST load + validate the operators registry and pass it to
// startHttpServer; a regression that dropped the registry would serve HTTP with NO
// per-connection identity. These source-text locks defend that invariant.
// (v1.80 PR-3: the registry is constructed via the hot-reloading
// `createRegistryProvider`, whose INITIAL load keeps the same fail-loud posture.)
test("http bootstrap loads the operators registry + passes it to startHttpServer (PR-2b/PR-3)", () => {
  expect(proxySrc).toMatch(
    /import\s+\{[^}]*\bcreateRegistryProvider\b[^}]*\}\s+from\s+["']\.\/identity\/operator-registry["']/,
  );
  expect(proxySrc).toMatch(/createRegistryProvider\(/);
  // the registry must reach the listener (not loaded-then-ignored)
  expect(proxySrc).toMatch(/startHttpServer\(\s*createMcpServer\s*,\s*\{[^}]*registry[^}]*\}/s);
  // v1.80 — the reload-time cross-check re-reads accounts.json (loadKnownAccounts
  // is a FUNCTION handed to the provider, never a startup snapshot).
  expect(proxySrc).toMatch(/loadKnownAccounts:\s*async\s*\(\)/);
});
