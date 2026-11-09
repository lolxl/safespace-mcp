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

test("stdio is the only transport: the bootstrap opens no network listener", () => {
  // SafeSpace serves MCP over stdio only. A regression that reintroduced a network
  // listener (an http/net server, or a transport module) would expose the tool
  // surface to the network without an identity layer — fail it here.
  expect(proxySrc).toMatch(/import\s+\{\s*createStdioTransport\s*\}\s+from\s+["']\.\/stdio-transport["']/);
  expect(proxySrc).toMatch(/\.connect\(createStdioTransport\(\)\)/);
  expect(proxySrc).not.toMatch(/from\s+["']node:(http|https|net)["']/);
  expect(proxySrc).not.toMatch(/from\s+["']\.\/transport\//);
  expect(proxySrc).not.toMatch(/\b(createServer|listen)\(/);
});
