import { expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const serverSrc = readFileSync(join(here, "server.ts"), "utf8");

// Post-issue-#115 fix: SERVER_VERSION is derived from package.json import, not a
// hardcoded literal. v1.73 — the constant + createMcpServer factory moved out of
// proxy.ts into server.ts; the regression-lock follows it here. Defense-in-depth:
// assert the structural pattern so a future regression re-introducing a hardcoded
// literal fails fast.
test("SERVER_VERSION in server.ts is derived from package.json (issue #115 regression-lock)", () => {
  expect(serverSrc).toMatch(/import\s+pkg\s+from\s+["']\.\.\/package\.json["']/);
  expect(serverSrc).toMatch(/^const SERVER_VERSION = pkg\.version;$/m);
  expect(serverSrc).not.toMatch(/^const SERVER_VERSION = "[0-9.]+";$/m);
});
