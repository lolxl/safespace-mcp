// Cold-path #1 — regression locks for the googleapis lazy-load deferral.
//
// The whole point of `lazy-google.ts`: the ~114 MB googleapis SDK must NOT be
// pulled onto the bootstrap import graph (createMcpServer spreads every handler
// fragment). A top-level VALUE import `import { google } from "googleapis"`
// re-introduces the eager parse and silently regresses cold-start for every
// transport — including the `npx safespace-mcp` path on a non-Google host. These
// tests lock both the runtime memo contract and the source-level invariant.

import { describe, expect, test } from "bun:test";
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { __resetGoogleMemoForTests, getGoogle } from "./lazy-google";

describe("lazy-google — cold-path #1 deferral", () => {
  test("getGoogle() resolves the real googleapis namespace and memoizes it", () => {
    __resetGoogleMemoForTests();
    const g1 = getGoogle();
    expect(typeof g1.gmail).toBe("function");
    expect(typeof g1.drive).toBe("function");
    expect(typeof g1.auth.OAuth2).toBe("function");
    // Second call returns the SAME memoized namespace — the resolve is paid once.
    expect(getGoogle()).toBe(g1);
  });

  test("__resetGoogleMemoForTests re-arms the lazy resolve without throwing", () => {
    const before = getGoogle();
    __resetGoogleMemoForTests();
    const after = getGoogle();
    expect(typeof after.youtube).toBe("function");
    // require() is module-cached, so re-resolving yields the same namespace object;
    // the contract is that reset re-resolves cleanly (mirrors keychain S6).
    expect(after).toBe(before);
  });

  test("no src module value-imports `google` from googleapis (deferral lock)", () => {
    // Every SDK-namespace import MUST be `import type { … } from "googleapis"`
    // (erased at compile time, zero runtime SDK load). The only runtime access to
    // the `google` VALUE is via getGoogle() → lazy `require("googleapis")`, which
    // is NOT an import statement and so never matches the value-import pattern.
    const srcRoot = join(import.meta.dir, "..");
    // Match any `import { … } from "googleapis"` (multiline); group 1 present iff
    // it is `import type` (the only allowed form).
    const googleapisImport = /import\s+(type\s+)?\{[\s\S]*?\}\s*from\s*["']googleapis["']/g;
    const offenders: string[] = [];

    const walk = (dir: string): void => {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        if (entry.isDirectory()) {
          if (entry.name === "node_modules") continue;
          walk(join(dir, entry.name));
          continue;
        }
        if (!entry.name.endsWith(".ts") || entry.name.endsWith(".test.ts")) continue;
        const file = join(dir, entry.name);
        const src = readFileSync(file, "utf8");
        for (let m = googleapisImport.exec(src); m !== null; m = googleapisImport.exec(src)) {
          if (!m[1]) offenders.push(file); // value import (no `type`) → regression
        }
      }
    };
    walk(srcRoot);

    expect(offenders).toEqual([]);
  });
});
