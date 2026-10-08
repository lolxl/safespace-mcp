// v1.67 D8 — config catalog + readStrictTruthy + drift sentinels.

import { describe, test, expect, afterEach } from "bun:test";
import { Glob } from "bun";
import * as path from "node:path";
import * as config from "./config";
import { readStrictTruthy } from "./config";

// A throwaway env name no production code reads (double underscore, like
// burst.test.ts's SAFESPACE__BURST_TEST_LIMIT) so toggling it can't perturb a
// real gate.
const TEST_VAR = "SAFESPACE__CONFIG_STRICT_TRUTHY_TEST";

afterEach(() => {
  delete process.env[TEST_VAR];
});

describe("readStrictTruthy", () => {
  test("true ONLY for the literal lowercase 'true'", () => {
    process.env[TEST_VAR] = "true";
    expect(readStrictTruthy(TEST_VAR)).toBe(true);
  });

  // Every value a typo / shell / dotenv loader might produce → false. This is
  // the load-bearing security property: a flag can never be widened by accident.
  for (const v of ["True", "TRUE", "TrUe", "1", "yes", "on", "false", "", " true ", "true\n", "0"]) {
    test(`false for ${JSON.stringify(v)}`, () => {
      process.env[TEST_VAR] = v;
      expect(readStrictTruthy(TEST_VAR)).toBe(false);
    });
  }

  test("false when unset", () => {
    delete process.env[TEST_VAR];
    expect(readStrictTruthy(TEST_VAR)).toBe(false);
  });

  test("reads LIVE on every call (never snapshots)", () => {
    delete process.env[TEST_VAR];
    expect(readStrictTruthy(TEST_VAR)).toBe(false);
    process.env[TEST_VAR] = "true"; // a shell exports it mid-session…
    expect(readStrictTruthy(TEST_VAR)).toBe(true); // …and the next call sees it.
  });
});

describe("env-name catalog", () => {
  const names = Object.entries(config).filter(
    ([k, v]) => k.startsWith("ENV_") && typeof v === "string",
  ) as [string, string][];

  test("every ENV_* const is a non-empty SAFESPACE_-prefixed string", () => {
    for (const [k, v] of names) {
      expect(v.startsWith("SAFESPACE_"), `${k}=${v}`).toBe(true);
      expect(v.length).toBeGreaterThan("SAFESPACE_".length);
      // Names are UPPER_SNAKE — no whitespace / lowercase / punctuation that a
      // typo'd literal could carry.
      expect(/^SAFESPACE_[A-Z0-9_]+$/.test(v), `${k}=${v}`).toBe(true);
    }
  });

  test("no two catalog entries share a value (a dup would mask a rename)", () => {
    const values = names.map(([, v]) => v);
    expect(new Set(values).size).toBe(values.length);
  });

  test("the catalog is non-trivial (the whole SAFESPACE_* surface, ~30)", () => {
    expect(names.length).toBeGreaterThanOrEqual(25);
  });
});

// ── Drift sentinels — config.ts is the SINGLE source of truth ──────────────
// These walk every non-test source file and FAIL CI if a future connector
// reintroduces an env read via a `SAFESPACE_` literal, or a bare strict-truthy
// compare, instead of going through the catalog + readStrictTruthy. This is the
// mechanism that keeps the v1.67 centralization from silently eroding.
describe("drift sentinels", () => {
  const SRC = import.meta.dir; // = src/
  const files: string[] = [];
  for (const rel of new Glob("**/*.ts").scanSync(SRC)) {
    if (rel.endsWith(".test.ts")) continue;
    if (rel === "config.ts") continue;
    // The audit test preload (registered in bunfig.toml) is test infrastructure, not
    // product code: it points a run without SAFESPACE_CONFIG_DIR at a temp dir.
    if (rel === "test-preload-audit.ts") continue;
    files.push(rel);
  }

  test("source files were discovered (the walk is not vacuously passing)", () => {
    expect(files.length).toBeGreaterThan(50);
  });

  test("no env READ via a SAFESPACE_ literal outside config.ts", async () => {
    // process.env.SAFESPACE_X / process.env["SAFESPACE_X"] / env.SAFESPACE_X /
    // env["SAFESPACE_X"] — the read forms. Prose mentions ("SAFESPACE_X is set")
    // and `.includes("SAFESPACE_…")` migration parsing do NOT match.
    const READ_RE =
      /process\.env\.SAFESPACE_|process\.env\[\s*["']SAFESPACE_|[^a-zA-Z_]env\.SAFESPACE_|[^a-zA-Z_]env\[\s*["']SAFESPACE_/;
    const offenders: string[] = [];
    for (const rel of files) {
      const text = await Bun.file(path.join(SRC, rel)).text();
      if (READ_RE.test(text)) offenders.push(rel);
    }
    expect(offenders).toEqual([]);
  });

  test('no bare `process.env[...] === "true"` outside config.ts (use readStrictTruthy)', async () => {
    const TRUTHY_RE = /process\.env\[[^\]]*\]\s*===\s*["']true["']/;
    const offenders: string[] = [];
    for (const rel of files) {
      const text = await Bun.file(path.join(SRC, rel)).text();
      if (TRUTHY_RE.test(text)) offenders.push(rel);
    }
    expect(offenders).toEqual([]);
  });
});
