// v1.22 Phase 1 — CI sentinel: 3-manifest version sync (NEW-4 closure).
//
// Closes the multi-cycle drift class first opened at v1.19.0 release
// (where only .claude-plugin/package.json was bumped; marketplace.json
// stuck at 1.18.0 and plugin.json stuck at 1.10.0 — 9-release drift).
//
// `scripts/sync-manifest-versions.sh` + `validate.sh` integration catches
// drift at developer-write-time (fast feedback during pre-commit).
// THIS test runs inside `bun test` (the existing required CI gate) so
// drift is caught even when a developer skips the shell wrapper.
//
// Defense-in-depth pairing per docs/v1.22-structural-fixes.md §2.2 +
// Q2 LOCKED (BOTH ship): script + test together; either alone leaves a
// drift escape hatch.
//
// Asserts ALL 3 manifest versions match — not 2-of-3. Drift in ANY
// direction (package.json bumped but marketplace lags; or marketplace
// typo'd; or plugin.json behind) fails loudly with a clear error
// message pointing at the diverged file.

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

// `import.meta.dir` resolves to the directory of THIS test file
// (.claude-plugin/src). The 3 manifests live one level up at
// .claude-plugin/{package,marketplace,plugin}.json.
const PLUGIN_DIR = join(import.meta.dir, "..");
const PKG_PATH = join(PLUGIN_DIR, "package.json");
const MKT_PATH = join(PLUGIN_DIR, "marketplace.json");
const PLG_PATH = join(PLUGIN_DIR, "plugin.json");

describe("manifest version sync sentinel (v1.22 NEW-4 closure)", () => {
  test("all 3 manifests have parseable JSON", () => {
    expect(() => JSON.parse(readFileSync(PKG_PATH, "utf8"))).not.toThrow();
    expect(() => JSON.parse(readFileSync(MKT_PATH, "utf8"))).not.toThrow();
    expect(() => JSON.parse(readFileSync(PLG_PATH, "utf8"))).not.toThrow();
  });

  test("marketplace.json contains exactly 1 plugin entry", () => {
    // Pre-condition for the sync invariant — the sync script targets
    // plugins[0].version. If the marketplace grows to multiple plugins
    // (extremely unlikely for safespace-mcp), the sync script + this
    // test must be revisited together.
    const mkt = JSON.parse(readFileSync(MKT_PATH, "utf8"));
    expect(Array.isArray(mkt.plugins)).toBe(true);
    expect(mkt.plugins.length).toBe(1);
  });

  test("package.json + marketplace.json + plugin.json versions MUST all match", () => {
    const pkg = JSON.parse(readFileSync(PKG_PATH, "utf8"));
    const mkt = JSON.parse(readFileSync(MKT_PATH, "utf8"));
    const plg = JSON.parse(readFileSync(PLG_PATH, "utf8"));

    const pkgVersion: unknown = pkg.version;
    const mktVersion: unknown = mkt.plugins?.[0]?.version;
    const plgVersion: unknown = plg.version;

    // Source of truth: package.json (SERVER_VERSION imports from here
    // per issue #115/#117). Both downstream manifests MUST mirror it.
    expect(typeof pkgVersion).toBe("string");
    expect(pkgVersion).toMatch(/^\d+\.\d+\.\d+/);
    expect(mktVersion).toBe(pkgVersion);
    expect(plgVersion).toBe(pkgVersion);
  });
});
