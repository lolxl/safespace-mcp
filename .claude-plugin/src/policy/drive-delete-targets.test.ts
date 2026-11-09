// drive_trash_file / drive_delete_file target allowlist — policy module tests.
// Pure parse/state/decision tests; the handler-level gate-before-SDK tests live in
// src/tools/drive-delete.test.ts.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  __internal,
  buildDriveDeleteAllowlistState,
  checkDriveDeleteAllowed,
  ENV_TARGETS,
  ENV_TARGETS_EXTRA,
  getDriveDeleteAllowlistState,
  parseDriveDeleteTargets,
  summarizeDriveDeleteAllowlist,
} from "./drive-delete-targets";
import { MAX_WALK_DEPTH, type AncestorFetcher } from "./drive-whitelist";
import { ENV_AUTONOMOUS } from "./autonomous-mode";

const F1 = "1FolderAAAAAAAAAAAAAAAA";
const F2 = "1FolderBBBBBBBBBBBBBBBB";
const FILE_A = "1FileAAAAAAAAAAAAAAAAAA";
const FILE_B = "1FileBBBBBBBBBBBBBBBBBB";

/** Build a fetcher from a child→parents map; records every fetched id. */
function fetcherFor(tree: Record<string, string[]>, calls: string[] = []): AncestorFetcher {
  return async (id) => {
    calls.push(id);
    if (!(id in tree)) return { kind: "not_found" };
    return { kind: "ok", parents: tree[id]! };
  };
}

describe("parseDriveDeleteTargets", () => {
  test("parses folder: and file: entries, trims, dedups", () => {
    const r = parseDriveDeleteTargets(` folder:${F1} , file:${FILE_A},folder:${F1},,`);
    expect(r.folders).toEqual([F1]);
    expect(r.files).toEqual([FILE_A]);
    expect(r.rejected).toEqual([]);
  });

  test("undefined → empty", () => {
    expect(parseDriveDeleteTargets(undefined)).toEqual({ folders: [], files: [], rejected: [] });
  });

  test("malformed entries are rejected (bad prefix, case, short id, no colon, empty payload, metachar)", () => {
    const bad = [
      `Folder:${F1}`, // case-sensitive prefix
      `tasklist:${F1}`,
      `folder:short`,
      F1, // no prefix
      "folder:",
      ":" + F1,
      `file:${FILE_A};rm`,
      `folder:${F1}:extra`,
    ];
    const r = parseDriveDeleteTargets(bad.join(","));
    expect(r.folders).toEqual([]);
    expect(r.files).toEqual([]);
    expect(r.rejected).toEqual(bad);
  });
});

describe("buildDriveDeleteAllowlistState", () => {
  test("both undefined → off", () => {
    expect(buildDriveDeleteAllowlistState(undefined, undefined)).toEqual({ kind: "off" });
  });
  test("both undefined + autonomous → active-empty (deny all, F2)", () => {
    const s = buildDriveDeleteAllowlistState(undefined, undefined, true);
    expect(s.kind).toBe("active");
    if (s.kind === "active") {
      expect(s.folders.size + s.files.size).toBe(0);
    }
  });
  test("empty string → active (explicit)", () => {
    expect(buildDriveDeleteAllowlistState("", undefined).kind).toBe("active");
  });
  test("merges base + extra", () => {
    const s = buildDriveDeleteAllowlistState(`folder:${F1}`, `file:${FILE_A},folder:${F2}`);
    expect(s.kind).toBe("active");
    if (s.kind === "active") {
      expect([...s.folders].sort()).toEqual([F1, F2].sort());
      expect([...s.files]).toEqual([FILE_A]);
      expect(summarizeDriveDeleteAllowlist(s)).toEqual({ kind: "active", count: 3 });
    }
  });
  test("summary: off → count 0", () => {
    expect(summarizeDriveDeleteAllowlist({ kind: "off" })).toEqual({ kind: "off", count: 0 });
  });
});

describe("checkDriveDeleteAllowed", () => {
  test("off → allow with ZERO fetcher calls", async () => {
    const calls: string[] = [];
    const d = await checkDriveDeleteAllowed(FILE_A, { kind: "off" }, fetcherFor({}, calls));
    expect(d).toEqual({ allowed: true, reason: "policy_off" });
    expect(calls).toEqual([]);
  });

  test("active + file hit → allow, no fetch", async () => {
    const calls: string[] = [];
    const state = buildDriveDeleteAllowlistState(`file:${FILE_A}`, undefined);
    const d = await checkDriveDeleteAllowed(FILE_A, state, fetcherFor({}, calls));
    expect(d).toEqual({ allowed: true, reason: "direct_match" });
    expect(calls).toEqual([]);
  });

  test("active + listed folder itself → allow", async () => {
    const state = buildDriveDeleteAllowlistState(`folder:${F1}`, undefined);
    const d = await checkDriveDeleteAllowed(F1, state, fetcherFor({}));
    expect(d).toEqual({ allowed: true, reason: "direct_match" });
  });

  test("active + folder ancestor hit (grandparent) → allow", async () => {
    const state = buildDriveDeleteAllowlistState(`folder:${F1}`, undefined);
    const tree = { [FILE_A]: [F2], [F2]: [F1], [F1]: ["root"] };
    const d = await checkDriveDeleteAllowed(FILE_A, state, fetcherFor(tree));
    expect(d).toEqual({ allowed: true, reason: "ancestor_match" });
  });

  test("a file entry does NOT authorize its children via ancestry (files are leaf matches)", async () => {
    // MIXED config (a file entry + an UNRELATED folder entry) so the ancestor loop
    // actually runs; FILE_A is an ancestor of the target but only a file entry.
    const state = buildDriveDeleteAllowlistState(`file:${FILE_A},folder:${F2}`, undefined);
    const tree = { [FILE_B]: [FILE_A], [FILE_A]: [F1], [F1]: [] };
    const calls: string[] = [];
    const d = await checkDriveDeleteAllowed(FILE_B, state, fetcherFor(tree, calls));
    expect(d).toEqual({ allowed: false, reason: "not_in_allowlist" });
    expect(calls).toEqual([FILE_B, FILE_A, F1]); // the walk really ran past FILE_A
  });

  test("a file-only config (no listed folder) denies a non-listed target without any network", async () => {
    const state = buildDriveDeleteAllowlistState(`file:${FILE_A}`, undefined);
    const calls: string[] = [];
    const d = await checkDriveDeleteAllowed(FILE_B, state, fetcherFor({ [FILE_B]: [FILE_A] }, calls));
    expect(d).toEqual({ allowed: false, reason: "not_in_allowlist" });
    expect(calls).toEqual([]);
  });

  test("miss: fully resolved chain with no listed folder → not_in_allowlist", async () => {
    const state = buildDriveDeleteAllowlistState(`folder:${F1}`, undefined);
    const tree = { [FILE_A]: [F2], [F2]: ["root"], root: [] };
    const d = await checkDriveDeleteAllowed(FILE_A, state, fetcherFor(tree));
    expect(d).toEqual({ allowed: false, reason: "not_in_allowlist" });
  });

  test("active-but-empty → deny everything", async () => {
    const state = buildDriveDeleteAllowlistState("", undefined);
    const d = await checkDriveDeleteAllowed(FILE_A, state, fetcherFor({}));
    expect(d.allowed).toBe(false);
  });

  test("FAIL-CLOSED: fetcher throws → ancestry_unverifiable", async () => {
    const state = buildDriveDeleteAllowlistState(`folder:${F1}`, undefined);
    const d = await checkDriveDeleteAllowed(FILE_A, state, async () => {
      throw new Error("boom");
    });
    expect(d).toEqual({ allowed: false, reason: "ancestry_unverifiable" });
  });

  test("FAIL-CLOSED: not_found (missing metadata) → ancestry_unverifiable", async () => {
    const state = buildDriveDeleteAllowlistState(`folder:${F1}`, undefined);
    const d = await checkDriveDeleteAllowed(FILE_A, state, fetcherFor({}));
    expect(d).toEqual({ allowed: false, reason: "ancestry_unverifiable" });
  });

  test("FAIL-CLOSED: ancestor fetch fails midway (parent 404) → ancestry_unverifiable", async () => {
    const state = buildDriveDeleteAllowlistState(`folder:${F1}`, undefined);
    const tree = { [FILE_A]: [F2] }; // F2 itself unknown → not_found
    const d = await checkDriveDeleteAllowed(FILE_A, state, fetcherFor(tree));
    expect(d).toEqual({ allowed: false, reason: "ancestry_unverifiable" });
  });

  test("FAIL-CLOSED: malformed metadata (parents not an array) → ancestry_unverifiable", async () => {
    const state = buildDriveDeleteAllowlistState(`folder:${F1}`, undefined);
    const bad = (async () => ({ kind: "ok", parents: undefined })) as unknown as AncestorFetcher;
    const d = await checkDriveDeleteAllowed(FILE_A, state, bad);
    expect(d).toEqual({ allowed: false, reason: "ancestry_unverifiable" });
  });

  test("FAIL-CLOSED: chain deeper than MAX_WALK_DEPTH → ancestry_unverifiable, fetches bounded", async () => {
    const state = buildDriveDeleteAllowlistState(`folder:${F1}`, undefined);
    // Linear chain longer than the limit; the listed folder sits beyond it.
    const ids = Array.from({ length: MAX_WALK_DEPTH + 5 }, (_, i) => `1Chain${String(i).padStart(2, "0")}AAAAAAAAAAAAAAAA`);
    const tree: Record<string, string[]> = {};
    ids.forEach((id, i) => {
      tree[id] = [i + 1 < ids.length ? ids[i + 1]! : F1];
    });
    const calls: string[] = [];
    const d = await checkDriveDeleteAllowed(ids[0]!, state, fetcherFor(tree, calls));
    expect(d).toEqual({ allowed: false, reason: "ancestry_unverifiable" });
    expect(calls.length).toBe(MAX_WALK_DEPTH);
  });

  test("cycle in parents terminates (visited set) → not_in_allowlist", async () => {
    const state = buildDriveDeleteAllowlistState(`folder:${F1}`, undefined);
    const tree = { [FILE_A]: [F2], [F2]: [FILE_A] };
    const d = await checkDriveDeleteAllowed(FILE_A, state, fetcherFor(tree));
    expect(d).toEqual({ allowed: false, reason: "not_in_allowlist" });
  });

  test("ancestry is walked FRESH on every call (no cache): moving a file out of the folder flips the answer", async () => {
    const state = buildDriveDeleteAllowlistState(`folder:${F1}`, undefined);
    const tree: Record<string, string[]> = { [FILE_A]: [F1], [F1]: [] };
    const calls: string[] = [];
    const f = fetcherFor(tree, calls);
    expect((await checkDriveDeleteAllowed(FILE_A, state, f)).allowed).toBe(true);
    tree[FILE_A] = [F2]; // file moved elsewhere
    tree[F2] = [];
    expect((await checkDriveDeleteAllowed(FILE_A, state, f)).allowed).toBe(false);
    expect(calls.filter((c) => c === FILE_A).length).toBe(2);
  });

  test("empty fileId → deny", async () => {
    const state = buildDriveDeleteAllowlistState(`folder:${F1}`, undefined);
    expect((await checkDriveDeleteAllowed("", state, fetcherFor({}))).allowed).toBe(false);
  });
});

describe("getDriveDeleteAllowlistState — per-call env read", () => {
  const saved: Record<string, string | undefined> = {};
  beforeEach(() => {
    for (const k of [ENV_TARGETS, ENV_TARGETS_EXTRA, ENV_AUTONOMOUS]) {
      saved[k] = process.env[k];
      delete process.env[k];
    }
    __internal.resetSingletons();
  });
  afterEach(() => {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    __internal.resetSingletons();
  });

  test("unset → off", () => {
    expect(getDriveDeleteAllowlistState().kind).toBe("off");
  });

  test("env change is picked up WITHOUT a manual reset (not frozen at load)", () => {
    expect(getDriveDeleteAllowlistState().kind).toBe("off");
    process.env[ENV_TARGETS] = `folder:${F1}`;
    const s = getDriveDeleteAllowlistState();
    expect(s.kind).toBe("active");
    if (s.kind === "active") expect(s.folders.has(F1)).toBe(true);
    delete process.env[ENV_TARGETS];
    expect(getDriveDeleteAllowlistState().kind).toBe("off");
  });

  test("same env → same cached object; changed env → new object", () => {
    process.env[ENV_TARGETS] = `file:${FILE_A}`;
    const a = getDriveDeleteAllowlistState();
    expect(getDriveDeleteAllowlistState()).toBe(a);
    process.env[ENV_TARGETS_EXTRA] = `file:${FILE_B}`;
    const b = getDriveDeleteAllowlistState();
    expect(b).not.toBe(a);
    if (b.kind === "active") expect(b.files.size).toBe(2);
  });

  test("_EXTRA alone → active (flip warned on stderr)", () => {
    process.env[ENV_TARGETS_EXTRA] = `folder:${F1}`;
    expect(getDriveDeleteAllowlistState().kind).toBe("active");
  });

  test("autonomous + unset → active-empty (deny all)", () => {
    process.env[ENV_AUTONOMOUS] = "true";
    const s = getDriveDeleteAllowlistState();
    expect(s.kind).toBe("active");
    if (s.kind === "active") expect(s.folders.size + s.files.size).toBe(0);
  });

  test("malformed entries dropped with a stderr warning that names the entry", () => {
    const orig = console.error;
    const lines: string[] = [];
    console.error = (m: unknown) => {
      lines.push(String(m));
    };
    try {
      process.env[ENV_TARGETS] = `folder:${F1},bogus:xyz`;
      const s = getDriveDeleteAllowlistState();
      if (s.kind === "active") expect(s.folders.size).toBe(1);
    } finally {
      console.error = orig;
    }
    expect(lines.some((l) => l.includes("rejected malformed entry: bogus:xyz"))).toBe(true);
  });

  test("set but zero valid entries → loud deny-all warning", () => {
    const orig = console.error;
    const lines: string[] = [];
    console.error = (m: unknown) => {
      lines.push(String(m));
    };
    try {
      process.env[ENV_TARGETS] = "garbage";
      getDriveDeleteAllowlistState();
    } finally {
      console.error = orig;
    }
    expect(lines.some((l) => l.includes("yielded 0 valid entries"))).toBe(true);
  });
});
