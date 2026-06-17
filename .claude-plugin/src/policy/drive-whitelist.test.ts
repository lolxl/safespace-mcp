import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import {
  AncestorCache,
  type AncestorFetcher,
  DEFAULT_CACHE_TTL_MS,
  MAX_WALK_DEPTH,
  WHITELIST_FILENAME,
  type WhitelistFile,
  checkShareAllowed,
  isValidDriveId,
  loadWhitelist,
  saveWhitelist,
} from "./drive-whitelist";

let tmp: string;

beforeEach(async () => {
  tmp = await fs.mkdtemp(path.join(tmpdir(), "wl-test-"));
});

afterEach(async () => {
  await fs.rm(tmp, { recursive: true, force: true });
});

// ----- isValidDriveId -----

describe("isValidDriveId", () => {
  test("accepts 20+ char alnum + underscore + dash", () => {
    expect(isValidDriveId("1aBcDeFgHiJkLmNoPqRs")).toBe(true);
    expect(isValidDriveId("a".repeat(33))).toBe(true);
    expect(isValidDriveId("AAA_-bbb_-CCC_-ddd_-")).toBe(true);
  });

  test("rejects too-short", () => {
    expect(isValidDriveId("short")).toBe(false);
    expect(isValidDriveId("a".repeat(19))).toBe(false);
  });

  test("rejects empty + non-string", () => {
    expect(isValidDriveId("")).toBe(false);
    // @ts-expect-error — testing the non-string guard
    expect(isValidDriveId(undefined)).toBe(false);
    // @ts-expect-error
    expect(isValidDriveId(123)).toBe(false);
  });

  test("rejects shell metachars + path traversal attempts", () => {
    expect(isValidDriveId("a".repeat(20) + ";rm -rf")).toBe(false);
    expect(isValidDriveId("a".repeat(20) + "/etc/passwd")).toBe(false);
    expect(isValidDriveId("a".repeat(20) + " ")).toBe(false);
    expect(isValidDriveId("../../" + "a".repeat(20))).toBe(false);
  });
});

// ----- loadWhitelist -----

describe("loadWhitelist", () => {
  test("returns kind=absent when file missing", async () => {
    const state = await loadWhitelist(tmp);
    expect(state.kind).toBe("absent");
  });

  test("returns kind=malformed on invalid JSON", async () => {
    await fs.writeFile(path.join(tmp, WHITELIST_FILENAME), "not json {", {
      mode: 0o600,
    });
    const state = await loadWhitelist(tmp);
    expect(state.kind).toBe("malformed");
  });

  test("returns kind=malformed when root is array", async () => {
    await fs.writeFile(path.join(tmp, WHITELIST_FILENAME), "[]", { mode: 0o600 });
    const state = await loadWhitelist(tmp);
    expect(state.kind).toBe("malformed");
  });

  test("returns kind=malformed when schema_version !== 1", async () => {
    await fs.writeFile(
      path.join(tmp, WHITELIST_FILENAME),
      JSON.stringify({ schema_version: 2, updated_at: "x", entries: [] }),
      { mode: 0o600 },
    );
    const state = await loadWhitelist(tmp);
    expect(state.kind).toBe("malformed");
  });

  test("returns kind=malformed when entry has unknown type", async () => {
    const file = {
      schema_version: 1,
      updated_at: "2026-05-17T10:00:00.000Z",
      entries: [
        {
          type: "BAD",
          id: "a".repeat(20),
          label: "x",
          added_at: "2026-05-17T10:00:00.000Z",
        },
      ],
    };
    await fs.writeFile(path.join(tmp, WHITELIST_FILENAME), JSON.stringify(file), {
      mode: 0o600,
    });
    const state = await loadWhitelist(tmp);
    expect(state.kind).toBe("malformed");
  });

  test("returns kind=malformed when entry id is empty string", async () => {
    const file = {
      schema_version: 1,
      updated_at: "2026-05-17T10:00:00.000Z",
      entries: [
        { type: "folder", id: "", label: "x", added_at: "2026-05-17T10:00:00.000Z" },
      ],
    };
    await fs.writeFile(path.join(tmp, WHITELIST_FILENAME), JSON.stringify(file), {
      mode: 0o600,
    });
    const state = await loadWhitelist(tmp);
    expect(state.kind).toBe("malformed");
  });

  test("error message never echoes field values (sec-rev invariant)", async () => {
    const sentinel = "SECRET-CANARY-FIELD-VALUE";
    const file = {
      schema_version: 1,
      updated_at: sentinel,
      entries: [{ type: "folder", id: "", label: sentinel, added_at: sentinel }],
    };
    await fs.writeFile(path.join(tmp, WHITELIST_FILENAME), JSON.stringify(file), {
      mode: 0o600,
    });
    const state = await loadWhitelist(tmp);
    expect(state.kind).toBe("malformed");
    if (state.kind === "malformed") {
      expect(state.error).not.toContain(sentinel);
    }
  });

  test("returns kind=loaded with empty entries", async () => {
    const file: WhitelistFile = {
      schema_version: 1,
      updated_at: "2026-05-17T10:00:00.000Z",
      entries: [],
    };
    await fs.writeFile(path.join(tmp, WHITELIST_FILENAME), JSON.stringify(file), {
      mode: 0o600,
    });
    const state = await loadWhitelist(tmp);
    expect(state.kind).toBe("loaded");
    if (state.kind === "loaded") {
      expect(state.file.entries).toHaveLength(0);
    }
  });

  test("returns kind=loaded with valid entries", async () => {
    const file: WhitelistFile = {
      schema_version: 1,
      updated_at: "2026-05-17T10:00:00.000Z",
      entries: [
        {
          type: "folder",
          id: "1aBcDeFgHiJkLmNoPqRs",
          label: "Test folder",
          added_at: "2026-05-17T10:00:00.000Z",
        },
        {
          type: "file",
          id: "1FileXyZ_0123456789ab",
          label: "Test file",
          added_at: "2026-05-17T10:01:00.000Z",
        },
      ],
    };
    await fs.writeFile(path.join(tmp, WHITELIST_FILENAME), JSON.stringify(file), {
      mode: 0o600,
    });
    const state = await loadWhitelist(tmp);
    expect(state.kind).toBe("loaded");
    if (state.kind === "loaded") {
      expect(state.file.entries).toHaveLength(2);
      expect(state.file.entries[0]!.type).toBe("folder");
      expect(state.file.entries[1]!.type).toBe("file");
    }
  });

  test("lenient ID format on load (short ID stored from older config)", async () => {
    const file = {
      schema_version: 1,
      updated_at: "2026-05-17T10:00:00.000Z",
      entries: [
        {
          type: "folder",
          id: "shortIdLegacy123",
          label: "Old",
          added_at: "2026-05-17T10:00:00.000Z",
        },
      ],
    };
    await fs.writeFile(path.join(tmp, WHITELIST_FILENAME), JSON.stringify(file), {
      mode: 0o600,
    });
    const state = await loadWhitelist(tmp);
    expect(state.kind).toBe("loaded");
  });
});

// ----- saveWhitelist -----

describe("saveWhitelist", () => {
  const validFile: WhitelistFile = {
    schema_version: 1,
    updated_at: "2026-05-17T10:00:00.000Z",
    entries: [
      {
        type: "folder",
        id: "1aBcDeFgHiJkLmNoPqRs",
        label: "Test",
        added_at: "2026-05-17T10:00:00.000Z",
      },
    ],
  };

  test("creates file at mode 0o600", async () => {
    await saveWhitelist(tmp, validFile);
    const stat = await fs.stat(path.join(tmp, WHITELIST_FILENAME));
    expect(stat.mode & 0o777).toBe(0o600);
  });

  test("rejects invalid Drive ID at write time", async () => {
    const bad: WhitelistFile = {
      schema_version: 1,
      updated_at: "x",
      entries: [{ type: "folder", id: "short", label: "x", added_at: "x" }],
    };
    await expect(saveWhitelist(tmp, bad)).rejects.toThrow(/invalid Drive ID/);
  });

  test("overwrites existing file atomically (round trip)", async () => {
    await saveWhitelist(tmp, validFile);
    const updated: WhitelistFile = {
      ...validFile,
      updated_at: "2026-05-18T11:00:00.000Z",
    };
    await saveWhitelist(tmp, updated);

    const state = await loadWhitelist(tmp);
    expect(state.kind).toBe("loaded");
    if (state.kind === "loaded") {
      expect(state.file.updated_at).toBe("2026-05-18T11:00:00.000Z");
    }
  });

  test("no stranded tmp files after successful write", async () => {
    await saveWhitelist(tmp, validFile);
    const files = await fs.readdir(tmp);
    expect(files.filter((f) => f.includes(".write."))).toHaveLength(0);
  });

  test("creates configDir if missing (recursive mkdir at 0o700)", async () => {
    const nested = path.join(tmp, "nested", "deeper");
    await saveWhitelist(nested, validFile);
    const stat = await fs.stat(nested);
    expect(stat.mode & 0o777).toBe(0o700);
  });
});

// ----- AncestorCache -----

describe("AncestorCache", () => {
  test("returns undefined on miss + increments miss counter", () => {
    const c = new AncestorCache(10, 1000);
    expect(c.get("nope")).toBeUndefined();
    expect(c.misses()).toBe(1);
    expect(c.hits()).toBe(0);
  });

  test("set + get round trip + hit counter", () => {
    const c = new AncestorCache(10, 1000);
    c.set("file1", new Set(["parent1", "parent2"]));
    const result = c.get("file1");
    expect(result).toBeDefined();
    expect(result?.has("parent1")).toBe(true);
    expect(c.hits()).toBe(1);
  });

  test("LRU eviction at capacity", () => {
    const c = new AncestorCache(2, 60_000);
    c.set("a", new Set(["pa"]));
    c.set("b", new Set(["pb"]));
    c.set("c", new Set(["pc"]));
    expect(c.get("a")).toBeUndefined();
    expect(c.get("b")).toBeDefined();
    expect(c.get("c")).toBeDefined();
    expect(c.size()).toBe(2);
  });

  test("get touches recency (LRU refresh)", () => {
    const c = new AncestorCache(2, 60_000);
    c.set("a", new Set(["pa"]));
    c.set("b", new Set(["pb"]));
    c.get("a");
    c.set("c", new Set(["pc"]));
    expect(c.get("a")).toBeDefined();
    expect(c.get("b")).toBeUndefined();
  });

  test("TTL expiry — entry past expiresAt is treated as miss", async () => {
    const c = new AncestorCache(10, 10);
    c.set("a", new Set(["pa"]));
    expect(c.get("a")).toBeDefined();
    await new Promise((r) => setTimeout(r, 20));
    expect(c.get("a")).toBeUndefined();
    expect(c.misses()).toBeGreaterThanOrEqual(1);
  });

  test("clear resets counters", () => {
    const c = new AncestorCache(10, 1000);
    c.set("a", new Set(["p"]));
    c.get("a");
    c.get("missing");
    c.clear();
    expect(c.size()).toBe(0);
    expect(c.hits()).toBe(0);
    expect(c.misses()).toBe(0);
  });
});

// ----- checkShareAllowed -----

function makeFetcher(
  parentsByFile: Record<
    string,
    string[] | { resolvedTargetId: string; parents: string[] }
  >,
): AncestorFetcher {
  return async (fileId: string) => {
    const data = parentsByFile[fileId];
    if (data === undefined) return { kind: "not_found" };
    if (Array.isArray(data)) return { kind: "ok", parents: data };
    return {
      kind: "ok",
      parents: data.parents,
      resolvedTargetId: data.resolvedTargetId,
    };
  };
}

const emptyFetcher: AncestorFetcher = async () => ({ kind: "ok", parents: [] });

describe("checkShareAllowed", () => {
  test("policy_off when state=absent", async () => {
    const result = await checkShareAllowed("any", { kind: "absent" }, emptyFetcher);
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe("policy_off");
  });

  // ─────────────── v1.53 F2 — autonomous/strict mode flip ───────────────
  test("absent + autonomous=true → DENY (default_deny_autonomous)", async () => {
    const result = await checkShareAllowed("any", { kind: "absent" }, emptyFetcher, undefined, true);
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("default_deny_autonomous");
  });

  test("absent + autonomous=false → policy_off (byte-identical to today)", async () => {
    const result = await checkShareAllowed("any", { kind: "absent" }, emptyFetcher, undefined, false);
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe("policy_off");
  });

  test("autonomous=true does NOT override a loaded whitelist match (still allowed by direct match)", async () => {
    const state = {
      kind: "loaded" as const,
      file: {
        schema_version: 1 as const,
        updated_at: "2026-01-01T00:00:00Z",
        entries: [{ type: "file" as const, id: "FILE1", label: "x", added_at: "2026-01-01T00:00:00Z" }],
      },
    };
    const result = await checkShareAllowed("FILE1", state, emptyFetcher, undefined, true);
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe("direct_match");
  });

  test("default_deny_malformed when state=malformed", async () => {
    const result = await checkShareAllowed(
      "any",
      { kind: "malformed", error: "x" },
      emptyFetcher,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("default_deny_malformed");
  });

  test("default_deny_empty when entries is empty", async () => {
    const result = await checkShareAllowed(
      "any",
      {
        kind: "loaded",
        file: { schema_version: 1, updated_at: "x", entries: [] },
      },
      emptyFetcher,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("default_deny_empty");
  });

  test("direct_match when fileId is type=file entry", async () => {
    const result = await checkShareAllowed(
      "fileX",
      {
        kind: "loaded",
        file: {
          schema_version: 1,
          updated_at: "x",
          entries: [{ type: "file", id: "fileX", label: "x", added_at: "x" }],
        },
      },
      emptyFetcher,
    );
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe("direct_match");
    expect(result.matchedId).toBe("fileX");
    expect(result.ancestorsWalked).toBe(0);
  });

  test("ancestor_match when parent is type=folder entry", async () => {
    const fetcher = makeFetcher({ fileX: ["folderA"] });
    const result = await checkShareAllowed(
      "fileX",
      {
        kind: "loaded",
        file: {
          schema_version: 1,
          updated_at: "x",
          entries: [{ type: "folder", id: "folderA", label: "x", added_at: "x" }],
        },
      },
      fetcher,
    );
    expect(result.allowed).toBe(true);
    expect(result.reason).toBe("ancestor_match");
    expect(result.matchedId).toBe("folderA");
    expect(result.ancestorsWalked).toBe(1);
  });

  test("ancestor_match deep (3 levels up)", async () => {
    const fetcher = makeFetcher({
      fileX: ["folderA"],
      folderA: ["folderB"],
      folderB: ["folderC"],
    });
    const result = await checkShareAllowed(
      "fileX",
      {
        kind: "loaded",
        file: {
          schema_version: 1,
          updated_at: "x",
          entries: [{ type: "folder", id: "folderC", label: "x", added_at: "x" }],
        },
      },
      fetcher,
    );
    expect(result.allowed).toBe(true);
    expect(result.matchedId).toBe("folderC");
  });

  test("no_match when fully walked, nothing in whitelist", async () => {
    const fetcher = makeFetcher({
      fileX: ["folderA"],
      folderA: [],
    });
    const result = await checkShareAllowed(
      "fileX",
      {
        kind: "loaded",
        file: {
          schema_version: 1,
          updated_at: "x",
          entries: [{ type: "folder", id: "OTHER", label: "x", added_at: "x" }],
        },
      },
      fetcher,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("no_match");
  });

  test("multi-parent lenient OR (1 whitelisted, 1 not → permit)", async () => {
    const fetcher = makeFetcher({
      fileX: ["folderUnknown", "folderWHITELISTED"],
    });
    const result = await checkShareAllowed(
      "fileX",
      {
        kind: "loaded",
        file: {
          schema_version: 1,
          updated_at: "x",
          entries: [
            {
              type: "folder",
              id: "folderWHITELISTED",
              label: "x",
              added_at: "x",
            },
          ],
        },
      },
      fetcher,
    );
    expect(result.allowed).toBe(true);
    expect(result.matchedId).toBe("folderWHITELISTED");
  });

  test("walk_failed when fetcher returns not_found", async () => {
    const result = await checkShareAllowed(
      "fileX",
      {
        kind: "loaded",
        file: {
          schema_version: 1,
          updated_at: "x",
          entries: [{ type: "folder", id: "folderA", label: "x", added_at: "x" }],
        },
      },
      async () => ({ kind: "not_found" }),
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("walk_failed");
  });

  test("walk_failed when fetcher throws", async () => {
    const result = await checkShareAllowed(
      "fileX",
      {
        kind: "loaded",
        file: {
          schema_version: 1,
          updated_at: "x",
          entries: [{ type: "folder", id: "folderA", label: "x", added_at: "x" }],
        },
      },
      async () => {
        throw new Error("Drive API down");
      },
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("walk_failed");
  });

  test("depth_limit when walk exceeds MAX_WALK_DEPTH", async () => {
    const parents: Record<string, string[]> = {};
    parents["fileX"] = ["folder0"];
    for (let i = 0; i < MAX_WALK_DEPTH + 5; i++) {
      parents[`folder${i}`] = [`folder${i + 1}`];
    }
    parents[`folder${MAX_WALK_DEPTH + 5}`] = [];

    const fetcher = makeFetcher(parents);
    const result = await checkShareAllowed(
      "fileX",
      {
        kind: "loaded",
        file: {
          schema_version: 1,
          updated_at: "x",
          entries: [{ type: "folder", id: "OTHER", label: "x", added_at: "x" }],
        },
      },
      fetcher,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("depth_limit");
    expect(result.ancestorsWalked).toBe(MAX_WALK_DEPTH);
  });

  test("cycle in parent graph does not cause unbounded walk", async () => {
    const fetcher = makeFetcher({
      fileX: ["folderA"],
      folderA: ["folderB"],
      folderB: ["folderA"],
    });
    const result = await checkShareAllowed(
      "fileX",
      {
        kind: "loaded",
        file: {
          schema_version: 1,
          updated_at: "x",
          entries: [{ type: "folder", id: "OTHER", label: "x", added_at: "x" }],
        },
      },
      fetcher,
    );
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("no_match");
    expect(result.ancestorsWalked).toBeLessThan(MAX_WALK_DEPTH);
  });

  test("shortcut chain bounded by MAX_WALK_DEPTH (sec-rev MEDIUM F1 regression)", async () => {
    // Build a chain of distinct shortcuts, each resolving to the next, none
    // having direct parents. Without the per-dequeue `walked` increment,
    // this would drive unbounded fetcher calls because each shortcut's
    // parents=[] never increments the inner-loop counter.
    const parents: Record<
      string,
      string[] | { resolvedTargetId: string; parents: string[] }
    > = {};
    for (let i = 0; i < MAX_WALK_DEPTH + 5; i++) {
      parents[`shortcut${i}`] = {
        resolvedTargetId: `shortcut${i + 1}`,
        parents: [],
      };
    }
    parents[`shortcut${MAX_WALK_DEPTH + 5}`] = [];

    let fetcherCalls = 0;
    const wrapped: AncestorFetcher = async (id) => {
      fetcherCalls++;
      const data = makeFetcher(parents);
      return data(id);
    };

    const result = await checkShareAllowed(
      "shortcut0",
      {
        kind: "loaded",
        file: {
          schema_version: 1,
          updated_at: "x",
          entries: [{ type: "folder", id: "OTHER", label: "x", added_at: "x" }],
        },
      },
      wrapped,
    );

    // Walk must terminate at depth limit; fetcher calls bounded.
    expect(result.allowed).toBe(false);
    expect(result.reason).toBe("depth_limit");
    expect(fetcherCalls).toBeLessThanOrEqual(MAX_WALK_DEPTH);
  });

  test("shortcut resolves to target, target's parents checked", async () => {
    const fetcher = makeFetcher({
      shortcutX: { resolvedTargetId: "targetY", parents: [] },
      targetY: ["folderWhitelisted"],
    });
    const result = await checkShareAllowed(
      "shortcutX",
      {
        kind: "loaded",
        file: {
          schema_version: 1,
          updated_at: "x",
          entries: [
            {
              type: "folder",
              id: "folderWhitelisted",
              label: "x",
              added_at: "x",
            },
          ],
        },
      },
      fetcher,
    );
    expect(result.allowed).toBe(true);
    expect(result.matchedId).toBe("folderWhitelisted");
  });

  test("cache hit path: second call uses cached ancestors, no fetcher calls", async () => {
    let fetcherCalls = 0;
    const wrapped: AncestorFetcher = async (id) => {
      fetcherCalls++;
      const data = makeFetcher({ fileX: ["folderA"], folderA: [] });
      return data(id);
    };
    const cache = new AncestorCache(10, 60_000);
    const state = {
      kind: "loaded" as const,
      file: {
        schema_version: 1 as const,
        updated_at: "x",
        entries: [
          { type: "folder" as const, id: "folderA", label: "x", added_at: "x" },
        ],
      },
    };

    const r1 = await checkShareAllowed("fileX", state, wrapped, cache);
    expect(r1.allowed).toBe(true);
    const callsAfterFirst = fetcherCalls;

    const r2 = await checkShareAllowed("fileX", state, wrapped, cache);
    expect(r2.allowed).toBe(true);
    expect(r2.reason).toBe("ancestor_match");
    expect(fetcherCalls).toBe(callsAfterFirst);
    expect(cache.hits()).toBeGreaterThanOrEqual(1);
  });

  test("walk_failed NOT cached (retry must be possible)", async () => {
    let fetcherCalls = 0;
    const wrapped: AncestorFetcher = async () => {
      fetcherCalls++;
      return { kind: "not_found" };
    };
    const cache = new AncestorCache(10, 60_000);
    const state = {
      kind: "loaded" as const,
      file: {
        schema_version: 1 as const,
        updated_at: "x",
        entries: [
          { type: "folder" as const, id: "folderA", label: "x", added_at: "x" },
        ],
      },
    };

    await checkShareAllowed("fileX", state, wrapped, cache);
    await checkShareAllowed("fileX", state, wrapped, cache);
    expect(fetcherCalls).toBe(2);
  });

  test("no_match (fully-walked deny) IS cached for performance", async () => {
    let fetcherCalls = 0;
    const wrapped: AncestorFetcher = async (id) => {
      fetcherCalls++;
      const data = makeFetcher({ fileX: ["folderA"], folderA: [] });
      return data(id);
    };
    const cache = new AncestorCache(10, 60_000);
    const state = {
      kind: "loaded" as const,
      file: {
        schema_version: 1 as const,
        updated_at: "x",
        entries: [
          { type: "folder" as const, id: "OTHER", label: "x", added_at: "x" },
        ],
      },
    };

    await checkShareAllowed("fileX", state, wrapped, cache);
    const callsAfterFirst = fetcherCalls;
    await checkShareAllowed("fileX", state, wrapped, cache);
    expect(fetcherCalls).toBe(callsAfterFirst);
  });
});

// ----- module constants sanity -----

describe("module constants", () => {
  test("MAX_WALK_DEPTH is 10 (matches DESIGN spec)", () => {
    expect(MAX_WALK_DEPTH).toBe(10);
  });

  test("DEFAULT_CACHE_TTL_MS is 10 minutes (matches DESIGN spec)", () => {
    expect(DEFAULT_CACHE_TTL_MS).toBe(10 * 60 * 1000);
  });
});
