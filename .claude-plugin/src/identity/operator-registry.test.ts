import { describe, expect, test } from "bun:test";
import {
  createRegistryProvider,
  loadOperatorRegistry,
  parseOperatorRegistry,
} from "./operator-registry";

// v1.74 PR-2b — the operators registry: default-deny + fail-loud validation. A
// misconfigured registry must NEVER silently widen access (it refuses to start);
// an unregistered login must resolve to null (refused at the transport).

const GOOD = JSON.stringify({
  operators: [
    { tailnetLogin: "alice@example.com", operatorId: "alice", tier: "write", allowedAccounts: ["alice@gmail.com"] },
    { tailnetLogin: "Bob@Example.com", operatorId: "bob", tier: "read", allowedAccounts: [] },
  ],
});

describe("parseOperatorRegistry — valid", () => {
  test("resolves a registered login → its policy (case-insensitive)", () => {
    const reg = parseOperatorRegistry(GOOD);
    expect(reg.size).toBe(2);
    const alice = reg.lookupByTailnetLogin("alice@example.com");
    expect(alice).toEqual({
      tailnetLogin: "alice@example.com",
      operatorId: "alice",
      tier: "write",
      allowedAccounts: ["alice@gmail.com"],
    });
    // Logins are emails → case-insensitive match (registry "Bob@Example.com").
    expect(reg.lookupByTailnetLogin("BOB@EXAMPLE.COM")?.operatorId).toBe("bob");
    expect(reg.lookupByTailnetLogin("bob@example.com")?.tier).toBe("read");
  });

  test("an unregistered (or blank) login → null (default-deny)", () => {
    const reg = parseOperatorRegistry(GOOD);
    expect(reg.lookupByTailnetLogin("mallory@example.com")).toBeNull();
    expect(reg.lookupByTailnetLogin("")).toBeNull();
  });

  test("an empty allowedAccounts array is legal", () => {
    const reg = parseOperatorRegistry(GOOD);
    expect(reg.lookupByTailnetLogin("bob@example.com")?.allowedAccounts).toEqual([]);
  });
});

describe("parseOperatorRegistry — fail-loud (refuse to start)", () => {
  const cases: Array<[string, string]> = [
    ["not JSON", "{not json"],
    ["top-level not an object", JSON.stringify([])],
    ["operators not an array", JSON.stringify({ operators: {} })],
    ["entry not an object", JSON.stringify({ operators: ["x"] })],
    [
      "tailnetLogin not name@provider",
      JSON.stringify({ operators: [{ tailnetLogin: "alice", operatorId: "alice", tier: "read", allowedAccounts: [] }] }),
    ],
    [
      "tailnetLogin with a control char",
      JSON.stringify({ operators: [{ tailnetLogin: "a\nb@x.com", operatorId: "alice", tier: "read", allowedAccounts: [] }] }),
    ],
    [
      "operatorId malformed (space)",
      JSON.stringify({ operators: [{ tailnetLogin: "a@x.com", operatorId: "has space", tier: "read", allowedAccounts: [] }] }),
    ],
    [
      "tier not in read|write|share",
      JSON.stringify({ operators: [{ tailnetLogin: "a@x.com", operatorId: "alice", tier: "admin", allowedAccounts: [] }] }),
    ],
    [
      "allowedAccounts not an array",
      JSON.stringify({ operators: [{ tailnetLogin: "a@x.com", operatorId: "alice", tier: "read", allowedAccounts: "x" }] }),
    ],
    [
      "allowedAccounts with a non-string",
      JSON.stringify({ operators: [{ tailnetLogin: "a@x.com", operatorId: "alice", tier: "read", allowedAccounts: [1] }] }),
    ],
    [
      "duplicate login (case-insensitive)",
      JSON.stringify({
        operators: [
          { tailnetLogin: "a@x.com", operatorId: "a1", tier: "read", allowedAccounts: [] },
          { tailnetLogin: "A@X.com", operatorId: "a2", tier: "read", allowedAccounts: [] },
        ],
      }),
    ],
  ];
  for (const [name, raw] of cases) {
    test(`throws on: ${name}`, () => {
      expect(() => parseOperatorRegistry(raw)).toThrow();
    });
  }
});

describe("parseOperatorRegistry — v1.92 per-operator burst overrides", () => {
  const withBurst = (extra: Record<string, unknown>) =>
    JSON.stringify({
      operators: [
        { tailnetLogin: "a@x.com", operatorId: "alice", tier: "write", allowedAccounts: [], ...extra },
      ],
    });

  test("valid integer overrides are carried onto the entry", () => {
    const reg = parseOperatorRegistry(withBurst({ writeBurstLimit: 5, deleteBurstLimit: 2 }));
    const e = reg.lookupByTailnetLogin("a@x.com");
    expect(e?.writeBurstLimit).toBe(5);
    expect(e?.deleteBurstLimit).toBe(2);
  });

  test("absent overrides leave the fields undefined (→ global env default)", () => {
    const reg = parseOperatorRegistry(withBurst({}));
    const e = reg.lookupByTailnetLogin("a@x.com");
    expect(e?.writeBurstLimit).toBeUndefined();
    expect(e?.deleteBurstLimit).toBeUndefined();
  });

  // Fail-loud: a typo'd cap must NEVER silently clamp (it could widen the ceiling).
  const badCases: Array<[string, Record<string, unknown>]> = [
    ["writeBurstLimit zero (below min)", { writeBurstLimit: 0 }],
    ["writeBurstLimit non-integer", { writeBurstLimit: 1.5 }],
    ["writeBurstLimit out of range (too big)", { writeBurstLimit: 100001 }],
    ["writeBurstLimit not a number", { writeBurstLimit: "5" }],
    ["deleteBurstLimit zero", { deleteBurstLimit: 0 }],
    ["deleteBurstLimit negative", { deleteBurstLimit: -1 }],
  ];
  for (const [name, extra] of badCases) {
    test(`throws on: ${name}`, () => {
      expect(() => parseOperatorRegistry(withBurst(extra))).toThrow();
    });
  }
});

describe("loadOperatorRegistry", () => {
  test("throws fail-loud when the path is not configured", () => {
    expect(() => loadOperatorRegistry({ operatorsFilePath: "" })).toThrow();
  });

  test("throws fail-loud when the file cannot be read (path not echoed)", () => {
    expect(() =>
      loadOperatorRegistry({
        operatorsFilePath: "/does/not/matter",
        readFileImpl: () => {
          throw new Error("ENOENT");
        },
      }),
    ).toThrow();
    // The thrown message must not echo the path — even when the UNDERLYING fs error
    // contains it. Capture explicitly so the assertion can't pass vacuously (the
    // throw MUST happen).
    let caught: Error | undefined;
    try {
      loadOperatorRegistry({
        operatorsFilePath: "/secret/path/operators.json",
        readFileImpl: () => {
          throw new Error("ENOENT: /secret/path/operators.json");
        },
      });
    } catch (e) {
      caught = e as Error;
    }
    expect(caught).toBeDefined(); // it MUST have thrown (not a vacuous pass)
    expect(caught!.message).not.toContain("/secret/path"); // and not echoed the path
  });

  test("loads + validates via an injected readFileImpl", () => {
    const reg = loadOperatorRegistry({
      operatorsFilePath: "/any",
      readFileImpl: () => GOOD,
    });
    expect(reg.lookupByTailnetLogin("alice@example.com")?.operatorId).toBe("alice");
  });
});

describe("parseOperatorRegistry — v1.74 PR-2c allowedAccounts ⊆ accounts.json cross-check", () => {
  test("passes when every allowedAccounts entry is a consented account", () => {
    const known = new Set(["alice@gmail.com", "bob@gmail.com"]);
    const reg = parseOperatorRegistry(GOOD, known); // GOOD's alice allows alice@gmail.com
    expect(reg.size).toBe(2);
  });

  test("FAIL-LOUD when an allowedAccounts entry is not a consented account (typo guard)", () => {
    const known = new Set(["bob@gmail.com"]); // alice@gmail.com is NOT consented
    expect(() => parseOperatorRegistry(GOOD, known)).toThrow();
  });

  test("the cross-check is skipped when no account index is supplied (Model A / tests)", () => {
    // No knownAccounts → allowedAccounts is shape-validated but not cross-checked.
    expect(() => parseOperatorRegistry(GOOD)).not.toThrow();
  });

  test("loadOperatorRegistry threads knownAccounts through to the cross-check", () => {
    expect(() =>
      loadOperatorRegistry({
        operatorsFilePath: "/any",
        readFileImpl: () => GOOD,
        knownAccounts: new Set(["bob@gmail.com"]), // missing alice@gmail.com → reject
      }),
    ).toThrow();
  });
});

// ----- v1.80 PR-3 — the hot-reload provider -----

describe("createRegistryProvider — v1.80 PR-3 hot-reload (lazy mtime, keep-last-good)", () => {
  const ONE_OP = JSON.stringify({
    operators: [
      { tailnetLogin: "alice@example.com", operatorId: "alice", tier: "write", allowedAccounts: [] },
    ],
  });
  const TWO_OPS = GOOD; // alice + bob (module fixture)

  /** An injectable fake file: mutate `content`/`mtime` to simulate edits;
   *  `reads` counts actual re-reads (the same-mtime fast path must not re-read). */
  function fakeFile(initial: string) {
    const f = {
      content: initial,
      mtime: 1000,
      reads: 0,
      statThrows: false,
      deps: {
        operatorsFilePath: "/fake/operators.json",
        readFileImpl: (_p: string) => {
          f.reads++;
          return f.content;
        },
        statMtimeImpl: (_p: string) => {
          if (f.statThrows) throw new Error("ENOENT");
          return f.mtime;
        },
      },
    };
    return f;
  }

  test("initial load stays FAIL-LOUD (startup posture unchanged): bad JSON / missing path throw", async () => {
    const bad = fakeFile("{nope");
    expect(createRegistryProvider(bad.deps)).rejects.toThrow(/invalid/);
    // a missing path (no env, no override) also throws
    const prevEnv = process.env.SAFESPACE_OPERATORS_FILE;
    delete process.env.SAFESPACE_OPERATORS_FILE;
    try {
      expect(createRegistryProvider({})).rejects.toThrow();
    } finally {
      if (prevEnv !== undefined) process.env.SAFESPACE_OPERATORS_FILE = prevEnv;
    }
  });

  test("unchanged mtime → the SAME cached instance, no re-read", async () => {
    const f = fakeFile(ONE_OP);
    const provider = await createRegistryProvider(f.deps);
    const a = await provider.current();
    const b = await provider.current();
    expect(b).toBe(a); // same instance — no re-parse
    expect(f.reads).toBe(1); // only the initial load read the file
    expect(a.size).toBe(1);
  });

  test("mtime change → the NEW registry is served (an added operator connects without restart)", async () => {
    const f = fakeFile(ONE_OP);
    const provider = await createRegistryProvider(f.deps);
    expect((await provider.current()).size).toBe(1);
    f.content = TWO_OPS;
    f.mtime = 2000;
    const fresh = await provider.current();
    expect(fresh.size).toBe(2);
    expect(fresh.lookupByTailnetLogin("bob@example.com")?.operatorId).toBe("bob");
  });

  test("an INVALID replacement keeps the last-good registry (never crash, never fall open) and retries after a fix", async () => {
    const f = fakeFile(TWO_OPS);
    const provider = await createRegistryProvider(f.deps);
    expect((await provider.current()).size).toBe(2);
    // A half-written / bad edit lands.
    f.content = "{broken";
    f.mtime = 2000;
    const kept = await provider.current();
    expect(kept.size).toBe(2); // last-good enforced
    expect(kept.lookupByTailnetLogin("alice@example.com")?.operatorId).toBe("alice");
    // default-deny persists for unknown logins on the kept registry
    expect(kept.lookupByTailnetLogin("mallory@example.com")).toBeNull();
    // The fix writes a new mtime → the next current() picks it up.
    f.content = ONE_OP;
    f.mtime = 3000;
    expect((await provider.current()).size).toBe(1);
  });

  test("a runtime stat failure (file deleted) keeps the last-good registry", async () => {
    const f = fakeFile(ONE_OP);
    const provider = await createRegistryProvider(f.deps);
    expect((await provider.current()).size).toBe(1);
    f.statThrows = true;
    expect((await provider.current()).size).toBe(1); // still serving last-good
    f.statThrows = false;
    expect((await provider.current()).size).toBe(1);
  });

  test("the allowedAccounts ⊆ accounts.json cross-check re-runs on each reload with FRESH accounts", async () => {
    const NEEDS_CAROL = JSON.stringify({
      operators: [
        { tailnetLogin: "alice@example.com", operatorId: "alice", tier: "write", allowedAccounts: ["carol@gmail.com"] },
      ],
    });
    const f = fakeFile(ONE_OP);
    let known: ReadonlySet<string> = new Set<string>([]);
    const provider = await createRegistryProvider({
      ...f.deps,
      loadKnownAccounts: async () => known,
    });
    // Reload referencing carol@ while accounts.json doesn't know her → keep-last-good.
    f.content = NEEDS_CAROL;
    f.mtime = 2000;
    expect((await provider.current()).lookupByTailnetLogin("alice@example.com")?.allowedAccounts).toEqual([]);
    // carol@ gets consented AFTER startup; the SAME file content now validates
    // (the cross-check read accounts.json FRESH, not a startup snapshot).
    known = new Set(["carol@gmail.com"]);
    f.mtime = 3000; // re-touched (the failed mtime was never committed; a new touch retries too)
    expect(
      (await provider.current()).lookupByTailnetLogin("alice@example.com")?.allowedAccounts,
    ).toEqual(["carol@gmail.com"]);
  });

  test("a reload-time loadKnownAccounts throw is an invalid replacement (keep-last-good)", async () => {
    const f = fakeFile(ONE_OP);
    let throwNow = false;
    const provider = await createRegistryProvider({
      ...f.deps,
      loadKnownAccounts: async () => {
        if (throwNow) throw new Error("accounts.json unreadable");
        return undefined;
      },
    });
    throwNow = true;
    f.content = TWO_OPS;
    f.mtime = 2000;
    expect((await provider.current()).size).toBe(1); // last-good kept
  });
});

describe("createRegistryProvider — warn-once bookkeeping (code-rev v1.80 gap)", () => {
  test("an invalid replacement warns ONCE per failed content, not once per request", async () => {
    const f = {
      content: JSON.stringify({
        operators: [
          { tailnetLogin: "alice@example.com", operatorId: "alice", tier: "write", allowedAccounts: [] },
        ],
      }),
      mtime: 1000,
    };
    const provider = await createRegistryProvider({
      operatorsFilePath: "/fake/operators.json",
      readFileImpl: () => f.content,
      statMtimeImpl: () => f.mtime,
    });
    const realError = console.error;
    let warns = 0;
    console.error = (...args: unknown[]) => {
      if (String(args[0] ?? "").includes("INVALID")) warns++;
    };
    try {
      f.content = "{broken";
      f.mtime = 2000;
      await provider.current();
      await provider.current();
      await provider.current(); // a request storm against the SAME broken content
      expect(warns).toBe(1);
      // a NEW (still broken) edit = new content → eligible to warn again
      f.content = "{still-broken";
      f.mtime = 3000;
      await provider.current();
      expect(warns).toBe(2);
    } finally {
      console.error = realError;
    }
  });
});
