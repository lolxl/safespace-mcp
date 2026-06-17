// v1.52 F1 — write/delete burst guard tests (docs/v1.52-autonomy-hardening.md
// §10 sec-rev hooks). Covers: reads exempt, the two buckets + their
// independence, sliding-window expiry, before-permit semantics (no retry-storm
// bypass), per-call env resolution, and the bad-value lenient fallback.
//
// v1.92 — the gate is now PER-OPERATOR. The Model-A path (op omitted / operatorId
// null → the shared sentinel bucket) must stay byte-identical, so the original
// tests pass `undefined` for `op`; a new block covers per-operator isolation +
// the registry cap override.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  __internal,
  __resetWriteBurstForTests,
  classifyWriteTool,
  enforceWriteBurst,
  getWriteBurstCounts,
  PERMANENT_DELETE_TOOLS,
} from "./write-burst";
import { MCPError } from "../errors";

const WRITE_ENV = "SAFESPACE_WRITE_BURST_LIMIT";
const DELETE_ENV = "SAFESPACE_DELETE_BURST_LIMIT";

function clearEnv(): void {
  delete process.env[WRITE_ENV];
  delete process.env[DELETE_ENV];
}

describe("write-burst F1 — classifier", () => {
  test("reads are exempt", () => {
    expect(classifyWriteTool("gmail_search", "read")).toBe("exempt");
    expect(classifyWriteTool("gmail_get_message", "read")).toBe("exempt");
    expect(classifyWriteTool("drive_search_all", "read")).toBe("exempt");
  });

  test("undefined min_tier (unknown tool) is exempt", () => {
    expect(classifyWriteTool("nonexistent_tool", undefined)).toBe("exempt");
  });

  test("permanent-delete tools → delete bucket", () => {
    for (const t of PERMANENT_DELETE_TOOLS) {
      expect(classifyWriteTool(t, "write")).toBe("delete");
    }
    // the canonical 5 are present
    expect(PERMANENT_DELETE_TOOLS.has("tasks_delete")).toBe(true);
    expect(PERMANENT_DELETE_TOOLS.has("calendar_delete_event")).toBe(true);
    expect(PERMANENT_DELETE_TOOLS.has("gmail_delete_draft")).toBe(true);
  });

  test("other state-changing tools → write bucket (incl. recoverable deletes)", () => {
    expect(classifyWriteTool("gmail_send", "write")).toBe("write");
    expect(classifyWriteTool("drive_create_file", "write")).toBe("write");
    expect(classifyWriteTool("youtube_playlist_item_remove", "write")).toBe("write");
    expect(classifyWriteTool("gmail_delete_filter", "write")).toBe("write");
    expect(classifyWriteTool("tasks_clear", "write")).toBe("write");
  });

  test("share-tier tools are counted (not read)", () => {
    expect(classifyWriteTool("drive_share_file", "share")).toBe("write");
  });
});

describe("write-burst F1 — enforcement (Model A, byte-identical)", () => {
  beforeEach(() => {
    clearEnv();
    __resetWriteBurstForTests();
  });
  afterEach(() => {
    clearEnv();
    __resetWriteBurstForTests();
  });

  test("exempt is a no-op even when called many times", () => {
    for (let i = 0; i < 1000; i++) enforceWriteBurst("exempt", undefined, 1000);
    expect(getWriteBurstCounts(undefined, 1000)).toEqual({ write: 0, delete: 0 });
  });

  test("write bucket: at limit → -32032 reason=write", () => {
    process.env[WRITE_ENV] = "3";
    enforceWriteBurst("write", undefined, 1000);
    enforceWriteBurst("write", undefined, 1000);
    enforceWriteBurst("write", undefined, 1000);
    let thrown: unknown;
    try {
      enforceWriteBurst("write", undefined, 1000);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(MCPError);
    expect((thrown as MCPError).errorName).toBe("write_burst_limit_exceeded");
    expect((thrown as MCPError).errorData.reason).toBe("write");
  });

  test("delete bucket: tighter, throws reason=delete", () => {
    process.env[DELETE_ENV] = "2";
    process.env[WRITE_ENV] = "100";
    enforceWriteBurst("delete", undefined, 1000);
    enforceWriteBurst("delete", undefined, 1000);
    let thrown: unknown;
    try {
      enforceWriteBurst("delete", undefined, 1000);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(MCPError);
    expect((thrown as MCPError).errorData.reason).toBe("delete");
  });

  test("buckets are independent: a full write bucket does not block deletes", () => {
    process.env[WRITE_ENV] = "1";
    process.env[DELETE_ENV] = "5";
    enforceWriteBurst("write", undefined, 1000);
    expect(() => enforceWriteBurst("write", undefined, 1000)).toThrow(MCPError);
    expect(() => enforceWriteBurst("delete", undefined, 1000)).not.toThrow();
  });

  test("sliding window: budget frees after WINDOW_MS", () => {
    process.env[DELETE_ENV] = "2";
    enforceWriteBurst("delete", undefined, 1000);
    enforceWriteBurst("delete", undefined, 1000);
    expect(() => enforceWriteBurst("delete", undefined, 1000)).toThrow(MCPError);
    const later = 1000 + __internal.WINDOW_MS + 1;
    expect(() => enforceWriteBurst("delete", undefined, later)).not.toThrow();
  });

  test("throttled calls do not consume budget (no retry-storm bypass)", () => {
    process.env[WRITE_ENV] = "2";
    enforceWriteBurst("write", undefined, 1000);
    enforceWriteBurst("write", undefined, 1000);
    expect(() => enforceWriteBurst("write", undefined, 1000)).toThrow(MCPError);
    expect(getWriteBurstCounts(undefined, 1000).write).toBe(2);
  });

  test("env override mid-session applies on the next call (uncached)", () => {
    process.env[WRITE_ENV] = "1";
    enforceWriteBurst("write", undefined, 1000);
    expect(() => enforceWriteBurst("write", undefined, 1000)).toThrow(MCPError);
    process.env[WRITE_ENV] = "5";
    expect(() => enforceWriteBurst("write", undefined, 1000)).not.toThrow();
  });

  test("bad env value ('0') falls back to lenient default, not 0=disable", () => {
    process.env[WRITE_ENV] = "0";
    for (let i = 0; i < __internal.WRITE_BURST_DEFAULT; i++) {
      enforceWriteBurst("write", undefined, 1000);
    }
    expect(() => enforceWriteBurst("write", undefined, 1000)).toThrow(MCPError);
  });

  test("an explicit null-operator scope shares the Model-A sentinel bucket", () => {
    process.env[WRITE_ENV] = "1";
    // The default (undefined op) and an explicit {operatorId:null} are the SAME bucket.
    enforceWriteBurst("write", { operatorId: null }, 1000);
    expect(() => enforceWriteBurst("write", undefined, 1000)).toThrow(MCPError);
  });
});

describe("write-burst F1 — per-operator isolation (v1.92)", () => {
  const alice = { operatorId: "alice" };
  const bob = { operatorId: "bob" };
  beforeEach(() => {
    clearEnv();
    __resetWriteBurstForTests();
  });
  afterEach(() => {
    clearEnv();
    __resetWriteBurstForTests();
  });

  test("one operator's full bucket does NOT throttle another operator", () => {
    process.env[WRITE_ENV] = "1";
    enforceWriteBurst("write", alice, 1000);
    expect(() => enforceWriteBurst("write", alice, 1000)).toThrow(MCPError);
    // bob is untouched — separate bucket.
    expect(() => enforceWriteBurst("write", bob, 1000)).not.toThrow();
  });

  test("delete buckets are also per-operator", () => {
    process.env[DELETE_ENV] = "1";
    enforceWriteBurst("delete", alice, 1000);
    expect(() => enforceWriteBurst("delete", alice, 1000)).toThrow(MCPError);
    expect(() => enforceWriteBurst("delete", bob, 1000)).not.toThrow();
  });

  test("a Model-A (null) operator is a distinct bucket from a named operator", () => {
    process.env[WRITE_ENV] = "1";
    enforceWriteBurst("write", { operatorId: null }, 1000);
    expect(() => enforceWriteBurst("write", { operatorId: null }, 1000)).toThrow(MCPError);
    // a named operator is NOT blocked by the Model-A bucket being full.
    expect(() => enforceWriteBurst("write", alice, 1000)).not.toThrow();
  });

  test("getWriteBurstCounts is per-operator", () => {
    process.env[WRITE_ENV] = "100";
    enforceWriteBurst("write", alice, 1000);
    enforceWriteBurst("write", alice, 1000);
    enforceWriteBurst("write", bob, 1000);
    expect(getWriteBurstCounts(alice, 1000)).toEqual({ write: 2, delete: 0 });
    expect(getWriteBurstCounts(bob, 1000)).toEqual({ write: 1, delete: 0 });
    expect(getWriteBurstCounts({ operatorId: null }, 1000)).toEqual({ write: 0, delete: 0 });
  });

  test("per-operator registry override beats the global env default", () => {
    process.env[WRITE_ENV] = "1"; // global default = 1
    const aliceHi = { operatorId: "alice", writeBurstLimit: 3 };
    // alice's override (3) lets her do 3 before throwing...
    enforceWriteBurst("write", aliceHi, 1000);
    enforceWriteBurst("write", aliceHi, 1000);
    enforceWriteBurst("write", aliceHi, 1000);
    expect(() => enforceWriteBurst("write", aliceHi, 1000)).toThrow(MCPError);
    // ...while bob (no override) is capped at the global default of 1.
    enforceWriteBurst("write", bob, 1000);
    expect(() => enforceWriteBurst("write", bob, 1000)).toThrow(MCPError);
  });

  test("a per-operator delete override is honored independently of write", () => {
    process.env[DELETE_ENV] = "1";
    const aliceHi = { operatorId: "alice", deleteBurstLimit: 2 };
    enforceWriteBurst("delete", aliceHi, 1000);
    enforceWriteBurst("delete", aliceHi, 1000);
    expect(() => enforceWriteBurst("delete", aliceHi, 1000)).toThrow(MCPError);
  });
});
