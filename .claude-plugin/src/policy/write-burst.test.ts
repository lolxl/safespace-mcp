// v1.52 F1 — write/delete burst guard tests (docs/v1.52-autonomy-hardening.md
// §10 sec-rev hooks). Covers: reads exempt, the two buckets + their
// independence, sliding-window expiry, before-permit semantics (no retry-storm
// bypass), per-call env resolution, and the bad-value lenient fallback.
//
// The gate is ONE process-wide window (the per-operator buckets and the
// per-operator limit overrides went away with Model B).

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
    // the canonical 6 are present
    expect(PERMANENT_DELETE_TOOLS.has("tasks_delete")).toBe(true);
    expect(PERMANENT_DELETE_TOOLS.has("calendar_delete_event")).toBe(true);
    expect(PERMANENT_DELETE_TOOLS.has("gmail_delete_draft")).toBe(true);
    expect(PERMANENT_DELETE_TOOLS.has("drive_delete_file")).toBe(true);
    // drive_trash_file is RECOVERABLE → NOT permanent
    expect(PERMANENT_DELETE_TOOLS.has("drive_trash_file")).toBe(false);
    expect(classifyWriteTool("drive_delete_file", "write")).toBe("delete");
    expect(classifyWriteTool("drive_trash_file", "write")).toBe("write");
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

describe("write-burst F1 — enforcement (one process-wide window)", () => {
  beforeEach(() => {
    clearEnv();
    __resetWriteBurstForTests();
  });
  afterEach(() => {
    clearEnv();
    __resetWriteBurstForTests();
  });

  test("exempt is a no-op even when called many times", () => {
    for (let i = 0; i < 1000; i++) enforceWriteBurst("exempt", 1000);
    expect(getWriteBurstCounts(1000)).toEqual({ write: 0, delete: 0 });
  });

  test("write bucket: at limit → -32032 reason=write", () => {
    process.env[WRITE_ENV] = "3";
    enforceWriteBurst("write", 1000);
    enforceWriteBurst("write", 1000);
    enforceWriteBurst("write", 1000);
    let thrown: unknown;
    try {
      enforceWriteBurst("write", 1000);
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
    enforceWriteBurst("delete", 1000);
    enforceWriteBurst("delete", 1000);
    let thrown: unknown;
    try {
      enforceWriteBurst("delete", 1000);
    } catch (e) {
      thrown = e;
    }
    expect(thrown).toBeInstanceOf(MCPError);
    expect((thrown as MCPError).errorData.reason).toBe("delete");
  });

  test("buckets are independent: a full write bucket does not block deletes", () => {
    process.env[WRITE_ENV] = "1";
    process.env[DELETE_ENV] = "5";
    enforceWriteBurst("write", 1000);
    expect(() => enforceWriteBurst("write", 1000)).toThrow(MCPError);
    expect(() => enforceWriteBurst("delete", 1000)).not.toThrow();
  });

  test("sliding window: budget frees after WINDOW_MS", () => {
    process.env[DELETE_ENV] = "2";
    enforceWriteBurst("delete", 1000);
    enforceWriteBurst("delete", 1000);
    expect(() => enforceWriteBurst("delete", 1000)).toThrow(MCPError);
    const later = 1000 + __internal.WINDOW_MS + 1;
    expect(() => enforceWriteBurst("delete", later)).not.toThrow();
  });

  test("throttled calls do not consume budget (no retry-storm bypass)", () => {
    process.env[WRITE_ENV] = "2";
    enforceWriteBurst("write", 1000);
    enforceWriteBurst("write", 1000);
    expect(() => enforceWriteBurst("write", 1000)).toThrow(MCPError);
    expect(getWriteBurstCounts(1000).write).toBe(2);
  });

  test("env override mid-session applies on the next call (uncached)", () => {
    process.env[WRITE_ENV] = "1";
    enforceWriteBurst("write", 1000);
    expect(() => enforceWriteBurst("write", 1000)).toThrow(MCPError);
    process.env[WRITE_ENV] = "5";
    expect(() => enforceWriteBurst("write", 1000)).not.toThrow();
  });

  test("bad env value ('0') falls back to lenient default, not 0=disable", () => {
    process.env[WRITE_ENV] = "0";
    for (let i = 0; i < __internal.WRITE_BURST_DEFAULT; i++) {
      enforceWriteBurst("write", 1000);
    }
    expect(() => enforceWriteBurst("write", 1000)).toThrow(MCPError);
  });
});
