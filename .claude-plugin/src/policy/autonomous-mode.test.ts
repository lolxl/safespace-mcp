// v1.53 F2 — `isAutonomousMode` strict-truthy parsing tests.
//
// Locks the env-var contract per docs/v1.52-autonomy-hardening.md §4.2: MUST
// require the literal string "true" lowercase. Every other value → false (the
// deployment stays in today's permissive OFF=allow behavior — fail toward
// today, not toward strict-deny, on a typo). Mirrors contact-lookup.test.ts.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ENV_AUTONOMOUS,
  enforceAutonomousDeleteDeny,
  isAutonomousMode,
} from "./autonomous-mode";
import { PERMANENT_DELETE_TOOLS } from "./write-burst";
import { MCPError } from "../errors";

describe("isAutonomousMode — strict-truthy env-var parsing (v1.53 F2)", () => {
  let originalEnv: string | undefined;

  beforeEach(() => {
    originalEnv = process.env[ENV_AUTONOMOUS];
    delete process.env[ENV_AUTONOMOUS];
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env[ENV_AUTONOMOUS];
    } else {
      process.env[ENV_AUTONOMOUS] = originalEnv;
    }
  });

  test("ENV_AUTONOMOUS constant matches design contract", () => {
    // Locked constant name — referenced in user-facing docs (PR description,
    // CLAUDE.md, SECURITY.md) and shell setup. Sentinel against rename.
    expect(ENV_AUTONOMOUS).toBe("SAFESPACE_AUTONOMOUS");
  });

  test("literal 'true' (lowercase) → true (the ONLY accepted shape)", () => {
    process.env[ENV_AUTONOMOUS] = "true";
    expect(isAutonomousMode()).toBe(true);
  });

  test("'True' (TitleCase) → false (typo fails toward today's permissive default)", () => {
    process.env[ENV_AUTONOMOUS] = "True";
    expect(isAutonomousMode()).toBe(false);
  });

  test("'TRUE' (uppercase) → false", () => {
    process.env[ENV_AUTONOMOUS] = "TRUE";
    expect(isAutonomousMode()).toBe(false);
  });

  test("'1' → false (NOT a truthy shorthand; requires the literal word)", () => {
    process.env[ENV_AUTONOMOUS] = "1";
    expect(isAutonomousMode()).toBe(false);
  });

  test("'yes' → false", () => {
    process.env[ENV_AUTONOMOUS] = "yes";
    expect(isAutonomousMode()).toBe(false);
  });

  test("'on' → false", () => {
    process.env[ENV_AUTONOMOUS] = "on";
    expect(isAutonomousMode()).toBe(false);
  });

  test("'false' → false (literal opposite, explicitly disabled)", () => {
    process.env[ENV_AUTONOMOUS] = "false";
    expect(isAutonomousMode()).toBe(false);
  });

  test("'0' → false", () => {
    process.env[ENV_AUTONOMOUS] = "0";
    expect(isAutonomousMode()).toBe(false);
  });

  test("empty string '' → false (set-but-empty does NOT enable)", () => {
    process.env[ENV_AUTONOMOUS] = "";
    expect(isAutonomousMode()).toBe(false);
  });

  test("undefined / unset → false (default = today's permissive behavior)", () => {
    delete process.env[ENV_AUTONOMOUS];
    expect(isAutonomousMode()).toBe(false);
  });

  test("' true ' (whitespace-padded) → false (no .trim() — exact match only)", () => {
    process.env[ENV_AUTONOMOUS] = " true ";
    expect(isAutonomousMode()).toBe(false);
  });

  test("'true\\n' (trailing newline) → false (dotenv often slips a trailing \\n)", () => {
    process.env[ENV_AUTONOMOUS] = "true\n";
    expect(isAutonomousMode()).toBe(false);
  });

  test("arbitrary garbage value → false", () => {
    process.env[ENV_AUTONOMOUS] = "enable_autonomous_please";
    expect(isAutonomousMode()).toBe(false);
  });
});

describe("enforceAutonomousDeleteDeny — F4 permanent-delete hard-deny (v1.54)", () => {
  // The injectable `autonomous` param makes these deterministic without touching
  // env (the env path is covered by the strict-truthy block above + the default
  // param test at the bottom of this block).

  // RECOVERABLE mutations that MUST NOT be denied — they live in F1's write
  // bucket, not PERMANENT_DELETE_TOOLS. Pinning them here is the over-deny guard
  // (sec-rev hook: classifier audited against each tool's true recoverability).
  const RECOVERABLE = [
    "gmail_send",
    "gmail_modify_message",
    "gmail_delete_filter", // recreate
    "drive_create_file",
    "drive_unshare_file", // recovery action
    "tasks_clear", // hides completed, recoverable
    "tasks_update",
    "youtube_playlist_item_remove", // re-add
    "youtube_playlist_update",
  ];
  const READS = ["gmail_search", "drive_search_all", "tasks_list"];

  test("not autonomous → no-op for EVERY permanent-delete tool (byte-identical to pre-v1.54)", () => {
    for (const t of PERMANENT_DELETE_TOOLS) {
      expect(() => enforceAutonomousDeleteDeny(t, false)).not.toThrow();
    }
  });

  test("autonomous → throws -32033 for EVERY permanent-delete tool", () => {
    for (const t of PERMANENT_DELETE_TOOLS) {
      let caught: unknown;
      try {
        enforceAutonomousDeleteDeny(t, true);
      } catch (e) {
        caught = e;
      }
      expect(caught, `expected ${t} to be denied`).toBeInstanceOf(MCPError);
      expect((caught as MCPError).errorName).toBe(
        "destructive_denied_in_autonomous_mode",
      );
      expect((caught as MCPError).code).toBe(-32033);
    }
  });

  test("the denied set is EXACTLY F1's PERMANENT_DELETE_TOOLS (canonical 5, no drift)", () => {
    // F4 reuses F1's set verbatim (locked Q5a) — pin the membership so a future
    // change to either feature's set is a deliberate, reviewed edit.
    expect([...PERMANENT_DELETE_TOOLS].sort()).toEqual([
      "calendar_delete_event",
      "gmail_delete_draft",
      "tasks_delete",
      "youtube_comment_delete",
      "youtube_playlist_delete",
    ]);
  });

  test("autonomous → recoverable mutations are NOT denied (over-deny guard)", () => {
    for (const t of RECOVERABLE) {
      expect(() => enforceAutonomousDeleteDeny(t, true), `${t} must pass`).not.toThrow();
    }
  });

  test("autonomous → read tools are NOT denied", () => {
    for (const t of READS) {
      expect(() => enforceAutonomousDeleteDeny(t, true)).not.toThrow();
    }
  });

  test("autonomous → unknown tool name is NOT denied (only the explicit set)", () => {
    expect(() => enforceAutonomousDeleteDeny("nonexistent_tool", true)).not.toThrow();
  });

  test("denial errorData echoes NO target / tool (no-PII-echo convention)", () => {
    let caught: unknown;
    try {
      enforceAutonomousDeleteDeny("tasks_delete", true);
    } catch (e) {
      caught = e;
    }
    // errorData carries only the recovery hint (injected by toJsonRpc), never a
    // tool name or target id — the tool name is already on the audit row.
    expect((caught as MCPError).errorData).toEqual({});
    const j = (caught as MCPError).toJsonRpc();
    expect(j.code).toBe(-32033);
    expect(typeof j.data.recovery).toBe("string");
    expect(j.data.recovery).not.toContain("tasks_delete");
  });

  test("default param reads isAutonomousMode() from env (the production call shape)", () => {
    const original = process.env[ENV_AUTONOMOUS];
    try {
      // env OFF → no-op even for a permanent-delete tool
      delete process.env[ENV_AUTONOMOUS];
      expect(() => enforceAutonomousDeleteDeny("tasks_delete")).not.toThrow();
      // env ON → denies (proves the default param is wired to the live flag)
      process.env[ENV_AUTONOMOUS] = "true";
      expect(() => enforceAutonomousDeleteDeny("tasks_delete")).toThrow(MCPError);
      // a recoverable tool still passes under the live flag
      expect(() => enforceAutonomousDeleteDeny("gmail_send")).not.toThrow();
    } finally {
      if (original === undefined) delete process.env[ENV_AUTONOMOUS];
      else process.env[ENV_AUTONOMOUS] = original;
    }
  });
});
