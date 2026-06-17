// v1.39 BLOCKER 4 — tasks-delete target allowlist tests. Mirrors the
// youtube-comment-targets test inventory, INVERTED for the off=allow default.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "../tools/test-audit";
import { tasksDelete } from "../tools/handlers";
import type { ToolContext } from "../tools/types";
import {
  __internal,
  buildTasksDeleteAllowlistState,
  getTasksDeleteAllowlistState,
  isTasksDeleteAllowed,
  parseTasksDeleteTargets,
  summarizeTasksDeleteAllowlist,
} from "./tasks-delete-targets";
import { ENV_AUTONOMOUS } from "./autonomous-mode";

const ENV = "SAFESPACE_TASKS_DELETE_TARGETS";
const ENV_EXTRA = "SAFESPACE_TASKS_DELETE_TARGETS_EXTRA";

// ───────────────────────── pure: parser ─────────────────────────
describe("parseTasksDeleteTargets", () => {
  test("accepts a valid tasklist:<id>", () => {
    const r = parseTasksDeleteTargets("tasklist:MyList_AAA-001");
    expect(r.ok).toEqual(["MyList_AAA-001"]);
    expect(r.rejected).toEqual([]);
  });
  test("rejects malformed tokens without crashing", () => {
    const r = parseTasksDeleteTargets(
      "bad,tasklist:,tasklist:has space,task:abc,Tasklist:Abc,tasklist:" +
        "x".repeat(129),
    );
    expect(r.ok).toEqual([]);
    expect(r.rejected.length).toBe(6);
  });
  test("trims, drops empties, and dedups", () => {
    const r = parseTasksDeleteTargets("  tasklist:A  , ,tasklist:A,tasklist:B");
    expect(r.ok).toEqual(["A", "B"]);
  });
  test("undefined input → empty", () => {
    expect(parseTasksDeleteTargets(undefined)).toEqual({ ok: [], rejected: [] });
  });
});

// ───────────────────────── pure: state build ─────────────────────────
describe("buildTasksDeleteAllowlistState", () => {
  test("both undefined → off", () => {
    expect(buildTasksDeleteAllowlistState(undefined, undefined)).toEqual({
      kind: "off",
    });
  });
  test("base set → active", () => {
    const s = buildTasksDeleteAllowlistState("tasklist:A", undefined);
    expect(s.kind).toBe("active");
    if (s.kind === "active") expect([...s.tasklists]).toEqual(["A"]);
  });
  test("extra-only → active (flips off→on)", () => {
    const s = buildTasksDeleteAllowlistState(undefined, "tasklist:B");
    expect(s.kind).toBe("active");
    if (s.kind === "active") expect([...s.tasklists]).toEqual(["B"]);
  });
  test("merges + dedups base and extra", () => {
    const s = buildTasksDeleteAllowlistState("tasklist:A,tasklist:B", "tasklist:B,tasklist:C");
    if (s.kind === "active") expect([...s.tasklists].sort()).toEqual(["A", "B", "C"]);
  });

  // ─────────────── v1.53 F2 — autonomous/strict mode flip ───────────────
  test("autonomous=false + both undefined → off (byte-identical to today)", () => {
    expect(buildTasksDeleteAllowlistState(undefined, undefined, false)).toEqual({
      kind: "off",
    });
  });
  test("autonomous=true + both undefined → active-empty → ALL deletes denied", () => {
    const s = buildTasksDeleteAllowlistState(undefined, undefined, true);
    expect(s.kind).toBe("active");
    if (s.kind === "active") expect(s.tasklists.size).toBe(0);
    expect(isTasksDeleteAllowed("anything", s)).toBe(false);
  });
  test("autonomous=true still honors an explicit listed tasklist", () => {
    const s = buildTasksDeleteAllowlistState("tasklist:A", undefined, true);
    expect(isTasksDeleteAllowed("A", s)).toBe(true);
    expect(isTasksDeleteAllowed("Z", s)).toBe(false);
  });
});

describe("getTasksDeleteAllowlistState — v1.53 F2 loader wiring", () => {
  const ENV_AUTO = ENV_AUTONOMOUS;
  let autoBackup: string | undefined;
  beforeEach(() => {
    autoBackup = process.env[ENV_AUTO];
    delete process.env[ENV_AUTO];
    delete process.env[ENV];
    delete process.env[ENV_EXTRA];
    __internal.resetSingletons();
  });
  afterEach(() => {
    if (autoBackup === undefined) delete process.env[ENV_AUTO];
    else process.env[ENV_AUTO] = autoBackup;
    __internal.resetSingletons();
  });

  test("SAFESPACE_AUTONOMOUS=true + unset targets → active-empty (deny all); flag is actually read", () => {
    // Pins the getTasksDeleteAllowlistState → isAutonomousMode() wiring.
    process.env[ENV_AUTO] = "true";
    const s = getTasksDeleteAllowlistState();
    expect(s.kind).toBe("active");
    expect(isTasksDeleteAllowed("anything", s)).toBe(false);
  });

  test("flag unset → off (allow all) — today's default preserved", () => {
    const s = getTasksDeleteAllowlistState();
    expect(s.kind).toBe("off");
    expect(isTasksDeleteAllowed("anything", s)).toBe(true);
  });
});

// ───────────────────────── pure: matching (off=ALLOW) ─────────────────────────
describe("isTasksDeleteAllowed — default-ALLOW (inverted vs comment-targets)", () => {
  test("off → ALLOW (the key inversion)", () => {
    expect(isTasksDeleteAllowed("anything", { kind: "off" })).toBe(true);
  });
  test("active + listed → allow", () => {
    expect(
      isTasksDeleteAllowed("A", { kind: "active", tasklists: new Set(["A"]) }),
    ).toBe(true);
  });
  test("active + unlisted → deny", () => {
    expect(
      isTasksDeleteAllowed("Z", { kind: "active", tasklists: new Set(["A"]) }),
    ).toBe(false);
  });
  test("active + empty → deny ALL", () => {
    expect(isTasksDeleteAllowed("A", { kind: "active", tasklists: new Set() })).toBe(false);
  });
  test("empty tasklistId under active → deny", () => {
    expect(isTasksDeleteAllowed("", { kind: "active", tasklists: new Set(["A"]) })).toBe(false);
  });
});

describe("summarizeTasksDeleteAllowlist", () => {
  test("off → count 0", () => {
    expect(summarizeTasksDeleteAllowlist({ kind: "off" })).toEqual({ kind: "off", count: 0 });
  });
  test("active → count", () => {
    expect(
      summarizeTasksDeleteAllowlist({ kind: "active", tasklists: new Set(["A", "B"]) }),
    ).toEqual({ kind: "active", count: 2 });
  });
});

// ───────────────────────── env loader (singleton) ─────────────────────────
describe("getTasksDeleteAllowlistState (env)", () => {
  afterEach(() => {
    delete process.env[ENV];
    delete process.env[ENV_EXTRA];
    __internal.resetSingletons();
  });
  test("unset → off", () => {
    delete process.env[ENV];
    delete process.env[ENV_EXTRA];
    __internal.resetSingletons();
    expect(getTasksDeleteAllowlistState().kind).toBe("off");
  });
  test("set → active", () => {
    process.env[ENV] = "tasklist:A";
    __internal.resetSingletons();
    const s = getTasksDeleteAllowlistState();
    expect(s.kind).toBe("active");
    if (s.kind === "active") expect(s.tasklists.has("A")).toBe(true);
  });
});

// ───────────────────────── gate integration (in tasksDelete) ─────────────────────────
describe("tasks_delete gate — ctx.tier=write, allowlist enforced before SDK", () => {
  const VALID_TASKLIST = "MyTaskList_001";
  const VALID_TASK = "Task_ABC-001";
  let sdkCalled = false;

  function ctxWrite(): ToolContext {
    return { allowedAccounts: null,
      credential: oauthCred("alice@example.com", () => "fake-token"),
      tier: "write",
      audit: NOOP_AUDIT,
    };
  }
  async function installSdkMock(): Promise<void> {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      sdkCalled = true;
      return { data: {}, status: 204 };
    });
  }

  beforeEach(() => {
    sdkCalled = false;
  });
  afterEach(async () => {
    delete process.env[ENV];
    delete process.env[ENV_EXTRA];
    __internal.resetSingletons();
    const { resetGaxiosHandler } = await import("../google-api/test-utils");
    resetGaxiosHandler();
  });

  test("active + UNLISTED tasklist → -32030, SDK never called", async () => {
    await installSdkMock();
    process.env[ENV] = "tasklist:SomeOtherList";
    __internal.resetSingletons();
    await expect(
      tasksDelete(ctxWrite(), { tasklist_id: VALID_TASKLIST, task_id: VALID_TASK }),
    ).rejects.toMatchObject({ errorName: "tasks_delete_denied_by_policy" });
    expect(sdkCalled).toBe(false);
  });

  test("active + LISTED tasklist → proceeds to SDK (deleted)", async () => {
    await installSdkMock();
    process.env[ENV] = `tasklist:${VALID_TASKLIST}`;
    __internal.resetSingletons();
    const res = await tasksDelete(ctxWrite(), {
      tasklist_id: VALID_TASKLIST,
      task_id: VALID_TASK,
    });
    expect(res).toMatchObject({ deleted: true });
    expect(sdkCalled).toBe(true);
  });

  test("OFF (unset) → proceeds to SDK (allow-all default = zero-impact)", async () => {
    await installSdkMock();
    delete process.env[ENV];
    delete process.env[ENV_EXTRA];
    __internal.resetSingletons();
    const res = await tasksDelete(ctxWrite(), {
      tasklist_id: VALID_TASKLIST,
      task_id: VALID_TASK,
    });
    expect(res).toMatchObject({ deleted: true });
    expect(sdkCalled).toBe(true);
  });
});
