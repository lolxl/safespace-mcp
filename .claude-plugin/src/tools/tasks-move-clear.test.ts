// v1.47 B2 — tasks_move / tasks_clear (Tasks surface completion).
// SDK-level mock via setGaxiosHandler (same surface as the v1.19 tasks tests
// in handlers.test.ts). Security-relevant assertions: tasklist_id / task_id /
// parent / previous regex validation pre-SDK, handler-side tier re-check
// (denied_tier audit + scope_mismatch), correct audit operation + hash shape
// (move = task-level with both hashes; clear = list-level, target_task_hash
// ABSENT), and the within-list-only move (NO destinationTasklist).

import { beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, recorderSink } from "./test-audit";
import { tasksClear, tasksMove } from "./handlers";
import type { TasksMutationAuditMeta } from "../audit";
import type { ToolContext } from "./types";

const VALID_TASKLIST_ID = "MTk5MTI4MTk2OTI2";
const VALID_TASK_ID = "task_abc_123";
const VALID_PARENT_ID = "task_parent_456";
const VALID_PREVIOUS_ID = "task_prev_789";

let captured: TasksMutationAuditMeta | undefined;

function makeCtx(tier: "read" | "write" | "share"): ToolContext {
  return {
    credential: oauthCred("alice@example.com", () => "fake-token"),
    tier,
    audit: recorderSink({
      tasksMutationMeta: (m) => {
        captured = m;
      },
    }),
  };
}

const WRITE_CTX = makeCtx("write");
const READ_CTX = makeCtx("read");

beforeEach(async () => {
  captured = undefined;
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});

describe("tasks_move", () => {
  test("happy path — POST .../tasks/{task}/move, returns Task, audit move + both hashes", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let url = "";
    let method = "";
    setGaxiosHandler(async (opts) => {
      url = opts.url ?? "";
      method = (opts.method ?? "").toUpperCase();
      return { data: { id: VALID_TASK_ID, title: "Moved task" }, status: 200 };
    });

    const out = (await tasksMove(WRITE_CTX, {
      tasklist_id: VALID_TASKLIST_ID,
      task_id: VALID_TASK_ID,
    })) as { id: string };

    expect(out.id).toBe(VALID_TASK_ID);
    expect(method).toBe("POST");
    expect(url).toContain(
      `/tasks/v1/lists/${VALID_TASKLIST_ID}/tasks/${VALID_TASK_ID}/move`,
    );

    expect(captured?.operation).toBe("move");
    expect(captured?.policy_decision).toBe("allowed");
    expect(captured?.target_tasklist_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(captured?.target_task_hash).toMatch(/^[0-9a-f]{64}$/);
  });

  test("parent + previous forwarded to the SDK as query params", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let params: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      params = (opts.params ?? {}) as Record<string, unknown>;
      return { data: { id: VALID_TASK_ID }, status: 200 };
    });

    await tasksMove(WRITE_CTX, {
      tasklist_id: VALID_TASKLIST_ID,
      task_id: VALID_TASK_ID,
      parent: VALID_PARENT_ID,
      previous: VALID_PREVIOUS_ID,
    });

    expect(params.parent).toBe(VALID_PARENT_ID);
    expect(params.previous).toBe(VALID_PREVIOUS_ID);
    // Within-list only — destinationTasklist is NEVER sent.
    expect(params.destinationTasklist).toBeUndefined();
  });

  test("omitting parent/previous sends neither (top level / first position)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let params: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      params = (opts.params ?? {}) as Record<string, unknown>;
      return { data: { id: VALID_TASK_ID }, status: 200 };
    });

    await tasksMove(WRITE_CTX, {
      tasklist_id: VALID_TASKLIST_ID,
      task_id: VALID_TASK_ID,
    });

    expect("parent" in params).toBe(false);
    expect("previous" in params).toBe(false);
  });

  test("missing tasklist_id / task_id rejected pre-SDK (handler not called)", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });
    await expect(
      tasksMove(WRITE_CTX, { task_id: VALID_TASK_ID }),
    ).rejects.toThrow(/tasklist_id/);
    await expect(
      tasksMove(WRITE_CTX, { tasklist_id: VALID_TASKLIST_ID }),
    ).rejects.toThrow(/task_id/);
    expect(handlerCalled).toBe(false);
  });

  test("hostile tasklist_id / task_id / parent / previous rejected pre-SDK (echoes RULE not value)", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });
    const hostile = "../etc/passwd\r\n";

    await expect(
      tasksMove(WRITE_CTX, { tasklist_id: hostile, task_id: VALID_TASK_ID }),
    ).rejects.toThrow(/tasklist_id.*\^\[A-Za-z0-9_-\]/);
    await expect(
      tasksMove(WRITE_CTX, { tasklist_id: VALID_TASKLIST_ID, task_id: hostile }),
    ).rejects.toThrow(/task_id.*\^\[A-Za-z0-9_-\]/);
    await expect(
      tasksMove(WRITE_CTX, {
        tasklist_id: VALID_TASKLIST_ID,
        task_id: VALID_TASK_ID,
        parent: hostile,
      }),
    ).rejects.toThrow(/parent.*\^\[A-Za-z0-9_-\]/);
    await expect(
      tasksMove(WRITE_CTX, {
        tasklist_id: VALID_TASKLIST_ID,
        task_id: VALID_TASK_ID,
        previous: hostile,
      }),
    ).rejects.toThrow(/previous.*\^\[A-Za-z0-9_-\]/);
    expect(handlerCalled).toBe(false);
  });

  test("tier=read → scope_mismatch + audit denied_tier + operation=move (BEFORE throw)", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });

    await expect(
      tasksMove(READ_CTX, {
        tasklist_id: VALID_TASKLIST_ID,
        task_id: VALID_TASK_ID,
      }),
    ).rejects.toThrow(/SAFESPACE_TIER|scope/i);

    expect(handlerCalled).toBe(false);
    expect(captured?.operation).toBe("move");
    expect(captured?.policy_decision).toBe("denied_tier");
    expect(captured?.target_tasklist_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(captured?.target_task_hash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe("tasks_clear", () => {
  test("happy path — POST .../lists/{tasklist}/clear, returns cleared:true, audit clear + tasklist hash only", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let url = "";
    let method = "";
    setGaxiosHandler(async (opts) => {
      url = opts.url ?? "";
      method = (opts.method ?? "").toUpperCase();
      return { data: "", status: 204 };
    });

    const out = (await tasksClear(WRITE_CTX, {
      tasklist_id: VALID_TASKLIST_ID,
    })) as { tasklist_id: string; cleared: boolean };

    expect(out.cleared).toBe(true);
    expect(out.tasklist_id).toBe(VALID_TASKLIST_ID);
    expect(method).toBe("POST");
    expect(url).toContain(`/tasks/v1/lists/${VALID_TASKLIST_ID}/clear`);

    expect(captured?.operation).toBe("clear");
    expect(captured?.policy_decision).toBe("allowed");
    expect(captured?.target_tasklist_hash).toMatch(/^[0-9a-f]{64}$/);
    // List-level — no single task. target_task_hash MUST be ABSENT.
    expect(captured?.target_task_hash).toBeUndefined();
  });

  test("missing / hostile tasklist_id rejected pre-SDK (handler not called)", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: "", status: 204 };
    });
    await expect(tasksClear(WRITE_CTX, {})).rejects.toThrow(/tasklist_id/);
    await expect(
      tasksClear(WRITE_CTX, { tasklist_id: "../etc/passwd\r\n" }),
    ).rejects.toThrow(/tasklist_id.*\^\[A-Za-z0-9_-\]/);
    expect(handlerCalled).toBe(false);
  });

  test("tier=read → scope_mismatch + audit denied_tier + operation=clear (BEFORE throw)", async () => {
    let handlerCalled = false;
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => {
      handlerCalled = true;
      return { data: "", status: 204 };
    });

    await expect(
      tasksClear(READ_CTX, { tasklist_id: VALID_TASKLIST_ID }),
    ).rejects.toThrow(/SAFESPACE_TIER|scope/i);

    expect(handlerCalled).toBe(false);
    expect(captured?.operation).toBe("clear");
    expect(captured?.policy_decision).toBe("denied_tier");
    expect(captured?.target_tasklist_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(captured?.target_task_hash).toBeUndefined();
  });
});
