// v1.99 — the enforced send-approval GATE: opt-in no-op (flag off / non-gated tool), the
// pending→approve→consume happy path, the anti-bait-and-switch fingerprint binding (tool /
// recipients / body / operator), one-time consume (no replay), fail-CLOSED on a corrupt store,
// and the APPROVAL_GATED_SENDS coverage pin (gmail_create_draft excluded). The store + audit
// land in a tmp SAFESPACE_CONFIG_DIR (no network, no real Keychain).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { NOOP_AUDIT, serviceTokenCred } from "../tools/test-audit";
import type { ToolContext } from "../tools/types";
import { approvePending, loadPendingSends, pendingSendsPath } from "../auth/send-approval-store";
import { APPROVAL_GATED_SENDS, requireSendApproval } from "./send-approval";

const ENV = ["SAFESPACE_REQUIRE_SEND_APPROVAL", "SAFESPACE_CONFIG_DIR"];
const saved: Record<string, string | undefined> = {};
let tmpDir: string;

function ctx(allowedAccounts: readonly string[] | null = null): ToolContext {
  return { allowedAccounts, credential: serviceTokenCred(() => "tok"), tier: "share", audit: NOOP_AUDIT };
}

const SEND = { tool: "gmail_send", recipients: ["alice@example.com"], body: "hello" };
const pendingId = (e: unknown): string => (e as { errorData: { pending_id: string } }).errorData.pending_id;

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-sendapproval-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  delete process.env.SAFESPACE_REQUIRE_SEND_APPROVAL;
});
afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  await fs.rm(tmpDir, { recursive: true, force: true });
});

describe("requireSendApproval — opt-in + coverage", () => {
  test("flag OFF → no-op (no pending recorded, no throw)", async () => {
    await requireSendApproval(ctx(), SEND);
    expect(await loadPendingSends(pendingSendsPath(), Date.now())).toEqual([]);
  });

  test("flag ON but a NON-gated tool (gmail_create_draft) → no-op", async () => {
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
    await requireSendApproval(ctx(), { tool: "gmail_create_draft", recipients: ["a@x.com"], body: "x" });
    expect(await loadPendingSends(pendingSendsPath(), Date.now())).toEqual([]);
  });

  test("APPROVAL_GATED_SENDS = the 5 human-sends, and EXCLUDES gmail_create_draft (a draft isn't delivered)", () => {
    expect([...APPROVAL_GATED_SENDS].sort()).toEqual([
      "discord_send_message",
      "gmail_send",
      "line_push_message",
      "slack_send_message",
      "telegram_send_message",
    ]);
    expect(APPROVAL_GATED_SENDS.has("gmail_create_draft")).toBe(false);
  });
});

describe("requireSendApproval — gate (flag ON)", () => {
  beforeEach(() => {
    process.env.SAFESPACE_REQUIRE_SEND_APPROVAL = "true";
  });

  test("first send → throws send_approval_required{pending_id} + records a pending (body stored for review)", async () => {
    const err = await requireSendApproval(ctx(), SEND).catch((e) => e);
    expect(err).toMatchObject({ errorName: "send_approval_required", errorData: { reason: "awaiting_approval" } });
    expect(typeof pendingId(err)).toBe("string");
    const recs = await loadPendingSends(pendingSendsPath(), Date.now());
    expect(recs).toHaveLength(1);
    expect(recs[0]!.status).toBe("pending");
    expect(recs[0]!.body).toBe("hello");
  });

  test("approved match → consumes + ALLOWS; the consumed approval cannot replay", async () => {
    const id = pendingId(await requireSendApproval(ctx(), SEND).catch((e) => e));
    await approvePending(pendingSendsPath(), id, Date.now());
    await expect(requireSendApproval(ctx(), SEND)).resolves.toBeUndefined();
    expect(await loadPendingSends(pendingSendsPath(), Date.now())).toHaveLength(0);
    // a 2nd identical retry is blocked again (one-time consume → no replay)
    await expect(requireSendApproval(ctx(), SEND)).rejects.toMatchObject({ errorName: "send_approval_required" });
  });

  test("bait-and-switch: approving body A does NOT allow body B", async () => {
    const id = pendingId(await requireSendApproval(ctx(), SEND).catch((e) => e));
    await approvePending(pendingSendsPath(), id, Date.now());
    await expect(requireSendApproval(ctx(), { ...SEND, body: "DIFFERENT" })).rejects.toMatchObject({
      errorName: "send_approval_required",
    });
  });

  test("recipient binding: approving [alice] does NOT allow [alice, bob]", async () => {
    const id = pendingId(await requireSendApproval(ctx(), SEND).catch((e) => e));
    await approvePending(pendingSendsPath(), id, Date.now());
    await expect(
      requireSendApproval(ctx(), { ...SEND, recipients: ["alice@example.com", "bob@example.com"] }),
    ).rejects.toMatchObject({ errorName: "send_approval_required" });
  });

  test("operator binding (Model B): operator A's approval is not consumable by operator B", async () => {
    const id = pendingId(await requireSendApproval(ctx(["a@x"]), SEND).catch((e) => e));
    await approvePending(pendingSendsPath(), id, Date.now());
    await expect(requireSendApproval(ctx(["b@x"]), SEND)).rejects.toMatchObject({ errorName: "send_approval_required" });
    // operator A's identical retry IS allowed (Model A null → "" is a distinct, byte-identical bucket)
    await expect(requireSendApproval(ctx(["a@x"]), SEND)).resolves.toBeUndefined();
  });

  test("a corrupt store FAILS CLOSED (throws store_error, never allows)", async () => {
    await fs.mkdir(tmpDir, { recursive: true });
    await fs.writeFile(pendingSendsPath(), "{ not valid json", { mode: 0o600 });
    await expect(requireSendApproval(ctx(), SEND)).rejects.toMatchObject({
      errorName: "send_approval_required",
      errorData: { reason: "store_error" },
    });
  });
});
