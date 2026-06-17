// v1.99 — the enforced send-approval GATE (OPT-IN supervised mode).
//
// `requireSendApproval` is called by the two outbound egress choke points (tools/egress.ts)
// AFTER their recipient + secret-shape checks — it is ADDITIVE, never a bypass. When
// SAFESPACE_REQUIRE_SEND_APPROVAL is off (default), it is a no-op (byte-identical). When on, an
// outbound message send to a human (the APPROVAL_GATED_SENDS set) is blocked with
// -32050 send_approval_required{pending_id} until the owner approves THAT EXACT send out of band
// (`safespace send approve <id>`); the agent then retries the identical send, which is matched by
// fingerprint, CONSUMED (one-time), and delivered.
//
// FAIL DIRECTIONS (two, opposite): flag OFF → no-op (safe — the recipient/secret/tier gates
// still run; approval is supervision, not the primary egress defense). Flag ON but the store is
// unreadable/corrupt → FAIL CLOSED (throw; never silently allow a send the owner couldn't have
// approved).

import { readStrictTruthy } from "../config";
import { MCPError } from "../errors";
import type { ToolContext } from "../tools/types";
import { auditSendApprovalEvent } from "../audit";
import {
  computeFingerprint,
  consumeApprovedByFingerprint,
  createPending,
  DEFAULT_TTL_MS,
  pendingSendsPath,
} from "../auth/send-approval-store";

export const ENV_REQUIRE_SEND_APPROVAL = "SAFESPACE_REQUIRE_SEND_APPROVAL";

/** The outbound message sends supervised mode gates — the agent's writes TO A HUMAN.
 *  Deliberately EXCLUDES `gmail_create_draft` (a draft is not delivered; it sits in the owner's
 *  OWN mailbox to send manually — gating it would be incoherent). An approval-coverage sentinel
 *  pins that exclusion + forces any future human-send tool to be classified here. */
export const APPROVAL_GATED_SENDS: ReadonlySet<string> = new Set([
  "gmail_send",
  "telegram_send_message",
  "slack_send_message",
  "line_push_message",
  "discord_send_message",
]);

/** True iff SAFESPACE_REQUIRE_SEND_APPROVAL is the literal lowercase "true" (strict-truthy;
 *  every other value → false → today's posture, byte-identical). */
export function isSendApprovalMode(): boolean {
  return readStrictTruthy(ENV_REQUIRE_SEND_APPROVAL);
}

/** Bind the approval to the calling operator (Model B). Model A (allowedAccounts === null) → ""
 *  → byte-identical. Mirrors the recipient gate's allowedAccounts partition. */
function operatorKey(ctx: ToolContext): string {
  return ctx.allowedAccounts === null ? "" : [...ctx.allowedAccounts].sort().join(",");
}

// Serialize the load → match → consume/create read-modify-write so two concurrent in-process
// sends can't double-consume one approval (single-writer server; the CLI is the only other
// writer and a cross-process race is benign — a half-written file fails the parse → fail-closed).
let lock: Promise<unknown> = Promise.resolve();
function withLock<T>(fn: () => Promise<T>): Promise<T> {
  const run = lock.then(fn, fn);
  lock = run.catch(() => undefined);
  return run;
}

/** The gate. No-op unless supervised mode is on AND `tool` is an approval-gated human-send.
 *  Otherwise: match an approved+unconsumed record by fingerprint → consume + allow; else create
 *  a pending record + throw -32050{pending_id}. A store error fails CLOSED. NEVER echoes the body.
 *
 *  CALLER CONTRACT (same as the egress gates): pass the FINAL outbound shape — `recipients`
 *  already contact-resolved + validated, `body` already byte-capped — so the fingerprint binds
 *  exactly what is sent (no contact-resolution bait-and-switch). */
export async function requireSendApproval(
  ctx: ToolContext,
  send: { tool: string; recipients: string[]; body: string },
  opts: { now?: number; ttlMs?: number } = {},
): Promise<void> {
  if (!isSendApprovalMode() || !APPROVAL_GATED_SENDS.has(send.tool)) return;
  const now = opts.now ?? Date.now();
  const ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
  const operator = operatorKey(ctx);
  const fingerprint = computeFingerprint(send.tool, send.recipients, send.body, operator);
  const filePath = pendingSendsPath();

  await withLock(async () => {
    // CONSUME (one-time) BEFORE the SDK send — a SINGLE load (mirrors gmail.ts's record-before-
    // send): on a later SDK failure the owner re-approves an identical send (the safe direction,
    // zero double-send). A store read/parse error → FAIL CLOSED. The store error is NOT echoed,
    // and there is no pending_id on this path (reason alone signals the failure mode).
    let consumed: Awaited<ReturnType<typeof consumeApprovedByFingerprint>>;
    try {
      consumed = await consumeApprovedByFingerprint(filePath, fingerprint, now);
    } catch {
      throw new MCPError("send_approval_required", { reason: "store_error" });
    }
    if (consumed !== null) {
      await auditSendApprovalEvent({
        event: "consumed",
        pending_id: consumed.pending_id,
        tool: send.tool,
        fingerprint,
        recipients: send.recipients,
        operator,
      });
      return;
    }
    let pending_id: string;
    try {
      pending_id = await createPending(
        filePath,
        { fingerprint, tool: send.tool, recipients: send.recipients, body: send.body, operator },
        now,
        ttlMs,
      );
    } catch {
      // Store unwritable / full (MAX_RECORDS) → FAIL CLOSED (the send can't be recorded for
      // approval, so it cannot proceed).
      throw new MCPError("send_approval_required", { reason: "store_error" });
    }
    await auditSendApprovalEvent({
      event: "pending",
      pending_id,
      tool: send.tool,
      fingerprint,
      recipients: send.recipients,
      operator,
    });
    throw new MCPError("send_approval_required", { pending_id, reason: "awaiting_approval" });
  });
}
