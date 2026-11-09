// v1.99 — the enforced send-approval GATE (OPT-IN supervised mode).
//
// `requireSendApproval` is called by the outbound egress choke points (tools/egress.ts)
// AFTER their recipient / target-allowlist + secret-shape checks, and by drive_share_file
// (anyone) AFTER the whitelist — it is ADDITIVE, never a bypass. When
// SAFESPACE_REQUIRE_SEND_APPROVAL is off (default), it is a no-op (byte-identical). When on, a
// gated outbound publish (the APPROVAL_GATED_SENDS set) is blocked with
// -32050 send_approval_required{pending_id} until the owner approves THAT EXACT send out of band
// (`safespace send approve <id>`); the agent then retries the identical send, which is matched by
// fingerprint, CONSUMED (one-time), and delivered. Public writes bind a typed target the owner
// can see in `safespace send list`.
//
// FAIL DIRECTIONS (two, opposite): flag OFF → no-op (safe — the recipient/secret/tier gates
// still run; approval is supervision, not the primary egress defense). Flag ON but the store is
// unreadable/corrupt → FAIL CLOSED (throw; never silently allow a send the owner couldn't have
// approved).

import { ENV_REQUIRE_SEND_APPROVAL, readStrictTruthy } from "../config";
import { MCPError } from "../errors";
import type { ToolContext } from "../tools/types";
import { auditSendApprovalEvent } from "../audit";
import {
  computeFingerprint,
  consumeApprovedByFingerprint,
  createPending,
  DEFAULT_TTL_MS,
  pendingSendsPath,
  type ApprovalTarget,
} from "../auth/send-approval-store";

export { ENV_REQUIRE_SEND_APPROVAL };
export type { ApprovalTarget };

/** The outbound publishes supervised mode gates: writes TO A HUMAN plus irretractable
 *  public-surface writes (v1.128 Q3-B). Deliberately EXCLUDES `gmail_create_draft` (a
 *  draft is not delivered). `drive_share_file` is in the set; the handler only CALLS
 *  this gate when `share_type === "anyone"` (`user` stays on the recipient allowlist).
 *  `forms_publish` is too (a published form is reachable by anyone with its link).
 *  A coverage sentinel requires every `direction:"outbound-write"` tool AND every
 *  HANDLER_GATED_EXTERNAL tool to be here or in APPROVAL_EXCLUDED_WRITES. */
export const APPROVAL_GATED_SENDS: ReadonlySet<string> = new Set([
  "gmail_send",
  "telegram_send_message",
  "slack_send_message",
  "line_push_message",
  "discord_send_message",
  "mattermost_send_message",
  "youtube_video_comment_post",
  "youtube_comment_reply",
  "x_post_create",
  "drive_share_file",
  "forms_publish",
]);

/** outbound-write + HANDLER_GATED_EXTERNAL tools that are NOT approval-gated, with
 *  the reason a coverage pin keeps honest. A new public-surface write must land in
 *  APPROVAL_GATED_SENDS (with a typed visible target) or here — never unclassified. */
export const APPROVAL_EXCLUDED_WRITES: Readonly<Record<string, string>> = {
  gmail_create_draft: "not delivered; sits in the owner's mailbox",
  youtube_video_update: "default-deny video-target allowlist; not in the Q3-B public-comment/post set",
  github_create_issue: "repo write allowlist",
  github_create_issue_comment: "repo write allowlist",
  github_update_issue: "repo write allowlist",
  github_create_pull_request: "repo write allowlist",
  github_merge_pull_request: "separate merge-target allowlist",
  github_create_pull_request_review: "event-conditional write/approve allowlists",
  github_set_issue_labels: "repo write allowlist",
  notion_create_page: "workspace-internal; F3a secret-shape only",
  notion_append_blocks: "workspace-internal; F3a secret-shape only",
  notion_update_page: "workspace-internal; F3a secret-shape only",
};

/** True iff SAFESPACE_REQUIRE_SEND_APPROVAL is the literal lowercase "true" (strict-truthy;
 *  every other value → false → today's posture, byte-identical). */
export function isSendApprovalMode(): boolean {
  return readStrictTruthy(ENV_REQUIRE_SEND_APPROVAL);
}

/** The operator key a pending approval is bound to. Always "" now that one process
 *  serves one operator; kept so the fingerprint of existing pending records still
 *  matches. */
function operatorKey(_ctx: ToolContext): string {
  return "";
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
  send: { tool: string; recipients: string[]; body: string; target?: ApprovalTarget },
  opts: { now?: number; ttlMs?: number } = {},
): Promise<void> {
  if (!isSendApprovalMode() || !APPROVAL_GATED_SENDS.has(send.tool)) return;
  const now = opts.now ?? Date.now();
  const ttlMs = opts.ttlMs ?? DEFAULT_TTL_MS;
  const operator = operatorKey(ctx);
  const fingerprint = computeFingerprint(send.tool, send.recipients, send.body, operator, send.target);
  // Same-call 401 retry (with-context rebuilds ctx but copies this field): the
  // approval was already consumed; do not create a new pending.
  if (ctx.sendApprovalConsumedFingerprint === fingerprint) return;
  const filePath = pendingSendsPath();

  await withLock(async () => {
    // CONSUME (one-time) BEFORE the SDK send — a SINGLE load (mirrors gmail.ts's record-before-
    // send). A later *new* call of an identical send still needs a fresh approval (the
    // safe direction, zero double-send). An in-process 401 retry of THIS call is the
    // other path: after consume we stamp ctx.sendApprovalConsumedFingerprint so the
    // retried handler does not burn the owner's approval. A store read/parse error →
    // FAIL CLOSED. The store error is NOT echoed, and there is no pending_id on this
    // path (reason alone signals the failure mode).
    let consumed: Awaited<ReturnType<typeof consumeApprovedByFingerprint>>;
    try {
      consumed = await consumeApprovedByFingerprint(filePath, fingerprint, now);
    } catch {
      throw new MCPError("send_approval_required", { reason: "store_error" });
    }
    if (consumed !== null) {
      ctx.sendApprovalConsumedFingerprint = fingerprint;
      await auditSendApprovalEvent({
        event: "consumed",
        pending_id: consumed.pending_id,
        tool: send.tool,
        fingerprint,
        recipients: send.recipients,
        operator,
        ...(send.target !== undefined ? { target: send.target } : {}),
      });
      return;
    }
    let pending_id: string;
    try {
      pending_id = await createPending(
        filePath,
        {
          fingerprint,
          tool: send.tool,
          recipients: send.recipients,
          body: send.body,
          operator,
          ...(send.target !== undefined ? { target: send.target } : {}),
        },
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
      ...(send.target !== undefined ? { target: send.target } : {}),
    });
    throw new MCPError("send_approval_required", { pending_id, reason: "awaiting_approval" });
  });
}
