// Audit EVENT appenders — the bare forensic / policy JSONL rows that sit
// ALONGSIDE the per-call auditEnd row (share / share-denied / recipient-denied /
// send-approval / cross-account aggregate).
// Extracted VERBATIM from audit.ts (the chain WRITER) as a sibling leaf. Each
// appender builds its payload then routes through the chain writer's
// `appendChainedRow`, which picks the chain file from the process role (the server's
// audit.jsonl, or audit-cli.jsonl for a `safespace` CLI process).
//
// RUNTIME-SAFE CYCLE: this module imports appendChainedRow / hashTargetEmail /
// getRunId from ../audit, which re-exports this module (the
// barrel). The cycle is safe because (a) those three are FUNCTION DECLARATIONS in
// audit.ts (hoisted — initialized before any statement runs) and (b) this module
// only CALLS them inside appender bodies (at runtime), never at module-eval time.
// Same documented pattern as tools/with-all-accounts.ts <-> tools/registry.

import { appendChainedRow, getRunId, hashTargetEmail } from "../audit";
import { canonicalizeTarget, type ApprovalTarget } from "../auth/send-approval-store";

export interface AuditShareEventContext {
  tool: "drive_share_file" | "drive_unshare_file";
  email: string;
  file_id: string;
  share_type: "anyone" | "user";
  role?: "reader" | "commenter";
  /** HMAC-SHA256 of target email (full 64-char hex). null for share_type=anyone. */
  target_email_hash: string | null;
  expiration_iso: string | null;
  granted_permission_id: string | null;
}

/** Append one forensic JSONL line to audit.jsonl for a share / unshare call.
 *
 *  Supplementary to the standard `auditEnd` line that with-context writes
 *  on every tool call. Both lines share `tool` + `account` fields so a log
 *  reader can correlate them, but only this one carries the share-specific
 *  forensic detail (which file, what role, who got access).
 *
 *  `event: "share_forensic"` is the discriminator — readers can grep
 *  `'"event":"share_forensic"'` for the audit detail without colliding
 *  with the standard call lines (which never carry `event`). */
export async function auditShareEvent(ctx: AuditShareEventContext): Promise<void> {
  const payload: Record<string, unknown> = {
    ts: new Date().toISOString(),
    tool: ctx.tool,
    account: ctx.email,
    event: "share_forensic",
    file_id: ctx.file_id,
    share_type: ctx.share_type,
    role: ctx.role ?? null,
    target_email_hash: ctx.target_email_hash,
    expiration_iso: ctx.expiration_iso,
    granted_permission_id: ctx.granted_permission_id,
  };
  await appendChainedRow(payload, "audit share event");
}

// Intentionally excludes target_email, share_type, role: the call was
// refused before those inputs were validated upstream. Adding any of
// those fields here would break the v2.1 spec invariant — see
// docs/DESIGN.md v2.1 Addendum "What the audit log records".
export interface AuditShareDeniedContext {
  email: string;
  file_id: string;
  ancestors_walked: number;
  duration_ms: number;
}

/** Append one forensic JSONL line for a drive_share_file call that was
 *  REFUSED by the v2.1 whitelist policy. The call never reached the API —
 *  intentionally, no target_email or share_type or role is recorded,
 *  because the user's intent at those fields was never validated.
 *
 *  `event: "share_denied_by_policy"` discriminator parallels
 *  `share_forensic`. Both lines share tool + account + file_id so a log
 *  reader can correlate denials with subsequent retries. */
export async function auditShareDeniedEvent(
  ctx: AuditShareDeniedContext,
): Promise<void> {
  const payload: Record<string, unknown> = {
    ts: new Date().toISOString(),
    tool: "drive_share_file",
    account: ctx.email,
    event: "share_denied_by_policy",
    file_id: ctx.file_id,
    ancestors_walked: ctx.ancestors_walked,
    duration_ms: ctx.duration_ms,
  };
  await appendChainedRow(payload, "audit share-denied");
}

// Intentionally excludes plaintext recipients, share_type, role: the call
// was refused at the v2.2 recipient gate; the rejected addresses are
// recorded only as HMAC-SHA256 hashes (same audit-salt as v1.2 share_forensic
// target_email_hash) so a log reader can correlate "denied to X" with
// "successful send to X" without storing plaintext.
export interface AuditRecipientDeniedContext {
  tool:
    | "drive_share_file"
    | "gmail_send"
    | "gmail_create_draft"
    | "line_push_message"
    | "telegram_send_message"
    | "discord_send_message"
    | "slack_send_message"
    | "mattermost_send_message";
  // v1.66 — `string | null`: a class-B connector (LINE) has no Google account, so
  // the denied event's `account` field is null (the `tool` disambiguates it).
  email: string | null;
  /** HMAC-SHA256 hex of each rejected recipient. Length may be less than
   *  `rejected_count` if any hash computation failed (treated as fail-closed
   *  — the recipient was still rejected; just no hash for it). The delta
   *  is observable via `rejected_count - rejected_recipient_hashes.length`. */
  rejected_recipient_hashes: string[];
  rejected_count: number;
  total_recipients: number;
  duration_ms: number;
}

/** Append one forensic JSONL line for a call refused by the v2.2 recipient
 *  allowlist. Same swallow-errors pattern as auditShareEvent /
 *  auditShareDeniedEvent — never block on append failure. */
export async function auditRecipientDeniedEvent(
  ctx: AuditRecipientDeniedContext,
): Promise<void> {
  const payload: Record<string, unknown> = {
    ts: new Date().toISOString(),
    tool: ctx.tool,
    account: ctx.email,
    event: "recipient_denied_by_policy",
    rejected_recipient_hashes: ctx.rejected_recipient_hashes,
    rejected_count: ctx.rejected_count,
    total_recipients: ctx.total_recipients,
    duration_ms: ctx.duration_ms,
  };
  await appendChainedRow(payload, "audit recipient-denied");
}

/** v1.99 — a send-approval gate decision (OPT-IN supervised mode). Records the tool, the
 *  pending id, the send fingerprint, the operator, each recipient as an HMAC-SHA256 HASH,
 *  and (when present) a `target_hash` of the canonical typed target — NEVER the body or
 *  the target plaintext (those live only in pending-sends.json for the owner's local
 *  review). Same swallow-errors / bare-append pattern as auditRecipientDeniedEvent
 *  (these forensic lines sit outside the v1.89 row_mac chain). `event` ∈ pending
 *  (blocked, awaiting approval) / consumed (an approved send went through) /
 *  approved|denied (the owner's CLI action). */
export interface AuditSendApprovalContext {
  event: "pending" | "consumed" | "approved" | "denied";
  pending_id: string;
  tool: string;
  fingerprint: string;
  recipients: string[];
  /** "" = Model A → recorded as null. */
  operator: string;
  /** Typed public-write target; hashed into target_hash, never stored plaintext. */
  target?: ApprovalTarget;
}

export async function auditSendApprovalEvent(ctx: AuditSendApprovalContext): Promise<void> {
  const hashes = (
    await Promise.all(ctx.recipients.map((r) => hashTargetEmail(r).catch(() => null)))
  ).filter((h): h is string => h !== null);
  const payload: Record<string, unknown> = {
    ts: new Date().toISOString(),
    tool: ctx.tool,
    event: `send_approval_${ctx.event}`,
    pending_id: ctx.pending_id,
    fingerprint: ctx.fingerprint,
    recipient_hashes: hashes,
    operator: ctx.operator === "" ? null : ctx.operator,
  };
  if (ctx.target !== undefined) {
    const th = await hashTargetEmail(JSON.stringify(canonicalizeTarget(ctx.target))).catch(() => null);
    if (th !== null) payload.target_hash = th;
  }
  // The writing process picks the chain: the server's `pending` / `consumed` rows join
  // audit.jsonl; the owner's CLI `approved` / `denied` (cli/send.ts) — and the rows of a
  // `safespace exec` send — join audit-cli.jsonl.
  await appendChainedRow(payload, "audit send-approval");
}

// v1.14 Phase 1: cross-account aggregate audit row.
// See docs/v1.14-cross-account-search.md §8 — per-call we emit:
//   - 1 outer row (this fn, `event: "cross_account_aggregate"`)
//   - N inner rows (existing `auditEnd`, one per per-account sub-call,
//     INCLUDING failures with `status: "failed"`)
// The outer + inner rows correlate via the outer `args_hash` (SHA256 of the
// full outer args including `accounts?` filter) and the time window. Account
// counts (`account_count_*`) are integers, NEVER identities — anti-enumeration.
export interface AuditCrossAccountAggregateContext {
  tool: string;
  argsHash: string;
  accountCountQueried: number;
  accountCountSucceeded: number;
  accountCountFailed: number;
}

/** Append one forensic JSONL line for a cross-account `_all` tool call.
 *
 *  Same swallow-errors pattern as auditShareEvent / auditShareDeniedEvent /
 *  auditRecipientDeniedEvent — never block on append failure.
 *
 *  `event: "cross_account_aggregate"` discriminator parallels existing
 *  forensic event lines so a log reader can grep cross-account calls
 *  separately from the standard per-account `auditEnd` lines. NO plaintext
 *  identities are recorded here — the per-account `account` field belongs
 *  on the inner rows (`auditEnd`). */
export async function auditCrossAccountAggregate(
  ctx: AuditCrossAccountAggregateContext,
): Promise<void> {
  const payload: Record<string, unknown> = {
    ts: new Date().toISOString(),
    tool: ctx.tool,
    event: "cross_account_aggregate",
    args_hash: ctx.argsHash,
    account_count_queried: ctx.accountCountQueried,
    account_count_succeeded: ctx.accountCountSucceeded,
    account_count_failed: ctx.accountCountFailed,
  };
  await appendChainedRow(payload, "audit cross-account-aggregate");
}
