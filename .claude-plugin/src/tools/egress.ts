// v1.64 Phase B (B3 — D2: centralize egress) — the safety-gateway egress gate.
//
// BEFORE B3: the two outbound gates lived as module-private helpers inside
// handlers/gmail.ts (enforceRecipientAllowlist + enforceOutboundSecret), wired
// ONLY by gmail_send + gmail_create_draft. A naive future connector / outbound
// tool that forgot to call them would ship with ZERO recipient / secret /
// tainted-source protection while *looking* protected (thesis §6.1 — the egress
// gates are NOT centralized today). B3 lifts them HERE, into one
// `enforceEgressGates`, so the envelope's egress protection has exactly ONE
// implementation that cannot drift weaker (or go missing) per outbound tool.
//
// BEHAVIOR-PRESERVING: the two gate functions below are moved VERBATIM from
// handlers/gmail.ts (same order, same audit recording, same error codes). The
// google-workspace path is byte-identical — the f3a-f3b-gate / tainted-source /
// gmail send+draft suites are the regression net.
//
// WHY THIS IS HANDLER-CALLED, NOT PIPELINE-FIRED (the §2.4 runPipeline pre-fire):
// the recipient allowlist MUST run on the CONTACT-RESOLVED recipients (a
// SAFESPACE_RECIPIENT_ALLOW_CONTACTS name→email resolution happens inside
// gmailSend), and that resolution — like the SDK send itself — lives inside the
// handler. A with-context.ts pre-handler step would gate the raw typed name
// (e.g. "alice"), false-rejecting every resolved recipient and breaking the
// contacts path. So `enforceEgressGates` is invoked by the handler at the
// existing resolved-recipient point (byte-identical ordering). Making the
// pipeline FIRE this off `ToolDef.direction === "outbound-write"` requires moving
// contact-resolution into the Source layer first — that is B6 (unify the choke
// points). Until then `direction` stays the registry LABEL (registry/types.ts)
// and this gate is the one place the egress logic lives.
//
// LAYERING: this module is the tools/ orchestration layer — it composes the
// policy/* primitives (recipient-allowlist / tainted-source / outbound-secret /
// autonomous-mode) with the audit sink + requireGoogle narrow, exactly as the
// pre-B3 gmail.ts helpers did. No new policy primitive; no behavior change.

import { auditRecipientDeniedEvent, hashTargetEmail } from "../audit";
import { MCPError } from "../errors";
import { isAutonomousMode } from "../policy/autonomous-mode";
import { requireSendApproval } from "../policy/send-approval";
import {
  getLineAllowlistState,
  isLineRecipientAllowed,
} from "../policy/line-recipient-allowlist";
import {
  getTelegramAllowlistState,
  isTelegramRecipientAllowed,
} from "../policy/telegram-recipient-allowlist";
import {
  getDiscordAllowlistState,
  isDiscordRecipientAllowed,
} from "../policy/discord-recipient-allowlist";
import {
  getSlackAllowlistState,
  isSlackRecipientAllowed,
} from "../policy/slack-recipient-allowlist";
import {
  getMattermostAllowlistState,
  isMattermostRecipientAllowed,
} from "../policy/mattermost-recipient-allowlist";
import {
  getGithubWriteAllowlistState,
  isGithubWriteTargetAllowed,
} from "../policy/github-write-targets";
import {
  getGithubMergeAllowlistState,
  isGithubMergeTargetAllowed,
} from "../policy/github-merge-targets";
import {
  getGithubApproveAllowlistState,
  isGithubApproveTargetAllowed,
} from "../policy/github-approve-targets";
import { scanOutboundSecret } from "../policy/outbound-secret";
import { getAllowlistState, isRecipientAllowed } from "../policy/recipient-allowlist";
import { isTaintedRecipient } from "../policy/tainted-source";
import { requireGoogle } from "./handlers/shared";
import type { ToolContext } from "./types";

/** The outbound tools whose calls pass through the egress gate. Matches the
 *  ToolDef.direction === "outbound-write" set (gmail_send + gmail_create_draft;
 *  registry/types.ts B0). A future outbound tool adds its name here AND routes
 *  through enforceEgressGates — the type is the forcing function that the new
 *  tool's denial event / error data names a real tool. */
export type OutboundTool = "gmail_send" | "gmail_create_draft";

/** Enforce the v2.2 recipient allowlist over the combined recipient set.
 *  All-or-nothing: if ANY recipient is rejected, audit the HMAC-SHA256
 *  hashes (never plaintext) and throw `recipient_denied_by_policy` (-32019).
 *  No-op when the policy is off or every recipient is allowed — an empty
 *  recipient set trivially passes (a body-only draft has no recipients). */
async function enforceRecipientAllowlist(
  ctx: ToolContext,
  allRecipients: string[],
  tool: OutboundTool,
): Promise<void> {
  // v1.56 F3b — tainted-source flag (observability, NON-blocking). If ANY
  // recipient first appeared inside untrusted BODY content recorded this session
  // (e.g. an address lifted from a malicious shared Doc the agent just read),
  // mark the audit row `tainted_source: true`. Runs FIRST, regardless of the
  // allowlist outcome below (a tainted recipient that is ALSO allowlist-denied is
  // still useful forensics), and NEVER blocks the send — the gate stays the
  // recipient allowlist (F2) / tier; F3b only annotates.
  if (allRecipients.some((addr) => isTaintedRecipient(addr))) {
    ctx.audit.record("taintedSource");
    // v1.57 F3b-gate — under autonomous mode, ESCALATE the flag to a deny. The
    // flag above still fired (so the denied row is forensically marked). This is
    // ORTHOGONAL to the F2 allowlist below: even an allowlisted recipient is
    // denied if the value is tainted-source (provenance ⟂ membership). Autonomous
    // only — interactive mode is byte-identical to v1.56 (flag, no block).
    if (isAutonomousMode()) {
      throw new MCPError("tainted_recipient_denied");
    }
  }
  const recipientStartMs = Date.now();
  const allowlistState = await getAllowlistState();
  // v1.80 PR-3 — partition the implicit SELF-SEND exemption to the calling
  // operator's allowedAccounts (Model B). null (Model A / unconfined) → no-op;
  // explicit allow/extra entries are never narrowed (see isRecipientAllowed).
  const confineSelfTo =
    ctx.allowedAccounts === null ? null : new Set(ctx.allowedAccounts);
  const rejected: string[] = [];
  for (const addr of allRecipients) {
    if (!isRecipientAllowed(addr, allowlistState, confineSelfTo)) {
      rejected.push(addr);
    }
  }
  if (rejected.length === 0) return;
  const rejected_recipient_hashes = (
    await Promise.all(rejected.map((r) => hashTargetEmail(r).catch(() => null)))
  ).filter((h): h is string => h !== null);
  await auditRecipientDeniedEvent({
    tool,
    email: requireGoogle(ctx).accountId,
    rejected_recipient_hashes,
    rejected_count: rejected.length,
    total_recipients: allRecipients.length,
    duration_ms: Date.now() - recipientStartMs,
  });
  throw new MCPError("recipient_denied_by_policy", {
    tool,
    rejected_count: rejected.length,
    total_recipients: allRecipients.length,
  });
}

/** v1.57 F3a — outbound secret-shape guard, shared by gmail_send + gmail_create_draft
 *  (one impl so neither can drift). Scans the body for a recognizable secret SHAPE
 *  (private-key block / provider API-key). Under autonomous mode → REJECT (-32035)
 *  BEFORE the SDK call; interactive mode → record an audit flag (`outbound_secret_shape`)
 *  and proceed (NON-blocking, locked Q5). The errorData / flag carries the shape
 *  CLASS only (a bounded closed-set value), NEVER the matched secret bytes.
 *
 *  v1.106 — EXPORTED so `youtube_video_update` (whose target-allowlist + per-field
 *  outboundSanitize live in the handler, mirroring the youtube_comment surface) can
 *  apply the SAME F3a guard without duplicating the autonomous→reject / interactive→
 *  flag logic. The github/notion public-write gates apply it via their egress wrappers
 *  above; the youtube video write applies it directly. One impl, no drift. */
export function enforceOutboundSecret(ctx: ToolContext, body: string): void {
  const shape = scanOutboundSecret(body);
  if (shape === null) return;
  if (isAutonomousMode()) {
    throw new MCPError("outbound_secret_rejected", { reason: shape });
  }
  ctx.audit.record("outboundSecretShape", shape);
}

/** v1.64 Phase B (B3 — D2) — THE centralized egress gate. The single entry
 *  point every outbound-write tool calls, in place of the pre-B3 pair of inline
 *  gmail.ts calls. Order is preserved 1:1 with the former gmail_send /
 *  gmail_create_draft inline sequence: the secret-shape (F3a) gate runs FIRST,
 *  then the recipient allowlist (v2.2) + tainted-source (F3b) gate. Both gates
 *  read the per-call audit sink + the recipient allowlist / autonomous-mode
 *  policy; the passed `egress` argument is never mutated.
 *
 *  CALLER CONTRACT: pass the FINAL outbound shape — `recipients` already
 *  contact-resolved + format-validated, `body` already byte-capped — at the same
 *  point the pre-B3 handler called the two gates (after resolution, before the
 *  RFC 2822 build + SDK dispatch). The gate runs on what is actually sent, not
 *  the raw args. */
export async function enforceEgressGates(
  ctx: ToolContext,
  egress: { tool: OutboundTool; recipients: string[]; body: string },
): Promise<void> {
  enforceOutboundSecret(ctx, egress.body);
  await enforceRecipientAllowlist(ctx, egress.recipients, egress.tool);
  // v1.99 — supervised mode: require owner approval for the actual SEND. No-op when the flag is
  // off OR for gmail_create_draft (not in APPROVAL_GATED_SENDS — a draft isn't delivered).
  // ADDITIVE, fires LAST (after recipient + secret), so a disallowed send never creates a pending.
  await requireSendApproval(ctx, { tool: egress.tool, recipients: egress.recipients, body: egress.body });
}

/** v1.85.1 — the shared service-token recipient egress gate. LINE / Telegram / Discord
 *  are IDENTICAL in shape: a SINGLE recipient id, an off→allow recipient allowlist, the
 *  F3a secret-shape scan FIRST, then HMAC-hash + audit + throw recipient_denied_by_policy
 *  (-32019) on a miss. This is the ONE impl; the three exported wrappers below bind their
 *  connector's allowlist so none can drift. (gmail's multi-recipient + contact-resolution
 *  + tainted-source gate and github's default-DENY target gate are deliberately NOT folded
 *  in — different shapes; forcing them in would be over-abstraction.) */
async function enforceServiceTokenRecipientGate(
  ctx: ToolContext,
  egress: {
    tool: "line_push_message" | "telegram_send_message" | "discord_send_message" | "slack_send_message" | "mattermost_send_message";
    recipient: string;
    body: string;
    /** Pre-bound to the connector's `is<X>RecipientAllowed(recipient, get<X>State())`. */
    isAllowed: () => boolean;
  },
): Promise<void> {
  // F3a secret-shape — autonomous → throw -32035; interactive → record outbound_secret_shape.
  enforceOutboundSecret(ctx, egress.body);

  const startMs = Date.now();
  if (egress.isAllowed()) {
    // v1.99 — recipient allowed → require owner approval for the SEND (supervised mode; no-op
    // when off). ADDITIVE, fires after the secret + recipient checks.
    await requireSendApproval(ctx, { tool: egress.tool, recipients: [egress.recipient], body: egress.body });
    return;
  }
  // hashTargetEmail is a generic HMAC-SHA256(salt, value) (the name predates non-email
  // recipients); it hashes the service-token recipient id with the same audit salt.
  const hash = await hashTargetEmail(egress.recipient).catch(() => null);
  await auditRecipientDeniedEvent({
    tool: egress.tool,
    email: null, // no Google account for a service-token push
    rejected_recipient_hashes: hash === null ? [] : [hash],
    rejected_count: 1,
    total_recipients: 1,
    duration_ms: Date.now() - startMs,
  });
  throw new MCPError("recipient_denied_by_policy", {
    tool: egress.tool,
    rejected_count: 1,
    total_recipients: 1,
  });
}

/** LINE OA push (class-B service-token). Binds the LINE recipient allowlist. */
export function enforceLineEgressGates(
  ctx: ToolContext,
  egress: { tool: "line_push_message"; to: string; body: string },
): Promise<void> {
  return enforceServiceTokenRecipientGate(ctx, {
    tool: egress.tool,
    recipient: egress.to,
    body: egress.body,
    isAllowed: () => isLineRecipientAllowed(egress.to, getLineAllowlistState()),
  });
}

/** Telegram Bot push (class-B service-token). Binds the Telegram recipient allowlist. */
export function enforceTelegramEgressGates(
  ctx: ToolContext,
  egress: { tool: "telegram_send_message"; chat_id: string; body: string },
): Promise<void> {
  return enforceServiceTokenRecipientGate(ctx, {
    tool: egress.tool,
    recipient: egress.chat_id,
    body: egress.body,
    isAllowed: () => isTelegramRecipientAllowed(egress.chat_id, getTelegramAllowlistState()),
  });
}

/** Discord Bot post (class-B service-token). Binds the Discord recipient allowlist. */
export function enforceDiscordEgressGates(
  ctx: ToolContext,
  egress: { tool: "discord_send_message"; channel_id: string; body: string },
): Promise<void> {
  return enforceServiceTokenRecipientGate(ctx, {
    tool: egress.tool,
    recipient: egress.channel_id,
    body: egress.body,
    isAllowed: () => isDiscordRecipientAllowed(egress.channel_id, getDiscordAllowlistState()),
  });
}

/** Slack Bot post (class-B service-token). Binds the Slack recipient allowlist. */
export function enforceSlackEgressGates(
  ctx: ToolContext,
  egress: { tool: "slack_send_message"; channel: string; body: string },
): Promise<void> {
  return enforceServiceTokenRecipientGate(ctx, {
    tool: egress.tool,
    recipient: egress.channel,
    body: egress.body,
    isAllowed: () => isSlackRecipientAllowed(egress.channel, getSlackAllowlistState()),
  });
}

/** Mattermost post (class-B service-token, self-hosted). Binds the Mattermost recipient
 *  allowlist. The configured-host pin lives in the client (`assertEgressHost`), not here —
 *  this gate is identical in shape to the other service-token recipient gates. */
export function enforceMattermostEgressGates(
  ctx: ToolContext,
  egress: { tool: "mattermost_send_message"; channel_id: string; body: string },
): Promise<void> {
  return enforceServiceTokenRecipientGate(ctx, {
    tool: egress.tool,
    recipient: egress.channel_id,
    body: egress.body,
    isAllowed: () => isMattermostRecipientAllowed(egress.channel_id, getMattermostAllowlistState()),
  });
}

/** v1.71 — the GitHub WRITE egress gate (PUBLIC-surface OAuth source). UNLIKE the
 *  class-B recipient gates above (off → allow), this is DEFAULT-DENY (mirrors the
 *  YouTube-comment public-surface model): the repo target allowlist runs FIRST (the
 *  dominant gate — fail fast before any body work), then the F3a secret-shape scan on
 *  the combined outbound text. The per-field `outboundSanitize` REJECT (which needs
 *  per-field byte caps) stays in the handler.
 *
 *  `body` = the combined agent-authored outbound text (title + body for create/update;
 *  body for a comment) — scanned for a secret shape so the agent can't leak a private
 *  key / API key into a PUBLIC issue. On a target-allowlist miss → throw
 *  `github_write_denied_by_policy` (-32042) with a closed-set reason; the owner/repo is
 *  NEVER echoed (PII-oracle defense, mirroring -32023's no-video_id-echo). */
export function enforceGithubWriteEgressGates(
  ctx: ToolContext,
  egress: {
    tool:
      | "github_create_issue"
      | "github_create_issue_comment"
      | "github_update_issue"
      | "github_create_pull_request"
      | "github_set_issue_labels";
    owner: string;
    repo: string;
    body: string;
  },
): void {
  const state = getGithubWriteAllowlistState();
  if (!isGithubWriteTargetAllowed(egress.owner, egress.repo, state)) {
    throw new MCPError("github_write_denied_by_policy", {
      tool: egress.tool,
      reason: state.kind === "off" ? "no_allowlist" : "not_in_allowlist",
    });
  }
  // F3a secret-shape — autonomous → throw -32035; interactive → record outbound_secret_shape.
  enforceOutboundSecret(ctx, egress.body);
}

/** v1.96 — the Notion WRITE egress gate. **Model B** (owner-locked, NOT the GitHub
 *  default-deny model): F3a secret-shape on the agent-authored outbound text, with NO
 *  target allowlist. Rationale — Notion's integration-sharing model is itself a natural
 *  allowlist (the integration can only write to pages explicitly shared with it, unlike a
 *  GitHub token that can write any repo the user can), so a SafeSpace-side default-deny
 *  page-id list would be largely redundant + high-friction. The per-field
 *  `outboundSanitize` REJECT (-32027) stays in the handler (the github-write posture).
 *  `body` = the combined agent text (title + content) — scanned so a secret shape can't be
 *  smuggled into a Notion page that might be web-published. No allowlist → no PII-oracle
 *  surface (nothing echoed); a secret in autonomous mode → -32035, else a recorded flag. */
export function enforceNotionWriteEgressGates(
  ctx: ToolContext,
  egress: {
    tool: "notion_create_page" | "notion_append_blocks" | "notion_update_page";
    body: string;
  },
): void {
  enforceOutboundSecret(ctx, egress.body);
}

/** v1.82 — the GitHub MERGE egress gate (PUBLIC-surface, IRREVERSIBLE). Mirrors
 *  {@link enforceGithubWriteEgressGates} but reads the SEPARATE default-deny MERGE
 *  allowlist (SAFESPACE_GITHUB_MERGE_TARGETS) — a repo write-allowlisted for issues/PRs
 *  is NOT thereby merge-allowlisted (merging to a default branch is a higher bar). The
 *  target-deny runs FIRST (fail fast before any merge), then the F3a secret-shape scan
 *  on the agent-authored merge commit text (commit_title + commit_message; empty when
 *  the caller lets GitHub auto-generate the message).
 *
 *  On a merge-allowlist miss → throw `github_merge_denied_by_policy` (-32046) with a
 *  closed-set reason; the owner/repo is NEVER echoed (PII-oracle, like -32042). */
export function enforceGithubMergeEgressGates(
  ctx: ToolContext,
  egress: { tool: "github_merge_pull_request"; owner: string; repo: string; body: string },
): void {
  const state = getGithubMergeAllowlistState();
  if (!isGithubMergeTargetAllowed(egress.owner, egress.repo, state)) {
    throw new MCPError("github_merge_denied_by_policy", {
      tool: egress.tool,
      reason: state.kind === "off" ? "no_allowlist" : "not_in_allowlist",
    });
  }
  // F3a secret-shape on the merge commit text — autonomous → throw -32035; interactive → flag.
  enforceOutboundSecret(ctx, egress.body);
}

/** A GitHub PR review event. APPROVE is the high-trust one — it vouches for the PR and
 *  (under branch protection) can UNBLOCK a merge; COMMENT / REQUEST_CHANGES only annotate
 *  or block. The gate below routes on this. */
export type GithubReviewEvent = "APPROVE" | "REQUEST_CHANGES" | "COMMENT";

/** v1.90 — the GitHub PR-REVIEW egress gate (PUBLIC-surface). EVENT-CONDITIONAL, the one
 *  place a github write gate branches on the action's trust level:
 *    - APPROVE          → the SEPARATE default-deny APPROVE allowlist
 *                         (SAFESPACE_GITHUB_APPROVE_TARGETS). An approve can advance a PR
 *                         toward landing (unblock a protected-branch merge), so it has its
 *                         own opt-in list — a repo write-allowlisted for comments is NOT
 *                         thereby approve-allowlisted. Miss → `github_approve_denied_by_policy`
 *                         (-32048).
 *    - COMMENT / REQUEST_CHANGES → the existing WRITE allowlist (same trust level as an
 *                         issue comment: they annotate / block but never advance the PR).
 *                         Miss → `github_write_denied_by_policy` (-32042).
 *  The target-deny runs FIRST (fail fast), then the F3a secret-shape scan on the
 *  agent-authored review `body` (empty when an APPROVE carries no comment). The owner/repo
 *  is NEVER echoed on either miss (PII-oracle, like -32042 / -32046). */
export function enforceGithubReviewEgressGates(
  ctx: ToolContext,
  egress: {
    tool: "github_create_pull_request_review";
    event: GithubReviewEvent;
    owner: string;
    repo: string;
    body: string;
  },
): void {
  if (egress.event === "APPROVE") {
    const state = getGithubApproveAllowlistState();
    if (!isGithubApproveTargetAllowed(egress.owner, egress.repo, state)) {
      throw new MCPError("github_approve_denied_by_policy", {
        tool: egress.tool,
        reason: state.kind === "off" ? "no_allowlist" : "not_in_allowlist",
      });
    }
  } else {
    const state = getGithubWriteAllowlistState();
    if (!isGithubWriteTargetAllowed(egress.owner, egress.repo, state)) {
      throw new MCPError("github_write_denied_by_policy", {
        tool: egress.tool,
        reason: state.kind === "off" ? "no_allowlist" : "not_in_allowlist",
      });
    }
  }
  // F3a secret-shape on the review body — autonomous → throw -32035; interactive → flag.
  enforceOutboundSecret(ctx, egress.body);
}
