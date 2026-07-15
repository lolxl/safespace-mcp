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
// PIPELINE-FIRED vs HANDLER-CALLED (2026-07-15, B6.1 wave A3+D): the gmail egress is
// now PIPELINE-FIRED. Its composite wrapper `enforceGmailComposeEgressGates` (below)
// composes the header gates + contact resolution + `enforceEgressGates` and is fired by
// withToolContext via each gmail tool's egress descriptor (tools/egress-pipeline.ts). The
// blocker the pre-A3 note called out — the recipient allowlist MUST run on the
// CONTACT-RESOLVED recipients, and resolution needs the OAuth credential — is solved by
// B6.1-D: contact resolution demoted to the google-workspace Source strategy
// (`source.resolveRecipients`, tools/source.ts), which the choke point passes INTO the
// composite gate, so the resolve happens inside the pipeline step (before the allowlist)
// rather than in the handler.
//
// B6.1 wave A (github + notion sweep, 2026-07-15): the LAST handler-called egress wrappers
// (enforceGithubWriteEgressGates / enforceGithubMergeEgressGates / enforceGithubReviewEgressGates
// / enforceNotionWriteEgressGates below) are now PIPELINE-FIRED too — withToolContext fires each
// github/notion write tool's egress descriptor (tools/egress-pipeline.ts) BEFORE the handler.
// These wrappers are UNCHANGED (they still set ctx.egressGateFired first + throw the same codes);
// only their CALLER moved from the handler to the choke point. They are CHECK-ONLY (return void),
// so the descriptor's gate returns void and the handler wires its own already-validated args. The
// HANDLER-CALLED egress posture is now RETIRED for every OAuth write (nothing left in this module
// is invoked from a handler).
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
import {
  getXPostAllowlistState,
  isXPostAccountAllowed,
} from "../policy/x-post-allowlist";
import {
  getCommentTargetAllowlistState,
  isCommentTargetAllowed,
} from "../policy/youtube-comment-targets";
import { checkCommentBurst } from "../policy/youtube-comment-burst";
import {
  getVideoTargetAllowlistState,
  isVideoTargetAllowed,
} from "../policy/youtube-video-targets";
import { outboundSanitize } from "../sanitize/outbound";
import { scanOutboundSecret } from "../policy/outbound-secret";
import { getAllowlistState, isRecipientAllowed } from "../policy/recipient-allowlist";
import { isTaintedRecipient } from "../policy/tainted-source";
import { requireGoogle, sha256Hex, EMAIL_RECIPIENT_RE, HEADER_INJECTION_RE } from "./handlers/shared";
import { hashResolvedRecipientEmails } from "./handlers/contacts";
import type { CommentPostAuditMeta, VideoMutationAuditMeta } from "../audit";
import type { RecipientResolver } from "./source";
import type { GmailComposeEgressShape, ToolContext, YoutubeVideoUpdateEgressShape } from "./types";

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

const MAX_RECIPIENTS = 10; // v1 anti-spam cap (sec-rev 5.9 LOW)
const MAX_EMAIL_BODY_BYTES = 1 * 1024 * 1024; // 1 MB body cap (5.9 code-rev MED-2)

// RFC 2822 §3.2.3: unstructured header fields must be printable US-ASCII.
// v1 rejects non-ASCII subjects (sec-rev 5.9 LOW). Future v2 may add MIME
// Q-encoding so CJK / emoji subjects round-trip cleanly.
const NON_ASCII_RE = /[^\x20-\x7E]/;

/** Comma-split a header field into trimmed, non-empty address tokens. Naive
 *  comma-split over-counts when display names contain commas ("Doe, John"
 *  <j@x.com>); that's OK — over-counting just rejects faster against the
 *  recipient cap, the conservative side for an anti-spam cap. */
const parseAddrs = (s: string): string[] =>
  s.split(",").map((x) => x.trim()).filter((x) => x.length > 0);

/** v1.64 Phase B (B3 — D2) — the gmail PRE-RESOLUTION header/ASCII/count gates.
 *  Centralized here (out of the two inline gmail.ts copies) so gmail_send +
 *  gmail_create_draft share ONE byte-identical implementation. This is a
 *  SEPARATE entry point from {@link enforceEgressGates} because these checks
 *  MUST run BEFORE the handler's contact-lookup resolution (they validate the
 *  raw typed to/cc/bcc/subject fields), whereas enforceEgressGates runs on the
 *  RESOLVED recipients. Order mirrors the former inline handler sequence 1:1:
 *    1. header-injection on the active-account From (Keychain-integrity D-i-D),
 *    2. header-injection on to/cc/bcc/subject (single combined condition),
 *    3. non-ASCII subject reject,
 *    4. parse to/cc/bcc into address tokens,
 *    5. (gmail_send ONLY) reject an empty `to`,
 *    6. combined to+cc+bcc recipient-count cap.
 *  Returns the three parsed arrays for the handler to resolve + dispatch. */
export function enforceGmailHeaderGates(
  ctx: ToolContext,
  envelope: { tool: OutboundTool; to: string; cc: string; bcc: string; subject: string },
): { toAddrs: string[]; ccAddrs: string[]; bccAddrs: string[] } {
  const { tool, to, cc, bcc, subject } = envelope;

  // Defense-in-depth: validate active-account email too (sec-rev 5.9 LOW-1).
  // requireGoogle(ctx).accountId comes from the Keychain index — a controlled
  // source — but running it through the same guard means a corrupted index
  // can't smuggle a forged header line via the From: field.
  if (HEADER_INJECTION_RE.test(requireGoogle(ctx).accountId)) {
    throw new Error(`${tool}: active account email contains illegal characters (Keychain integrity issue)`);
  }

  if (
    HEADER_INJECTION_RE.test(to) ||
    HEADER_INJECTION_RE.test(cc) ||
    HEADER_INJECTION_RE.test(bcc) ||
    HEADER_INJECTION_RE.test(subject)
  ) {
    throw new Error(`${tool}: 'to', 'cc', 'bcc', and 'subject' must not contain CR/LF/NUL/NEL/U+2028/U+2029 (header injection prevention)`);
  }

  if (NON_ASCII_RE.test(subject)) {
    throw new Error(`${tool}: 'subject' must be plain ASCII in v1 (no non-ASCII characters)`);
  }

  // Cap recipient count (sec-rev 5.9 LOW) over the COMBINED to+cc+bcc set —
  // a prompt-injected Claude call could otherwise blast 500 addresses by
  // splitting them across the three fields. Zero-count on `to` also rejects
  // whitespace-only `to` (5.9 code-rev MED-2) — send-only, since a draft may
  // have no recipient yet. cc/bcc may be empty independently.
  const toAddrs = parseAddrs(to);
  const ccAddrs = parseAddrs(cc);
  const bccAddrs = parseAddrs(bcc);
  if (tool === "gmail_send" && toAddrs.length === 0) {
    throw new Error("gmail_send: 'to' must contain at least one non-empty recipient");
  }
  const totalRecipients = toAddrs.length + ccAddrs.length + bccAddrs.length;
  if (totalRecipients > MAX_RECIPIENTS) {
    throw new Error(`${tool}: at most ${MAX_RECIPIENTS} recipients per call across to+cc+bcc (got ${totalRecipients})`);
  }
  return { toAddrs, ccAddrs, bccAddrs };
}

/** v1.64 Phase B (B3 — D2) — THE centralized egress gate. The single entry
 *  point every outbound-write tool calls, in place of the pre-B3 pair of inline
 *  gmail.ts calls. Order is preserved 1:1 with the former gmail_send /
 *  gmail_create_draft inline sequence: the per-recipient email-format gate +
 *  body byte-cap run FIRST, then the secret-shape (F3a) gate, then the recipient
 *  allowlist (v2.2) + tainted-source (F3b) gate. Both gates read the per-call
 *  audit sink + the recipient allowlist / autonomous-mode policy; the passed
 *  `egress` argument is never mutated.
 *
 *  CALLER CONTRACT: pass the FINAL outbound shape — `recipients` already
 *  contact-resolved (the header/count gate + contact-lookup ran upstream) — at
 *  the same point the pre-B3 handler called the two gates (after resolution,
 *  before the RFC 2822 build + SDK dispatch). Per-recipient email-format
 *  validation + the body byte-cap now happen INSIDE this gate (moved from the
 *  two inline gmail.ts copies). The gate runs on what is actually sent, not the
 *  raw args. */
export async function enforceEgressGates(
  ctx: ToolContext,
  egress: { tool: OutboundTool; recipients: string[]; body: string },
): Promise<void> {
  // v1.116 — mark the centralized egress gate as FIRED (see ToolContext.egressGateFired
  // in tools/types.ts). Set FIRST so a gate that DENIES below still counts as fired.
  ctx.egressGateFired = true;
  // Per-recipient email-format gate (#22) across the resolved to + cc + bcc set.
  // Without this, a prompt-injected call could pass `cc: "not-an-email"` and
  // reach Google's API (an opaque 400); local rejection gives a clearer message
  // and avoids a wasted round-trip. Runs on the RESOLVED values so a buggy
  // People API response that returned a malformed email is still caught locally.
  for (const addr of egress.recipients) {
    if (!EMAIL_RECIPIENT_RE.test(addr)) {
      throw new Error(`${egress.tool}: recipient is not a valid email address: ${addr}`);
    }
  }
  // Pre-flight body byte cap (5.9 code-rev MED-2). Gmail's hard limit is 25 MB
  // raw; we cap at 1 MB to bound request body size and prevent accidental
  // megablob sends. Count utf-8 bytes, not chars.
  const bodyBytes = Buffer.byteLength(egress.body, "utf-8");
  if (bodyBytes > MAX_EMAIL_BODY_BYTES) {
    throw new Error(`${egress.tool}: body exceeds ${MAX_EMAIL_BODY_BYTES} bytes (got ${bodyBytes})`);
  }
  enforceOutboundSecret(ctx, egress.body);
  await enforceRecipientAllowlist(ctx, egress.recipients, egress.tool);
  // v1.99 — supervised mode: require owner approval for the actual SEND. No-op when the flag is
  // off OR for gmail_create_draft (not in APPROVAL_GATED_SENDS — a draft isn't delivered).
  // ADDITIVE, fires LAST (after recipient + secret), so a disallowed send never creates a pending.
  await requireSendApproval(ctx, { tool: egress.tool, recipients: egress.recipients, body: egress.body });
}

/** B6.1 wave A3+D — THE gmail compose composite egress gate (gmail_send +
 *  gmail_create_draft). Relocated VERBATIM from the two gmail.ts handler blocks: the
 *  same 1:1 ordering the pre-A3 handler ran, now fired by withToolContext via each
 *  tool's egress descriptor (tools/egress-pipeline.ts) BEFORE the handler. TRANSFORMING:
 *  RETURNS the shape with `resolved` populated (the contact-resolved recipients for
 *  gmail_send; the parsed literal arrays for gmail_create_draft) — the handler wires
 *  THAT off ctx.egress (requireEgressResult), never a local recomputation.
 *
 *  Order (byte-identical to the pre-A3 gmail.ts sequence):
 *    1. enforceGmailHeaderGates — header-injection (incl. the Keychain-integrity From
 *       D-i-D) / non-ASCII subject / recipient-count on the RAW fields (does NOT set the
 *       fired flag — a pre-resolution partial gate must not masquerade as full coverage).
 *    2. (gmail_send only) contact-lookup resolution via the Source strategy
 *       `resolveRecipients` — resolves names→emails BEFORE the allowlist sees them.
 *       ABSENT resolver → identity passthrough (equivalent to opt-in-off / a source with
 *       no contact strategy). gmail_create_draft is literal-only (D3 — no resolution).
 *    3. enforceEgressGates — per-recipient email-format + 1 MiB body cap → F3a
 *       secret-shape → v2.2 recipient allowlist + F3b tainted-source → supervised-send
 *       approval. Sets ctx.egressGateFired FIRST (so a denial still counts as fired).
 *    4. resolvedRecipientHash audit — ONLY when a contact-lookup happened (position
 *       unchanged: after all gates passed, before the handler; a gate throw → not recorded).
 *
 *  INVARIANT (see EgressDescriptor in tools/egress-pipeline.ts): the only network sub-step
 *  is the People-API resolve (step 2), and every audit/approval side effect (steps 3–4)
 *  runs AFTER it — so the choke point's gate-stage 401-retry can re-fire the whole gate on
 *  a resolve 401 with NO double approval / double audit (steps 1–2 before it are local +
 *  idempotent). */
export async function enforceGmailComposeEgressGates(
  ctx: ToolContext,
  shape: GmailComposeEgressShape,
  resolveRecipients?: RecipientResolver,
): Promise<GmailComposeEgressShape> {
  // 1. header / non-ASCII / recipient-count gates on the RAW fields → parsed arrays.
  const { toAddrs, ccAddrs, bccAddrs } = enforceGmailHeaderGates(ctx, {
    tool: shape.tool,
    to: shape.to,
    cc: shape.cc,
    bcc: shape.bcc,
    subject: shape.subject,
  });

  let resolvedTo: string[];
  let resolvedCc: string[];
  let resolvedBcc: string[];
  let lookedUpEmails: string[];

  if (shape.tool === "gmail_send" && resolveRecipients !== undefined) {
    // 2. contact-lookup resolution (send only). Runs BEFORE the allowlist so a
    //    non-email input (a name) resolves to an email first; sizes preserve 1:1 order.
    const preResolvedAll = [...toAddrs, ...ccAddrs, ...bccAddrs];
    const { resolvedEmails, lookedUpEmails: lu } = await resolveRecipients(
      ctx,
      preResolvedAll,
      "gmail_send",
    );
    resolvedTo = resolvedEmails.slice(0, toAddrs.length);
    resolvedCc = resolvedEmails.slice(toAddrs.length, toAddrs.length + ccAddrs.length);
    resolvedBcc = resolvedEmails.slice(toAddrs.length + ccAddrs.length);
    lookedUpEmails = lu;
  } else {
    // gmail_create_draft (literal-only, D3), OR a send with no resolver strategy →
    // identity passthrough (equivalent to opt-in-off): the parsed arrays are final.
    resolvedTo = toAddrs;
    resolvedCc = ccAddrs;
    resolvedBcc = bccAddrs;
    lookedUpEmails = [];
  }
  const allRecipients = [...resolvedTo, ...resolvedCc, ...resolvedBcc];

  // 3. the centralized egress gate on the RESOLVED recipients (format + body-cap →
  //    F3a → recipient allowlist + F3b → supervised-send approval; sets the fired flag).
  await enforceEgressGates(ctx, {
    tool: shape.tool,
    recipients: allRecipients,
    body: shape.body,
  });

  // 4. resolved-recipient hash audit (ONLY when a contact-lookup happened; after all
  //    gates passed, before the handler — a gate throw above → not recorded, as today).
  if (lookedUpEmails.length > 0) {
    ctx.audit.record("resolvedRecipientHash", hashResolvedRecipientEmails(allRecipients));
  }

  return { ...shape, resolved: { to: resolvedTo, cc: resolvedCc, bcc: resolvedBcc } };
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
  ctx.egressGateFired = true;
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
  ctx.egressGateFired = true;
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
  ctx.egressGateFired = true;
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
  ctx.egressGateFired = true;
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
  ctx.egressGateFired = true;
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

/** v1.115 — the X POST egress gate (PUBLIC-surface OAuth source). DEFAULT-DENY account
 *  allowlist (numeric user id — usernames rotate), then F3a secret-shape, then the
 *  6-step `outboundSanitize` REJECT. Order is locked: allowlist FIRST (fail fast before
 *  any body work), then secret-shape, then sanitize. Returns the sanitized text for the
 *  allowlist-constructed request body.
 *
 *  On an allowlist miss → throw `x_post_denied_by_policy` (-32056) with a closed-set
 *  reason; the account id is NEVER echoed (PII-oracle defense, mirroring -32042). */
export function enforceXPostEgressGates(
  ctx: ToolContext,
  accountId: string,
  text: string,
): string {
  ctx.egressGateFired = true;
  const state = getXPostAllowlistState();
  if (!isXPostAccountAllowed(accountId, state)) {
    throw new MCPError("x_post_denied_by_policy", {
      tool: "x_post_create",
      reason: state.kind === "off" ? "no_allowlist" : "not_in_allowlist",
    });
  }
  // F3a secret-shape — autonomous → throw -32035; interactive → record outbound_secret_shape.
  enforceOutboundSecret(ctx, text);
  // Public-surface 6-step REJECT (-32027 on failure). Weighted-280 is pre-checked in the
  // handler (before this gate); the byte cap here is a defense-in-depth backstop.
  return outboundSanitize(text, { tool: "x_post_create", maxBytes: 2000 });
}

/** v1.121 B6.1 wave A2b — the YouTube COMMENT WRITE egress gate (PUBLIC-surface),
 *  shared by youtube_video_comment_post + youtube_comment_reply. Relocated VERBATIM
 *  from the two youtube.ts handler gate blocks: the default-empty hard-deny comment
 *  TARGET allowlist FIRST → the per-session burst PRE-check → the 6-step
 *  outboundSanitize REJECT, with the SAME `commentPostMeta` denial rows, throw
 *  payloads / error codes, and no-echo posture (video_id / text NEVER echoed). Since
 *  B6.1 wave A2b it is PIPELINE-FIRED by withToolContext (via the tool's egress
 *  descriptor) BEFORE the handler runs; the handler must NOT call it (anti-double-
 *  fire — egress-callsite.test.ts enforces both directions) and wires the SANITIZED
 *  return off ctx.egress (requireEgressResult).
 *
 *  TRANSFORMING: returns the outboundSanitize'd text (the vetted bytes — no TOCTOU
 *  between what was scanned and what egresses). The success-only `incrementCommentBurst`
 *  STAYS post-SDK in the handler; `checkCommentBurst` here is a PURE read (non-mutating),
 *  so the pre-handler firing stays idempotent across the choke point's 401-retry
 *  (the retry carries ctx.egress forward and does NOT re-fire the gate).
 *
 *  `parentCommentId` (REPLY only; undefined for comment_post) is carried so the reply's
 *  denial rows keep `parent_comment_id_hash` — its ABSENCE omits the field, byte-identical
 *  to the two pre-A2b handler blocks. */
export function enforceYoutubeCommentEgressGates(
  ctx: ToolContext,
  egress: {
    tool: "youtube_video_comment_post" | "youtube_comment_reply";
    videoId: string;
    body: string;
    parentCommentId?: string;
  },
): string {
  ctx.egressGateFired = true;
  const target_video_hash = sha256Hex(egress.videoId);
  const comment_length = egress.body.length;
  const parent_comment_id_hash =
    egress.parentCommentId !== undefined ? sha256Hex(egress.parentCommentId) : undefined;
  // Denial-meta builder — reproduces the exact key order (+ conditional parent hash)
  // the two pre-A2b handler blocks used for the commentPostMeta denial rows.
  const denyMeta = (
    policy_decision: CommentPostAuditMeta["policy_decision"],
  ): CommentPostAuditMeta =>
    parent_comment_id_hash === undefined
      ? { target_video_hash, comment_length, policy_decision }
      : { target_video_hash, parent_comment_id_hash, comment_length, policy_decision };

  // ── Allowlist gate (default-empty hard-deny) ──
  // Direct `video:<id>` match only (design §4.1.1). NO video_id echo (PII oracle).
  const state = getCommentTargetAllowlistState();
  if (!isCommentTargetAllowed("video", egress.videoId, state)) {
    ctx.audit.record(
      "commentPostMeta",
      denyMeta(state.kind === "off" ? "denied_no_allowlist" : "denied_not_in_allowlist"),
    );
    throw new MCPError("comment_target_denied_by_policy", { tool: egress.tool });
  }

  // ── Burst-limit PRE-check (NO increment — that stays post-success in the handler) ──
  const burst = checkCommentBurst();
  if (!burst.ok) {
    ctx.audit.record("commentPostMeta", denyMeta("denied_burst_limit"));
    throw new MCPError("comment_burst_limit_exceeded", { tool: egress.tool });
  }

  // ── Outbound sanitize (6-step REJECT) → the vetted bytes for the wire ──
  try {
    return outboundSanitize(egress.body, { tool: egress.tool });
  } catch (err) {
    ctx.audit.record("commentPostMeta", denyMeta("denied_outbound_sanitize_rejected"));
    throw err;
  }
}

/** v1.121 B6.1 wave A2b — the youtube_video_update snippet-write egress gate
 *  (PUBLIC-surface). Relocated VERBATIM from the youtube.ts handler gate block: the
 *  default-empty hard-deny video TARGET allowlist FIRST → per-field outboundSanitize
 *  → the F3a secret-shape scan on the SAME combined text the handler built
 *  (`[title, description ?? "", ...tags].join("\n")`). Same throw payloads / error
 *  codes and no-echo posture (a target-allowlist miss records NO videoMutationMeta —
 *  the denial is captured via the row's errorCode -32052, the github-write model; NO
 *  video_id echo). PIPELINE-FIRED BEFORE the handler; TRANSFORMING — RETURNS the same
 *  shape with each field outbound-SANITIZED; the handler wires THAT off ctx.egress and
 *  constructs the requestBody with its own validated category_id (digit-only, unsanitized). */
export function enforceYoutubeVideoUpdateEgressGates(
  ctx: ToolContext,
  shape: YoutubeVideoUpdateEgressShape,
): YoutubeVideoUpdateEgressShape {
  ctx.egressGateFired = true;
  // Forensic-meta builder reused for the sanitize-reject denial row — typed off
  // VideoMutationAuditMeta minus policy_decision, lengths from the RAW input (same
  // raw-length convention as the pre-A2b handler; matches the allowed row).
  const baseMeta = (): Omit<VideoMutationAuditMeta, "policy_decision"> => {
    const m: Omit<VideoMutationAuditMeta, "policy_decision"> = {
      target_video_hash: sha256Hex(shape.videoId),
      operation: "video_update",
      title_length: shape.title.length,
    };
    if (shape.description !== undefined) m.description_length = shape.description.length;
    if (shape.tags !== undefined) m.tag_count = shape.tags.length;
    return m;
  };

  // ── Target allowlist (default-empty hard-deny) — NO videoMutationMeta on this miss ──
  const state = getVideoTargetAllowlistState();
  if (!isVideoTargetAllowed(shape.videoId, state)) {
    throw new MCPError("video_target_denied_by_policy", {
      tool: "youtube_video_update",
      reason: state.kind === "off" ? "no_allowlist" : "not_in_allowlist",
    });
  }

  // ── Per-field outbound sanitize (category_id excluded — digit-only by construction) ──
  let sanitizedTitle: string;
  let sanitizedDescription: string | undefined;
  let sanitizedTags: string[] | undefined;
  try {
    sanitizedTitle = outboundSanitize(shape.title, { tool: "youtube_video_update" });
    if (shape.description !== undefined) {
      sanitizedDescription = outboundSanitize(shape.description, { tool: "youtube_video_update" });
    }
    if (shape.tags !== undefined) {
      sanitizedTags = shape.tags.map((t) => outboundSanitize(t, { tool: "youtube_video_update" }));
    }
  } catch (err) {
    ctx.audit.record("videoMutationMeta", {
      ...baseMeta(),
      policy_decision: "denied_outbound_sanitize_rejected",
    });
    throw err;
  }

  // ── F3a outbound secret-shape on the combined public text ──
  // Autonomous → throw outbound_secret_rejected (-32035); interactive → record a flag.
  enforceOutboundSecret(
    ctx,
    [sanitizedTitle, sanitizedDescription ?? "", ...(sanitizedTags ?? [])].join("\n"),
  );

  return {
    kind: "youtube-video-update",
    videoId: shape.videoId,
    title: sanitizedTitle,
    ...(sanitizedDescription !== undefined ? { description: sanitizedDescription } : {}),
    ...(sanitizedTags !== undefined ? { tags: sanitizedTags } : {}),
  };
}
