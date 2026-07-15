// Gmail — extracted verbatim from the former monolithic
// src/tools/handlers.ts (mechanical per-API split; function bodies byte-identical).
// Re-exported via ./index.ts so existing `./handlers` import paths are unchanged.

import { MCPError } from "../../errors";
import { buildBatchModifyBody, newBoundary, parseBatchResponse } from "../../google-api/batch";
import { gmailClientFromToken, oauth2ClientFromToken } from "../../google-api/client";
import { mapGoogleError, toGoogleError } from "../../google-api/errors";
import { requireEgressResult } from "../egress-pipeline";
import type { ToolContext } from "../types";

import { requireGoogle, HEADER_INJECTION_RE } from "./shared";

export async function gmailSearch(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const query = typeof args.query === "string" ? args.query : "";
  if (!query) {
    throw new Error("gmail_search requires a non-empty 'query' string");
  }
  // Defense-in-depth: schema declares max:50 but a non-conforming MCP client
  // could pass a larger value (or Infinity). Clamp at the handler boundary so
  // a bad caller can't trigger an oversized Gmail response. Mirrors driveSearch.
  const requested = typeof args.max_results === "number" ? args.max_results : 10;
  const maxResults = Math.min(requested, 50);
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.messages.list({
      userId: "me",
      q: query,
      maxResults,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_search", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.1 PR-2: gmail_list_labels (READ tool) ─────────
 *
 * Pure pass-through. No kill-switch (no write effect), no arg validation
 * (no inputs beyond the implicit account_id middleware param), no extra
 * sanitize considerations beyond the default <untrusted-source> wrap that
 * withToolContext applies.
 *
 * Required scope is `gmail.labels` only — narrower than `gmail.readonly`.
 * Google's labels.list endpoint also accepts `gmail.readonly` / `gmail.modify`,
 * but registry declares the most specific one to (a) gate users with
 * pre-v1.1 tokens behind re-consent, and (b) match the security-reviewer
 * "registry is authoritative for required scope" finding.
 */
export async function gmailListLabels(
  ctx: ToolContext,
  _args: Record<string, unknown>,
): Promise<unknown> {
  // Use `gmailClientFromToken(requireGoogle(ctx).getAccessToken())` rather than
  // `getGmailClient(requireGoogle(ctx).accountId)` — withToolContext has already
  // refreshed; the alternate path would do a redundant Keychain read + refresh.
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.labels.list({ userId: "me" });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_list_labels", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── gmail_create_label (WRITE tool, gmail.labels scope) ─────────
 *
 * Creates a user-defined label. Write counterpart to gmail_list_labels —
 * reuses the same narrow `gmail.labels` scope (already requested by
 * gmail_list_labels in v1.1) so no new consent surface.
 *
 * Defenses (validation order mirrors gmailSend — v1.4 code-rev MINOR):
 *   1. Type gate — `name` must be string.
 *   2. Trim + non-empty gate — leading/trailing whitespace stripped before
 *      send (mirrors Gmail web UI), then trimmed name must be non-empty.
 *   3. HEADER_INJECTION_RE rejection on the RAW (pre-trim) name (CR/LF/
 *      NUL/NEL/U+2028/U+2029). Defensive: labels.create's `name` field
 *      passes through to Gmail's JSON body, not into an RFC 2822 header,
 *      so header-line injection is not the actual threat — but rejecting
 *      these characters in any user-controlled identifier-shaped field
 *      keeps the project's invariant consistent. Prevents prompt-injected
 *      "labels" that smuggle line breaks into log views / Gmail UI.
 *      Uses the module-shared `HEADER_INJECTION_RE` const (v1.4 sec-rev
 *      LOW-2 — collapsed from a duplicate copy).
 *   4. Byte-length cap — ≤ 225 UTF-8 bytes after trim. Local fail-fast
 *      against Gmail's observed UI limit; the upstream limit is not
 *      publicly documented (v1.4 sec-rev LOW-3) so this is advisory,
 *      not authoritative.
 *   5. System-label name blacklist (case-insensitive): INBOX/SENT/UNREAD/
 *      IMPORTANT/STARRED/DRAFT/TRASH/SPAM/CHAT + CATEGORY_* prefix.
 *      Reuses `system_label_forbidden` MCPError code. Echoed name capped
 *      at 64 chars (sec-rev LOW-1). Google would reject server-side too
 *      (409 / 400) but local rejection gives a cleaner recovery hint.
 *   6. Visibility enum gate — JSON Schema enforces this at the MCP
 *      boundary; we re-check at handler boundary for defense-in-depth
 *      against non-conforming MCP clients.
 *   7. Idempotency — list-then-match BEFORE create. Eliminates the
 *      duplicate-label class of prompt-injection abuse: a malicious
 *      message body that talks Claude into calling create_label 100 times
 *      with subtly different cases collapses to one (or zero) actual
 *      writes. Returns the existing Label resource on match.
 *
 * Audit: the standard auditEnd line written by withToolContext records
 * tool name + account + args_hash + status, which is enough to forensically
 * answer "did SafeSpace create this label." No share_forensic-style extra
 * line — label create has no per-recipient blast radius.
 */
const GMAIL_LABEL_MAX_NAME_BYTES = 225;
const GMAIL_SYSTEM_LABEL_NAMES_LOWER: ReadonlySet<string> = new Set([
  "inbox",
  "sent",
  "unread",
  "important",
  "starred",
  "draft",
  "trash",
  "spam",
  "chat",
]);
type LabelListVisibility = "labelShow" | "labelShowIfUnread" | "labelHide";
type MessageListVisibility = "show" | "hide";

interface GmailLabel {
  id: string;
  name: string;
  type?: string;
}

export async function gmailCreateLabel(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // Validation order mirrors gmailSend (v1.4 code-rev MINOR): type gate →
  // non-empty (after trim) → header-injection → length → blacklist.
  if (typeof args.name !== "string") {
    throw new Error("gmail_create_label: 'name' must be a string");
  }
  const trimmed = args.name.trim();
  if (trimmed.length === 0) {
    throw new Error("gmail_create_label: 'name' must be non-empty after trim");
  }
  if (HEADER_INJECTION_RE.test(args.name)) {
    throw new Error(
      "gmail_create_label: 'name' must not contain CR/LF/NUL/NEL/U+2028/U+2029",
    );
  }
  if (Buffer.byteLength(trimmed, "utf-8") > GMAIL_LABEL_MAX_NAME_BYTES) {
    // 225 is the observed Gmail UI limit, mirrored locally for a fail-fast
    // path; Google's public reference doesn't publish a documented hard cap
    // for labels.create.name (v1.4 sec-rev LOW-3), so upstream may also
    // reject independently.
    throw new Error(
      `gmail_create_label: 'name' exceeds 225 bytes (local cap mirrors observed Gmail UI limit; upstream may also reject)`,
    );
  }

  const lower = trimmed.toLowerCase();
  if (GMAIL_SYSTEM_LABEL_NAMES_LOWER.has(lower) || lower.startsWith("category_")) {
    // Cap the echoed `name` in MCPError data to bound attacker-controlled
    // bytes in the JSON-RPC error envelope (v1.4 sec-rev LOW-1). Recovery
    // hint in errors.ts is the load-bearing information; trimmed name is
    // included only so caller logs distinguish multiple blacklist hits.
    throw new MCPError("system_label_forbidden", {
      name: trimmed.length > 64 ? trimmed.slice(0, 64) : trimmed,
    });
  }

  const labelListVisibility: LabelListVisibility =
    args.label_list_visibility === undefined ? "labelShow" : (args.label_list_visibility as LabelListVisibility);
  if (
    labelListVisibility !== "labelShow" &&
    labelListVisibility !== "labelShowIfUnread" &&
    labelListVisibility !== "labelHide"
  ) {
    throw new Error(
      "gmail_create_label: 'label_list_visibility' must be one of labelShow|labelShowIfUnread|labelHide",
    );
  }
  const messageListVisibility: MessageListVisibility =
    args.message_list_visibility === undefined ? "show" : (args.message_list_visibility as MessageListVisibility);
  if (messageListVisibility !== "show" && messageListVisibility !== "hide") {
    throw new Error(
      "gmail_create_label: 'message_list_visibility' must be one of show|hide",
    );
  }

  // Two SDK calls in sequence:
  //   1. list (idempotency check by exact name match — case-sensitive to
  //      mirror Gmail allowing distinct labels that differ only in case)
  //   2. create (only if no match)
  //
  // The MCPError instanceof check below is defensive — system_label_forbidden
  // is raised above and already escapes before this try-catch, but any future
  // typed error raised inside the SDK boundary should not be reshaped into
  // an upstream_error.
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());

    // Step 1 — idempotency lookup via SDK.
    const listRes = await gmail.users.labels.list({ userId: "me" });
    const listData = listRes.data as { labels?: GmailLabel[] } | null;
    if (listData && Array.isArray(listData.labels)) {
      const existing = listData.labels.find((l) => l.name === trimmed);
      if (existing) return existing;
    }

    // Step 2 — create.
    const createRes = await gmail.users.labels.create({
      userId: "me",
      requestBody: {
        name: trimmed,
        labelListVisibility,
        messageListVisibility,
      },
    });
    return createRes.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_create_label", email: requireGoogle(ctx).accountId });
  }
}

export async function gmailGetMessage(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const id = typeof args.id === "string" ? args.id : "";
  if (!id) {
    throw new Error("gmail_get_message requires a non-empty 'id' string");
  }
  // format=full returns the full payload: headers + body.data (base64url) + parts.
  // Sanitize will wrap user-controlled string leaves: header values (From/Subject/...)
  // and body.data. Header `name` strings are also user-reachable inputs in inbound
  // mail (RFC 2822 doesn't prevent custom header injection) so wrapping them is
  // correct, not over-paranoid.
  //
  // base64 scan boundary (5.1 sec-review): body.data arrives base64url-encoded
  // and is wrapped AS-IS — patterns like `ignore-prev` will NOT fire on encoded
  // bytes because base64 destroys all whitespace-delimited keyword matching.
  // We accept this trade-off:
  //   - The wrapper + <warning> preamble (per DESIGN.md §P1(c)) is the primary
  //     security boundary; flags are observability hints only.
  //   - Decoding before wrap would change the response shape (Claude expects
  //     base64; multipart parts have their own per-part encoding) and bloat
  //     responses 4/3×. Step 5.4 binary handling would have to align.
  // If pattern coverage on body text becomes important, revisit by decoding
  // text/* mimeType parts inside the proxy before wrapping.
  // format=full preserved exactly — sanitize + sample 9c tests assume that shape.
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.messages.get({ userId: "me", id, format: "full" });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_get_message", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── 5.9 gmail_send (FIRST WRITE TOOL) ─────────
 *
 * Security posture per Plan agent D3 + sec-rev:
 *   1. Tier gating — v2.0 replaced the v1.x SAFESPACE_ENABLE_SEND=1 kill
 *      switch with SAFESPACE_TIER=write (or share). Tier filter in proxy.ts
 *      hides this tool from tools/list at tier=read so Claude never sees
 *      it. Per-tool registry min_tier="write" is the authoritative gate.
 *   2. RFC 2822 header injection rejection — CR/LF in `to` or `subject`
 *      would let an attacker (or a prompt-injected Claude tool call) add
 *      `Bcc: attacker@evil.com\r\n` to the headers. Reject before constructing.
 *      sanitize() only protects RESPONSES; request inputs need their own gate.
 *   3. Audit JSONL fires automatically via withToolContext finally block.
 *      Every send produces one durable line — operationally critical for
 *      "did SafeSpace really send this?" debugging.
 *   4. NO interactive confirmation in the handler — MCP has no UI primitive.
 *      Claude itself is expected to ask the user before invoking write tools.
 *
 * v1 limits (deliberate):
 *   - Plain text body only (no multipart/alternative HTML)
 *   - No attachments
 *   - ASCII subject only (no MIME Q-encoding for non-ASCII headers in v1)
 *   - No CC/BCC fields in the schema (would widen the header-injection
 *     surface and add UX complexity); use `to` with multiple comma-sep
 *     addresses if needed.
 *
 * Per Plan D9: do NOT soften the with-context aggressive double-401 cleanup
 * for gmail_send specifically — a double-401 with a fresh refresh probably
 * means the refresh token IS invalid, and silently keeping a dead token
 * would be worse than the current "delete + re-consent" recovery.
 */

// HEADER_INJECTION_RE is declared at the top of this module — shared with
// gmailCreateLabel since v1.4 (sec-rev LOW-2). Threat set (CR/LF/NUL/NEL/
// U+2028/U+2029) is unchanged from Step 5.9.
//
// v1.64 Phase B (B3 — D2): the gmail pre-egress gate constants + helpers that
// used to live here — MAX_RECIPIENTS, MAX_EMAIL_BODY_BYTES, NON_ASCII_RE, and
// the parseAddrs helper — MOVED to src/tools/egress.ts alongside the new
// enforceGmailHeaderGates, so gmail_send + gmail_create_draft share ONE
// byte-identical copy of the header / non-ASCII / recipient-count / format /
// body-cap logic (see enforceGmailHeaderGates + enforceEgressGates there).

/* ───────── shared compose helper (gmail_send + gmail_create_draft) ─────────
 *
 * v1.43: the RFC 2822 assembly is shared so both tools build byte-identical
 * wire messages.
 *
 * v1.64 Phase B (B3 — D2): the two egress gates that used to live here —
 * enforceRecipientAllowlist (v2.2 recipient allowlist + v1.56 tainted-source +
 * v1.57 F3b-gate) and enforceOutboundSecret (v1.57 F3a) — MOVED to
 * src/tools/egress.ts (enforceEgressGates), so the envelope's egress protection
 * has exactly ONE implementation a future outbound tool can never miss or drift
 * weaker. gmail_send / gmail_create_draft now call enforceEgressGates at the
 * same resolved-recipient point (byte-identical behavior).
 */

/** Assemble a minimal RFC 2822 message and return the base64url `raw` that
 *  Gmail's drafts.create / messages.send expect. CRLF line endings per spec;
 *  From always emitted; To/Cc/Bcc emitted only when non-empty so partial
 *  drafts / to-only sends stay MIME-clean. Callers MUST have already run the
 *  header-injection + email-format gates on every field. */
function buildRfc2822Raw(
  from: string,
  fields: {
    to: string[];
    cc: string[];
    bcc: string[];
    subject: string;
    body: string;
  },
): string {
  const headers: string[] = [`From: ${from}`];
  if (fields.to.length > 0) headers.push(`To: ${fields.to.join(", ")}`);
  if (fields.cc.length > 0) headers.push(`Cc: ${fields.cc.join(", ")}`);
  if (fields.bcc.length > 0) headers.push(`Bcc: ${fields.bcc.join(", ")}`);
  headers.push(
    `Subject: ${fields.subject}`,
    `MIME-Version: 1.0`,
    `Content-Type: text/plain; charset="utf-8"`,
    ``,
    fields.body,
  );
  return Buffer.from(headers.join("\r\n"), "utf-8").toString("base64url");
}

/** B6.1 wave A3+D — the SINGLE-SOURCE gmail_send arg validator: the type-then-
 *  presence checks (to/subject/body/cc/bcc typed → non-empty to/subject/body),
 *  messages VERBATIM from the pre-A3 inline block. Called by BOTH the pipeline
 *  descriptor's `extract` (tools/egress-pipeline.ts — the production gate input) and
 *  the handler below (defense-in-depth re-run of the same pure check), so the two can
 *  never drift. cc/bcc default to "" so the returned shape is always the full set. */
export function validateGmailSendArgs(args: Record<string, unknown>): {
  to: string;
  subject: string;
  body: string;
  cc: string;
  bcc: string;
} {
  // Type-then-presence split (5.9 code-rev MED-1): "wrong type" vs
  // "missing/empty" surface as distinct errors so operators debugging a
  // misconfigured MCP client get an actionable message.
  if (typeof args.to !== "string") {
    throw new Error("gmail_send: 'to' must be a string");
  }
  if (typeof args.subject !== "string") {
    throw new Error("gmail_send: 'subject' must be a string");
  }
  if (typeof args.body !== "string") {
    throw new Error("gmail_send: 'body' must be a string");
  }
  if (args.cc !== undefined && typeof args.cc !== "string") {
    throw new Error("gmail_send: 'cc' must be a string when provided");
  }
  if (args.bcc !== undefined && typeof args.bcc !== "string") {
    throw new Error("gmail_send: 'bcc' must be a string when provided");
  }
  const to = args.to;
  const subject = args.subject;
  const body = args.body;
  const cc = (args.cc as string | undefined) ?? "";
  const bcc = (args.bcc as string | undefined) ?? "";
  if (!to.trim() || !subject || !body) {
    throw new Error("gmail_send requires non-empty 'to', 'subject', and 'body'");
  }
  return { to, subject, body, cc, bcc };
}

/** B6.1 wave A3+D — the SINGLE-SOURCE gmail_create_draft arg validator: the
 *  all-optional per-field type loop + the at-least-one-non-empty check, messages
 *  VERBATIM from the pre-A3 inline block. Called by BOTH the pipeline descriptor's
 *  `extract` and the handler below (defense-in-depth), so the two can never drift. */
export function validateGmailCreateDraftArgs(args: Record<string, unknown>): {
  to: string;
  subject: string;
  body: string;
  cc: string;
  bcc: string;
} {
  // Type gates — all fields optional, so validate only when present.
  for (const k of ["to", "cc", "bcc", "subject", "body"] as const) {
    if (args[k] !== undefined && typeof args[k] !== "string") {
      throw new Error(`gmail_create_draft: '${k}' must be a string when provided`);
    }
  }
  const to = (args.to as string | undefined) ?? "";
  const cc = (args.cc as string | undefined) ?? "";
  const bcc = (args.bcc as string | undefined) ?? "";
  const subject = (args.subject as string | undefined) ?? "";
  const body = (args.body as string | undefined) ?? "";

  // Reject a totally-empty draft. A draft with only a body or only a subject
  // (no recipient yet) is legitimate — that's the whole point of a draft.
  if (!to.trim() && !subject && !body) {
    throw new Error("gmail_create_draft requires at least one of non-empty 'to', 'subject', or 'body'");
  }
  return { to, subject, body, cc, bcc };
}

export async function gmailSend(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // v2.0: kill switch removed. Tier-based tools/list filter in proxy.ts gates
  // exposure; if Claude can see this tool, the current tier is `write` or
  // higher and the operator has explicitly opted into sending. Claude Code's
  // per-call approve UI is the operational confirmation layer.

  // v1.10 (#14): cc / bcc are optional. Bcc routing matches RFC 5322 §3.6.3:
  // Gmail's users.messages.send delivers a copy to each Bcc address but
  // strips the Bcc header from the delivered MIME, so including `Bcc:` in
  // the raw RFC 2822 is correct and required for the recipients to be
  // addressed (no separate bcc field — everything rides in `raw`).

  // account_id is resolved upstream by withToolContext into ctx.credential (the
  // oauth email + token getter); do NOT re-read args.account_id here (would
  // double-resolve).

  // B6.1 wave A3+D — the egress gate (header/count gates → contact-lookup
  // resolution → recipient-format/body-cap → F3a secret-shape → v2.2 recipient
  // allowlist + F3b tainted-source → supervised-send approval) is PIPELINE-FIRED:
  // withToolContext runs this tool's descriptor (extract = validateGmailSendArgs →
  // gate = enforceGmailComposeEgressGates, resolving recipients via
  // source.resolveRecipients) BEFORE this handler and stores the gate's transformed
  // shape (RESOLVED recipients + the vetted subject/body) on ctx.egress. The handler
  // must NOT call the gate itself (anti-double-fire — egress-callsite.test.ts) and
  // wires the PIPELINE's resolved recipients (never a local recomputation).
  //
  // Defense-in-depth: re-run the SAME pure validator the pipeline's extract ran
  // (identical result in production; keeps the handler independently unit-testable).
  validateGmailSendArgs(args);

  // The pipeline-fired gate's transformed shape — the RESOLVED recipients + vetted
  // fields. `resolved`-absent (the extracted shape reached the handler without the
  // gate transform) → fail loud, never send with unresolved names.
  const shape = requireEgressResult(ctx, "gmail-compose");
  if (shape.resolved === undefined) {
    throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
  }

  // Build minimal RFC 2822 message → base64url `raw` (CRLF endings; From
  // mandatory per §3.6.2; Cc/Bcc only when non-empty so to-only sends stay
  // MIME-clean). Uses the PIPELINE's RESOLVED emails + vetted subject/body so the
  // headers carry what we actually send to, not the name Claude typed. v1.43:
  // shared helper — gmail_create_draft builds byte-identical wire messages.
  const raw = buildRfc2822Raw(requireGoogle(ctx).accountId, {
    to: shape.resolved.to,
    cc: shape.resolved.cc,
    bcc: shape.resolved.bcc,
    subject: shape.subject,
    body: shape.body,
  });

  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.messages.send({
      userId: "me",
      requestBody: { raw },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_send", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.1 PR-3: gmail_modify_message (WRITE tool) ─────────
 *
 * Mirrors gmail_send's defense pattern, scaled to label modification:
 *   1. Tier gating — v2.0 replaced SAFESPACE_ENABLE_MODIFY=1 with
 *      SAFESPACE_TIER=write (or share). Tier filter hides this tool at
 *      tier=read. Registry min_tier="write" is the authoritative gate.
 *   2. Message id format gate — Gmail ids are 16+ lowercase hex chars.
 *      Local rejection saves a doomed round-trip to Google for typos
 *      (sec-rev PR-3 M1, same rationale as gmail_send's per-recipient
 *      email-format gate).
 *   3. Per-array cap (10 labels per side, independent). A prompt-injected
 *      Claude call could otherwise paste a 100-label add list.
 *   4. TRASH/SPAM block on add path ONLY. Asymmetric BY DESIGN — a user
 *      may need to recover a message FROM trash via removeLabelIds:
 *      ["TRASH"], or unmark a false-positive spam via
 *      removeLabelIds:["SPAM"]. Both are recovery actions Google's Gmail
 *      UI exposes natively. Blocking the add path covers the destructive
 *      direction (TRASH auto-deletes after 30 days; SPAM trains Gmail's
 *      classifier upward).
 *   5. Audit JSONL fires automatically via withToolContext finally block.
 *   6. NO interactive confirmation in handler — same as gmail_send.
 *      Claude itself must ask the user before invoking write tools.
 *
 * What this handler does NOT cover (intentional non-features):
 *   - Batch modify (one call → multiple message ids). Out of scope; KISS.
 *   - Label create/delete/rename. Use Gmail UI; not a v1.1 capability.
 *   - Trash/untrash via dedicated endpoints. The single modify endpoint
 *     covers untrash via removeLabelIds (defense-in-depth covered above).
 *
 * Scope-excess note (carried from PR-1 sec-rev): the `gmail.modify` OAuth
 * scope on the access token also permits messages.trash, messages.import,
 * drafts.*, which this handler never calls. Defense relies on the registry
 * being the authoritative requiredScopes declaration; do NOT add handler-level
 * "check we're still calling modify" guards (fragile coupling, sec-rev PR-3 L3).
 */
const MAX_LABEL_IDS_PER_CALL = 10;
const BLOCKED_ADD_LABEL_IDS: ReadonlySet<string> = new Set(["TRASH", "SPAM"]);
// Gmail message ids are 16+ lowercase hex characters. Local format gate
// is a sanity check, not a security boundary (Google validates server-side).
const GMAIL_MESSAGE_ID_RE = /^[0-9a-f]{16,}$/;

export async function gmailModifyMessage(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // v2.0: kill switch removed. See gmailSend for rationale.

  if (typeof args.id !== "string") {
    throw new Error("gmail_modify_message: 'id' must be a string");
  }
  if (!args.id) {
    throw new Error("gmail_modify_message requires non-empty 'id'");
  }
  if (!GMAIL_MESSAGE_ID_RE.test(args.id)) {
    throw new Error(
      `gmail_modify_message: 'id' is invalid Gmail message id format (expected 16+ lowercase hex chars, got ${JSON.stringify(args.id)})`,
    );
  }
  const id = args.id;

  // Optional arrays. `addLabelIds: undefined` is treated as `[]`.
  // Wrong type (e.g. "INBOX" instead of ["INBOX"]) is a hard reject —
  // silently coercing would hide a caller bug.
  if (args.addLabelIds !== undefined && !Array.isArray(args.addLabelIds)) {
    throw new Error("gmail_modify_message: 'addLabelIds' must be a string array");
  }
  if (args.removeLabelIds !== undefined && !Array.isArray(args.removeLabelIds)) {
    throw new Error("gmail_modify_message: 'removeLabelIds' must be a string array");
  }
  const addLabelIds = (args.addLabelIds ?? []) as unknown[];
  const removeLabelIds = (args.removeLabelIds ?? []) as unknown[];

  for (const entry of addLabelIds) {
    if (typeof entry !== "string") {
      throw new Error("gmail_modify_message: 'addLabelIds' must be a string array");
    }
    // L1 from PR #46 review: pre-reject empty/whitespace-only labels so
    // users get a clear local message instead of an opaque upstream 400.
    // Mirrors gmail_send's empty `to`/`subject`/`body` rejection pattern.
    if (entry.trim() === "") {
      throw new Error("gmail_modify_message: 'addLabelIds' must not contain empty strings");
    }
  }
  for (const entry of removeLabelIds) {
    if (typeof entry !== "string") {
      throw new Error("gmail_modify_message: 'removeLabelIds' must be a string array");
    }
    if (entry.trim() === "") {
      throw new Error("gmail_modify_message: 'removeLabelIds' must not contain empty strings");
    }
  }
  const adds = addLabelIds as string[];
  const removes = removeLabelIds as string[];

  if (adds.length === 0 && removes.length === 0) {
    throw new Error(
      "gmail_modify_message: at least one of addLabelIds or removeLabelIds must be non-empty",
    );
  }
  if (adds.length > MAX_LABEL_IDS_PER_CALL) {
    throw new MCPError("label_limit_exceeded", {
      limit: MAX_LABEL_IDS_PER_CALL,
      side: "add",
      got: adds.length,
    });
  }
  if (removes.length > MAX_LABEL_IDS_PER_CALL) {
    throw new MCPError("label_limit_exceeded", {
      limit: MAX_LABEL_IDS_PER_CALL,
      side: "remove",
      got: removes.length,
    });
  }

  // Block list on ADD only. See header comment for asymmetric-by-design rationale.
  for (const labelId of adds) {
    if (BLOCKED_ADD_LABEL_IDS.has(labelId)) {
      throw new MCPError("system_label_forbidden", { labelId });
    }
  }

  // MCPError instanceof check is defensive — system_label_forbidden +
  // label_limit_exceeded are raised above and already escape before this
  // try-catch, but any future typed error raised inside the SDK boundary
  // should not be reshaped into an upstream_error.
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.messages.modify({
      userId: "me",
      id,
      requestBody: { addLabelIds: adds, removeLabelIds: removes },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_modify_message", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v2.3 PR-C: gmail_modify_messages_batch (WRITE tool) ─────────
 *
 * Variant of gmail_modify_message that applies the SAME label change to
 * 1-100 messages in a single Gmail multipart/mixed batch HTTP call.
 *
 * Sec gates mirror the single-message variant exactly, plus a per-batch
 * ID cap. The cap is 100 here even though Gmail's API supports 1000 —
 * the cap is a prompt-injection blast-radius guard, not an API ceiling.
 * A model that gets tricked into "label these 100 messages as TRASH" is
 * already wrong; 10x larger blast doesn't change the response (block
 * TRASH/SPAM adds), but a 1000-message batch with a SUBTLE wrong label
 * is a much bigger cleanup. 100 is also the typical sweep size (one
 * page of search results); larger batches should be split client-side.
 *
 * Implementation: DIRECT multipart/mixed HTTP POST to
 * `https://gmail.googleapis.com/batch/gmail/v1`. Each sub-request is
 * `POST /gmail/v1/users/me/messages/{id}/modify` with its own JSON body.
 * The googleapis SDK has no built-in batch helper (deprecated `google-batch`
 * npm package was last released 2017-11-22 and is documented as "for poc
 * purpose only"). Multipart construction + parse live in
 * `src/google-api/batch.ts` with their own unit tests.
 *
 * Per-sub-response semantics: success is HTTP 200 with the updated message
 * resource as the body (`{id, threadId, labelIds}`). The handler returns
 * an aggregate `{success, modified_count, duplicates_dropped}` shape.
 * Any sub-response with status outside 2xx fails the whole call (preserves
 * the all-or-nothing contract of Gmail's batchModify REST). Future iteration
 * could surface per-message status; current MCP error shape is binary.
 */
const MAX_MESSAGE_IDS_PER_BATCH = 100;
const GMAIL_BATCH_ENDPOINT = "https://gmail.googleapis.com/batch/gmail/v1";

export async function gmailModifyMessagesBatch(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (!Array.isArray(args.ids)) {
    throw new Error("gmail_modify_messages_batch: 'ids' must be a string array");
  }
  if (args.ids.length === 0) {
    throw new Error("gmail_modify_messages_batch: 'ids' must contain at least one message id");
  }
  if (args.ids.length > MAX_MESSAGE_IDS_PER_BATCH) {
    throw new MCPError("batch_too_large", {
      limit: MAX_MESSAGE_IDS_PER_BATCH,
      got: args.ids.length,
    });
  }
  // Validate every ID locally — Gmail's batchModify rejects the whole
  // call with an opaque 400 on any bad ID, so name the bad one ourselves.
  // Also collect to dedupe — Gmail accepts duplicates but it's wasteful
  // and likely a caller bug (e.g. pasted the same ID twice).
  const idSet = new Set<string>();
  for (let i = 0; i < args.ids.length; i++) {
    const entry = args.ids[i];
    if (typeof entry !== "string") {
      throw new Error(`gmail_modify_messages_batch: 'ids[${i}]' must be a string`);
    }
    if (!GMAIL_MESSAGE_ID_RE.test(entry)) {
      throw new Error(
        `gmail_modify_messages_batch: 'ids[${i}]' is invalid Gmail message id format (expected 16+ lowercase hex chars)`,
      );
    }
    idSet.add(entry);
  }
  const ids = [...idSet];

  // Label arrays — identical validation to single-message variant.
  if (args.addLabelIds !== undefined && !Array.isArray(args.addLabelIds)) {
    throw new Error("gmail_modify_messages_batch: 'addLabelIds' must be a string array");
  }
  if (args.removeLabelIds !== undefined && !Array.isArray(args.removeLabelIds)) {
    throw new Error("gmail_modify_messages_batch: 'removeLabelIds' must be a string array");
  }
  const addLabelIds = (args.addLabelIds ?? []) as unknown[];
  const removeLabelIds = (args.removeLabelIds ?? []) as unknown[];

  for (const entry of addLabelIds) {
    if (typeof entry !== "string") {
      throw new Error("gmail_modify_messages_batch: 'addLabelIds' must be a string array");
    }
    if (entry.trim() === "") {
      throw new Error("gmail_modify_messages_batch: 'addLabelIds' must not contain empty strings");
    }
  }
  for (const entry of removeLabelIds) {
    if (typeof entry !== "string") {
      throw new Error("gmail_modify_messages_batch: 'removeLabelIds' must be a string array");
    }
    if (entry.trim() === "") {
      throw new Error("gmail_modify_messages_batch: 'removeLabelIds' must not contain empty strings");
    }
  }
  const adds = addLabelIds as string[];
  const removes = removeLabelIds as string[];

  if (adds.length === 0 && removes.length === 0) {
    throw new Error(
      "gmail_modify_messages_batch: at least one of addLabelIds or removeLabelIds must be non-empty",
    );
  }
  if (adds.length > MAX_LABEL_IDS_PER_CALL) {
    throw new MCPError("label_limit_exceeded", {
      limit: MAX_LABEL_IDS_PER_CALL,
      side: "add",
      got: adds.length,
    });
  }
  if (removes.length > MAX_LABEL_IDS_PER_CALL) {
    throw new MCPError("label_limit_exceeded", {
      limit: MAX_LABEL_IDS_PER_CALL,
      side: "remove",
      got: removes.length,
    });
  }

  for (const labelId of adds) {
    if (BLOCKED_ADD_LABEL_IDS.has(labelId)) {
      throw new MCPError("system_label_forbidden", { labelId });
    }
  }

  try {
    const boundary = newBoundary();
    const body = buildBatchModifyBody(
      ids,
      {
        addLabelIds: adds.length > 0 ? adds : undefined,
        removeLabelIds: removes.length > 0 ? removes : undefined,
      },
      boundary,
    );
    const oauth = oauth2ClientFromToken(requireGoogle(ctx).getAccessToken());
    // OAuth2Client.request auto-attaches the Bearer token. Use
    // responseType: "text" so gaxios delivers the multipart string verbatim
    // (default is "json", which would fail to parse a multipart body).
    const res = await oauth.request<string>({
      url: GMAIL_BATCH_ENDPOINT,
      method: "POST",
      headers: {
        "Content-Type": `multipart/mixed; boundary=${boundary}`,
      },
      body,
      responseType: "text",
    });

    // Gmail returns the outer response with its OWN boundary in
    // Content-Type. We re-parse it from the response header to avoid any
    // assumption that Gmail echoes our boundary back.
    const respCT =
      (res.headers as Record<string, string | undefined>)?.["content-type"] ??
      (res.headers as Record<string, string | undefined>)?.["Content-Type"] ??
      "";
    const respBoundaryMatch = respCT.match(/boundary=([^;]+)/i);
    // Per CR PR #95 M2: if Google's response is missing boundary, surface
    // upstream_malformed directly instead of silently falling back to our
    // request boundary (which would "succeed" parsing into 0 results and
    // then trip the part-count check — same outcome but obscured chain).
    if (!respBoundaryMatch?.[1]) {
      mapGoogleError(
        {
          response: {
            status: 502,
            data: {
              error: {
                code: 502,
                message:
                  "batch response missing multipart boundary in Content-Type — upstream malformed",
              },
            },
          },
        },
        { tool: "gmail_modify_messages_batch", email: requireGoogle(ctx).accountId },
      );
    }
    const respBoundary = respBoundaryMatch![1].replace(/^"|"$/g, "");
    const subResponses = parseBatchResponse(String(res.data ?? ""), respBoundary);

    // Sub-response shape contract:
    //   - parseBatchResponse returns exactly N entries for a well-formed
    //     batch response (one per sub-request in order).
    //   - Empty array means the envelope was malformed (no boundary found).
    //   - status=0 within an entry means the sub-response had no HTTP line.
    // Any of these failure modes is an upstream malformed batch → throw an
    // UpstreamError via mapGoogleError. Per-sub failures (4xx/5xx) collapse
    // to one error since the handler contract is binary success/fail.
    // Per sec-rev PR #95 L1: any batch failure path leaves the caller
    // uncertain whether OTHER sub-requests succeeded server-side. Append a
    // fixed warning so users don't blindly retry and double-apply labels.
    const PARTIAL_FAILURE_WARNING =
      "Batch partial-failure possible: some messages may have been modified before failure. Verify state before retry.";

    if (subResponses.length !== ids.length) {
      mapGoogleError(
        {
          response: {
            status: 502,
            data: {
              error: {
                code: 502,
                message: `batch response part count mismatch (expected ${ids.length}, got ${subResponses.length}) — ${PARTIAL_FAILURE_WARNING}`,
              },
            },
          },
        },
        { tool: "gmail_modify_messages_batch", email: requireGoogle(ctx).accountId },
      );
    }
    const firstFailure = subResponses.find(
      (r) => r.status < 200 || r.status >= 300,
    );
    if (firstFailure) {
      // Per CR PR #95 M1: status=0 means the sub-response had no parseable
      // HTTP line — that's upstream-malformed, not a 0-status HTTP response.
      // Promote to 502 so middleware doesn't see a nonsense httpStatus=0.
      if (firstFailure.status === 0) {
        mapGoogleError(
          {
            response: {
              status: 502,
              data: {
                error: {
                  code: 502,
                  message: `batch sub-response missing HTTP status line — upstream malformed. ${PARTIAL_FAILURE_WARNING}`,
                },
              },
            },
          },
          { tool: "gmail_modify_messages_batch", email: requireGoogle(ctx).accountId },
        );
      }
      // Try to extract Google's error envelope from the sub-body for a
      // useful message; fall back to the raw status.
      let parsedMessage = `sub-request failed status=${firstFailure.status}`;
      try {
        const parsed = JSON.parse(firstFailure.body) as {
          error?: { message?: string; status?: string };
        };
        if (parsed.error?.message) {
          parsedMessage = parsed.error.message;
        }
      } catch {
        // sub-body not JSON — keep the synthetic message.
      }
      mapGoogleError(
        {
          response: {
            status: firstFailure.status,
            data: {
              error: {
                code: firstFailure.status,
                message: `${parsedMessage} — ${PARTIAL_FAILURE_WARNING}`,
              },
            },
          },
        },
        { tool: "gmail_modify_messages_batch", email: requireGoogle(ctx).accountId },
      );
    }

    return {
      success: true,
      modified_count: ids.length,
      duplicates_dropped: (args.ids as unknown[]).length - ids.length,
    };
  } catch (err) {
    if (err instanceof MCPError) throw err;
    // Re-thrown UpstreamError from the per-sub mapGoogleError call has
    // .httpStatus set — let it propagate as-is so middleware sees the same
    // shape Phase 2 migrations produce.
    const e = err as { httpStatus?: number };
    if (typeof e.httpStatus === "number") throw err;
    mapGoogleError(err, { tool: "gmail_modify_messages_batch", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.43 gmail_create_draft (WRITE tool) ─────────
 *
 * Compose a draft. Mirrors gmail_send's defense pipeline with draft
 * semantics: every recipient field is OPTIONAL (a draft may have no
 * recipients yet), but at least one of to/subject/body must be non-empty so
 * we never create an empty draft. Recipients are gated by the SAME recipient
 * allowlist as gmail_send (v1.43 Q2 LOCKED) — a draft is a latent send, and
 * gating at create time stops a disallowed-recipient draft from ever existing
 * for a human to one-click "Send". NO contact-lookup resolution (D3):
 * to/cc/bcc must be literal emails. gmail.modify scope (already requested;
 * implicitly authorizes users.drafts.*).
 *
 * NOT a send: drafts.create stores the message under DRAFT — no email leaves.
 * The agent has no send-draft tool; the human sends from Gmail (which re-
 * parses recipients), or via the fully-gated gmail_send.
 */
export async function gmailCreateDraft(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // B6.1 wave A3+D — the egress gate (header/count gates → recipient-format/body-cap
  // → F3a secret-shape → v2.2 recipient allowlist + F3b tainted-source) is
  // PIPELINE-FIRED, exactly like gmail_send (a draft is a latent send → the SAME
  // gate). NO contact-lookup for drafts (D3 — literal emails only): the gate skips
  // resolution for gmail_create_draft, so `resolved` carries the parsed literal
  // arrays. supervised-send approval does NOT apply to a draft (not in
  // APPROVAL_GATED_SENDS). The handler must NOT call the gate (anti-double-fire —
  // egress-callsite.test.ts) and wires the PIPELINE's parsed recipients off ctx.egress.
  //
  // Defense-in-depth: re-run the SAME pure validator the pipeline's extract ran.
  validateGmailCreateDraftArgs(args);

  const shape = requireEgressResult(ctx, "gmail-compose");
  if (shape.resolved === undefined) {
    throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
  }

  const raw = buildRfc2822Raw(requireGoogle(ctx).accountId, {
    to: shape.resolved.to,
    cc: shape.resolved.cc,
    bcc: shape.resolved.bcc,
    subject: shape.subject,
    body: shape.body,
  });

  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.drafts.create({
      userId: "me",
      requestBody: { message: { raw } },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_create_draft", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.43 gmail_list_drafts (READ tool) ─────────
 * Pass-through list of draft ids (drafts[{id, message{id, threadId}}] +
 * nextPageToken). Handler-clamps max_results at 50 (defense-in-depth vs a
 * non-conforming MCP client; mirrors gmailSearch). gmail.readonly scope. */
export async function gmailListDrafts(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const requested = typeof args.max_results === "number" ? args.max_results : 10;
  const maxResults = Math.min(requested, 50);
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.drafts.list({ userId: "me", maxResults });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_list_drafts", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.43 gmail_get_draft (READ tool) ─────────
 * Fetch one draft (format=full). The nested message goes through the same
 * sanitize tree-walk as gmail_get_message — headers + body.data are untrusted
 * (another operator may have authored or synced the draft). gmail.readonly. */
export async function gmailGetDraft(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const id = typeof args.id === "string" ? args.id : "";
  if (!id) {
    throw new Error("gmail_get_draft requires a non-empty 'id' string");
  }
  // Injection-clean id, symmetric with gmail_delete_draft (v1.43 sec-rev LOW):
  // keeps the "every id-bearing handler validates its id" invariant uniform.
  if (HEADER_INJECTION_RE.test(id)) {
    throw new Error("gmail_get_draft: 'id' must not contain CR/LF/NUL/NEL/U+2028/U+2029");
  }
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.drafts.get({ userId: "me", id, format: "full" });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_get_draft", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.43 gmail_delete_draft (WRITE tool) ─────────
 * Permanently delete a draft (drafts bypass Trash — NOT recoverable). Lowest
 * blast radius: operates only on the caller's own draft, no egress, no
 * recipient relevance → no allowlist. Id validated non-empty + injection-clean
 * (defensive; the id rides a URL path, not a header). gmail.modify scope. */
export async function gmailDeleteDraft(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const id = typeof args.id === "string" ? args.id : "";
  if (!id) {
    throw new Error("gmail_delete_draft requires a non-empty 'id' string");
  }
  if (HEADER_INJECTION_RE.test(id)) {
    throw new Error("gmail_delete_draft: 'id' must not contain CR/LF/NUL/NEL/U+2028/U+2029");
  }
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    await gmail.users.drafts.delete({ userId: "me", id });
    return { success: true, id };
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_delete_draft", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.44 gmail_get_thread (READ tool, A2) ─────────
 * Fetch a whole conversation as a LIGHTWEIGHT index: format=metadata returns
 * each message's headers (From/To/Subject/Date) + snippet but NO body.data, so
 * the response stays bounded even for a 50-message thread (Q2 LOCKED). To read
 * a specific message's full body, the caller drills in with gmail_get_message;
 * to download an attachment, gmail_get_attachment. Same sanitize tree-walk as
 * gmail_get_message — header values + snippet are untrusted and wrap; opaque
 * ids pass via SKIP_FIELDS. gmail.readonly scope. */
export async function gmailGetThread(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const id = typeof args.id === "string" ? args.id : "";
  if (!id) {
    throw new Error("gmail_get_thread requires a non-empty 'id' string");
  }
  if (HEADER_INJECTION_RE.test(id)) {
    throw new Error("gmail_get_thread: 'id' must not contain CR/LF/NUL/NEL/U+2028/U+2029");
  }
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.threads.get({ userId: "me", id, format: "metadata" });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_get_thread", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.44 gmail_get_attachment (READ tool, A2) ─────────
 * Download ONE attachment via messages.attachments.get(messageId, attachmentId)
 * — both handles come from a prior gmail_get_message / gmail_get_thread payload
 * (payload.parts[*]: filename + body.attachmentId + body.size). Returns
 * {size, data} where data is base64url. SIZE CAP: 5 MB (mirrors DRIVE_MAX_BYTES
 * + reuses the `file_too_large` -32007 error — Q3 LOCKED, ZERO new error code);
 * an oversized attachment is REJECTED rather than dumped into context (a
 * post-fetch guard — attachments.get has no HEAD/stream; it protects CONTEXT,
 * while Gmail's own 25 MB attachment limit bounds bandwidth). Binary `data` is
 * returned base64url AS-IS (Q4 LOCKED) — no proxy-side decode (avoids 4/3 bloat
 * + binary-in-JSON); the sanitize wrap treats it as opaque, same accepted
 * trade-off as gmail_get_message body.data. gmail.readonly scope. */
const ATTACHMENT_MAX_BYTES = 5 * 1024 * 1024; // 5 MB — mirrors DRIVE_MAX_BYTES

export async function gmailGetAttachment(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const messageId = typeof args.message_id === "string" ? args.message_id : "";
  const attachmentId = typeof args.attachment_id === "string" ? args.attachment_id : "";
  if (!messageId) {
    throw new Error("gmail_get_attachment requires a non-empty 'message_id' string");
  }
  if (!attachmentId) {
    throw new Error("gmail_get_attachment requires a non-empty 'attachment_id' string");
  }
  if (HEADER_INJECTION_RE.test(messageId) || HEADER_INJECTION_RE.test(attachmentId)) {
    throw new Error("gmail_get_attachment: 'message_id' and 'attachment_id' must not contain CR/LF/NUL/NEL/U+2028/U+2029");
  }
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.messages.attachments.get({
      userId: "me",
      messageId,
      id: attachmentId,
    });
    // Size cap (Q3): Gmail returns `size` = decoded byte count. Reject an
    // oversized attachment BEFORE returning so a multi-MB blob never lands in
    // context. Fall back to the decoded length of `data` if `size` is absent.
    const data = typeof res.data.data === "string" ? res.data.data : "";
    const declaredSize = typeof res.data.size === "number" ? res.data.size : undefined;
    const sizeBytes = declaredSize ?? (data ? Buffer.from(data, "base64url").length : 0);
    if (sizeBytes > ATTACHMENT_MAX_BYTES) {
      throw new MCPError("file_too_large", {
        message_id: messageId,
        size: sizeBytes,
        max: ATTACHMENT_MAX_BYTES,
      });
    }
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_get_attachment", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.51 Gmail filters (backlog B3) ─────────
 *
 * gmail_list_filters (READ) + gmail_create_filter (WRITE) + gmail_delete_filter
 * (WRITE) on the NEW `gmail.settings.basic` scope. A Gmail filter persists a
 * rule that auto-acts on incoming mail, so create is the security-critical
 * surface. Two persistent-abuse vectors, both blocked by reusing existing
 * patterns:
 *
 *   (a) `forward` action — a forwarding filter is a persistent exfiltration
 *       channel (every future matching message silently copied to an attacker).
 *       SafeSpace REJECTS it outright. The action body is built field-by-field
 *       from a 2-field allowlist {addLabelIds, removeLabelIds} (mirror v1.50
 *       buildValidatedPerson), so `forward` is never copied through even if a
 *       non-conforming client smuggles it past the additionalProperties:false
 *       schema; an explicit `"forward" in raw` reject gives a clear message.
 *
 *   (b) addLabelIds containing TRASH / SPAM — a silent auto-delete / auto-spam
 *       rule (TRASH auto-purges after 30 days; SPAM trains the classifier).
 *       Reuses the SAME `BLOCKED_ADD_LABEL_IDS` set + `system_label_forbidden`
 *       (-32011) as gmail_modify_message. removeLabelIds is unrestricted —
 *       removeLabelIds:["INBOX"] (auto-archive) and ["UNREAD"] (auto-mark-read)
 *       are the legitimate "auto-organize inbox" use case.
 *
 * Criteria (the match predicate) is benign — it only SELECTS which messages a
 * filter applies to; it causes no egress or deletion. Still built from a fixed
 * allowlist with byte caps + header-injection rejection on the free-text fields
 * for cross-tool consistency. ≥1 criteria field required (an empty criteria
 * matches ALL mail). ≥1 action field required (forward is blocked, so an
 * all-empty action would be a no-op rule).
 *
 * ZERO new error code (reuse system_label_forbidden / label_limit_exceeded /
 * scope_mismatch; field + forward rejection = plain Error), ZERO new audit
 * channel (config change, recoverable → standard auditEnd row), NO allowlist
 * gate (a filter is the caller's own private mailbox config, no recipient blast
 * radius; tier=write is the floor). Both write handlers re-check ctx.tier as
 * defense-in-depth (mirror v1.50 contacts), even though registry min_tier +
 * the proxy tools/list filter are the primary gate.
 */
const FILTER_CRITERIA_TEXT_FIELDS = ["from", "to", "subject", "query", "negatedQuery"] as const;
const FILTER_CRITERIA_BOOL_FIELDS = ["hasAttachment", "excludeChats"] as const;
const FILTER_SIZE_COMPARISONS: ReadonlySet<string> = new Set([
  "smaller",
  "larger",
  "unspecified",
]);
const FILTER_CRITERIA_TEXT_MAX_BYTES = 1024;
// Gmail filter ids are opaque URL-safe strings (e.g. "ANe1Bmj..."). A local
// format gate is a sanity check, not a security boundary (Google validates
// server-side); the class rejects path traversal / CRLF / NUL / whitespace.
const GMAIL_FILTER_ID_RE = /^[A-Za-z0-9_.-]{1,256}$/;

interface FilterCriteria {
  from?: string;
  to?: string;
  subject?: string;
  query?: string;
  negatedQuery?: string;
  hasAttachment?: boolean;
  excludeChats?: boolean;
  size?: number;
  sizeComparison?: string;
}
interface FilterAction {
  addLabelIds?: string[];
  removeLabelIds?: string[];
}

/** Build a validated FilterCriteria from caller input by ALLOWLIST — any
 *  top-level key outside the fixed set throws. Free-text fields get a byte cap
 *  + header-injection reject; size/sizeComparison are type/enum gated. */
function buildValidatedFilterCriteria(raw: Record<string, unknown>): FilterCriteria {
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(raw)) {
    const v = raw[key];
    if ((FILTER_CRITERIA_TEXT_FIELDS as readonly string[]).includes(key)) {
      if (typeof v !== "string") {
        throw new Error(`gmail_create_filter: criteria '${key}' must be a string`);
      }
      if (HEADER_INJECTION_RE.test(v)) {
        throw new Error(
          `gmail_create_filter: criteria '${key}' must not contain CR/LF/NUL/NEL/U+2028/U+2029`,
        );
      }
      if (Buffer.byteLength(v, "utf-8") > FILTER_CRITERIA_TEXT_MAX_BYTES) {
        throw new Error(
          `gmail_create_filter: criteria '${key}' exceeds ${FILTER_CRITERIA_TEXT_MAX_BYTES} bytes`,
        );
      }
      out[key] = v;
    } else if ((FILTER_CRITERIA_BOOL_FIELDS as readonly string[]).includes(key)) {
      if (typeof v !== "boolean") {
        throw new Error(`gmail_create_filter: criteria '${key}' must be a boolean`);
      }
      out[key] = v;
    } else if (key === "size") {
      if (typeof v !== "number" || !Number.isInteger(v) || v < 0) {
        throw new Error("gmail_create_filter: criteria 'size' must be a non-negative integer");
      }
      out[key] = v;
    } else if (key === "sizeComparison") {
      if (typeof v !== "string" || !FILTER_SIZE_COMPARISONS.has(v)) {
        throw new Error(
          "gmail_create_filter: criteria 'sizeComparison' must be one of smaller|larger|unspecified",
        );
      }
      out[key] = v;
    } else {
      throw new Error(
        `gmail_create_filter: criteria field '${key}' is not allowed (allowed: ${[
          ...FILTER_CRITERIA_TEXT_FIELDS,
          ...FILTER_CRITERIA_BOOL_FIELDS,
          "size",
          "sizeComparison",
        ].join(", ")})`,
      );
    }
  }
  return out as FilterCriteria;
}

/** Validate one filter label-id array: every entry a non-empty string, ≤10
 *  per side. `field` selects the label_limit_exceeded `side` discriminator. */
function validateFilterLabelArray(v: unknown, field: "addLabelIds" | "removeLabelIds"): string[] {
  if (!Array.isArray(v)) {
    throw new Error(`gmail_create_filter: action '${field}' must be a string array`);
  }
  const out: string[] = [];
  for (const entry of v) {
    if (typeof entry !== "string") {
      throw new Error(`gmail_create_filter: action '${field}' must be a string array`);
    }
    if (entry.trim() === "") {
      throw new Error(`gmail_create_filter: action '${field}' must not contain empty strings`);
    }
    out.push(entry);
  }
  if (out.length > MAX_LABEL_IDS_PER_CALL) {
    throw new MCPError("label_limit_exceeded", {
      limit: MAX_LABEL_IDS_PER_CALL,
      side: field === "addLabelIds" ? "add" : "remove",
      got: out.length,
    });
  }
  return out;
}

/** Build a validated FilterAction by ALLOWLIST. `forward` is rejected outright
 *  (key exfil vector); any other unknown key throws; TRASH/SPAM-add reuses the
 *  gmail_modify_message system-label block. */
function buildValidatedFilterAction(raw: Record<string, unknown>): FilterAction {
  // Explicit, clear rejection BEFORE the generic allowlist loop so the caller
  // gets a specific message rather than the generic "field not allowed".
  if ("forward" in raw) {
    throw new Error(
      "gmail_create_filter: the 'forward' action is not permitted (a forwarding filter is a persistent exfiltration channel) — SafeSpace blocks it. Use ordinary addLabelIds / removeLabelIds.",
    );
  }
  const out: FilterAction = {};
  for (const key of Object.keys(raw)) {
    if (key === "addLabelIds") {
      const arr = validateFilterLabelArray(raw[key], "addLabelIds");
      for (const labelId of arr) {
        if (BLOCKED_ADD_LABEL_IDS.has(labelId)) {
          throw new MCPError("system_label_forbidden", { labelId });
        }
      }
      out.addLabelIds = arr;
    } else if (key === "removeLabelIds") {
      out.removeLabelIds = validateFilterLabelArray(raw[key], "removeLabelIds");
    } else {
      throw new Error(
        `gmail_create_filter: action field '${key}' is not allowed (only addLabelIds / removeLabelIds; forward is blocked)`,
      );
    }
  }
  return out;
}

/* ───────── v1.51 gmail_list_filters (READ tool) ─────────
 * Pass-through list of the account's message filters on gmail.settings.basic.
 * Filter `id` passes through SKIP_FIELDS (opaque); user-authored criteria text
 * (from/subject/query/...) wraps via the default sanitize tree-walk. A `forward`
 * action authored in the Gmail web UI is surfaced as-is on READ (we never
 * create one) so the operator can see and gmail_delete_filter it. */
export async function gmailListFilters(
  ctx: ToolContext,
  _args: Record<string, unknown>,
): Promise<unknown> {
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.settings.filters.list({ userId: "me" });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_list_filters", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.51 gmail_create_filter (WRITE tool) ─────────
 * Allowlist-construct criteria + action (see header block above), require ≥1 of
 * each, then create. forward blocked; TRASH/SPAM-add blocked; label caps 10. */
export async function gmailCreateFilter(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (ctx.tier === "read") {
    throw new MCPError("scope_mismatch", {
      tool: "gmail_create_filter",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  if (typeof args.criteria !== "object" || args.criteria === null || Array.isArray(args.criteria)) {
    throw new Error("gmail_create_filter: 'criteria' must be an object");
  }
  if (typeof args.action !== "object" || args.action === null || Array.isArray(args.action)) {
    throw new Error("gmail_create_filter: 'action' must be an object");
  }

  const criteria = buildValidatedFilterCriteria(args.criteria as Record<string, unknown>);
  const action = buildValidatedFilterAction(args.action as Record<string, unknown>);

  if (Object.keys(criteria).length === 0) {
    throw new Error(
      "gmail_create_filter: 'criteria' requires at least one match field (an empty criteria would match ALL mail)",
    );
  }
  if ((action.addLabelIds?.length ?? 0) === 0 && (action.removeLabelIds?.length ?? 0) === 0) {
    throw new Error(
      "gmail_create_filter: 'action' requires at least one of addLabelIds / removeLabelIds (forward is not permitted)",
    );
  }

  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await gmail.users.settings.filters.create({
      userId: "me",
      requestBody: { criteria, action },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_create_filter", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.51 gmail_delete_filter (WRITE tool) ─────────
 * Delete one filter by id. Recoverable (recreate), no mail touched, no egress →
 * tier=write is the only floor (NO allowlist gate). Id validated non-empty +
 * format-gated (defensive; the id rides a URL path). */
export async function gmailDeleteFilter(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (ctx.tier === "read") {
    throw new MCPError("scope_mismatch", {
      tool: "gmail_delete_filter",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }
  const id = typeof args.id === "string" ? args.id : "";
  if (!id) {
    throw new Error("gmail_delete_filter requires a non-empty 'id' string");
  }
  if (!GMAIL_FILTER_ID_RE.test(id)) {
    throw new Error(
      "gmail_delete_filter: 'id' is invalid Gmail filter id format (expected URL-safe [A-Za-z0-9_.-], ≤256 chars; obtain via gmail_list_filters)",
    );
  }
  try {
    const gmail = gmailClientFromToken(requireGoogle(ctx).getAccessToken());
    await gmail.users.settings.filters.delete({ userId: "me", id });
    return { success: true, id };
  } catch (err) {
    throw toGoogleError(err, { tool: "gmail_delete_filter", email: requireGoogle(ctx).accountId });
  }
}

