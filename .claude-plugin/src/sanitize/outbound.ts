/**
 * v1.16 Phase 2b — outbound sanitize pipeline for user-composed text being
 * POSTED to a PUBLIC surface (YouTube comments).
 *
 * IMPORTANT: This is the FIRST outbound sanitize module in SafeSpace. The
 * existing inbound sanitize (src/sanitize/index.ts) defends Claude from
 * READING attacker text; this outbound pipeline defends the PUBLIC from a
 * prompt-injected Claude COMPOSING attacker text and posting it via
 * SafeSpace under the user's real YouTube channel identity.
 *
 * Threat (forward-looking, NOT today-load-bearing): a prompt-injected Claude
 * (e.g., via a Drive doc) composes a comment containing wrapper-escape
 * sequences. If posted to YouTube and later read back by ANY SafeSpace
 * process, the embedded close-tag could (theoretically) confuse inbound
 * parsing. Per-call random nonce (sanitize/index.ts:135) already prevents
 * prediction of any process's wrapper close-tag — so the defense matters
 * only as a forward investment for future code paths where the same MCP
 * process writes-then-reads a comment.
 *
 * Why gmail_send body does NOT use this: gmail recipients are gated by
 * SAFESPACE_RECIPIENT_ALLOW (v2.2) — a bounded human audience who already
 * trust the user. YouTube comments target an anonymous PUBLIC audience —
 * fundamentally different threat audience. Documented here to prevent
 * future scope-creep PRs from adding outbound sanitize to gmail_send
 * without re-establishing the threat model.
 *
 * 6-step pipeline (LOCKED ORDER, per docs/v1.16-youtube-api.md §9 — counted
 * from the OUTBOUND_STEPS array below; design doc §9 says "7-step" but the
 * implementation collapses to 6 by combining/omitting one step — array is
 * the single source of truth):
 *
 *   Step 1: REJECT (not strip) zero-width chars from ZERO_WIDTH_RE.
 *           Silent strip would change user intent; REJECT is the safe
 *           failure mode for outbound. Per design §9 step 1.
 *   Step 2: NFC normalize (confusables defense; lift unchanged from
 *           inbound semantics).
 *   Step 3: Length cap at YOUTUBE_COMMENT_MAX_BYTES (10000 bytes, matches
 *           YouTube's documented max). Reject over-length — do NOT
 *           silently truncate (would mask intent).
 *   Step 4: REJECT text matching `</untrusted-source-[0-9a-f]+>` — the
 *           inbound wrapper close-tag shape for ANY nonce length. Match
 *           is case-insensitive.
 *   Step 5: REJECT literal `<safespace-truncated/>` (TRUNCATE_MARKER
 *           defense, per patterns.ts:60).
 *   Step 6: REJECT text matching the inbound preamble pattern
 *           (`<warning>Content below is from an external source`),
 *           defends sanitize/index.ts:138 preamble integrity.
 *
 * Step ORDER lock: step 1 runs BEFORE step 4 so a `[ZWJ]</untrusted-...>`
 * payload fails at step 1 (zero-width REJECT) and never reaches step 4 —
 * prevents the ZWSP-split bypass of the regex.
 *
 * Per design hook #13 + sec-rev hooks #11 #13 (Phase 2b carry-forward).
 */

import { MCPError } from "../errors";
import { TRUNCATE_MARKER, ZERO_WIDTH_RE } from "./patterns";

/** YouTube comment max byte cap. Matches YouTube's documented limit. */
export const YOUTUBE_COMMENT_MAX_BYTES = 10000;

/** Regex matching the inbound wrapper close-tag shape for ANY nonce length.
 *  Case-insensitive — defends against `</UNTRUSTED-SOURCE-DEADBEEF>` etc. */
const WRAPPER_CLOSE_RE = /<\/untrusted-source-[0-9a-f]+>/i;

/** Regex matching the inbound preamble (sanitize/index.ts:138).
 *  Case-insensitive — defends against capitalized variants. */
const WARNING_PREAMBLE_RE = /<warning>Content below is from an external source/i;

/** Locked step ORDER (test sentinel). Step 1 MUST precede step 4 so
 *  ZWSP-prefixed wrapper-close payloads fail at step 1 (zero-width REJECT)
 *  rather than slipping past step 4 (the regex against the unwrapped form).
 *  Mutating this array's order is a sec-rev event. */
export const OUTBOUND_STEPS = [
  "zero_width_reject",      // Step 1
  "nfc_normalize",          // Step 2
  "length_cap",             // Step 3
  "wrapper_close_reject",   // Step 4
  "truncate_marker_reject", // Step 5
  "warning_preamble_reject",// Step 6
] as const;

export interface OutboundSanitizeOptions {
  /** Tool name — appears in error data for forensic correlation. */
  tool: string;
  /** Optional override for the length cap (default YOUTUBE_COMMENT_MAX_BYTES).
   *  Reserved for future callers; YouTube comment-post + comment-reply both
   *  use the default. */
  maxBytes?: number;
}

/** Reason codes for outbound rejection. Mirrors the LOCKED policy_decision
 *  enum sub-set in docs/v1.16-youtube-api.md §7 (denied_outbound_sanitize_
 *  rejected is the upstream summary; this enum names the specific step). */
export type OutboundSanitizeReason =
  | "zero_width"
  | "length_exceeded"
  | "wrapper_close"
  | "truncate_marker"
  | "warning_preamble";

/** 6-step pipeline. Returns sanitized (NFC-normalized) text on success;
 *  throws MCPError("outbound_sanitize_rejected") on rejection at any step.
 *
 *  The handler's outer try/catch (which wraps the SDK call + mapGoogleError)
 *  is NOT involved for outbound rejection — outbound REJECT is a CLIENT
 *  input error, not a Google API error. Handlers route the throw through
 *  audit-write BEFORE re-raising (per design §7 audit-on-denial).
 *
 *  Error code: throws MCPError("outbound_sanitize_rejected") (-32027).
 *  Aligned with per-gate-new-code pattern (cf. -32023 / -32025 added in
 *  Phase 2a; -32024 / -32026 in Phase 1b). errorData.reason carries
 *  5-value enum discriminator (zero_width / length_exceeded / wrapper_close /
 *  truncate_marker / warning_preamble).
 */
export function outboundSanitize(text: string, opts: OutboundSanitizeOptions): string {
  // ─── Step 1: REJECT zero-width chars ──────────────────────────────────
  // Per design §9 step 1: REJECT (not strip). Silent strip would change
  // user intent (lossy transformation); rejection forces a clean retry.
  // ZERO_WIDTH_RE has `g` flag — read its `.test()` result FIRST (regex
  // statefulness — lastIndex resets per .test() call on `g` regexes is
  // implementation-defined; the SHARED `ZERO_WIDTH_RE` may carry state
  // from inbound sanitize). To be defensive, reset before test.
  ZERO_WIDTH_RE.lastIndex = 0;
  if (ZERO_WIDTH_RE.test(text)) {
    throw new MCPError("outbound_sanitize_rejected", {
      tool: opts.tool,
      reason: "zero_width" satisfies OutboundSanitizeReason,
      detail:
        "Text contains zero-width characters (U+00AD/U+200B-U+200D/U+2060/U+FEFF). " +
        "REJECT (not strip) per outbound sanitize policy — silent strip would change user intent.",
    });
  }

  // ─── Step 2: NFC normalize (confusables defense) ──────────────────────
  // Idempotent for already-normalized text. Defends against attacker
  // composing visually-identical Latin-Cyrillic homoglyph splits.
  const normalized = text.normalize("NFC");

  // ─── Step 3: Length cap ───────────────────────────────────────────────
  // Defends against attacker payload of 1 MB of ASCII. Cap is bytes-based
  // (Buffer.byteLength) so non-ASCII chars count their UTF-8 byte size.
  const maxBytes = opts.maxBytes ?? YOUTUBE_COMMENT_MAX_BYTES;
  if (Buffer.byteLength(normalized, "utf-8") > maxBytes) {
    throw new MCPError("outbound_sanitize_rejected", {
      tool: opts.tool,
      reason: "length_exceeded" satisfies OutboundSanitizeReason,
      detail: `Text exceeds ${maxBytes} bytes (YouTube comment max).`,
    });
  }

  // ─── Step 4: REJECT wrapper-close pattern ─────────────────────────────
  // Defends against attacker composing literal `</untrusted-source-NONCE>`
  // to confuse a future inbound sanitize that reads the comment back.
  // Per-call random nonce makes the defense forward-looking, not today-
  // load-bearing — see module docstring.
  if (WRAPPER_CLOSE_RE.test(normalized)) {
    throw new MCPError("outbound_sanitize_rejected", {
      tool: opts.tool,
      reason: "wrapper_close" satisfies OutboundSanitizeReason,
      detail:
        "Text contains SafeSpace inbound wrapper close-tag pattern " +
        "(`</untrusted-source-<hex>>`). Defends against confusing future inbound parse.",
    });
  }

  // ─── Step 5: REJECT TRUNCATE_MARKER literal ───────────────────────────
  // Defends against attacker composing the literal `<safespace-truncated/>`
  // marker to fake a SafeSpace-side truncation event in subsequent reads.
  if (normalized.includes(TRUNCATE_MARKER)) {
    throw new MCPError("outbound_sanitize_rejected", {
      tool: opts.tool,
      reason: "truncate_marker" satisfies OutboundSanitizeReason,
      detail: `Text contains the literal SafeSpace truncate marker (${TRUNCATE_MARKER}).`,
    });
  }

  // ─── Step 6: REJECT inbound preamble pattern ──────────────────────────
  // Defends against attacker composing the inbound warning preamble to
  // fake a SafeSpace-side wrap of attacker content.
  if (WARNING_PREAMBLE_RE.test(normalized)) {
    throw new MCPError("outbound_sanitize_rejected", {
      tool: opts.tool,
      reason: "warning_preamble" satisfies OutboundSanitizeReason,
      detail: "Text contains SafeSpace inbound warning-preamble pattern.",
    });
  }

  return normalized;
}
