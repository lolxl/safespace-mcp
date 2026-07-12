// Cross-group shared helpers — extracted verbatim from the former monolithic
// src/tools/handlers.ts (mechanical per-API split; function bodies byte-identical).
// Re-exported via ./index.ts so existing `./handlers` import paths are unchanged.

import * as crypto from "node:crypto";

import { MCPError } from "../../errors";
import type { Credential, ToolContext } from "../types";

/** v1.112.8 — stable fail-closed throw for the provider/credential guards below.
 *  Generic MCPError (never a plain Error that leaks internal detail as -32603).
 *  Does NOT echo which credential kind/provider arrived. */
function throwCredentialMismatch(): never {
  throw new MCPError("internal_routing_error", { reason: "credential_mismatch" });
}

/** v1.64 Phase B (B2 — Credential union, D3b). Base narrow: `ctx.credential` →
 *  the OAuth variant (kind only, provider-agnostic). The PROVIDER-asserting
 *  `requireGoogle` / `requireGithub` (v1.70 G2) build on this — handlers narrow
 *  via THOSE, not this, so a credential of the wrong provider can never reach a
 *  handler that would send its token to the wrong API.
 *
 *  A non-oauth credential reaching an OAuth handler is an INTERNAL routing bug
 *  (the proxy routes by `authModel`), not a user-facing condition. v1.112.8:
 *  throws `internal_routing_error{credential_mismatch}` (stable MCPError) so the
 *  client never sees a plain -32603 with internal message text. This is the R6
 *  guard: a handler can never fabricate an accountId/token for a non-oauth kind,
 *  because the only path to those values runs through this narrow. */
export function requireOAuth(
  ctx: ToolContext,
): Extract<Credential, { kind: "oauth" }> {
  if (ctx.credential.kind !== "oauth") {
    throwCredentialMismatch();
  }
  return ctx.credential;
}

/** v1.70 (G2) — narrow to the OAuth variant AND assert the google-workspace
 *  provider. THE cross-provider-token backstop (thesis R8): a github (or any
 *  non-google) credential reaching a googleapis handler throws HERE, before
 *  `.getAccessToken()` is ever read — so a GitHub bearer can never be sent to a
 *  Google API. Every google-workspace handler narrows via this (not bare
 *  `requireOAuth`). */
export function requireGoogle(
  ctx: ToolContext,
): Extract<Credential, { kind: "oauth" }> {
  const cred = requireOAuth(ctx);
  if (cred.provider !== "google") {
    throwCredentialMismatch();
  }
  return cred;
}

/** v1.70 (G2) — the github analogue of {@link requireGoogle}: narrow + assert the
 *  github provider. The github read handlers (G4) narrow via this; a google (or
 *  any non-github) credential reaching one throws before its token is read. */
export function requireGithub(
  ctx: ToolContext,
): Extract<Credential, { kind: "oauth" }> {
  const cred = requireOAuth(ctx);
  if (cred.provider !== "github") {
    throwCredentialMismatch();
  }
  return cred;
}

/** v1.78 (Notion B) — the notion analogue of {@link requireGithub}: narrow + assert
 *  the notion provider. The notion read handlers narrow via this; a google / github (or
 *  any non-notion) credential reaching one throws before its token is read (the
 *  cross-provider backstop — a Google bearer can never reach api.notion.com). */
export function requireNotion(
  ctx: ToolContext,
): Extract<Credential, { kind: "oauth" }> {
  const cred = requireOAuth(ctx);
  if (cred.provider !== "notion") {
    throwCredentialMismatch();
  }
  return cred;
}

/** v1.114 (X) — the x analogue of {@link requireNotion}: narrow + assert
 *  the x provider. The x read handlers narrow via this; a google / github / notion (or
 *  any non-x) credential reaching one throws before its token is read (the
 *  cross-provider backstop — a Google bearer can never reach api.x.com). */
export function requireX(
  ctx: ToolContext,
): Extract<Credential, { kind: "oauth" }> {
  const cred = requireOAuth(ctx);
  if (cred.provider !== "x") {
    throwCredentialMismatch();
  }
  return cred;
}

/** v1.66 Phase C PR 2 — the service-token analogue of {@link requireOAuth}. Narrow
 *  `ctx.credential` to the service-token variant for a class-B connector handler
 *  (e.g. LINE) and return it (carrying the `.token()` getter for the bearer header).
 *
 *  A service-token handler is routed through `withNonOAuthContext`, whose
 *  `source.resolveCredential` only ever produces a `service-token` credential — so
 *  any other kind reaching such a handler is an INTERNAL routing bug, not a
 *  user-facing condition. v1.112.8: throws `internal_routing_error{credential_mismatch}`
 *  (stable MCPError). This is the R6 guard for class B: a LINE handler can never
 *  fabricate / reach for an OAuth account, and an OAuth handler that mistakenly
 *  called this would throw. The token is read ONLY here, inline when building the
 *  Authorization header — never stored as a field. */
export function requireServiceToken(
  ctx: ToolContext,
): Extract<Credential, { kind: "service-token" }> {
  if (ctx.credential.kind !== "service-token") {
    throwCredentialMismatch();
  }
  return ctx.credential;
}

// Shared input-character defense (sec-rev 5.9 MED + v1.4 PR sec-rev LOW-2).
//   \r \n  - RFC 2822 header terminators (gmail_send threat)
//   \x00   - NUL truncates headers in C-based parsers
//   U+0085 - NEL, some SMTP relays normalize to LF
//   U+2028 - LINE SEPARATOR (JS engines treat as line terminator)
//   U+2029 - PARAGRAPH SEPARATOR (same)
// Module-level so the regex compiles once (5.9 code-rev HIGH). Hoisted to
// the top of the module so multiple handlers (gmail_send, gmail_create_label,
// future header-shaped inputs) share one source of truth — a future
// widening of the character class then applies to all callers instead of
// drifting silently between duplicated copies (v1.4 sec-rev LOW-2).
export const HEADER_INJECTION_RE = /[\r\n\x00\u0085\u2028\u2029]/;

/**
 * Error shape that `mapGoogleError` raises for non-typed upstream failures.
 * `httpStatus` lets `withToolContext` route 401 → force-refresh retry, 403 →
 * scope_mismatch, 429 → rate_limited, 5xx → upstream_error.
 */
export interface UpstreamError extends Error {
  httpStatus?: number;
}

// Loose RFC 5322 sanity check: one '@' with non-empty local + domain parts,
// domain has at least one dot, no whitespace. Same shape as the EMAIL_RE
// in src/auth/active.ts and src/cli.ts (intentionally duplicated rather
// than imported to keep handlers/ standalone). Plain-address only;
// "Display Name <local@domain>" not supported in v1 — matches the
// schema description ("Recipient email(s), comma-separated"). (#22)
//
// v1.14 Phase 1: exported per docs/v1.14-cross-account-search.md §10 so
// `withAllAccounts` can reuse the same character-class shape for validating
// caller-supplied `accounts?` filter entries. The anchored `^...$` + restricted
// character class implicitly rejects CR/LF/path/control chars (sec-rev hook
// 5) — future regex relaxations MUST preserve those invariants.
export const EMAIL_RECIPIENT_RE = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

/* ── helper: defense-in-depth max_results clamp ─────────────────────────
 *
 * Mirrors v1.14 `gmailSearchAll` / v1.15 `contactsSearch` patterns —
 * non-conforming MCP clients can slip NaN / Infinity past `typeof === "number"`.
 * `Math.min(NaN, CAP)` = NaN → Math.floor(NaN) = NaN → SDK 400. Force a
 * finite ≥1 value or fall back to DEFAULT. */
export function clampYoutubeMaxResults(
  raw: unknown,
  defaultMax: number,
  cap: number,
): number {
  const requested = typeof raw === "number" ? raw : defaultMax;
  const finite =
    Number.isFinite(requested) && requested >= 1 ? requested : defaultMax;
  return Math.floor(Math.min(finite, cap));
}

/** SHA-256 hex of a string. Plain SHA-256 (NOT HMAC) per design §7 —
 *  matches `args_hash` convention; the HMAC family (target_email_hash /
 *  rejected_recipient_hashes) is reserved for fields where the keyspace
 *  is small enough that dictionary attacks matter (email addresses). Video
 *  / comment IDs are large opaque keyspaces. */
export function sha256Hex(s: string): string {
  return crypto.createHash("sha256").update(s).digest("hex");
}

/** Tasks API identifier regex (design §2.2 + §2.4 + sec-rev hook #5).
 *
 *   {1,128} length cap — Google Tasks IDs observed up to ~120 chars; the 128
 *   ceiling is a snug DoS guard. Tightened from prior {1,256} ceiling per
 *   §2.4 "task_id cap tightened to match tasklist_id".
 *
 *   `[A-Za-z0-9_-]` character class — matches Google's URL-safe base64-ish
 *   alphabet (same shape as Calendar event IDs / Docs document IDs). Rejects:
 *     - path traversal (`../`, `/`)
 *     - CRLF injection (`\r\n`)
 *     - NUL bytes (`\x00`)
 *     - whitespace, control bytes, other URL-unsafe chars
 *
 *   Handler validates BEFORE the SDK so malformed input fails fast with a
 *   clear message rather than hitting Google and returning an opaque 400/404.
 */
export const TASKLIST_ID_RE = /^[A-Za-z0-9_-]{1,128}$/;
