// v1.56 F3b — tainted-source provenance (Autonomy Hardening track).
//
// docs/v1.56-f3-tainted-source-and-lure-flag.md. Closes the provenance leg of
// C2/C6/C8/C9 (social-engineering-threat-analysis.md): the sanitize pipeline
// marks an inbound read untrusted, but that taint does not PROPAGATE — an agent
// can lift an attacker-supplied email out of an <untrusted-source> block and use
// it as a gmail_send recipient, and SafeSpace sees a clean-looking egress arg
// with no memory of its origin. F3b records the email/URL tokens that appear in
// untrusted BODY content this session, and the gmail egress path flags a send
// whose recipient matches one (audit-flag only this cycle — NO deny).
//
// EXTRACTION LIVES IN THE READ HANDLERS (locked Option 1, not the generic
// sanitize walk): the dominant gmail read (gmail_get_message) returns a base64url
// body (no plaintext to extract) and {name,value} header arrays (plaintext, but
// those are the From/To we DELIBERATELY do NOT taint — Q3 body-only kills the
// reply-to-sender false-positive). So the v1 taint SOURCES are the reads that
// return a known plaintext BODY field — drive_get_file_content (`content`) +
// docs_get_content (document text). gmail_get_thread snippets + calendar
// descriptions are documented fast-follows. gmail_get_message full body
// (base64url) is NOT a source in v1 (the same blind spot every existing pattern
// flag has).
//
// SESSION-SCOPED, like the F1 burst counters: a module-level Set, reset on MCP
// restart (restart IS the recovery path), size-capped + log-on-cap so growth is
// bounded and truncation is never silent. HEURISTIC, not a proof (locked N3): an
// agent that TRANSFORMS a lifted value (de-obfuscates `a [at] b.ru`) defeats the
// exact-match — the flag is a strong signal on the common verbatim-lift case.

// Email + URL extractors. Bounded, single-pass. EMAIL deliberately conservative
// (one @, a dotted domain) to avoid over-matching; URL is http(s) only.
const EMAIL_RE = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
const URL_RE = /https?:\/\/[^\s<>"')\]]+/gi;

// Hard cap on the session set. A berserk read loop cannot grow it without bound;
// past the cap we stop adding (and log once) rather than evict, so a real
// attacker token recorded early is never silently dropped to make room for noise.
const MAX_TOKENS = 2000;

let taintedTokens: Set<string> = new Set();
let capLogged = false;

/** Normalize an email/URL token for storage + comparison. Emails + URL hosts are
 *  case-insensitive; lowercasing the whole token is conservative + collision-safe
 *  (an email never equals a URL). Trims surrounding whitespace. */
function normalizeToken(raw: string): string {
  return raw.trim().toLowerCase();
}

function addToken(raw: string): void {
  const tok = normalizeToken(raw);
  if (tok.length === 0) return;
  if (taintedTokens.has(tok)) return;
  if (taintedTokens.size >= MAX_TOKENS) {
    if (!capLogged) {
      capLogged = true;
      console.error(
        `[safespace] tainted-source set hit the ${MAX_TOKENS}-token cap; further tokens this session are not recorded (restart to reset).`,
      );
    }
    return;
  }
  taintedTokens.add(tok);
}

/** Extract email + URL tokens from ONE plaintext string and record them as
 *  tainted for this session. Safe to call on large bodies (two bounded regexes,
 *  single pass each). Use ONLY on known plaintext BODY content — never on header
 *  From/To/Cc fields (locked Q3). */
export function recordTaintedFromText(text: string): void {
  if (typeof text !== "string" || text.length === 0) return;
  const emails = text.match(EMAIL_RE);
  if (emails) for (const e of emails) addToken(e);
  const urls = text.match(URL_RE);
  if (urls) for (const u of urls) addToken(u);
}

// Bounded walk depth for recordTaintedFromValue (mirrors the sanitize MAX_DEPTH
// rationale — well beyond any realistic Docs nesting).
const MAX_WALK_DEPTH = 64;

/** Walk the string leaves of a structured read response (e.g. the Docs document
 *  resource, whose text lives in nested textRun.content leaves) and record each.
 *  Use ONLY for reads with NO header-address fields (drive/docs content) so this
 *  cannot taint a From/To address. Depth-bounded; non-throwing on cycles (it
 *  tracks visited objects) so a malformed response can never break a read. */
export function recordTaintedFromValue(value: unknown, _depth = 0, _seen?: WeakSet<object>): void {
  if (_depth > MAX_WALK_DEPTH) return;
  if (typeof value === "string") {
    recordTaintedFromText(value);
    return;
  }
  if (value === null || typeof value !== "object") return;
  const seen = _seen ?? new WeakSet<object>();
  if (seen.has(value as object)) return;
  seen.add(value as object);
  if (Array.isArray(value)) {
    for (const el of value) recordTaintedFromValue(el, _depth + 1, seen);
    return;
  }
  for (const v of Object.values(value as Record<string, unknown>)) {
    recordTaintedFromValue(v, _depth + 1, seen);
  }
}

/** True iff this recipient email first appeared inside untrusted BODY content
 *  recorded this session. Exact (normalized) match. Used by the gmail egress
 *  path to set the `tainted_source` audit flag (NON-blocking, v1.56). */
export function isTaintedRecipient(email: string): boolean {
  if (typeof email !== "string") return false;
  return taintedTokens.has(normalizeToken(email));
}

/** Diagnostic: current session token count. */
export function getTaintedCount(): number {
  return taintedTokens.size;
}

/** Test-only state reset. Gated to test env so a stray production call throws. */
export function __resetTaintedSourceForTests(): void {
  if (process.env.NODE_ENV !== "test" && process.env.BUN_ENV !== "test") {
    throw new Error("__resetTaintedSourceForTests is for tests only");
  }
  taintedTokens = new Set();
  capLogged = false;
}

/** @internal */
export const __internal = { MAX_TOKENS, MAX_WALK_DEPTH, EMAIL_RE, URL_RE };
