// Docs — extracted verbatim from the former monolithic
// src/tools/handlers.ts (mechanical per-API split; function bodies byte-identical).
// Re-exported via ./index.ts so existing `./handlers` import paths are unchanged.

import { MCPError } from "../../errors";
import { recordTaintedFromValue } from "../../policy/tainted-source";
import { docsClientFromToken } from "../../google-api/client";
import { toGoogleError } from "../../google-api/errors";
import type { ToolContext } from "../types";

import { requireGoogle, HEADER_INJECTION_RE, sha256Hex } from "./shared";

/* ───────── v1.12 Phase 1b: docs_get_content (READ tool) ─────────
 *
 * Returns the full Document resource from `documents.documents.get` verbatim
 * — mirrors `gmail_get_message`'s "full tree, structured response" pattern.
 * Claude navigates the structure itself (paragraphs, tables, comments,
 * headings); no proxy-side simplification.
 *
 * Sanitize coverage:
 *   - withToolContext wraps the response through `sanitize`, which walks the
 *     Docs tree and wraps every user-visible string leaf (textRun.content,
 *     title, comment text, etc.) in <untrusted-source-NONCE>.
 *   - SKIP_FIELDS (v1.12 additions: objectId / revisionId / inheritedNamedStyleType
 *     — see src/sanitize/patterns.ts) pass through unwrapped so Claude can
 *     keep using them as opaque references.
 *   - MAX_DEPTH bumped to 64 (from 32) in v1.12 to accommodate Docs nesting;
 *     4-deep nested tables reach depth ~36. See sanitize/index.ts comment.
 *
 * `includeTabsContent` decision: NOT exposed in v1.12 — caller gets the
 * pre-tabs response shape (content under `body`, no `tabs[]` array). Adding
 * an explicit `include_tabs` parameter is deferred to Phase 2 if measured
 * demand arises. See docs/v1.12-docs-api.md §3.
 */
export async function docsGetContent(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const documentId = typeof args.document_id === "string" ? args.document_id : "";
  if (!documentId) {
    throw new Error("docs_get_content requires a non-empty 'document_id' string");
  }
  // Google Docs document IDs share the same character class as Drive file
  // IDs: url-safe base64 with `-` / `_`, typically 30–60+ chars. Reject IDs
  // with whitespace / control chars / illegal URL characters at the handler
  // boundary so a malformed input fails fast with a clear message rather
  // than hitting Google and returning an opaque 400/404.
  if (!/^[A-Za-z0-9_-]+$/.test(documentId)) {
    throw new Error(
      "docs_get_content: 'document_id' must be url-safe (letters / digits / `-` / `_`)",
    );
  }

  try {
    const docs = docsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await docs.documents.get({ documentId });
    // v1.56 F3b — walk the (untrusted) document's text leaves (body text lives in
    // nested textRun.content) and record email/URL tokens as tainted-source. A
    // Google Doc has no header-address fields, so walking all string leaves
    // cannot taint a From/To (honors the locked body-only scope, Q3).
    // Observability only; the read result is returned unchanged.
    recordTaintedFromValue(res.data);
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "docs_get_content", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.12 Phase 1b: docs_create (WRITE tool) ─────────
 *
 * Creates a new empty Google Doc with the given title. Returns the Document
 * resource from `documents.documents.create` (includes `documentId` + `title`
 * + initial body skeleton).
 *
 * Validation order mirrors gmailCreateLabel (v1.4 code-rev MINOR):
 *   1. Type gate — `title` must be string.
 *   2. Trim + non-empty gate — leading/trailing whitespace stripped before
 *      send; trimmed title must be non-empty.
 *   3. HEADER_INJECTION_RE rejection on the RAW (pre-trim) title (CR/LF/
 *      NUL/NEL/U+2028/U+2029). Same regex as gmail_send + gmail_create_label.
 *      The title flows into the Docs API JSON body, not into an RFC 2822
 *      header, so header-line injection isn't the literal threat — but
 *      rejecting these characters in any user-controlled identifier-shaped
 *      field keeps the project's invariant consistent and prevents
 *      prompt-injected newlines from rendering badly in Docs / Drive UIs.
 *   4. Byte-length cap — ≤ 1000 UTF-8 bytes after trim. Defensive
 *      client-side cap; Google Docs API does NOT publish a documented title
 *      byte limit (it accepts very long titles), so the 1000-byte cap is
 *      SafeSpace's own anti-prompt-injection blast-radius guard, mirroring
 *      gmail_create_label's 225-byte cap rationale.
 *
 * NO idempotency check — unlike gmail_create_label which de-dupes by name
 * against the existing label list, Docs has no name-collision semantics:
 * Google happily creates multiple documents with identical titles, and the
 * documentId is the only identity. Prompt-injection blast-radius is bounded
 * by the title byte cap + tier gating + Claude Code's per-call confirm UI.
 *
 * SECURITY (PR #105 sec-rev H2): the googleapis SDK type for
 * `documents.create({ requestBody: Schema$Document })` accepts the FULL
 * `Schema$Document` shape (server-side ignores output-only fields, but the
 * SDK doesn't enforce). Handler MUST explicitly construct `{ requestBody:
 * { title } }` — NEVER pass-through user-supplied requestBody. Tests assert
 * the SDK call's `requestBody` contains EXACTLY `{title}` and nothing else
 * (sentinel regression guard).
 */
const DOCS_TITLE_MAX_BYTES = 1000;

export async function docsCreate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.title !== "string") {
    throw new Error("docs_create: 'title' must be a string");
  }
  const rawTitle = args.title;
  const trimmed = rawTitle.trim();
  if (trimmed.length === 0) {
    throw new Error("docs_create: 'title' must be non-empty after trim");
  }
  if (HEADER_INJECTION_RE.test(rawTitle)) {
    throw new Error(
      "docs_create: 'title' must not contain CR/LF/NUL/NEL/U+2028/U+2029",
    );
  }
  if (Buffer.byteLength(trimmed, "utf-8") > DOCS_TITLE_MAX_BYTES) {
    // 1000 bytes is SafeSpace's defensive cap (not API-enforced). Echo the
    // limit but NOT the title — sec-rev §7 hook #7 (cross-PR L1 echo): error
    // paths must not reflect the full user-supplied title back to the caller.
    throw new Error(
      `docs_create: 'title' exceeds ${DOCS_TITLE_MAX_BYTES} bytes (defensive client-side cap; Google Docs API itself does not publish a documented title limit)`,
    );
  }

  try {
    const docs = docsClientFromToken(requireGoogle(ctx).getAccessToken());
    // SECURITY (PR #105 sec-rev H2): construct { title } explicitly — never
    // forward user-supplied requestBody. The SDK type accepts full
    // Schema$Document; server ignores extras, but constructing minimally
    // bounds the blast surface even if the SDK contract drifts.
    const res = await docs.documents.create({
      requestBody: { title: trimmed },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "docs_create", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.12 Phase 2: docs_append_text (limited WRITE tool) ─────────
 *
 * Appends plain text to the END of an existing Google Doc body. Append-only —
 * the caller CANNOT delete or modify existing content via this tool. Uses a
 * single `insertText` request with `endOfSegmentLocation { segmentId: "" }`,
 * which resolves to the doc body end without requiring a pre-flight
 * `documents.get` round-trip.
 *
 * Validation order:
 *   1. document_id type + non-empty + url-safe regex (mirrors docsGetContent)
 *   2. text type + non-empty
 *   3. text byte-cap — ≤ 100 KB UTF-8. SafeSpace defensive client-side cap;
 *      the Docs API itself accepts much larger payloads. Bounds prompt-
 *      injection blast radius for batched-append abuse, mirroring docs_create
 *      title cap + gmail_create_label name cap rationale.
 *
 * INTENTIONAL omission: HEADER_INJECTION_RE is NOT applied to `text`. The
 * value becomes Docs body content (not an HTTP / RFC 2822 header), and
 * CR/LF/etc. are LEGITIMATE in body text (line breaks are user-meaningful).
 * The sanitize-on-read pipeline already wraps ALL Docs textRun.content as
 * untrusted via SKIP_FIELDS + per-textRun wrap (see sanitize/patterns.ts),
 * so future `docs_get_content` calls against the appended text remain safe.
 *
 * SECURITY (mirrors PR #105 / PR #109 sec-rev H2): the googleapis SDK type
 * for `documents.batchUpdate({ requestBody: Schema$BatchUpdateDocumentRequest })`
 * accepts an arbitrary `requests[]` array of Schema$Request union members.
 * Handler MUST explicitly construct `{ requests: [{ insertText: { ... } }] }`
 * — NEVER pass-through user-supplied requests. Tests assert the SDK call's
 * `requestBody` contains EXACTLY `{requests}` with `requests.length === 1`
 * and `Object.keys(requests[0])` EXACTLY equals `["insertText"]`. Any future
 * "accept extra requests" refactor that smuggles deleteContentRange /
 * replaceAllText / updateTextStyle into the batch would trip the sentinel.
 */
const DOCS_APPEND_TEXT_MAX_BYTES = 100 * 1024;

export async function docsAppendText(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  const documentId = typeof args.document_id === "string" ? args.document_id : "";
  if (!documentId) {
    throw new Error("docs_append_text requires a non-empty 'document_id' string");
  }
  // Same character-class gate as docs_get_content — url-safe base64
  // (letters/digits/`-`/`_`). Fails fast on whitespace / control bytes /
  // URL-unsafe characters rather than waiting for a Google 400/404.
  if (!/^[A-Za-z0-9_-]+$/.test(documentId)) {
    throw new Error(
      "docs_append_text: 'document_id' must be url-safe (letters / digits / `-` / `_`)",
    );
  }

  if (typeof args.text !== "string") {
    throw new Error("docs_append_text: 'text' must be a string");
  }
  const text = args.text;
  if (text.length === 0) {
    throw new Error("docs_append_text: 'text' must be non-empty");
  }
  // NOTE: HEADER_INJECTION_RE is INTENTIONALLY NOT applied here. See the
  // module doc-comment above — body text legitimately contains CR/LF as
  // user-meaningful line breaks. Threat model differs from header-shaped
  // fields (gmail_send, gmail_create_label, docs_create title).
  const byteLen = Buffer.byteLength(text, "utf-8");
  if (byteLen > DOCS_APPEND_TEXT_MAX_BYTES) {
    // Echo the limit + actual byte count, but NOT the text itself
    // (sec-rev §7 hook #7: error paths must not reflect user-supplied
    // content back to the caller).
    throw new Error(
      `docs_append_text: 'text' exceeds ${DOCS_APPEND_TEXT_MAX_BYTES} bytes (defensive client-side cap; got ${byteLen} bytes)`,
    );
  }

  try {
    const docs = docsClientFromToken(requireGoogle(ctx).getAccessToken());
    // SECURITY (PR #105 / PR #109 sec-rev H2): explicitly construct the
    // single-element requests array. Never spread or pass-through user-
    // supplied requests. `endOfSegmentLocation { segmentId: "" }` targets
    // the main document body (per Docs API: empty segmentId = body, named
    // segments are headers/footers/footnotes and are intentionally NOT
    // exposed to this tool).
    await docs.documents.batchUpdate({
      documentId,
      requestBody: {
        requests: [
          {
            insertText: {
              endOfSegmentLocation: { segmentId: "" },
              text,
            },
          },
        ],
      },
    });
    return {
      documentId,
      // `appended_chars` is JS string length (UTF-16 code units, but here
      // also useful as "approximate character count" for the caller).
      // `appended_bytes` is the UTF-8 byte count actually sent.
      appended_chars: text.length,
      appended_bytes: byteLen,
    };
  } catch (err) {
    throw toGoogleError(err, { tool: "docs_append_text", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.17 Phase 2: docs_modify_structured (WRITE tool) ─────────
 *
 * Apply structured modifications to a Google Doc via `documents.batchUpdate`.
 * Per design `docs/v1.17-deferred-completion.md` §2.4 — ships a SLIM 7-type
 * positive allowlist (insertText / deleteContentRange / updateTextStyle /
 * replaceAllText / updateParagraphStyle / createParagraphBullets /
 * deleteParagraphBullets); 26+ Google API request types REJECTED at handler
 * boundary (createNamedRange / insertTable / insertInlineImage / header-
 * footer ops / page breaks / etc.).
 *
 * Design contract (locked per §10 Q2 + §2.4 + §8 hook #3):
 *   - POSITIVE allowlist is the LOAD-BEARING gate. Google adding a 27th
 *     request type tomorrow does NOT compromise the gate.
 *   - NEGATIVE 26+ list is a SNAPSHOT regression sentinel for the
 *     currently-known Google API surface (visibility for future
 *     contributors when Google's API expands).
 *   - Caller-supplied request ORDER is preserved verbatim — Google applies
 *     in order, range indices SHIFT between requests, caller is responsible
 *     for correct sequencing.
 *   - `replaceAllText.containsText.matchCase` flag is PASS-THROUGH per §2.4
 *     + design F17 — search semantics, not a smuggle vector.
 *   - Sub-fields of allowed request types are NOT allowlisted by SafeSpace
 *     (Google's API rejects malformed values); only request TYPE gated.
 *   - `replaceAllText.occurrencesChanged` summed across batch → audit
 *     `total_text_replacements` per hook #12 (forensic "did Claude rewrite
 *     the whole doc?" answerable from audit alone; no hard cap — audit
 *     visibility IS the defense).
 *   - Hard cap on requests array length: 50 (anti-DoS; same blast-radius
 *     posture as gmail_modify_messages_batch).
 *
 * Sec-rev hooks ADDRESSED (per design §8):
 *   #3   docs_modify_structured per-request-type allowlist — POSITIVE
 *        ALLOWED_REQUEST_TYPES Set is the gate; NEGATIVE 27-type list
 *        tested individually as snapshot regression sentinel
 *   #7   Audit-on-denial — tier-denial path records meta BEFORE throw so
 *        forensic row carries target_document_id_hash + denied_tier
 *   #8   No PII echo — errors reference RULE/INDEX not user-supplied value
 *   #11  Opaque-ID path-segment validation — DOCS_DOCUMENT_ID_RE rejects
 *        path-traversal / CRLF / NUL / wrong-charset / length-DoS pre-SDK
 *   #12  replaceAllText blast-radius audit — total_text_replacements summed
 *        from Google's replies[i].replaceAllText.occurrencesChanged after
 *        SDK success; pre-SDK call carries no replacements count yet
 *
 * Hooks #1 (sendUpdates calendar) / #2 (calendar attendee) / #4 (youtube
 * recovery-bypass) / #5 (delete blast radius) / #6 (contact-lookup) /
 * #9 (calendar non-self deep-equality) / #10 (write-tier delete) /
 * #13 (commentDeleteMeta discriminator) DO NOT APPLY to Phase 2 (Phase 1
 * Calendar / Phase 3 YouTube territory).
 */
const DOCS_DOCUMENT_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const DOCS_MODIFY_MAX_REQUESTS = 50;
const DOCS_MODIFY_INSERT_TEXT_MAX_BYTES = 100 * 1024;
const DOCS_MODIFY_REPLACE_TEXT_MAX_BYTES = 1000;

/**
 * Phase 2 ALLOWED request types — 7 verbatim per design §10 Q2 LOCKED.
 * POSITIVE closed set is the load-bearing gate (hook #3): caller's
 * `requests[i]` MUST have exactly 1 key, and that key MUST be in this Set.
 * Google adding a 27th request type tomorrow → handler auto-rejects
 * (would not match the Set).
 */
const DOCS_MODIFY_ALLOWED_REQUEST_TYPES: ReadonlySet<string> = new Set([
  "insertText",
  "deleteContentRange",
  "updateTextStyle",
  "replaceAllText",
  "updateParagraphStyle",
  "createParagraphBullets",
  "deleteParagraphBullets",
]);

/**
 * 27 currently-known Google `documents.batchUpdate` request types REJECTED
 * by the positive allowlist above. NEGATIVE list exported via _test export
 * so the test file can iterate-and-reject each one individually (snapshot
 * regression sentinel per design §8 hook #3 — gives future contributors
 * visibility into what was previously rejected when Google's API expands).
 * Order matches §2.4 carry-forward list.
 */
const DOCS_MODIFY_FORBIDDEN_REQUEST_TYPES_FOR_NEGATIVE_SENTINEL_TEST: readonly string[] = [
  "insertTable",
  "insertTableRow",
  "insertTableColumn",
  "deleteTable",
  "deleteTableRow",
  "deleteTableColumn",
  "updateTableColumnProperties",
  "updateTableRowStyle",
  "updateTableCellStyle",
  "mergeTableCells",
  "unmergeTableCells",
  "insertInlineImage",
  "insertPageBreak",
  "insertSectionBreak",
  "createHeader",
  "createFooter",
  "deleteHeader",
  "deleteFooter",
  "createNamedRange",
  "deleteNamedRange",
  "updateDocumentStyle",
  "updateSectionStyle",
  "createFootnote",
  "replaceImage",
  "updateImageProperties",
  "insertPositionedImage",
  "pinTableHeaderRows",
];

/** Test-only re-export of the positive allowlist Set + negative sentinel
 *  list. NOT part of the runtime API surface — pure test introspection. */
export const _DOCS_MODIFY_ALLOWED_REQUEST_TYPES_FOR_TEST: ReadonlySet<string> =
  DOCS_MODIFY_ALLOWED_REQUEST_TYPES;
export const _DOCS_MODIFY_FORBIDDEN_REQUEST_TYPES_FOR_TEST: readonly string[] =
  DOCS_MODIFY_FORBIDDEN_REQUEST_TYPES_FOR_NEGATIVE_SENTINEL_TEST;

export async function docsModifyStructured(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. document_id (hook #11 path-segment validation) ──────────────
  if (typeof args.document_id !== "string") {
    throw new Error("docs_modify_structured: 'document_id' must be a string");
  }
  if (!DOCS_DOCUMENT_ID_RE.test(args.document_id)) {
    // Echo the RULE, NOT the bad value (hook #8 — no PII echo).
    throw new Error(
      "docs_modify_structured: 'document_id' must match /^[a-zA-Z0-9_-]{1,80}$/",
    );
  }
  const documentId = args.document_id;

  // ─── 2. requests array shape ────────────────────────────────────────
  if (!Array.isArray(args.requests)) {
    throw new Error("docs_modify_structured: 'requests' must be an array");
  }
  if (args.requests.length === 0) {
    throw new Error(
      "docs_modify_structured: 'requests' array must be non-empty",
    );
  }
  if (args.requests.length > DOCS_MODIFY_MAX_REQUESTS) {
    throw new Error(
      `docs_modify_structured: at most ${DOCS_MODIFY_MAX_REQUESTS} requests per call (got ${args.requests.length})`,
    );
  }
  const requests = args.requests;

  // ─── 3. Per-request shape + positive allowlist (hook #3) ────────────
  // Positive ALLOWED set is the LOAD-BEARING gate (design §8 hook #3) —
  // each request MUST have exactly 1 key, and that key MUST be in the
  // 7-type allowlist. Unknown request types (e.g., Google adds a 27th)
  // auto-reject. Negative 27-type list is a snapshot regression sentinel
  // tested individually but NOT consulted at runtime — the gate is positive.
  //
  // Per-request sub-field validation (insertText.text byte cap,
  // replaceAllText text/replaceText cap, deleteContentRange.range shape)
  // is enforced inline after the key check — caller-supplied content gets
  // bounded; structural malformation (bad fields / wrong types / out-of-
  // bounds indices) is left to Google's 400 per design §2.4.
  const requestTypes: string[] = [];
  for (let i = 0; i < requests.length; i++) {
    const req = requests[i];
    if (typeof req !== "object" || req === null || Array.isArray(req)) {
      throw new Error(
        `docs_modify_structured: requests[${i}] must be an object`,
      );
    }
    const keys = Object.keys(req as Record<string, unknown>);
    if (keys.length !== 1) {
      // Multi-key (e.g., {insertText, deleteContentRange} in one request)
      // OR zero-key ({}) — both rejected. Google API spec is "exactly one
      // request type per request" (oneof discriminator); SafeSpace mirrors
      // the constraint at the boundary so a malformed batch fails fast.
      throw new Error(
        `docs_modify_structured: requests[${i}] must have exactly ONE key (got ${keys.length})`,
      );
    }
    const requestType = keys[0]!;
    if (!DOCS_MODIFY_ALLOWED_REQUEST_TYPES.has(requestType)) {
      // Echo the request TYPE (closed-enum, not user content) + the
      // allowlist for caller actionability. No PII echo (hook #8) — request
      // type names are Google API surface, not user data.
      throw new Error(
        `docs_modify_structured: requests[${i}] type '${requestType}' not in allowlist {insertText, deleteContentRange, updateTextStyle, replaceAllText, updateParagraphStyle, createParagraphBullets, deleteParagraphBullets}`,
      );
    }
    requestTypes.push(requestType);

    // ─── 3a. Per-allowed-type sub-field validation (anti-DoS bounds) ──
    // Only enforces SafeSpace-side caps (insertText.text 100KB,
    // replaceAllText text/replaceText 1KB each, deleteContentRange.range
    // structural shape). All other sub-fields (location, range shape on
    // non-delete types, textStyle, fields field-masks, bulletPreset) pass
    // through verbatim — Google validates structural correctness.
    const body = (req as Record<string, unknown>)[requestType] as
      | Record<string, unknown>
      | undefined;
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      throw new Error(
        `docs_modify_structured: requests[${i}].${requestType} must be an object`,
      );
    }
    if (requestType === "insertText") {
      const text = body.text;
      if (typeof text !== "string") {
        throw new Error(
          `docs_modify_structured: requests[${i}].insertText.text must be a string`,
        );
      }
      if (text.length === 0) {
        throw new Error(
          `docs_modify_structured: requests[${i}].insertText.text must be non-empty`,
        );
      }
      const byteLen = Buffer.byteLength(text, "utf-8");
      if (byteLen > DOCS_MODIFY_INSERT_TEXT_MAX_BYTES) {
        throw new Error(
          `docs_modify_structured: requests[${i}].insertText.text exceeds ${DOCS_MODIFY_INSERT_TEXT_MAX_BYTES} bytes (got ${byteLen} bytes)`,
        );
      }
    } else if (requestType === "replaceAllText") {
      const containsText = body.containsText as
        | Record<string, unknown>
        | undefined;
      if (
        typeof containsText !== "object" ||
        containsText === null ||
        Array.isArray(containsText)
      ) {
        throw new Error(
          `docs_modify_structured: requests[${i}].replaceAllText.containsText must be an object`,
        );
      }
      const searchText = containsText.text;
      if (typeof searchText !== "string") {
        throw new Error(
          `docs_modify_structured: requests[${i}].replaceAllText.containsText.text must be a string`,
        );
      }
      if (
        Buffer.byteLength(searchText, "utf-8") >
        DOCS_MODIFY_REPLACE_TEXT_MAX_BYTES
      ) {
        throw new Error(
          `docs_modify_structured: requests[${i}].replaceAllText.containsText.text exceeds ${DOCS_MODIFY_REPLACE_TEXT_MAX_BYTES} bytes`,
        );
      }
      // matchCase is PASS-THROUGH per design §2.4 + F17 — NOT validated /
      // stripped / overridden. Search-semantics flag, not a smuggle vector.
      const replaceText = body.replaceText;
      if (typeof replaceText !== "string") {
        throw new Error(
          `docs_modify_structured: requests[${i}].replaceAllText.replaceText must be a string`,
        );
      }
      if (
        Buffer.byteLength(replaceText, "utf-8") >
        DOCS_MODIFY_REPLACE_TEXT_MAX_BYTES
      ) {
        throw new Error(
          `docs_modify_structured: requests[${i}].replaceAllText.replaceText exceeds ${DOCS_MODIFY_REPLACE_TEXT_MAX_BYTES} bytes`,
        );
      }
    } else if (requestType === "deleteContentRange") {
      const range = body.range as Record<string, unknown> | undefined;
      if (typeof range !== "object" || range === null || Array.isArray(range)) {
        throw new Error(
          `docs_modify_structured: requests[${i}].deleteContentRange.range must be an object`,
        );
      }
      if (
        typeof range.startIndex !== "number" ||
        typeof range.endIndex !== "number"
      ) {
        throw new Error(
          `docs_modify_structured: requests[${i}].deleteContentRange.range must have numeric startIndex + endIndex`,
        );
      }
      if (range.endIndex <= range.startIndex) {
        throw new Error(
          `docs_modify_structured: requests[${i}].deleteContentRange.range endIndex must be > startIndex`,
        );
      }
    }
    // updateTextStyle / updateParagraphStyle / createParagraphBullets /
    // deleteParagraphBullets: caller's sub-fields pass through verbatim.
    // Google's API validates structural correctness (e.g., fields field-mask
    // syntax, valid bulletPreset enum value). SafeSpace's gate is the
    // request-TYPE allowlist; sub-field correctness is Google's territory
    // per design §2.4 (KEEP MINIMAL Phase 2).
  }

  // ─── 4. Build CALLER-SUPPLIED-ORDER request_types_csv (design §5 F15) ─
  // CSV preserves caller-supplied request ORDER (NOT sorted) — forensically
  // relevant per design §5: "did replaceAllText run before or after
  // deleteContentRange?" affects what was mutated. Duplicate types
  // preserved (caller may legitimately have N occurrences of same type).
  const requestTypesCsv = requestTypes.join(",");
  const documentIdHash = sha256Hex(documentId);

  // ─── 5. Tier check (defense-in-depth) — audit BEFORE throw (hook #7) ──
  // Tier check sits BEFORE the SDK call but AFTER all input-shape
  // validation (cheap caller-bug rejections happen first; tier-denied
  // forensic row carries the ATTEMPTED operation's full meta —
  // target_document_id_hash + modification_count + request_types_csv —
  // so a log reader can see exactly what Claude tried to do).
  // total_text_replacements is NOT set on tier-denial rows (SDK never
  // ran; no Google reply to sum). ABSENCE is meaningful per design §5.
  if (ctx.tier === "read") {
    ctx.audit.record("docsModifyMeta", {
      target_document_id_hash: documentIdHash,
      modification_count: requests.length,
      request_types_csv: requestTypesCsv,
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "docs_modify_structured",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 6. Record allow-meta BEFORE SDK call (hook #7 / hook #12) ──────
  // Pre-SDK record carries everything EXCEPT total_text_replacements
  // (no reply yet). If the SDK call fails (5xx, network timeout), the
  // audit row STILL has target_document_id_hash + modification_count +
  // request_types_csv + policy_decision: "allowed" — forensically signals
  // "Claude attempted these N requests against doc X" even on failure.
  // Post-SDK record (step 8) overwrites with the same meta PLUS
  // total_text_replacements (last-write-wins per with-context.ts capture).
  ctx.audit.record("docsModifyMeta", {
    target_document_id_hash: documentIdHash,
    modification_count: requests.length,
    request_types_csv: requestTypesCsv,
    policy_decision: "allowed",
  });

  // ─── 7. SDK call — caller's requests pass through verbatim (in order) ─
  // SECURITY (mirrors PR #105 / PR #109 / PR #110 sec-rev H2): the
  // requestBody is constructed LITERALLY with only `{requests}`. The
  // requests array contents pass through verbatim BUT each request has
  // already been gated by the per-type positive allowlist (step 3) +
  // sub-field caps (step 3a). Google's `documents.batchUpdate` applies
  // requests in array order — caller controls ordering, handler does NOT
  // reorder / dedupe / merge per design §2.4 "Request order semantics".
  try {
    const docs = docsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await docs.documents.batchUpdate({
      documentId,
      requestBody: { requests },
    });

    // ─── 8. Post-SDK: compute total_text_replacements + re-record ─────
    // Per design §2.4 + hook #12: sum `replies[i].replaceAllText.
    // occurrencesChanged` across the batch. Field is conditionally absent
    // on non-replaceAllText replies (Google returns the field only for the
    // request type that produced it). Sum captures forensic "did Claude
    // rewrite the whole doc?" — answerable from audit alone, no hard cap.
    let totalTextReplacements = 0;
    let sawReplaceAllText = false;
    const replies = Array.isArray(res.data.replies) ? res.data.replies : [];
    for (const reply of replies) {
      const rar = reply?.replaceAllText as
        | { occurrencesChanged?: number }
        | undefined;
      if (rar && typeof rar.occurrencesChanged === "number") {
        totalTextReplacements += rar.occurrencesChanged;
        sawReplaceAllText = true;
      }
    }
    // Re-record meta WITH total_text_replacements only when at least one
    // replaceAllText reply was observed — ABSENCE of the field on rows
    // without replaceAllText is forensically meaningful per design §5
    // ("no replaceAllText was executed" vs "executed and changed N
    // occurrences"). Pre-SDK meta from step 6 stays in place if no
    // replaceAllText was in the batch (its policy_decision="allowed" is
    // still the correct final state).
    if (sawReplaceAllText) {
      ctx.audit.record("docsModifyMeta", {
        target_document_id_hash: documentIdHash,
        modification_count: requests.length,
        request_types_csv: requestTypesCsv,
        total_text_replacements: totalTextReplacements,
        policy_decision: "allowed",
      });
    }

    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "docs_modify_structured", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.13 Phase 1b: calendar_list_events + calendar_get_event (READ tools) ─────────
 *
 * Read-tier Google Calendar API tools. See docs/v1.13-calendar-api.md §3.
 * Phase 1 mirrors the gmail_get_message / drive_search / docs_get_content
 * pattern — handler is a thin shim over the SDK; sanitize + error mapping
 * happen at the middleware layer.
 *
 * Sec-rev hooks applied (per design §7):
 *   #1  MAX_DEPTH=64 sufficient — Calendar events are SHALLOW (deepest realistic
 *       leaf: ~8 for conferenceData.entryPoints[].uri). No depth bump needed.
 *   #2  SKIP_FIELDS additions handled in src/sanitize/patterns.ts — 8 keys
 *       (iCalUID / htmlLink / hangoutLink / recurringEventId + 4 closed enums:
 *       status / transparency / visibility / eventType). `etag` was already
 *       listed for the cross-API set.
 *   #7  Input validation handled at the JSON-Schema layer + handler boundary
 *       (calendar_id format check; event_id non-empty for `get`).
 *   #8  No recipient-allowlist gate on read paths — read tools do not send
 *       outbound email; allowlist applies only to Phase 2 write paths.
 *   #9  Calendar ID format — accept "primary" literal OR email-shape value.
 *       Google secondary calendars are `c_xxxxx@group.calendar.google.com`,
 *       so the email-shape regex naturally covers them. Reject anything else
 *       (whitespace / control bytes / illegal URL chars) at the handler
 *       boundary so malformed input fails fast with a clear message.
 *   #11 Cross-PR L1 echo: error paths route through `toGoogleError` which
 *       does NOT reflect user-supplied event content (summary/description)
 *       back to the caller. Same shape as existing tools.
 *   #12 OAuth scope downgrade safety: if `calendar.events` is revoked but
 *       Gmail/Drive remain, the pre-check (`with-context.ts`) throws
 *       `scope_mismatch` BEFORE the SDK call — other tools unaffected.
 *
 * Hooks #3, #4, #5, #6, #10, #13 apply to Phase 2 (`calendar_create_event`)
 * write-tier territory — see `calendarCreateEvent` handler below.
 */

