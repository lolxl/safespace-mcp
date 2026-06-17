// v1.60 — Google Slides (presentations). Mirrors the Docs handlers
// (slides_get ≈ docs_get_content, slides_create ≈ docs_create, slides_modify ≈
// docs_modify_structured). docs/v1.60-slides.md.

import { MCPError } from "../../errors";
import { slidesClientFromToken } from "../../google-api/client";
import { toGoogleError } from "../../google-api/errors";
import type { ToolContext } from "../types";
import { requireGoogle, HEADER_INJECTION_RE } from "./shared";

const SLIDES_PRESENTATION_ID_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const SLIDES_TITLE_MAX_BYTES = 1000;
const SLIDES_MODIFY_MAX_REQUESTS = 50;
const SLIDES_INSERT_TEXT_MAX_BYTES = 100 * 1024; // 100 KB per insertText.text
const SLIDES_REPLACE_TEXT_MAX_BYTES = 1000; // per replaceAllText text/replaceText (mirror Docs)

/* ───────── slides_get (READ) — mirror docs_get_content ───────── */
export async function slidesGet(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.presentation_id !== "string") {
    throw new Error("slides_get: 'presentation_id' must be a string");
  }
  if (!SLIDES_PRESENTATION_ID_RE.test(args.presentation_id)) {
    // Echo the RULE, not the bad value (no PII echo).
    throw new Error("slides_get: 'presentation_id' must match /^[a-zA-Z0-9_-]{1,80}$/");
  }
  try {
    const slides = slidesClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await slides.presentations.get({ presentationId: args.presentation_id });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "slides_get", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── slides_create (WRITE) — mirror docs_create ───────── */
export async function slidesCreate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.title !== "string") {
    throw new Error("slides_create: 'title' must be a string");
  }
  const rawTitle = args.title;
  const trimmed = rawTitle.trim();
  if (trimmed.length === 0) {
    throw new Error("slides_create: 'title' must be non-empty after trim");
  }
  if (HEADER_INJECTION_RE.test(rawTitle)) {
    throw new Error("slides_create: 'title' must not contain CR/LF/NUL/NEL/U+2028/U+2029");
  }
  if (Buffer.byteLength(trimmed, "utf-8") > SLIDES_TITLE_MAX_BYTES) {
    // Echo the limit, NOT the title (no full-input echo on the error path).
    throw new Error(
      `slides_create: 'title' exceeds ${SLIDES_TITLE_MAX_BYTES} bytes (defensive client-side cap)`,
    );
  }
  try {
    const slides = slidesClientFromToken(requireGoogle(ctx).getAccessToken());
    // Construct { title } explicitly — never forward a caller-supplied requestBody.
    const res = await slides.presentations.create({ requestBody: { title: trimmed } });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "slides_create", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── slides_modify (WRITE) — mirror docs_modify_structured ─────────
 *
 * POSITIVE request-type allowlist is the LOAD-BEARING gate: each requests[i]
 * MUST have exactly ONE key, and that key MUST be in the allowlist. A
 * Google-added 50th request type auto-rejects. Caller content (insertText.text,
 * replaceAllText text/replaceText) is byte-capped; structural fields pass to
 * Google verbatim (Google validates correctness).
 *
 * SECURITY — the SSRF exclusion (the one Slides-specific risk): every request
 * type that takes an external URL Google's servers FETCH with the user's identity
 * is EXCLUDED — `createImage`, `createSheetsChart`, `createVideo`, AND
 * `replaceAllShapesWithImage` / `replaceAllShapesWithSheetsChart`. Same SSRF class
 * as the Sheets IMAGE / IMPORTRANGE formula REJECT (v1.21). They are NOT in the
 * allowlist → rejected. `deleteObject` (whole-element delete, higher blast) is
 * also excluded for v1.
 */
export const SLIDES_MODIFY_ALLOWED_REQUEST_TYPES: ReadonlySet<string> = new Set([
  "insertText",
  "deleteText",
  "replaceAllText",
  "createSlide",
  "updateTextStyle",
  "updateParagraphStyle",
]);

/** Known-rejected request types — the negative-sentinel snapshot (NOT consulted
 *  at runtime; the positive allowlist is the gate). Includes the SSRF set + the
 *  high-blast set so a test can iterate-and-reject each individually. */
export const _SLIDES_MODIFY_FORBIDDEN_REQUEST_TYPES_FOR_TEST: readonly string[] = [
  // SSRF (external-URL fetch by Google's servers)
  "createImage",
  "createSheetsChart",
  "createVideo",
  // high-blast / out-of-scope for v1
  "deleteObject",
  "createShape",
  "createTable",
  "createLine",
  "insertTableRows",
  "insertTableColumns",
  "deleteTableRow",
  "deleteTableColumn",
  "updatePageElementTransform",
  "updateShapeProperties",
  "updateImageProperties",
  "updatePageProperties",
  "replaceAllShapesWithImage",
  "replaceAllShapesWithSheetsChart",
  "duplicateObject",
  "groupObjects",
  "ungroupObjects",
];

export async function slidesModify(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  if (typeof args.presentation_id !== "string") {
    throw new Error("slides_modify: 'presentation_id' must be a string");
  }
  if (!SLIDES_PRESENTATION_ID_RE.test(args.presentation_id)) {
    throw new Error("slides_modify: 'presentation_id' must match /^[a-zA-Z0-9_-]{1,80}$/");
  }
  const presentationId = args.presentation_id;

  if (!Array.isArray(args.requests)) {
    throw new Error("slides_modify: 'requests' must be an array");
  }
  if (args.requests.length === 0) {
    throw new Error("slides_modify: 'requests' array must be non-empty");
  }
  if (args.requests.length > SLIDES_MODIFY_MAX_REQUESTS) {
    throw new Error(
      `slides_modify: at most ${SLIDES_MODIFY_MAX_REQUESTS} requests per call (got ${args.requests.length})`,
    );
  }
  const requests = args.requests;

  for (let i = 0; i < requests.length; i++) {
    const req = requests[i];
    if (typeof req !== "object" || req === null || Array.isArray(req)) {
      throw new Error(`slides_modify: requests[${i}] must be an object`);
    }
    const keys = Object.keys(req as Record<string, unknown>);
    if (keys.length !== 1) {
      throw new Error(`slides_modify: requests[${i}] must have exactly ONE key (got ${keys.length})`);
    }
    const requestType = keys[0]!;
    if (!SLIDES_MODIFY_ALLOWED_REQUEST_TYPES.has(requestType)) {
      // Echo the request TYPE (Google API surface, not user data) + the allowlist.
      throw new Error(
        `slides_modify: requests[${i}] type '${requestType}' not in allowlist {insertText, deleteText, replaceAllText, createSlide, updateTextStyle, updateParagraphStyle}`,
      );
    }
    const body = (req as Record<string, unknown>)[requestType] as
      | Record<string, unknown>
      | undefined;
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      throw new Error(`slides_modify: requests[${i}].${requestType} must be an object`);
    }
    // Per-type content byte caps (anti-DoS). Structural fields pass to Google.
    // (deleteText / createSlide / updateTextStyle / updateParagraphStyle carry
    // only ranges / ids / style objects — integers + enums, no freeform text —
    // so they need no content cap; Google validates their structural shape.)
    if (requestType === "insertText") {
      if (typeof body.text !== "string") {
        throw new Error(`slides_modify: requests[${i}].insertText.text must be a string`);
      }
      if (body.text.length === 0) {
        throw new Error(`slides_modify: requests[${i}].insertText.text must be non-empty`);
      }
      if (Buffer.byteLength(body.text, "utf-8") > SLIDES_INSERT_TEXT_MAX_BYTES) {
        throw new Error(`slides_modify: requests[${i}].insertText.text exceeds ${SLIDES_INSERT_TEXT_MAX_BYTES} bytes`);
      }
    } else if (requestType === "replaceAllText") {
      const replaceText = body.replaceText;
      if (typeof replaceText !== "string") {
        throw new Error(`slides_modify: requests[${i}].replaceAllText.replaceText must be a string`);
      }
      if (Buffer.byteLength(replaceText, "utf-8") > SLIDES_REPLACE_TEXT_MAX_BYTES) {
        throw new Error(`slides_modify: requests[${i}].replaceAllText.replaceText exceeds ${SLIDES_REPLACE_TEXT_MAX_BYTES} bytes`);
      }
      // containsText (the find-string) — gate its shape before reading .text
      // (mirror docs_modify_structured: a non-object / array / non-string text
      // is an explicit reject, not a silent skip).
      if (body.containsText !== undefined) {
        const containsText = body.containsText;
        if (typeof containsText !== "object" || containsText === null || Array.isArray(containsText)) {
          throw new Error(`slides_modify: requests[${i}].replaceAllText.containsText must be an object`);
        }
        const findText = (containsText as Record<string, unknown>).text;
        if (findText !== undefined) {
          if (typeof findText !== "string") {
            throw new Error(`slides_modify: requests[${i}].replaceAllText.containsText.text must be a string`);
          }
          if (Buffer.byteLength(findText, "utf-8") > SLIDES_REPLACE_TEXT_MAX_BYTES) {
            throw new Error(`slides_modify: requests[${i}].replaceAllText.containsText.text exceeds ${SLIDES_REPLACE_TEXT_MAX_BYTES} bytes`);
          }
        }
      }
    }
  }

  try {
    const slides = slidesClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await slides.presentations.batchUpdate({
      presentationId,
      requestBody: { requests: requests as object[] },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "slides_modify", email: requireGoogle(ctx).accountId });
  }
}
