// Slides tool definitions (v1.60). Mirror the Docs ToolDefs. Assembled by ./index.ts.

import type { ToolDef } from "./types";
import * as handlers from "../handlers";
import { PRESENTATIONS } from "./scopes";

export const slidesTools: Record<string, ToolDef> = {
  slides_get: {
    name: "slides_get",
    description:
      "Get the full structured content of a Google Slides presentation (READ OPERATION; presentations.get). Returns the raw `Presentation` resource — slides[], each with pageElements (shapes / text boxes / tables / images), the slide layout/master, presentationId, title, and page size. Use for the deck structure, slide text, and element ids (needed to target slides_modify edits). User-visible text (textRun.content, title) is sanitize-wrapped; Google opaque ids (objectId, presentationId, revisionId) pass through unwrapped. presentation_id MUST match /^[a-zA-Z0-9_-]{1,80}$/ (validated handler-side).",
    inputSchema: {
      type: "object",
      properties: {
        presentation_id: {
          type: "string",
          description:
            "Google Slides presentation ID (url-safe; the id segment from the presentation URL, NOT the full URL).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["presentation_id"],
      additionalProperties: false,
    },
    requiredScopes: [PRESENTATIONS],
    handler: handlers.slidesGet,
    min_tier: "read",
  },
  slides_create: {
    name: "slides_create",
    description:
      "Create a new (empty) Google Slides presentation with the given title (WRITE OPERATION; presentations.create). Returns the new Presentation resource (presentationId + title + the default first slide). title is type-checked + trimmed (must be non-empty), rejected for CR/LF/NUL/NEL/U+2028/U+2029 (HEADER_INJECTION_RE), and capped at 1000 UTF-8 bytes (defensive client-side cap). NO idempotency check (Slides has no name-collision semantics; the presentationId is the only identity). To populate the deck, follow with slides_modify.",
    inputSchema: {
      type: "object",
      properties: {
        title: {
          type: "string",
          description: "Presentation title (1–1000 UTF-8 bytes after trim; no CR/LF/NUL).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to use; defaults to the most recently used account.",
        },
      },
      required: ["title"],
      additionalProperties: false,
    },
    requiredScopes: [PRESENTATIONS],
    handler: handlers.slidesCreate,
    min_tier: "write",
  },
  slides_modify: {
    name: "slides_modify",
    description:
      "Apply structured edits to an existing Google Slides presentation (WRITE OPERATION; presentations.batchUpdate). `requests` is an array (1–50) where each request has EXACTLY ONE key, and that key MUST be in the POSITIVE ALLOWLIST (default-deny): insertText / deleteText / replaceAllText / createSlide / updateTextStyle / updateParagraphStyle. Any other request type — including createImage / createSheetsChart / createVideo (rejected: they fetch an external URL = SSRF, same class as the Sheets IMAGE/IMPORTRANGE reject) and deleteObject (whole-element delete) — is rejected at the handler boundary. insertText.text is capped at 100 KB; replaceAllText text fields at 1 KB. Structural fields (location, range, objectId, textStyle, fields) pass to Google verbatim. Returns the batchUpdate replies.",
    inputSchema: {
      type: "object",
      properties: {
        presentation_id: {
          type: "string",
          description: "Google Slides presentation ID (url-safe; /^[a-zA-Z0-9_-]{1,80}$/).",
        },
        requests: {
          type: "array",
          minItems: 1,
          maxItems: 50,
          items: { type: "object" },
          description:
            "1–50 batchUpdate requests. Each object has exactly ONE allowlisted request-type key (insertText / deleteText / replaceAllText / createSlide / updateTextStyle / updateParagraphStyle). See the tool description for the rejected types (createImage/Sheets-chart/video = SSRF; deleteObject = high-blast).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to use; defaults to the most recently used account.",
        },
      },
      required: ["presentation_id", "requests"],
      additionalProperties: false,
    },
    requiredScopes: [PRESENTATIONS],
    handler: handlers.slidesModify,
    min_tier: "write",
  },
};
