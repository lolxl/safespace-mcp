// Docs tool definitions — extracted verbatim from the former
// monolithic src/tools/registry.ts TOOL_REGISTRY (mechanical per-API split).
// Assembled in original key order by ./index.ts.

import type { ToolDef } from "./types";
import * as handlers from "../handlers";
import {
  DOCUMENTS_READONLY,
  DOCUMENTS,
} from "./scopes";

export const docsTools: Record<string, ToolDef> = {
  docs_get_content: {
    name: "docs_get_content",
    description:
      "Get the full structured content of a Google Docs document (READ OPERATION). Returns the raw `Document` resource from Docs API `documents.get` verbatim — including body.content[] (StructuralElements: paragraphs, tables, sectionBreaks, tableOfContents), title, documentStyle, namedStyles, inlineObjects, headers, footers, footnotes, lists, namedRanges. Use this when you need heading hierarchy, table cells, comments, lists, or per-paragraph styling. For a flat plain-text body, use drive_get_file_content instead (cheaper). User-visible text (textRun.content, title, comment text, etc.) is sanitize-wrapped per the standard <untrusted-source> pipeline; Google opaque metadata (objectId / revisionId / inheritedNamedStyleType) passes through unwrapped. Tabbed-doc content (Google Docs UI's new tabs feature) is NOT included in v1.12 — only the active tab's content under `body` is returned (Phase 2 may add an explicit include_tabs parameter).",
    inputSchema: {
      type: "object",
      properties: {
        document_id: {
          type: "string",
          description:
            "Google Docs document ID (url-safe chars: letters/digits/`-`/`_`, typically 30+ chars). NOT a URL — paste just the id segment from the doc's URL.",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["document_id"],
      additionalProperties: false,
    },
    // `documents.readonly` is the narrowest scope sufficient for documents.get;
    // V1_SCOPES grants the broader `documents` (full) which satisfies this via
    // SCOPE_HIERARCHY (with-context.ts).
    requiredScopes: [DOCUMENTS_READONLY],
    handler: handlers.docsGetContent,
    min_tier: "read",
  },
  docs_create: {
    name: "docs_create",
    description:
      "Create a new empty Google Doc with the given title (WRITE OPERATION, undoable — the doc can be moved to Drive trash via Drive web UI). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share) in the proxy environment. Returns the created Document resource — record .documentId to read or edit it later. The title is trimmed before send, must be 1-1000 UTF-8 bytes after trim (SafeSpace defensive cap — the Docs API itself accepts much longer titles), and must not contain CR/LF/NUL/NEL/U+2028/U+2029. NO idempotency check: Google allows multiple documents with identical titles, so calling this twice with the same title creates two distinct docs.",
    inputSchema: {
      type: "object",
      properties: {
        title: {
          type: "string",
          description:
            "Document title (1-1000 bytes UTF-8 after trim, no CR/LF/NUL/NEL/U+2028/U+2029).",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["title"],
      additionalProperties: false,
    },
    // Full `documents` scope required — `documents.readonly` cannot create.
    requiredScopes: [DOCUMENTS],
    handler: handlers.docsCreate,
    min_tier: "write",
  },
  docs_append_text: {
    name: "docs_append_text",
    description:
      "Append plain text to the end of an existing Google Docs document body (WRITE OPERATION, limited — APPEND-ONLY; cannot delete or modify existing content). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share) in the proxy environment. Uses Docs API `documents.batchUpdate` with a single `insertText` request at `endOfSegmentLocation` (main body) — single round-trip, atomic. NO pre-flight `documents.get`; the empty `segmentId` resolves to the doc body end. CR/LF and other line terminators in `text` are LEGITIMATE (line breaks in body content) and are NOT rejected (unlike header-shaped fields). `text` is capped at 100 KB UTF-8 (SafeSpace defensive client-side cap — Docs API itself accepts much larger payloads). Returns {documentId, appended_chars (chars in text), appended_bytes (UTF-8 byte count)}.",
    inputSchema: {
      type: "object",
      properties: {
        document_id: {
          type: "string",
          description:
            "Google Docs document ID (url-safe chars: letters/digits/`-`/`_`, typically 30+ chars). NOT a URL — paste just the id segment from the doc's URL.",
        },
        text: {
          type: "string",
          description:
            "Plain text to append to the end of the doc body (max 100 KB UTF-8). Line breaks are preserved.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["document_id", "text"],
      additionalProperties: false,
    },
    // Full `documents` scope required — `documents.readonly` cannot write.
    // Already part of V1_SCOPES (added in Phase 1a for docs_create).
    requiredScopes: [DOCUMENTS],
    handler: handlers.docsAppendText,
    min_tier: "write",
  },
  docs_modify_structured: {
    name: "docs_modify_structured",
    description:
      "Apply STRUCTURED modifications to a Google Doc via documents.batchUpdate (WRITE OPERATION — supports both insertion AND deletion, see allowlist below). ALWAYS ask the user for explicit confirmation before calling this tool, especially when the batch contains deleteContentRange or replaceAllText (HIGH blast radius — can wipe / mass-rewrite content). Requires SAFESPACE_TIER=write (or share). Supports SEVEN request types only: insertText, deleteContentRange, updateTextStyle, replaceAllText, updateParagraphStyle, createParagraphBullets, deleteParagraphBullets. ALL OTHER request types REJECTED at handler boundary (27+ currently-known forbidden types include createNamedRange, insertTable / insertTableRow / insertTableColumn, insertInlineImage, createHeader / createFooter, insertPageBreak / insertSectionBreak, updateDocumentStyle, replaceImage, etc.). Caller-supplied request ORDER is preserved verbatim — Google applies requests in array order; range indices SHIFT between requests, so caller is responsible for correct sequencing (e.g., deletes from end-of-doc backwards). replaceAllText.containsText.matchCase is pass-through. Per-call caps: requests.length ≤ 50, insertText.text ≤ 100 KB UTF-8, replaceAllText.containsText.text + replaceText ≤ 1 KB each. Returns Google's batchUpdate response verbatim ({documentId, replies, writeControl, ...}). Audit row gains target_document_id_hash + modification_count + request_types_csv (CALLER-SUPPLIED ORDER, NOT sorted) + total_text_replacements (when replaceAllText was in the batch).",
    inputSchema: {
      type: "object",
      properties: {
        document_id: {
          type: "string",
          pattern: "^[a-zA-Z0-9_-]{1,80}$",
          description:
            "Google Docs document ID (url-safe chars: letters / digits / `-` / `_`, max 80). NOT a URL — paste just the id segment from the doc's URL.",
        },
        requests: {
          type: "array",
          minItems: 1,
          maxItems: 50,
          items: { type: "object" },
          description:
            "Array of batchUpdate request objects. Each MUST have EXACTLY ONE key, and that key MUST be one of: insertText, deleteContentRange, updateTextStyle, replaceAllText, updateParagraphStyle, createParagraphBullets, deleteParagraphBullets. Applied IN ARRAY ORDER; range indices shift between requests.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["document_id", "requests"],
      additionalProperties: false,
    },
    // Full `documents` scope required — `documents.readonly` cannot write.
    // Already part of V1_SCOPES (added in Phase 1a for docs_create).
    requiredScopes: [DOCUMENTS],
    handler: handlers.docsModifyStructured,
    min_tier: "write",
  },
};
