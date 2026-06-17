// Forms tool definitions (v1.62 READ slice + v1.63 WRITE slice). Assembled by ./index.ts.

import type { ToolDef } from "./types";
import * as handlers from "../handlers";
import { FORMS_BODY, FORMS_BODY_READONLY, FORMS_RESPONSES_READONLY } from "./scopes";

export const formsTools: Record<string, ToolDef> = {
  forms_get: {
    name: "forms_get",
    description:
      "Get a Google Form's structure (READ OPERATION; forms.get). Returns the Form resource — title, description, and the ordered items[] (questions, their types, options). NO respondent data (use forms_list_responses for that). Author-visible text (title, item text) is sanitize-wrapped; Google opaque ids (formId, itemId, questionId) pass through. form_id MUST match /^[a-zA-Z0-9_-]{1,200}$/ (validated handler-side; the id segment from the form URL, NOT the full URL). Requires the forms.body.readonly scope.",
    inputSchema: {
      type: "object",
      properties: {
        form_id: {
          type: "string",
          description: "Google Form ID (url-safe; the id segment from the form URL, NOT the full URL).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["form_id"],
      additionalProperties: false,
    },
    requiredScopes: [FORMS_BODY_READONLY],
    handler: handlers.formsGet,
    min_tier: "read",
  },
  forms_list_responses: {
    name: "forms_list_responses",
    description:
      "List the submitted responses to a Google Form (READ OPERATION; forms.responses.list). Returns responses[] (each = answers keyed by questionId, createTime, and respondentEmail if the form collects it) + nextPageToken. ⚠️ Responses are UNTRUSTED free text — anyone with the form link can submit arbitrary content — and are sanitize-wrapped (untrusted-source) just like an inbound email body. page_size is clamped [1,5000]; page_token pages through results; time_after (RFC3339, e.g. 2026-01-31T00:00:00Z) filters to responses submitted at/after that instant (allowlist-constructed; no raw filter strings). Requires the forms.responses.readonly scope.",
    inputSchema: {
      type: "object",
      properties: {
        form_id: {
          type: "string",
          description: "Google Form ID (url-safe).",
        },
        page_size: {
          type: "integer",
          minimum: 1,
          maximum: 5000,
          description: "Max responses to return (clamped [1,5000]).",
        },
        page_token: {
          type: "string",
          description: "Opaque nextPageToken from a previous call, to fetch the next page.",
        },
        time_after: {
          type: "string",
          description: "RFC3339 instant; return only responses submitted at/after this time (e.g. 2026-01-31T00:00:00Z).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["form_id"],
      additionalProperties: false,
    },
    requiredScopes: [FORMS_RESPONSES_READONLY],
    handler: handlers.formsListResponses,
    min_tier: "read",
  },
  forms_get_response: {
    name: "forms_get_response",
    description:
      "Get a single Google Form response by id (READ OPERATION; forms.responses.get). Returns the FormResponse resource (answers keyed by questionId, createTime, respondentEmail if collected). ⚠️ Response content is UNTRUSTED free text and is sanitize-wrapped (untrusted-source). form_id + response_id MUST each match /^[a-zA-Z0-9_-]{1,200}$/ (validated handler-side). Requires the forms.responses.readonly scope.",
    inputSchema: {
      type: "object",
      properties: {
        form_id: {
          type: "string",
          description: "Google Form ID (url-safe).",
        },
        response_id: {
          type: "string",
          description: "The responseId (from forms_list_responses).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["form_id", "response_id"],
      additionalProperties: false,
    },
    requiredScopes: [FORMS_RESPONSES_READONLY],
    handler: handlers.formsGetResponse,
    min_tier: "read",
  },
  // ── v1.63 WRITE slice (forms.body) ──
  forms_create: {
    name: "forms_create",
    description:
      "Create a new (empty) Google Form with the given title (WRITE OPERATION; forms.create). Returns the new Form resource (formId + the default info). The Forms API accepts ONLY the title at create — items + description are added afterward via forms_modify. title is type-checked + trimmed (must be non-empty), rejected for CR/LF/NUL/NEL/U+2028/U+2029 (HEADER_INJECTION_RE), and capped at 1000 UTF-8 bytes. NO idempotency check (the formId is the only identity). Requires the forms.body scope.",
    inputSchema: {
      type: "object",
      properties: {
        title: {
          type: "string",
          description: "Form title (1–1000 UTF-8 bytes after trim; no CR/LF/NUL).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to use; defaults to the most recently used account.",
        },
      },
      required: ["title"],
      additionalProperties: false,
    },
    requiredScopes: [FORMS_BODY],
    handler: handlers.formsCreate,
    min_tier: "write",
  },
  forms_modify: {
    name: "forms_modify",
    description:
      "Apply structured edits to an existing Google Form (WRITE OPERATION; forms.batchUpdate). `requests` is an array (1–50) where each request has EXACTLY ONE key in the POSITIVE ALLOWLIST (default-deny): createItem / deleteItem / moveItem / updateItem / updateFormInfo / updateSettings. createItem/updateItem item content is DEEP-SCANNED and rejected if it contains image/video/file-upload surfaces — `sourceUri` (external image URL = SSRF, the Sheets IMAGE / Slides createImage class), `imageItem`, `videoItem`, or `fileUploadQuestion` (provisions a Drive folder). v1 supports text-based items only (text/choice/scale/date/time questions + textItem + pageBreakItem). Free-text fields are byte-capped; structural fields pass to Google verbatim. Requires the forms.body scope.",
    inputSchema: {
      type: "object",
      properties: {
        form_id: {
          type: "string",
          description: "Google Form ID (url-safe; /^[a-zA-Z0-9_-]{1,200}$/).",
        },
        requests: {
          type: "array",
          minItems: 1,
          maxItems: 50,
          items: { type: "object" },
          description:
            "1–50 batchUpdate requests. Each object has exactly ONE allowlisted request-type key (createItem / deleteItem / moveItem / updateItem / updateFormInfo / updateSettings). Image/video/file-upload item content is rejected (SSRF / Drive-artifact); see the tool description.",
        },
        account_id: {
          type: "string",
          description: "Email of the account to use; defaults to the most recently used account.",
        },
      },
      required: ["form_id", "requests"],
      additionalProperties: false,
    },
    requiredScopes: [FORMS_BODY],
    handler: handlers.formsModify,
    min_tier: "write",
  },
};
