// Sheets tool definitions — extracted verbatim from the former
// monolithic src/tools/registry.ts TOOL_REGISTRY (mechanical per-API split).
// Assembled in original key order by ./index.ts.

import type { ToolDef } from "./types";
import * as handlers from "../handlers";
import {
  SPREADSHEETS,
} from "./scopes";

export const sheetsTools: Record<string, ToolDef> = {
  sheets_get_values: {
    name: "sheets_get_values",
    description:
      "Read cell values from a Google Sheets spreadsheet (READ OPERATION). Returns the raw values response from Sheets API `spreadsheets.values.get` — `{range, majorDimension: 'ROWS', values: Array<Array<string|number|boolean>>}`. The `spreadsheet_id` MUST match /^[a-zA-Z0-9_-]{40,100}$/ (handler-side validation BEFORE any SDK call). The `range` MUST be valid A1 notation (e.g., 'Sheet1!A1:Z100' / 'Sheet1!A:Z' / 'Sheet1!1:100' / 'Sheet1' / quoted-sheet `'Sheet with spaces'!A1`) — strict-parsed pre-SDK; rejects suffix injection / newline injection / row-zero / column overflow / fullwidth-Unicode hijack (see design §7 hostile-input table for the full 14-entry list). `value_render_option` allowlist: {FORMATTED_VALUE (default; renders strings with currency / thousands separators), UNFORMATTED_VALUE (raw cell content with type coercion)}. FORMULA rendering REJECTED with `-32028 value_render_option_rejected` (design §11 Q4 — formula text leaks user secrets via IMPORTRANGE referrer / paired-sheet IDs / named-cell references). User-typed cell content (title / value / formattedValue / note) is sanitize-wrapped per the standard <untrusted-source> pipeline; opaque Google keys (spreadsheetId / sheetId / dataSourceId / etc.) pass through unwrapped. Quota: 1 read unit / call (Sheets API quota: 300 reads/min/project default).",
    inputSchema: {
      type: "object",
      properties: {
        spreadsheet_id: {
          type: "string",
          description:
            "Sheets spreadsheet identifier (Drive file ID; 40-100 chars). Must match /^[a-zA-Z0-9_-]{40,100}$/ — obtained from `drive_search` / `drive_search_all` with `mimeType='application/vnd.google-apps.spreadsheet'` filter.",
        },
        range: {
          type: "string",
          maxLength: 256,
          description:
            "A1 notation range (e.g., 'Sheet1!A1:Z100' / 'Sheet1!A:Z' / 'Sheet1' / quoted-sheet `'Sheet with spaces'!A1`). 256-byte cap; strict-parsed pre-SDK (see design §7 for the LOCKED regex + hostile-input table).",
        },
        value_render_option: {
          type: "string",
          enum: ["FORMATTED_VALUE", "UNFORMATTED_VALUE"],
          description:
            "Cell render mode. FORMATTED_VALUE (default) returns user-display strings ($1,234.56). UNFORMATTED_VALUE returns raw numeric/string values. FORMULA mode is REJECTED (design §11 Q4 LOCKED — formula text leaks user secrets).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["spreadsheet_id", "range"],
      additionalProperties: false,
    },
    requiredScopes: [SPREADSHEETS],
    handler: handlers.sheetsGetValues,
    min_tier: "read",
  },
  sheets_get_metadata: {
    name: "sheets_get_metadata",
    description:
      "Get structural metadata for a Google Sheets spreadsheet (READ OPERATION; NO cell values returned). Returns `{spreadsheetId, properties: {title, locale, timeZone, ...}, sheets: [{properties: {sheetId, title, index, sheetType, gridProperties: {rowCount, columnCount}}}], namedRanges?, spreadsheetUrl}`. Use this BEFORE `sheets_get_values` to enumerate sheet tab titles + named ranges + row/column counts. `includeGridData: false` HARD-LOCKED (DoS guard per design §2.2 + hook #5 — `includeGridData: true` returns full cell payload of every sheet, can balloon to 500MB+; use `sheets_get_values` for cell content). `fields` parameter defaults to `'properties,sheets.properties,namedRanges,spreadsheetUrl'` (constrained projection — prevents silent payload bloat from new Google fields). Caller may override but the value MUST match FieldMask grammar /^[a-zA-Z][a-zA-Z0-9_,.()]*$/ (whitespace / quotes / special chars rejected) and ≤512 bytes. User-typed fields (title / value / formattedValue / note / description) sanitize-wrapped per the standard <untrusted-source> pipeline; opaque Google keys (spreadsheetId / sheetId / dataSourceId / chartId / etc.) pass through unwrapped. Cross-account discovery: use `drive_search_all` with `mimeType='application/vnd.google-apps.spreadsheet'` filter (shipped v1.14) to find spreadsheet IDs across accounts, then call this tool per-account. Quota: 1 read unit / call.",
    inputSchema: {
      type: "object",
      properties: {
        spreadsheet_id: {
          type: "string",
          description:
            "Sheets spreadsheet identifier (Drive file ID; 40-100 chars). Must match /^[a-zA-Z0-9_-]{40,100}$/.",
        },
        fields: {
          type: "string",
          maxLength: 512,
          description:
            "Optional Google FieldMask projection (e.g., 'properties.title,sheets.properties.title'). Defaults to 'properties,sheets.properties,namedRanges,spreadsheetUrl'. Must match /^[a-zA-Z][a-zA-Z0-9_,.()]*$/ — whitespace / quotes / `/` separator rejected (use dotted-path form).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["spreadsheet_id"],
      additionalProperties: false,
    },
    requiredScopes: [SPREADSHEETS],
    handler: handlers.sheetsGetMetadata,
    min_tier: "read",
  },
  sheets_create: {
    name: "sheets_create",
    description:
      "Create a new empty Google Sheets spreadsheet (WRITE OPERATION). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). Returns the created Spreadsheet resource — `{spreadsheetId, spreadsheetUrl, properties: {title, locale, timeZone, ...}, sheets: [{properties: {sheetId, title, ...}}]}`. The user-visible URL is at `spreadsheetUrl`; copy that into a browser tab to open the new sheet. **4-key positive ALLOWLIST**: only `title` (required) / `locale` / `timeZone` / `sheets[].properties.title` are accepted; ALL OTHER fields (charts / namedRanges / conditionalFormats / dataSources / developerMetadata / protectedRanges / sheets[].data / etc. — 30 forbidden fields total per design §2.3) are REJECTED at the handler boundary (30-field NEGATIVE sentinel; handler constructs requestBody LITERALLY with no `...args` spread). **Formula-smuggle DEFENDED**: `sheets[].data` rejected via positive allowlist construction — closes the bypass class where pre-populated cell data with `userEnteredValue.formulaValue` would smuggle a formula past the v1.20 Phase 1 RAW HARD-LOCK on values.append (sheets.create ignores valueInputOption entirely). Per design §2.3 / §10 hook #19. Multi-sheet creation capped at 10 entries (Phase 2c+ will replace with `sheets_batch_update.addSheet`). `locale` MUST match BCP 47 form /^[a-zA-Z][a-zA-Z0-9_-]{0,15}$/ (e.g., `en_US`, `zh-Hant-TW`); `timeZone` MUST match IANA tz form /^[A-Za-z][A-Za-z0-9_/+-]{0,63}$/ (e.g., `America/Los_Angeles`, `Asia/Taipei`). Audit gains target_spreadsheet_id_hash + operation='create' + policy_decision (2-step audit-before-SDK pattern per design §5 — sentinel `<pending-create>` hash before SDK, real hash patched on success).",
    inputSchema: {
      type: "object",
      properties: {
        title: {
          type: "string",
          minLength: 1,
          maxLength: 256,
          description:
            "Spreadsheet title (REQUIRED). Non-empty after trim; ≤256 bytes UTF-8 (Google natural cap).",
        },
        locale: {
          type: "string",
          maxLength: 16,
          description:
            "Optional BCP 47 locale (e.g., 'en_US', 'zh-Hant-TW'). Must match /^[a-zA-Z][a-zA-Z0-9_-]{0,15}$/.",
        },
        timeZone: {
          type: "string",
          maxLength: 64,
          description:
            "Optional IANA timezone (e.g., 'America/Los_Angeles', 'Asia/Taipei'). Must match /^[A-Za-z][A-Za-z0-9_/+-]{0,63}$/.",
        },
        sheets: {
          type: "array",
          maxItems: 10,
          description:
            "Optional initial sheet tabs (≤10). Each entry MUST be of shape {properties: {title}} — NO `sheets[].data` accepted (formula-smuggle bypass defense per design §10 hook #19). Per-sheet title same caps as the spreadsheet title.",
          items: {
            type: "object",
            properties: {
              properties: {
                type: "object",
                properties: {
                  title: {
                    type: "string",
                    minLength: 1,
                    maxLength: 256,
                    description: "Per-sheet tab title.",
                  },
                },
                required: ["title"],
                additionalProperties: false,
              },
            },
            required: ["properties"],
            additionalProperties: false,
          },
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["title"],
      additionalProperties: false,
    },
    requiredScopes: [SPREADSHEETS],
    handler: handlers.sheetsCreate,
    min_tier: "write",
  },
  sheets_update_values: {
    name: "sheets_update_values",
    description:
      "Overwrite (REPLACE) cells in a Google Sheets range (WRITE OPERATION). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). Returns Sheets API `spreadsheets.values.update` response `{spreadsheetId, updatedRange, updatedRows, updatedColumns, updatedCells}`. **value_input_option allowlist {RAW (default), USER_ENTERED}** — RAW stores formula-shaped cells as literal text (NEVER evaluated). USER_ENTERED evaluates formulas like the Sheets UI does; cells starting with `=`/`+` are gated by the 11-function formula REJECT list (IMPORTRANGE / IMPORTXML / IMPORTHTML / IMPORTDATA / IMPORTFEED / HYPERLINK / GOOGLEFINANCE / GOOGLETRANSLATE / IMAGE / WEBSERVICE / LAMBDA — case-insensitive post-NFKC normalize); matches throw `-32029 formula_rejected` BEFORE the SDK call. Higher risk than append (silent data loss if `range` mis-typed). **Per-cell content cap 50KB UTF-8**; **per-batch total cap 100KB**; **per-call cell-count cap 10000**. Cell type STRICT — only `string|number|boolean` accepted per cell (no `null`, no nested objects/arrays). The `range` MUST be valid A1 notation; strict-parsed pre-SDK. **Last-write-wins (Google API contract limitation — Sheets does NOT support If-Match conditional requests; not a SafeSpace TODO).** Audit gains target_spreadsheet_id_hash + target_range_hash + operation='update_values' + policy_decision; on formula REJECT also rejected_formula_function (UPPERCASED name from closed 11-item set; bounded value space — no PII echo).",
    inputSchema: {
      type: "object",
      properties: {
        spreadsheet_id: {
          type: "string",
          description:
            "Sheets spreadsheet identifier (Drive file ID; 40-100 chars). Must match /^[a-zA-Z0-9_-]{40,100}$/.",
        },
        range: {
          type: "string",
          maxLength: 256,
          description:
            "A1 notation range (e.g., 'Sheet1!A1:B3'). REPLACES cells in this range. 256-byte cap; strict-parsed pre-SDK.",
        },
        values: {
          type: "array",
          description:
            "2D array of rows to overwrite. Each cell MUST be `string | number | boolean`. Per-cell 50KB / per-batch 100KB / per-call 10000 cells.",
          items: {
            type: "array",
            items: {
              type: ["string", "number", "boolean"],
            },
          },
        },
        value_input_option: {
          type: "string",
          enum: ["RAW", "USER_ENTERED"],
          description:
            "How to interpret cell values. RAW (default; safer) stores leading `=`/`+`/`-`/`@` as literal text — formulas are NEVER evaluated. USER_ENTERED evaluates formulas like the Sheets UI; gated by 11-function REJECT list per design §3 / Q2 LOCKED. Caller MUST explicitly opt in to USER_ENTERED.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["spreadsheet_id", "range", "values"],
      additionalProperties: false,
    },
    requiredScopes: [SPREADSHEETS],
    handler: handlers.sheetsUpdateValues,
    min_tier: "write",
  },
  sheets_batch_update: {
    name: "sheets_batch_update",
    description:
      "Apply structured batch modifications to a Google Sheets spreadsheet via `spreadsheets.batchUpdate` (WRITE OPERATION). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). Returns Sheets API response `{spreadsheetId, replies: [...]}`. **7-type positive ALLOWLIST** (Q3 LOCKED) — only `addSheet` / `deleteSheet` / `updateSheetProperties` / `repeatCell` / `updateCells` / `mergeCells` / `unmergeCells` accepted; ~47 other Google API request types REJECTED at handler boundary (`addChart` / `addPivotTable` / `findReplace` / `sortRange` / `pasteData` / `setDataValidation` / `addProtectedRange` / `addNamedRange` / etc. — see design §2.2 NEGATIVE sentinel). `updateSpreadsheetProperties` HARD-REJECTED (sec-rev hook #3 + #16 — closes the SSRF whitelist toggle `importFunctionsExternalUrlAccessAllowed`; `sheets_create` already covers this at create-time, `sheets_batch_update` closes the post-create backdoor). **Each request MUST have EXACTLY ONE key** in the allowlist (multi-key smuggle defense). **Per-type sub-allowlists**: `addSheet.properties` accepts `{title}` ONLY (cross-tool symmetry with `sheets_create.sheets[]`); `updateSheetProperties.properties` accepts `{sheetId, title?, hidden?}`; `repeatCell.cell` + `updateCells.rows[].values[]` accept `userEnteredValue` (3-key {stringValue, numberValue, boolValue} — `formulaValue` + `errorValue` HARD-REJECTED per hook #23 N4 BLOCKING) + `userEnteredFormat` (5 sub-keys: backgroundColor + textFormat.{bold, italic, fontFamily, fontSize}). **FieldMask sub-key allowlist** (hook #19) — `updateSheetProperties.fields` ⊆ {title, hidden}; `repeatCell.fields` + `updateCells.fields` ⊆ the 5 userEnteredFormat sub-keys + userEnteredValue paths; CLEAR-via-mask side-effect closed. `updateCells` requires EXACTLY ONE of `range` (GridRange) OR `start` (GridCoordinate) — both-or-neither REJECTED. **`value_input_option` allowlist {RAW (default), USER_ENTERED}** — USER_ENTERED gated by the 11-function formula REJECT list per stringValue cell. **`includeSpreadsheetInResponse: false` HARD-OMITTED** (hook #15 — handler does NOT accept this input key; DoS guard matches v1.17 `docs_modify_structured.include_document_in_response: false` precedent). **Cell content caps (cumulative across all requests)**: per-cell 50KB / per-batch 100KB / per-call 10000 cells; **per-batch-update 50-request cap** (Layer 4 cheapest-first per §8.3). **Last-write-wins (Google API contract limitation — Sheets does NOT support If-Match conditional requests; not a SafeSpace TODO).** Audit gains target_spreadsheet_id_hash + operation='batch_update' + policy_decision + request_types_csv (caller-supplied ORDER) + optional total_cell_writes; on formula REJECT also rejected_formula_function.",
    inputSchema: {
      type: "object",
      properties: {
        spreadsheet_id: {
          type: "string",
          description:
            "Sheets spreadsheet identifier (Drive file ID; 40-100 chars). Must match /^[a-zA-Z0-9_-]{40,100}$/.",
        },
        requests: {
          type: "array",
          minItems: 1,
          maxItems: 50,
          description:
            "Array of structured modification requests (1-50). Each entry MUST have EXACTLY ONE key in the 7-type allowlist {addSheet, deleteSheet, updateSheetProperties, repeatCell, updateCells, mergeCells, unmergeCells}.",
          items: {
            type: "object",
            additionalProperties: false,
            maxProperties: 1,
            properties: {
              addSheet: {
                type: "object",
                additionalProperties: false,
                properties: {
                  properties: {
                    type: "object",
                    additionalProperties: false,
                    properties: {
                      title: {
                        type: "string",
                        minLength: 1,
                        maxLength: 256,
                      },
                    },
                    required: ["title"],
                  },
                },
                required: ["properties"],
              },
              deleteSheet: {
                type: "object",
                additionalProperties: false,
                properties: {
                  sheetId: { type: "integer" },
                },
                required: ["sheetId"],
              },
              updateSheetProperties: {
                type: "object",
                additionalProperties: false,
                properties: {
                  properties: {
                    type: "object",
                    additionalProperties: false,
                    properties: {
                      sheetId: { type: "integer" },
                      title: { type: "string", minLength: 1, maxLength: 256 },
                      hidden: { type: "boolean" },
                    },
                    required: ["sheetId"],
                  },
                  fields: { type: "string" },
                },
                required: ["properties", "fields"],
              },
              repeatCell: {
                type: "object",
                additionalProperties: false,
                properties: {
                  range: { type: "object" },
                  cell: { type: "object" },
                  fields: { type: "string" },
                },
                required: ["range", "cell", "fields"],
              },
              updateCells: {
                type: "object",
                additionalProperties: false,
                properties: {
                  range: { type: "object" },
                  start: { type: "object" },
                  rows: { type: "array" },
                  fields: { type: "string" },
                },
                required: ["rows", "fields"],
              },
              mergeCells: {
                type: "object",
                additionalProperties: false,
                properties: {
                  range: { type: "object" },
                  mergeType: {
                    type: "string",
                    enum: ["MERGE_ALL", "MERGE_COLUMNS", "MERGE_ROWS"],
                  },
                },
                required: ["range"],
              },
              unmergeCells: {
                type: "object",
                additionalProperties: false,
                properties: {
                  range: { type: "object" },
                },
                required: ["range"],
              },
            },
          },
        },
        value_input_option: {
          type: "string",
          enum: ["RAW", "USER_ENTERED"],
          description:
            "How to interpret cell values in updateCells / repeatCell. RAW (default; safer) stores formula-shaped cells as literal text. USER_ENTERED evaluates formulas; gated by 11-function REJECT list per design §3.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["spreadsheet_id", "requests"],
      additionalProperties: false,
    },
    requiredScopes: [SPREADSHEETS],
    handler: handlers.sheetsBatchUpdate,
    min_tier: "write",
  },
  sheets_append_values: {
    name: "sheets_append_values",
    description:
      "Append rows to the bottom of a range in a Google Sheets spreadsheet (WRITE OPERATION). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). Returns the Sheets API `spreadsheets.values.append` response `{spreadsheetId, tableRange, updates: {updatedRange, updatedRows, updatedColumns, updatedCells}}`. **`valueInputOption: 'RAW' HARD-LOCKED`** (design §11 Q3 LOCKED + sec-rev hook #3) — handler ALWAYS passes literal `RAW` to the SDK; NEVER caller-supplied. The schema additionally pins `additionalProperties: false` so caller-supplied `value_input_option` is rejected at the schema gate BEFORE the handler runs (sec-rev hook #23 — defense-in-depth). Rationale: RAW stores leading `=`/`+`/`-`/`@` as literal text — formulas are NEVER evaluated, closing the formula-injection class entirely at the write boundary. `USER_ENTERED` (which evaluates formulas) is deferred to Phase 2c+ alongside a formula REJECT list (design §11 Risk 3). **Per-cell content cap 50KB UTF-8** (matches Google's natural cell ceiling); **per-batch total cap 100KB** (mirrors v1.17 `docs_modify_structured` insertText.text cap); **per-call cell-count cap 10000** (anti-DoS / runaway-loop guard). Cell type STRICT — only `string|number|boolean` accepted per cell (no `null`, no nested objects/arrays). `insert_data_option` defaults to `INSERT_ROWS` (safer — pushes existing rows down); `OVERWRITE` opt-in for the 'log latest reading at row N' pattern. The `range` MUST be valid A1 notation; strict-parsed pre-SDK (rejects suffix injection / newline injection / row-zero / column overflow / fullwidth-Unicode hijack — see design §7 hostile-input table). Audit gains target_spreadsheet_id_hash + target_range_hash + operation='append_values' + policy_decision (recorded BEFORE SDK call per design §5 + v1.17 §8 hook #7 — forensic survives 5xx).",
    inputSchema: {
      type: "object",
      properties: {
        spreadsheet_id: {
          type: "string",
          description:
            "Sheets spreadsheet identifier (Drive file ID; 40-100 chars). Must match /^[a-zA-Z0-9_-]{40,100}$/.",
        },
        range: {
          type: "string",
          maxLength: 256,
          description:
            "A1 notation range (e.g., 'Sheet1!A:Z', 'Sheet1', 'Log!A1'). Append targets the cells below the last non-empty row in this range. 256-byte cap; strict-parsed pre-SDK.",
        },
        values: {
          type: "array",
          description:
            "2D array of rows to append. Each row is an array of cells; each cell MUST be `string | number | boolean` (null / nested objects / arrays REJECTED). Per-cell cap 50KB UTF-8; per-batch cap 100KB; per-call cell-count cap 10000.",
          items: {
            type: "array",
            items: {
              type: ["string", "number", "boolean"],
            },
          },
        },
        insert_data_option: {
          type: "string",
          enum: ["INSERT_ROWS", "OVERWRITE"],
          description:
            "How to handle existing data when appending. INSERT_ROWS (default; safer) pushes existing rows down to make room. OVERWRITE replaces cells in place — opt-in for log-style writes that target a specific row.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["spreadsheet_id", "range", "values"],
      additionalProperties: false,
    },
    requiredScopes: [SPREADSHEETS],
    handler: handlers.sheetsAppendValues,
    min_tier: "write",
  },
};
