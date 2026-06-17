// Sheets — extracted verbatim from the former monolithic
// src/tools/handlers.ts (mechanical per-API split; function bodies byte-identical).
// Re-exported via ./index.ts so existing `./handlers` import paths are unchanged.

import { MCPError } from "../../errors";
import { sheetsClientFromToken } from "../../google-api/client";
import { A1_MAX_LENGTH, parseA1Range } from "../../sheets/a1";
import { validateCellValue } from "../../sheets/formula-reject";
import { SHEETS_BATCH_MAX_BYTES, SHEETS_BATCH_UPDATE_MAX_REQUESTS, SHEETS_CELL_MAX_BYTES, SHEETS_MAX_CELLS_PER_CALL } from "../../sheets/limits";
import { toGoogleError } from "../../google-api/errors";
import type { ToolContext } from "../types";

import { requireGoogle, sha256Hex } from "./shared";

/** Sheets spreadsheet ID regex (design §11 Q7 LOCKED). Drive file-ID format
 * with Sheets-specific 40-char floor — observed Sheets IDs are 44+ chars;
 * 40 rejects shorter Drive document-fragment IDs. 100-char ceiling matches
 * Google's natural Drive ID maximum. */
const SHEETS_SPREADSHEET_ID_RE = /^[a-zA-Z0-9_-]{40,100}$/;

/** Allowlist for `value_render_option` per design §2.1 + §11 Q4 LOCKED.
 * `FORMULA` REJECTED at the handler boundary (sec-rev hook #20) — formula
 * text leaks user secrets (paired-sheet IDs / external service tokens via
 * IMPORTRANGE referrer / named-cell references). Closed-set semantics
 * prevent silent attack-surface expansion when Google adds a 4th render
 * option. */
const SHEETS_VALUE_RENDER_ALLOWED: ReadonlySet<string> = new Set([
  "FORMATTED_VALUE",
  "UNFORMATTED_VALUE",
]);

/** FieldMask grammar regex for `sheets_get_metadata.fields` parameter.
 * Google's FieldMask uses letters / digits / commas / dots / parens to
 * project nested response fields. Whitespace / quotes / special chars
 * rejected. Length cap 512 bytes per design §2.2. The `/` separator for
 * nested-path projection (e.g., `properties/title`) is NOT included Phase
 * 1b-1 — see design §16 L3 carry-forward (Phase 1b probe-then-tighten
 * pattern). Real-world callers may use the dotted-path form
 * (`properties.title`) which IS supported by Google's FieldMask alternate
 * syntax. */
const SHEETS_FIELDS_RE = /^[a-zA-Z][a-zA-Z0-9_,.()]*$/;
const SHEETS_FIELDS_MAX_LENGTH = 512;

export async function sheetsGetValues(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. spreadsheet_id strict-parse (sec-rev hook #1) ──
  // Echo the RULE, NOT the bad value — mirror tasks_list / contacts_get
  // (sec-rev hook #13 / cross-API invariant: error paths must not reflect
  // user-supplied content back to the caller verbatim).
  if (typeof args.spreadsheet_id !== "string") {
    throw new Error("sheets_get_values: 'spreadsheet_id' must be a string");
  }
  if (!SHEETS_SPREADSHEET_ID_RE.test(args.spreadsheet_id)) {
    throw new Error(
      "sheets_get_values: 'spreadsheet_id' must match /^[a-zA-Z0-9_-]{40,100}$/",
    );
  }
  const spreadsheetId = args.spreadsheet_id;

  // ─── 2. A1 range strict-parse (sec-rev hook #2) ──
  // Shared `parseA1Range` from src/sheets/a1.ts. Handles typeof / empty /
  // length-cap / regex match. 14+ hostile inputs covered by a1.test.ts.
  if (typeof args.range !== "string") {
    throw new Error("sheets_get_values: 'range' must be a string");
  }
  const parsed = parseA1Range(args.range);
  if (!parsed.valid || parsed.normalized === undefined) {
    throw new Error(
      `sheets_get_values: 'range' fails A1 notation strict-parse ` +
        `(≤${A1_MAX_LENGTH} bytes; see design §7 hostile-input table)`,
    );
  }
  const range = parsed.normalized;

  // ─── 3. value_render_option allowlist (sec-rev hook #4 + #20) ──
  // §11 Q4 LOCKED — FORMULA rejected at handler boundary with NEW error
  // code -32028 + closed-enum `reason` discriminator. NO PII echo per hook #13.
  // v1.20 Phase 1b-2 L3 dead-code cleanup: single assignment site for
  // `valueRenderOption`; previously the post-gate ternary fallback ("if
  // string, use; else default") was structurally unreachable because the
  // preceding block threw on every non-string and every non-allowlist
  // string. Restructured below: default first, then conditionally override
  // inside the gate that throws on shape failure (mirror tasks_create
  // status-allowlist pattern).
  let valueRenderOption: "FORMATTED_VALUE" | "UNFORMATTED_VALUE" =
    "FORMATTED_VALUE";
  if (args.value_render_option !== undefined) {
    if (
      typeof args.value_render_option !== "string" ||
      !SHEETS_VALUE_RENDER_ALLOWED.has(args.value_render_option)
    ) {
      throw new MCPError("value_render_option_rejected", {
        tool: "sheets_get_values",
        reason: "formula_rendering_rejected",
      });
    }
    valueRenderOption = args.value_render_option as
      | "FORMATTED_VALUE"
      | "UNFORMATTED_VALUE";
  }

  // ─── 4. SDK call ──
  // `dateTimeRenderOption` HARD-OMITTED per sec-rev hook #21 / design §2.1.
  // Google defaults to SERIAL_NUMBER when the field is absent. Sentinel
  // test asserts the SDK args do NOT contain `dateTimeRenderOption`.
  try {
    const sheets = sheetsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await sheets.spreadsheets.values.get({
      spreadsheetId,
      range,
      valueRenderOption,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "sheets_get_values", email: requireGoogle(ctx).accountId });
  }
}

export async function sheetsGetMetadata(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. spreadsheet_id strict-parse (sec-rev hook #1) ──
  if (typeof args.spreadsheet_id !== "string") {
    throw new Error("sheets_get_metadata: 'spreadsheet_id' must be a string");
  }
  if (!SHEETS_SPREADSHEET_ID_RE.test(args.spreadsheet_id)) {
    throw new Error(
      "sheets_get_metadata: 'spreadsheet_id' must match /^[a-zA-Z0-9_-]{40,100}$/",
    );
  }
  const spreadsheetId = args.spreadsheet_id;

  // ─── 2. fields validation (optional FieldMask projection) ──
  // Design §2.2 — default `"properties,sheets.properties,namedRanges,
  // spreadsheetUrl"` constrained projection; caller MAY override but the
  // value MUST match the FieldMask grammar. Length cap 512 bytes.
  let fields: string | undefined;
  if (args.fields !== undefined) {
    if (typeof args.fields !== "string") {
      throw new Error("sheets_get_metadata: 'fields' must be a string");
    }
    if (Buffer.byteLength(args.fields, "utf-8") > SHEETS_FIELDS_MAX_LENGTH) {
      throw new Error(
        `sheets_get_metadata: 'fields' exceeds ${SHEETS_FIELDS_MAX_LENGTH} bytes`,
      );
    }
    if (!SHEETS_FIELDS_RE.test(args.fields)) {
      throw new Error(
        "sheets_get_metadata: 'fields' must match FieldMask grammar /^[a-zA-Z][a-zA-Z0-9_,.()]*$/",
      );
    }
    fields = args.fields;
  } else {
    fields = "properties,sheets.properties,namedRanges,spreadsheetUrl";
  }

  // ─── 3. SDK call ──
  // `includeGridData` HARD-LOCKED to false via OMISSION per sec-rev hook #5 /
  // design §2.2. Google defaults to false when the field is absent. NOT
  // passing the key (rather than passing false explicitly) is the strictest
  // posture — sentinel test asserts the SDK args do NOT contain
  // `includeGridData` key. Use `sheets_get_values` for cell content; this
  // tool is for STRUCTURE only.
  try {
    const sheets = sheetsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await sheets.spreadsheets.get({
      spreadsheetId,
      fields,
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "sheets_get_metadata", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.20 Phase 1b-2: sheets_create + sheets_append_values (WRITE tier) ─────────
 *
 * See `docs/v1.20-sheets-api.md` §2.3 / §2.4 / §5. Both handlers:
 *   - validate inputs BEFORE the tier check (v1.17 convention)
 *   - record `sheetsMutationMeta` BEFORE the SDK call (v1.17 §8 hook #7
 *     forensic-survives-failure invariant)
 *   - construct the SDK request body LITERALLY from a positive ALLOWLIST
 *     (NO `...args` spread — 30-field NEGATIVE sentinel enforced by
 *     construction)
 *
 * `sheets_create` uses the 2-step audit-meta pattern (§5):
 *   1. BEFORE SDK call: record with `target_spreadsheet_id_hash =
 *      sha256("<pending-create>")` so the audit row carries the operation +
 *      policy_decision even if the SDK 5xxs
 *   2. AFTER SDK success: re-record with the real spreadsheet_id hash
 *      (last-write-wins; with-context.ts captures whichever fired last)
 *
 * `sheets_append_values` HARD-LOCKS `valueInputOption: "RAW"` (Q3 LOCKED).
 * The schema layer additionally pins `additionalProperties: false` so a
 * caller-supplied `value_input_option` is rejected at the schema gate BEFORE
 * the handler runs (sec-rev hook #23). Defense-in-depth: even if the schema
 * regresses, the handler still ignores any caller override and passes
 * literal "RAW" to the SDK. */

/** Sheets spreadsheet title cap (1-256 bytes UTF-8 — Google natural cap per
 *  design §2.3). */
const SHEETS_TITLE_MAX_BYTES = 256;
/** BCP 47 locale regex per design §2.3 (`^[a-zA-Z][a-zA-Z0-9_-]{0,15}$`).
 *  Conservative: accepts `en` / `en_US` / `zh-Hant-TW` / `fil-PH` etc.
 *  Rejects whitespace / quotes / dot / slash injection vectors. */
const SHEETS_LOCALE_RE = /^[a-zA-Z][a-zA-Z0-9_-]{0,15}$/;
/** IANA tz regex per design §2.3 (`^[A-Za-z][A-Za-z0-9_/+\-]{0,63}$`).
 *  Accepts `America/Los_Angeles` / `Asia/Taipei` / `Etc/GMT+8`. Rejects
 *  whitespace / quotes / null / control chars. */
const SHEETS_TIMEZONE_RE = /^[A-Za-z][A-Za-z0-9_/+\-]{0,63}$/;
// v1.22 Phase 2 I-1 — `SHEETS_CELL_MAX_BYTES` / `SHEETS_BATCH_MAX_BYTES`
// / `SHEETS_MAX_CELLS_PER_CALL` extracted to `src/sheets/limits.ts`
// (single source of truth). v1.20 + v1.21 previously defined them inline
// twice; consolidation closes the v1.21 carry-forward I-1 drift class.
/** Max sheets array length in `sheets_create` per design §2.3 ("4-key body
 *  allowlist (LOCKED)" — Phase 1 ships flat single-sheet creation; multi-
 *  sheet input ≤10 entries is the upper bound during the transition window).
 *  Phase 2c will replace this with sheets_batch_update.addSheet. */
const SHEETS_CREATE_MAX_SHEETS = 10;
/** Closed-enum allowlist for `insert_data_option` per design §2.4. Default
 *  INSERT_ROWS (safer — pushes existing rows down). OVERWRITE opt-in for
 *  log-style writes. */
const SHEETS_INSERT_DATA_OPTION_ALLOWED: ReadonlySet<string> = new Set([
  "INSERT_ROWS",
  "OVERWRITE",
]);

export async function sheetsCreate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. Input validation (BEFORE tier check — v1.17 convention) ──
  // 4-key positive ALLOWLIST per design §2.3: title (required) / locale /
  // timeZone / sheets[] (each {properties: {title}} only; sheets[].data
  // REJECTED — see formula-smuggle bypass defense below).
  if (typeof args.title !== "string") {
    throw new Error("sheets_create: 'title' must be a string");
  }
  if (args.title.trim().length === 0) {
    throw new Error("sheets_create: 'title' must be non-empty after trim");
  }
  if (Buffer.byteLength(args.title, "utf-8") > SHEETS_TITLE_MAX_BYTES) {
    throw new Error(
      `sheets_create: 'title' exceeds ${SHEETS_TITLE_MAX_BYTES} bytes`,
    );
  }
  const title = args.title;

  let locale: string | undefined;
  if (args.locale !== undefined) {
    if (typeof args.locale !== "string") {
      throw new Error("sheets_create: 'locale' must be a string");
    }
    if (!SHEETS_LOCALE_RE.test(args.locale)) {
      throw new Error(
        "sheets_create: 'locale' must match BCP 47 form /^[a-zA-Z][a-zA-Z0-9_-]{0,15}$/",
      );
    }
    locale = args.locale;
  }

  let timeZone: string | undefined;
  if (args.timeZone !== undefined) {
    if (typeof args.timeZone !== "string") {
      throw new Error("sheets_create: 'timeZone' must be a string");
    }
    if (!SHEETS_TIMEZONE_RE.test(args.timeZone)) {
      throw new Error(
        "sheets_create: 'timeZone' must match IANA tz form /^[A-Za-z][A-Za-z0-9_/+-]{0,63}$/",
      );
    }
    timeZone = args.timeZone;
  }

  // sheets[] — strict per-element validation:
  //   - MUST be an array
  //   - ≤ SHEETS_CREATE_MAX_SHEETS entries
  //   - each element MUST be a plain object {properties: {title}}
  //   - per-sheet title MUST satisfy the same caps as the top-level title
  //
  // MED-1 (sec-rev hook #19): sheets[].data is the documented bypass vector
  // — Google Sheets API allows pre-populated cell data via
  // `sheets[i].data[].rowData[].values[].userEnteredValue.formulaValue`,
  // which would smuggle a formula past the v1.20 Phase 1 RAW HARD-LOCK on
  // values.append (sheets.create ignores valueInputOption entirely). The
  // handler defends by constructing each sheets[] entry LITERALLY with only
  // {properties: {title}} — anything else the caller supplied is silently
  // dropped (sentinel test pins this via JSON.stringify(requestBody)).
  let sheetsArray: Array<{ properties: { title: string } }> | undefined;
  if (args.sheets !== undefined) {
    if (!Array.isArray(args.sheets)) {
      throw new Error("sheets_create: 'sheets' must be an array");
    }
    if (args.sheets.length > SHEETS_CREATE_MAX_SHEETS) {
      throw new Error(
        `sheets_create: 'sheets' length exceeds ${SHEETS_CREATE_MAX_SHEETS}`,
      );
    }
    sheetsArray = [];
    for (let i = 0; i < args.sheets.length; i++) {
      const entry = args.sheets[i];
      if (
        entry === null ||
        typeof entry !== "object" ||
        Array.isArray(entry)
      ) {
        throw new Error(
          `sheets_create: 'sheets[${i}]' must be an object {properties: {title}}`,
        );
      }
      const props = (entry as Record<string, unknown>).properties;
      if (
        props === undefined ||
        props === null ||
        typeof props !== "object" ||
        Array.isArray(props)
      ) {
        throw new Error(
          `sheets_create: 'sheets[${i}].properties' must be an object {title}`,
        );
      }
      const sheetTitle = (props as Record<string, unknown>).title;
      if (typeof sheetTitle !== "string") {
        throw new Error(
          `sheets_create: 'sheets[${i}].properties.title' must be a string`,
        );
      }
      if (sheetTitle.trim().length === 0) {
        throw new Error(
          `sheets_create: 'sheets[${i}].properties.title' must be non-empty after trim`,
        );
      }
      if (Buffer.byteLength(sheetTitle, "utf-8") > SHEETS_TITLE_MAX_BYTES) {
        throw new Error(
          `sheets_create: 'sheets[${i}].properties.title' exceeds ${SHEETS_TITLE_MAX_BYTES} bytes`,
        );
      }
      // Construct LITERALLY — only {properties: {title}}. Drops any caller-
      // supplied sheets[i].data / sheets[i].charts / sheets[i].properties.
      // sheetId / etc. (30-field NEGATIVE sentinel enforced by construction).
      sheetsArray.push({ properties: { title: sheetTitle } });
    }
  }

  // ─── 2. Tier check (defense-in-depth — proxy normally hides write tools
  //                     at tier=read, this catches bypass) ──
  // sec-rev hook #11 (PR-prompt §9): audit meta recorded BEFORE the throw so
  // the auditEnd finally block has data — at this point we don't yet have a
  // real spreadsheet_id (Google assigns it), so use the sentinel hash for
  // BOTH the denied path AND the pre-SDK audit emission.
  const pendingHash = sha256Hex("<pending-create>");
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("sheetsMutationMeta", {
      target_spreadsheet_id_hash: pendingHash,
      operation: "create",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "sheets_create",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 3. Record audit meta BEFORE SDK call (2-step pattern — design §5) ──
  // Step 1: record with sentinel hash so a 5xx / network / quota failure
  // still leaves a forensic row showing "create was attempted". After SDK
  // success we re-record with the real ID hash (last-write-wins).
  ctx.audit.record("sheetsMutationMeta", {
    target_spreadsheet_id_hash: pendingHash,
    operation: "create",
    policy_decision: "allowed",
  });

  // ─── 4. Construct requestBody LITERALLY (4-key positive ALLOWLIST +
  //        30-field NEGATIVE sentinel enforced by construction) ──
  // Top-level: {properties, sheets?}; properties: {title, locale?, timeZone?};
  // sheets[i]: {properties: {title}}. NO spread, NO `additional fields. The
  // negative sentinel test in handlers.test.ts asserts NONE of the 30
  // forbidden fields from design §2.3 ever appears in the SDK call body.
  const properties: { title: string; locale?: string; timeZone?: string } = {
    title,
  };
  if (locale !== undefined) properties.locale = locale;
  if (timeZone !== undefined) properties.timeZone = timeZone;
  const requestBody: {
    properties: typeof properties;
    sheets?: Array<{ properties: { title: string } }>;
  } = { properties };
  if (sheetsArray !== undefined) requestBody.sheets = sheetsArray;

  // ─── 5. SDK call + Step 2 of 2-step pattern (patch hash with real ID) ──
  try {
    const sheets = sheetsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await sheets.spreadsheets.create({ requestBody });
    // Step 2: re-record with the REAL spreadsheet_id hash. Idempotent via
    // last-write-wins in with-context.ts capture. On 5xx the pendingHash
    // from Step 1 remains the recorded value — forensic clarity.
    const realId = res.data.spreadsheetId;
    if (typeof realId === "string") {
      ctx.audit.record("sheetsMutationMeta", {
        target_spreadsheet_id_hash: sha256Hex(realId),
        operation: "create",
        policy_decision: "allowed",
      });
    }
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "sheets_create", email: requireGoogle(ctx).accountId });
  }
}

export async function sheetsAppendValues(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. spreadsheet_id strict-parse (carry-forward Phase 1b-1 sec-rev #1) ──
  if (typeof args.spreadsheet_id !== "string") {
    throw new Error("sheets_append_values: 'spreadsheet_id' must be a string");
  }
  if (!SHEETS_SPREADSHEET_ID_RE.test(args.spreadsheet_id)) {
    throw new Error(
      "sheets_append_values: 'spreadsheet_id' must match /^[a-zA-Z0-9_-]{40,100}$/",
    );
  }
  const spreadsheetId = args.spreadsheet_id;

  // ─── 2. A1 range strict-parse (carry-forward Phase 1b-1 sec-rev #2) ──
  if (typeof args.range !== "string") {
    throw new Error("sheets_append_values: 'range' must be a string");
  }
  const parsed = parseA1Range(args.range);
  if (!parsed.valid || parsed.normalized === undefined) {
    throw new Error(
      `sheets_append_values: 'range' fails A1 notation strict-parse ` +
        `(≤${A1_MAX_LENGTH} bytes; see design §7 hostile-input table)`,
    );
  }
  const range = parsed.normalized;

  // ─── 3. values 2D array validation + per-cell + per-batch + cell-count
  //        caps (sec-rev hook #16) ──
  if (!Array.isArray(args.values)) {
    throw new Error("sheets_append_values: 'values' must be a 2D array");
  }
  let totalCells = 0;
  let totalBytes = 0;
  for (let r = 0; r < args.values.length; r++) {
    const row = args.values[r];
    if (!Array.isArray(row)) {
      throw new Error(
        `sheets_append_values: 'values[${r}]' must be an array of strings|numbers|booleans`,
      );
    }
    for (let c = 0; c < row.length; c++) {
      const cell = row[c];
      // Per design §2.4 "Type coercion": handler accepts string|number|boolean.
      // null/undefined/nested objects/arrays REJECTED. Pins the type cleanly
      // (no `unknown` widening) so future "tidying" PRs don't loosen the
      // surface.
      const t = typeof cell;
      if (t !== "string" && t !== "number" && t !== "boolean") {
        throw new Error(
          `sheets_append_values: 'values[${r}][${c}]' must be string|number|boolean`,
        );
      }
      // Only string cells need byte-length checking. Numbers + booleans are
      // bounded by their primitive sizes (no DoS surface).
      if (t === "string") {
        const cellBytes = Buffer.byteLength(cell as string, "utf-8");
        if (cellBytes > SHEETS_CELL_MAX_BYTES) {
          throw new Error(
            `sheets_append_values: 'values[${r}][${c}]' exceeds ${SHEETS_CELL_MAX_BYTES} bytes (per-cell cap)`,
          );
        }
        totalBytes += cellBytes;
        if (totalBytes > SHEETS_BATCH_MAX_BYTES) {
          throw new Error(
            `sheets_append_values: total batch payload exceeds ${SHEETS_BATCH_MAX_BYTES} bytes`,
          );
        }
      }
      totalCells++;
      if (totalCells > SHEETS_MAX_CELLS_PER_CALL) {
        throw new Error(
          `sheets_append_values: cell count exceeds ${SHEETS_MAX_CELLS_PER_CALL}`,
        );
      }
    }
  }

  // ─── 4. insert_data_option allowlist (closed enum; default INSERT_ROWS) ──
  let insertDataOption: "INSERT_ROWS" | "OVERWRITE" = "INSERT_ROWS";
  if (args.insert_data_option !== undefined) {
    if (
      typeof args.insert_data_option !== "string" ||
      !SHEETS_INSERT_DATA_OPTION_ALLOWED.has(args.insert_data_option)
    ) {
      throw new Error(
        "sheets_append_values: 'insert_data_option' must be one of {INSERT_ROWS, OVERWRITE}",
      );
    }
    insertDataOption = args.insert_data_option as "INSERT_ROWS" | "OVERWRITE";
  }

  // ─── 5. Tier check (defense-in-depth) ──
  // Audit meta recorded BEFORE the throw so the auditEnd finally block has
  // forensic data even on a denied path (sec-rev hook #11). Both the spreadsheet
  // ID hash AND the range hash are known up-front (unlike create which uses
  // the 2-step pattern).
  const spreadsheetHash = sha256Hex(spreadsheetId);
  const rangeHash = sha256Hex(range);
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("sheetsMutationMeta", {
      target_spreadsheet_id_hash: spreadsheetHash,
      target_range_hash: rangeHash,
      operation: "append_values",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "sheets_append_values",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 6. Record audit meta BEFORE SDK call (sec-rev hook #11) ──
  // Forensic-survives-failure: if the SDK 5xxs / hits quota / 403s, the
  // row STILL ships with the spreadsheet + range hashes so the operator can
  // correlate "Claude attempted to append to X" with subsequent retries.
  ctx.audit.record("sheetsMutationMeta", {
    target_spreadsheet_id_hash: spreadsheetHash,
    target_range_hash: rangeHash,
    operation: "append_values",
    policy_decision: "allowed",
  });

  // ─── 7. SDK call with `valueInputOption: "RAW"` HARD-LOCKED (Q3 LOCKED) ──
  // The literal string "RAW" is passed unconditionally — no caller override.
  // Sentinel test pins that the SDK args contain `valueInputOption: "RAW"`
  // regardless of what the caller supplied. Schema layer (registry.ts) also
  // pins `additionalProperties: false` so `value_input_option` is rejected
  // at the schema gate BEFORE the handler runs (defense-in-depth).
  try {
    const sheets = sheetsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await sheets.spreadsheets.values.append({
      spreadsheetId,
      range,
      valueInputOption: "RAW",
      insertDataOption,
      requestBody: { values: args.values as Array<Array<string | number | boolean>> },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "sheets_append_values", email: requireGoogle(ctx).accountId });
  }
}

/* ───────── v1.21 Phase 1b: sheets_update_values + sheets_batch_update (WRITE tier) ─────────
 *
 * See `docs/v1.21-sheets-phase2c.md` §2 / §3 / §4 / §10. Both handlers:
 *   - validate inputs BEFORE the tier check (v1.17 convention)
 *   - record `sheetsMutationMeta` BEFORE the SDK call (v1.17 §8 hook #7
 *     forensic-survives-failure invariant)
 *   - unlock `value_input_option: USER_ENTERED` (FIRST in SafeSpace) gated
 *     by the formula REJECT list (`src/sheets/formula-reject.ts`); RAW
 *     remains the DEFAULT (Q1 LOCKED — caller MUST explicitly opt in)
 *
 * `sheets_update_values` (§2.1): REPLACES cells in the target range. Higher-
 *   risk than append (silent data loss if range mis-typed). USER_ENTERED
 *   piped through formula REJECT per cell.
 *
 * `sheets_batch_update` (§2.2): FIRST per-RPC ALLOWLIST for Sheets — 7 types
 *   accepted + ~47 NEGATIVE sentinel rejected. `userEnteredValue` sub-key
 *   allowlist {stringValue, numberValue, boolValue} (hook #23 — formulaValue +
 *   errorValue HARD-REJECTED to close formula-bypass class).
 *   FieldMask sub-key allowlist (hook #19 — CLEAR-via-mask side-effect closed).
 *   `updateSpreadsheetProperties` HARD-REJECTED (hook #3 + #16 —
 *   `importFunctionsExternalUrlAccessAllowed` SSRF whitelist toggle closed).
 *
 * Sec-rev hooks #1-#23 from design §10 — see per-section comments below.
 */

/** Allowlist for `value_input_option` (Q1 LOCKED). RAW default; USER_ENTERED
 *  opt-in. Closed set — silent attack-surface expansion is rejected. */
const SHEETS_VALUE_INPUT_OPTION_ALLOWED: ReadonlySet<string> = new Set([
  "RAW",
  "USER_ENTERED",
]);

// v1.22 Phase 2 I-1 — `SHEETS_BATCH_UPDATE_MAX_REQUESTS` extracted to
// `src/sheets/limits.ts` (single source of truth alongside the 3 byte/cell
// caps). Layer 4 cap — checked FIRST per §8.3 cheapest-first ordering.
// Matches v1.17 `docs_modify_structured.requests.length ≤ 50` cap.

/** 7-type POSITIVE ALLOWLIST for `sheets_batch_update.requests[i]` (Q3
 *  LOCKED). Each request MUST have EXACTLY ONE key (§2.2 step 1) and that
 *  key MUST be in this Set. LOAD-BEARING gate (mirror v1.17
 *  `docs_modify_structured` 7-type positive pattern). Google adding a 53rd
 *  request type tomorrow → handler auto-rejects (would not match Set).
 *  v1.22 Phase 2 NEW-2 — wording sync from prior "6-type" doc-bug per
 *  design §2.4 (Set has 7 entries; mergeCells + unmergeCells counted as
 *  2 separate entries despite being grouped as one row in v1.21 design). */
const SHEETS_BATCH_UPDATE_ALLOWED_TYPES: ReadonlySet<string> = new Set([
  "addSheet",
  "deleteSheet",
  "updateSheetProperties",
  "repeatCell",
  "updateCells",
  "mergeCells",
  "unmergeCells",
]);

/** NEGATIVE sentinel list of known forbidden request types — enumerated
 *  individually against `googleapis@144` SDK `.d.ts` per design §2.2 +
 *  hook #18. Defense-in-depth snapshot regression sentinel: the positive
 *  ALLOWLIST above is the gate; this list is the audit trail for "what
 *  was previously rejected" when Google's API expands. Count: 47.
 *
 *  Critical types named explicitly per design §2.2 + §11 Risk 5:
 *    - `appendCells` (writeable sibling of updateCells)
 *    - `sortRange` (mass cell reorder blast-radius)
 *    - `findReplace` (mass pattern rewrite across entire sheet)
 *    - `pasteData` (large-payload write across arbitrary range)
 *    - `updateSpreadsheetProperties` (SSRF whitelist toggle —
 *      `importFunctionsExternalUrlAccessAllowed` — hook #3 + #16)
 *
 *  Order matches design §2.2 table grouping (charts / pivots / conditional
 *  formats / protected ranges / developer metadata / named ranges /
 *  banding / filters / sliders / dimensions / sheet movement /
 *  find-replace / sort / sheets / data validation / data sources / misc /
 *  sheet writes / sheet-level properties).
 */
const SHEETS_BATCH_UPDATE_FORBIDDEN_TYPES: readonly string[] = [
  // charts (5)
  "addChart",
  "updateChartSpec",
  "deleteEmbeddedObject",
  "updateEmbeddedObjectBorder",
  "updateEmbeddedObjectPosition",
  // pivots (2)
  "addPivotTable",
  "updatePivotTable",
  // conditional formats (3)
  "addConditionalFormatRule",
  "updateConditionalFormatRule",
  "deleteConditionalFormatRule",
  // protected ranges (3)
  "addProtectedRange",
  "updateProtectedRange",
  "deleteProtectedRange",
  // developer metadata (3)
  "createDeveloperMetadata",
  "updateDeveloperMetadata",
  "deleteDeveloperMetadata",
  // named ranges (3)
  "addNamedRange",
  "updateNamedRange",
  "deleteNamedRange",
  // banding (3)
  "addBanding",
  "updateBanding",
  "deleteBanding",
  // filters (5)
  "addFilterView",
  "updateFilterView",
  "duplicateFilterView",
  "clearBasicFilter",
  "setBasicFilter",
  // sliders (2)
  "addSlicer",
  "updateSlicerSpec",
  // dimensions (9)
  "addDimensionGroup",
  "deleteDimensionGroup",
  "updateDimensionGroup",
  "updateDimensionProperties",
  "autoResizeDimensions",
  "appendDimension",
  "insertDimension",
  "deleteDimension",
  "moveDimension",
  // sheet movement (3)
  "autoFill",
  "cutPaste",
  "copyPaste",
  // sheet shape (2)
  "insertRange",
  "deleteRange",
  // find-replace (1) — HIGH BLAST-RADIUS
  "findReplace",
  // sort (2) — HIGH BLAST-RADIUS
  "sortRange",
  "deleteDuplicates",
  // sheets (1)
  "duplicateSheet",
  // data validation (2)
  "setDataValidation",
  "clearDataValidation",
  // data sources (4)
  "addDataSource",
  "updateDataSource",
  "deleteDataSource",
  "refreshDataSource",
  // misc cell ops (4)
  "randomizeRange",
  "trimWhitespace",
  "textToColumns",
  "updateBorders",
  // large-payload write (1) — HIGH BLAST-RADIUS
  "pasteData",
  // sheet writes (1) — defense-in-depth (positive ALLOWLIST already excludes)
  "appendCells",
  // sheet-level properties (1) — SSRF whitelist toggle CLOSURE
  "updateSpreadsheetProperties",
];

/** Test-only re-exports (mirror v1.17 `_DOCS_MODIFY_*_FOR_TEST` pattern). */
export const _SHEETS_BATCH_UPDATE_ALLOWED_TYPES_FOR_TEST: ReadonlySet<string> =
  SHEETS_BATCH_UPDATE_ALLOWED_TYPES;
export const _SHEETS_BATCH_UPDATE_FORBIDDEN_TYPES_FOR_TEST: readonly string[] =
  SHEETS_BATCH_UPDATE_FORBIDDEN_TYPES;

/** FieldMask sub-allowlist for `updateSheetProperties.fields` (hook #19 P4).
 *  Closes the CLEAR-via-FieldMask side-effect class — caller could supply
 *  `properties: {sheetId, title}` (SET-side passes the sub-allowlist) but
 *  `fields: "tabColor,gridProperties"` (Google interprets as "clear these
 *  fields to default"). Must match design §2.2.X + P2 — addSheet aligns
 *  with v1.20 sheets_create.sheets[].properties allowlist. */
const SHEETS_UPDATE_SHEET_PROPERTIES_FIELDS_ALLOWED: ReadonlySet<string> = new Set([
  "title",
  "hidden",
]);

/** FieldMask sub-allowlist for `repeatCell.fields` + `updateCells.fields`
 *  (hook #19 P4 + P9). Matches the 5-sub-key `userEnteredFormat`
 *  allowlist + `userEnteredValue` accepted forms. Whole-object forms
 *  (`userEnteredFormat`) are accepted only when the cell value carries
 *  exclusively allowlisted sub-keys (handler validates). */
const SHEETS_CELL_FIELDS_ALLOWED: ReadonlySet<string> = new Set([
  "userEnteredFormat",
  "userEnteredFormat.backgroundColor",
  "userEnteredFormat.textFormat",
  "userEnteredFormat.textFormat.bold",
  "userEnteredFormat.textFormat.italic",
  "userEnteredFormat.textFormat.fontFamily",
  "userEnteredFormat.textFormat.fontSize",
  "userEnteredValue",
  "userEnteredValue.stringValue",
  "userEnteredValue.numberValue",
  "userEnteredValue.boolValue",
]);

/** Font-family allowlist regex (§2.2.Z) — conservative ASCII subset. */
const SHEETS_FONT_FAMILY_RE = /^[A-Za-z0-9 _-]{1,64}$/;

// v1.22 Phase 2 I-1 — v1.21's `SHEETS_PHASE2C_*` shadow constants were
// extracted to `src/sheets/limits.ts`. v1.21 had redeclared the v1.20
// values locally with `_PHASE2C_` prefix for self-contained Phase 1b
// reasoning (locality preference — Phase 2c handlers live 500+ lines
// below v1.20 handlers in the same file). Phase 2 consolidation imports
// the canonical names (`SHEETS_CELL_MAX_BYTES` / `SHEETS_BATCH_MAX_BYTES`
// / `SHEETS_MAX_CELLS_PER_CALL`) at the top of this file and uses them
// directly in the batch_update / update_values handlers below.

/** Parse + validate a FieldMask string against a per-type allowlist.
 *
 *  Per round-2 N3 carry-forward — parser regex pinned for defense-in-depth
 *  (handler-side per-component check is the load-bearing gate; the parser
 *  regex prevents legitimate-looking-but-malformed inputs from passing
 *  through with surprising semantics):
 *    - no whitespace anywhere
 *    - no empty components (rejects "title," / "title,,hidden" / "")
 *    - each dotted segment matches `[a-zA-Z][a-zA-Z0-9]*` (each segment
 *      MUST start with a letter; dotted-paths supported per design §2.2.X —
 *      Google accepts both comma-separated AND dotted-paths)
 *
 *  v1.22 Phase 2 NEW-3 (design §2.5) — regex tightened from
 *  `[a-zA-Z][a-zA-Z0-9.]*` (one-letter-start then free dots/digits) to a
 *  strict dotted-segment grammar. The old regex accepted:
 *    - trailing dot:    "title."
 *    - double dot:      "title..foo"
 *    - digit-start tail: "title.123abc"
 *  The handler-side per-component allowlist Set would still reject those
 *  at the next layer (load-bearing gate), but the regex tighten adds
 *  defense-in-depth so hostile inputs fail at the syntactic boundary with
 *  a cleaner error. ALL existing accept cases (e.g.,
 *  `userEnteredFormat.backgroundColor`,
 *  `userEnteredFormat.textFormat.bold`) STILL accept.
 *
 *  Returns the parsed component array on success; throws Error on any
 *  malformation OR any disallowed component. Hook #19 sentinel: hostile
 *  `"tabColor,gridProperties"` REJECTED; `"*"` mask-wildcard REJECTED.
 */
function parseAndValidateFieldMask(
  raw: unknown,
  allowed: ReadonlySet<string>,
  errorPrefix: string,
): string[] {
  if (typeof raw !== "string") {
    throw new Error(`${errorPrefix}.fields must be a string`);
  }
  if (raw.length === 0) {
    throw new Error(`${errorPrefix}.fields must be non-empty`);
  }
  // v1.22 Phase 2 NEW-3 — comma-separated dotted-paths, no whitespace,
  // no empty components, no wildcards. Each dotted segment must start
  // with a letter and contain only letters + digits (no leading dot, no
  // trailing dot, no double dot, no digit-start segment).
  const SHEETS_FIELD_MASK_RE =
    /^[a-zA-Z][a-zA-Z0-9]*(?:\.[a-zA-Z][a-zA-Z0-9]*)*(?:,[a-zA-Z][a-zA-Z0-9]*(?:\.[a-zA-Z][a-zA-Z0-9]*)*)*$/;
  if (!SHEETS_FIELD_MASK_RE.test(raw)) {
    throw new Error(
      `${errorPrefix}.fields fails FieldMask grammar (no whitespace / no empty components / no wildcards; comma-separated dotted-paths only)`,
    );
  }
  const components = raw.split(",");
  for (const c of components) {
    if (!allowed.has(c)) {
      // Echo the COMPONENT (closed-enum set per the per-type allowlist), NOT
      // user content. No PII echo (hook #13).
      throw new Error(
        `${errorPrefix}.fields path component '${c}' not in allowlist`,
      );
    }
  }
  return components;
}

/** v1.25 Phase 3 — `sheets_batch_update` GridRange + GridCoordinate
 *  sub-allowlist. Closes v1.21 M-1 carry-forward (3 cycles deferred:
 *  v1.22+v1.23+v1.24). Per design §2.3 + Q4 LOCKED.
 *
 *  PRE-Phase-3 state: `repeatCell.range` / `updateCells.range` /
 *  `updateCells.start` / `mergeCells.range` / `unmergeCells.range` only
 *  validated as "object, not null, not array" and then passed VERBATIM
 *  to the SDK. An attacker-controlled batch could smuggle non-standard
 *  GridRange fields (e.g., `evilField: "x"`) — Google's API ignores
 *  them today but a future API extension could surface UB.
 *
 *  Sub-allowlist (closed-set construction):
 *    - GridRange: {sheetId?, startRowIndex?, endRowIndex?, startColumnIndex?, endColumnIndex?}
 *      — all 5 keys OPTIONAL per Google's API (absence = "from start" /
 *      "to end" / first-tab); index fields are 0-based; sheetId is the
 *      integer tab ID (Q4 LOCKED — `sheetId` INCLUDED for integer-type
 *      pin closure of the string-smuggle bypass `sheetId: "injected"`).
 *    - GridCoordinate: {sheetId?, rowIndex?, columnIndex?} — design §2.3
 *      lists all 3 keys; integer-type pinned identically.
 *
 *  Validation defense — literal-construct return: validators DO NOT
 *  mutate the caller's object; they build a NEW object containing only
 *  allowlisted fields. Protects against prototype pollution + closes
 *  the "what if Google adds a new field someone could smuggle through"
 *  class. Mirrors v1.21 `validateUserEnteredValue` pattern.
 *
 *  Index ceiling 9999999 chosen to match design §2.3 (mirrors v1.20
 *  cell coordinate cap) — large enough for any real spreadsheet,
 *  bounded enough to short-circuit DoS via Number.MAX_SAFE_INTEGER.
 */
const SHEETS_GRID_RANGE_KEYS: ReadonlySet<string> = new Set([
  "sheetId",
  "startRowIndex",
  "endRowIndex",
  "startColumnIndex",
  "endColumnIndex",
]);
const SHEETS_GRID_COORDINATE_KEYS: ReadonlySet<string> = new Set([
  "sheetId",
  "rowIndex",
  "columnIndex",
]);
const SHEETS_GRID_INDEX_MAX = 9999999;

// v1.26 Phase 1 Item 4 (NEW-7) — `-0` integer-type pin: ACCEPTED per Q2
// LOCKED Option B. `Number.isInteger(-0) === true` and `-0 >= 0 === true`,
// so `-0` passes the validator. JavaScript canonicalizes `-0` to `0` for
// arithmetic + JSON serialization (`JSON.stringify(-0) === "0"`); Google
// Sheets API treats identically. Strict `Object.is(v, -0)` REJECT was
// REJECTED at design Q2 — risks breaking real callers passing `-0`
// accidentally from float math (e.g., `Math.floor(-0.5) === -1`, but
// `Math.floor(0.5) === 0` while subsequent arithmetic on derived values
// could yield `-0` paths).
function validateGridRange(
  raw: unknown,
  errorPrefix: string,
): Record<string, unknown> {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`${errorPrefix} must be an object (GridRange)`);
  }
  const obj = raw as Record<string, unknown>;
  // Reject unknown keys (closes opaque pass-through bypass).
  for (const k of Object.keys(obj)) {
    if (!SHEETS_GRID_RANGE_KEYS.has(k)) {
      throw new Error(
        `${errorPrefix}.${k} not in GridRange allowlist {sheetId, startRowIndex, endRowIndex, startColumnIndex, endColumnIndex}`,
      );
    }
  }
  // Integer-type pin per Q4 LOCKED (string / float / negative all REJECTED).
  if (obj.sheetId !== undefined) {
    if (
      typeof obj.sheetId !== "number" ||
      !Number.isInteger(obj.sheetId) ||
      obj.sheetId < 0
    ) {
      throw new Error(`${errorPrefix}.sheetId must be a non-negative integer`);
    }
  }
  for (const idxKey of [
    "startRowIndex",
    "endRowIndex",
    "startColumnIndex",
    "endColumnIndex",
  ]) {
    if (obj[idxKey] !== undefined) {
      const v = obj[idxKey];
      if (
        typeof v !== "number" ||
        !Number.isInteger(v) ||
        v < 0 ||
        v > SHEETS_GRID_INDEX_MAX
      ) {
        throw new Error(
          `${errorPrefix}.${idxKey} must be an integer in [0, ${SHEETS_GRID_INDEX_MAX}]`,
        );
      }
    }
  }
  // Literal-construct return — defense-in-depth against prototype pollution.
  const out: Record<string, unknown> = {};
  for (const k of SHEETS_GRID_RANGE_KEYS) {
    if (obj[k] !== undefined) out[k] = obj[k];
  }
  return out;
}

function validateGridCoordinate(
  raw: unknown,
  errorPrefix: string,
): Record<string, unknown> {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`${errorPrefix} must be an object (GridCoordinate)`);
  }
  const obj = raw as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (!SHEETS_GRID_COORDINATE_KEYS.has(k)) {
      throw new Error(
        `${errorPrefix}.${k} not in GridCoordinate allowlist {sheetId, rowIndex, columnIndex}`,
      );
    }
  }
  if (obj.sheetId !== undefined) {
    if (
      typeof obj.sheetId !== "number" ||
      !Number.isInteger(obj.sheetId) ||
      obj.sheetId < 0
    ) {
      throw new Error(`${errorPrefix}.sheetId must be a non-negative integer`);
    }
  }
  for (const idxKey of ["rowIndex", "columnIndex"]) {
    if (obj[idxKey] !== undefined) {
      const v = obj[idxKey];
      if (
        typeof v !== "number" ||
        !Number.isInteger(v) ||
        v < 0 ||
        v > SHEETS_GRID_INDEX_MAX
      ) {
        throw new Error(
          `${errorPrefix}.${idxKey} must be an integer in [0, ${SHEETS_GRID_INDEX_MAX}]`,
        );
      }
    }
  }
  // Literal-construct return.
  const out: Record<string, unknown> = {};
  for (const k of SHEETS_GRID_COORDINATE_KEYS) {
    if (obj[k] !== undefined) out[k] = obj[k];
  }
  return out;
}

/** v1.25 Phase 3 — GridRange + GridCoordinate sub-allowlist exports for
 *  sentinel tests (size + membership pinning). */
export const _SHEETS_GRID_RANGE_KEYS_FOR_TEST: ReadonlySet<string> =
  SHEETS_GRID_RANGE_KEYS;
export const _SHEETS_GRID_COORDINATE_KEYS_FOR_TEST: ReadonlySet<string> =
  SHEETS_GRID_COORDINATE_KEYS;

/** Build the literal `userEnteredValue` sub-object per the 3-key allowlist
 *  (hook #23 N4 BLOCKING — `formulaValue` + `errorValue` HARD-REJECTED
 *  pre-SDK). Returns the validated sub-object on success; throws Error on
 *  any disallowed key. ALSO runs formula REJECT on stringValue when
 *  `formulaRejectEnabled` (USER_ENTERED mode).
 *
 *  Returns `{value, isString, stringContent}` where isString indicates a
 *  stringValue cell (used for cell-byte counting) and stringContent is
 *  the raw string for formula REJECT iteration.
 */
function validateUserEnteredValue(
  raw: unknown,
  errorPrefix: string,
  formulaRejectEnabled: boolean,
):
  | {
      value: Record<string, unknown>;
      isString: boolean;
      stringContent?: string;
    }
  // v1.32 Phase 2 — REJECT shape threads the optional forensic homoglyph
  // source bytes alongside the function name so sheets_batch_update can wire
  // it to audit + MCPError (same PRESENCE-as-signal contract as the
  // sheets_update_values direct path). rejectedHomoglyphSource is ABSENT for
  // pure-ASCII attacks (Q3 LOCK byte-stability preserved downstream).
  | {
      rejectedFunction: string;
      // v1.41 — nested-smuggle discriminator (PRESENCE-as-signal; present only
      // on the STEP 5 path) threaded the same way as rejectedHomoglyphSource.
      rejectedNested?: true;
      rejectedHomoglyphSource?: string;
    } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`${errorPrefix}.userEnteredValue must be an object`);
  }
  const obj = raw as Record<string, unknown>;
  const keys = Object.keys(obj);
  if (keys.length !== 1) {
    throw new Error(
      `${errorPrefix}.userEnteredValue must have EXACTLY ONE key (got ${keys.length}) — Google's union type requires exactly one`,
    );
  }
  const key = keys[0]!;
  // hook #23 N4 BLOCKING — formulaValue + errorValue HARD-REJECTED to close
  // formula-bypass class. formulaValue would carry formula body WITHOUT `=`
  // prefix → formula REJECT regex `^[=+]\s*...` would MISS → complete bypass
  // of 11-function REJECT list (including LAMBDA closure from P3). Force
  // formulas through stringValue with `=` prefix which IS REJECT-list-gated.
  if (key === "formulaValue" || key === "errorValue") {
    throw new Error(
      `${errorPrefix}.userEnteredValue.${key} field not in allowlist — formulas MUST be supplied as stringValue starting with '=' which goes through formula REJECT list (design §10 hook #23 N4 BLOCKING)`,
    );
  }
  if (key !== "stringValue" && key !== "numberValue" && key !== "boolValue") {
    throw new Error(
      `${errorPrefix}.userEnteredValue.${key} not in allowlist {stringValue, numberValue, boolValue}`,
    );
  }
  const v = obj[key];
  if (key === "stringValue") {
    if (typeof v !== "string") {
      throw new Error(
        `${errorPrefix}.userEnteredValue.stringValue must be a string`,
      );
    }
    if (formulaRejectEnabled) {
      const r = validateCellValue(v);
      if (!r.ok) {
        // v1.32 Phase 2 — surface the forensic homoglyph source bytes via
        // PRESENCE-as-signal spread-when-defined (mirror formula-reject.ts:324).
        return {
          rejectedFunction: r.rejected_function,
          // v1.41 — thread the nested-smuggle discriminator (PRESENCE-as-
          // signal; Q3 order: nested before homoglyph source).
          ...(r.rejected_formula_nested !== undefined && {
            rejectedNested: r.rejected_formula_nested,
          }),
          ...(r.rejected_formula_homoglyph_source !== undefined && {
            rejectedHomoglyphSource: r.rejected_formula_homoglyph_source,
          }),
        };
      }
    }
    return {
      value: { stringValue: v },
      isString: true,
      stringContent: v,
    };
  }
  if (key === "numberValue") {
    if (typeof v !== "number") {
      throw new Error(
        `${errorPrefix}.userEnteredValue.numberValue must be a number`,
      );
    }
    return { value: { numberValue: v }, isString: false };
  }
  // boolValue
  if (typeof v !== "boolean") {
    throw new Error(
      `${errorPrefix}.userEnteredValue.boolValue must be a boolean`,
    );
  }
  return { value: { boolValue: v }, isString: false };
}

/** Build literal `userEnteredFormat` sub-object per the 5-sub-key allowlist
 *  (§2.2.Z). Returns the validated sub-object. */
function validateUserEnteredFormat(
  raw: unknown,
  errorPrefix: string,
): Record<string, unknown> {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error(`${errorPrefix}.userEnteredFormat must be an object`);
  }
  const obj = raw as Record<string, unknown>;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(obj)) {
    if (key === "backgroundColor") {
      const bg = obj.backgroundColor;
      if (typeof bg !== "object" || bg === null || Array.isArray(bg)) {
        throw new Error(
          `${errorPrefix}.userEnteredFormat.backgroundColor must be an object`,
        );
      }
      const bgo = bg as Record<string, unknown>;
      const color: Record<string, number> = {};
      for (const ck of Object.keys(bgo)) {
        if (ck !== "red" && ck !== "green" && ck !== "blue" && ck !== "alpha") {
          throw new Error(
            `${errorPrefix}.userEnteredFormat.backgroundColor.${ck} not in allowlist {red, green, blue, alpha}`,
          );
        }
        const cv = bgo[ck];
        if (typeof cv !== "number" || cv < 0 || cv > 1) {
          throw new Error(
            `${errorPrefix}.userEnteredFormat.backgroundColor.${ck} must be a number in [0, 1]`,
          );
        }
        color[ck] = cv;
      }
      out.backgroundColor = color;
    } else if (key === "textFormat") {
      const tf = obj.textFormat;
      if (typeof tf !== "object" || tf === null || Array.isArray(tf)) {
        throw new Error(
          `${errorPrefix}.userEnteredFormat.textFormat must be an object`,
        );
      }
      const tfo = tf as Record<string, unknown>;
      const text: Record<string, unknown> = {};
      for (const tk of Object.keys(tfo)) {
        if (tk === "bold" || tk === "italic") {
          const tv = tfo[tk];
          if (typeof tv !== "boolean") {
            throw new Error(
              `${errorPrefix}.userEnteredFormat.textFormat.${tk} must be a boolean`,
            );
          }
          text[tk] = tv;
        } else if (tk === "fontFamily") {
          const fv = tfo.fontFamily;
          if (typeof fv !== "string" || !SHEETS_FONT_FAMILY_RE.test(fv)) {
            throw new Error(
              `${errorPrefix}.userEnteredFormat.textFormat.fontFamily must match /^[A-Za-z0-9 _-]{1,64}$/`,
            );
          }
          text.fontFamily = fv;
        } else if (tk === "fontSize") {
          const fs = tfo.fontSize;
          if (typeof fs !== "number" || fs < 1 || fs > 400) {
            throw new Error(
              `${errorPrefix}.userEnteredFormat.textFormat.fontSize must be a number in [1, 400]`,
            );
          }
          text.fontSize = fs;
        } else {
          throw new Error(
            `${errorPrefix}.userEnteredFormat.textFormat.${tk} not in allowlist {bold, italic, fontFamily, fontSize}`,
          );
        }
      }
      out.textFormat = text;
    } else {
      throw new Error(
        `${errorPrefix}.userEnteredFormat.${key} not in allowlist {backgroundColor, textFormat}`,
      );
    }
  }
  return out;
}

/**
 * `sheets_update_values` — WRITE tier. REPLACES cells in the target range.
 * USER_ENTERED gated by formula REJECT list (Q1 LOCKED — FIRST USER_ENTERED
 * unlock in SafeSpace).
 *
 * Handler order (v1.17 convention + Q4 LOCKED — cheap caller-bug rejections
 * happen first; formula REJECT before tier so the audit row carries the
 * forensic policy_decision even on read-tier denial):
 *   1. spreadsheet_id strict-parse
 *   2. A1 range strict-parse
 *   3. values 2D array shape + per-cell type + cell content caps
 *   4. value_input_option allowlist (closed-enum)
 *   5. Formula REJECT (USER_ENTERED only) — audit BEFORE throw (hook #11)
 *   6. Tier check — audit BEFORE throw
 *   7. Audit allowed BEFORE SDK call (hook #11 forensic-survives-failure)
 *   8. SDK call — MCPError pass-through before mapGoogleError
 */
export async function sheetsUpdateValues(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. spreadsheet_id strict-parse (carry-forward Phase 1b-1 hook #1) ──
  if (typeof args.spreadsheet_id !== "string") {
    throw new Error("sheets_update_values: 'spreadsheet_id' must be a string");
  }
  if (!SHEETS_SPREADSHEET_ID_RE.test(args.spreadsheet_id)) {
    throw new Error(
      "sheets_update_values: 'spreadsheet_id' must match /^[a-zA-Z0-9_-]{40,100}$/",
    );
  }
  const spreadsheetId = args.spreadsheet_id;

  // ─── 2. A1 range strict-parse (carry-forward Phase 1b-1 hook #2) ──
  if (typeof args.range !== "string") {
    throw new Error("sheets_update_values: 'range' must be a string");
  }
  const parsed = parseA1Range(args.range);
  if (!parsed.valid || parsed.normalized === undefined) {
    throw new Error(
      `sheets_update_values: 'range' fails A1 notation strict-parse ` +
        `(≤${A1_MAX_LENGTH} bytes; see design §7 hostile-input table)`,
    );
  }
  const range = parsed.normalized;

  // ─── 3. values 2D array validation + per-cell + per-batch + cell-count
  //        caps (hook #6) ──
  if (!Array.isArray(args.values)) {
    throw new Error("sheets_update_values: 'values' must be a 2D array");
  }
  let totalCells = 0;
  let totalBytes = 0;
  for (let r = 0; r < args.values.length; r++) {
    const row = args.values[r];
    if (!Array.isArray(row)) {
      throw new Error(
        `sheets_update_values: 'values[${r}]' must be an array of strings|numbers|booleans`,
      );
    }
    for (let c = 0; c < row.length; c++) {
      const cell = row[c];
      const t = typeof cell;
      if (t !== "string" && t !== "number" && t !== "boolean") {
        throw new Error(
          `sheets_update_values: 'values[${r}][${c}]' must be string|number|boolean`,
        );
      }
      if (t === "string") {
        const cellBytes = Buffer.byteLength(cell as string, "utf-8");
        if (cellBytes > SHEETS_CELL_MAX_BYTES) {
          throw new Error(
            `sheets_update_values: 'values[${r}][${c}]' exceeds ${SHEETS_CELL_MAX_BYTES} bytes (per-cell cap)`,
          );
        }
        totalBytes += cellBytes;
        if (totalBytes > SHEETS_BATCH_MAX_BYTES) {
          throw new Error(
            `sheets_update_values: total batch payload exceeds ${SHEETS_BATCH_MAX_BYTES} bytes`,
          );
        }
      }
      totalCells++;
      if (totalCells > SHEETS_MAX_CELLS_PER_CALL) {
        throw new Error(
          `sheets_update_values: cell count exceeds ${SHEETS_MAX_CELLS_PER_CALL}`,
        );
      }
    }
  }

  // ─── 4. value_input_option allowlist (closed-enum; default RAW — Q1 LOCKED) ──
  let valueInputOption: "RAW" | "USER_ENTERED" = "RAW";
  if (args.value_input_option !== undefined) {
    if (
      typeof args.value_input_option !== "string" ||
      !SHEETS_VALUE_INPUT_OPTION_ALLOWED.has(args.value_input_option)
    ) {
      throw new Error(
        "sheets_update_values: 'value_input_option' must be one of {RAW, USER_ENTERED}",
      );
    }
    valueInputOption = args.value_input_option as "RAW" | "USER_ENTERED";
  }

  // ─── 5. Formula REJECT (USER_ENTERED only) — audit BEFORE throw (hook #11) ──
  // The audit row carries the forensic policy_decision + rejected function
  // name BEFORE the MCPError is thrown so the auditEnd finally block has
  // forensic data even on a denied path (mirror v1.16 PR #135 INFO-4
  // forensic-survives-failure pattern).
  const spreadsheetHash = sha256Hex(spreadsheetId);
  const rangeHash = sha256Hex(range);
  if (valueInputOption === "USER_ENTERED") {
    for (let r = 0; r < args.values.length; r++) {
      const row = args.values[r];
      for (let c = 0; c < row.length; c++) {
        const cell = row[c];
        const result = validateCellValue(cell);
        if (!result.ok) {
          ctx.audit.record("sheetsMutationMeta", {
            target_spreadsheet_id_hash: spreadsheetHash,
            target_range_hash: rangeHash,
            operation: "update_values",
            policy_decision: "denied_formula_rejected",
            rejected_formula_function: result.rejected_function,
            // v1.41 — nested-smuggle discriminator (Q3 order: after function,
            // before homoglyph source). ABSENT for direct STEP 4 attacks.
            ...(result.rejected_formula_nested !== undefined && {
              rejected_formula_nested: result.rejected_formula_nested,
            }),
            // v1.32 Phase 2 — forensic source bytes (PRESENCE-as-signal:
            // ABSENT for ASCII attacks → audit row byte-identical to v1.31).
            ...(result.rejected_formula_homoglyph_source !== undefined && {
              rejected_formula_homoglyph_source:
                result.rejected_formula_homoglyph_source,
            }),
          });
          throw new MCPError("formula_rejected", {
            reason: "formula_rejected",
            rejected_formula_function: result.rejected_function,
            // v1.41 — nested-smuggle discriminator on the caller-facing error
            // (Q3 order: after function, before homoglyph). ABSENT for direct.
            ...(result.rejected_formula_nested !== undefined && {
              rejected_formula_nested: result.rejected_formula_nested,
            }),
            // v1.32 Phase 2 — same forensic field on the caller-facing error
            // (no PII echo; bytes are the rejected identifier, never the value).
            ...(result.rejected_formula_homoglyph_source !== undefined && {
              rejected_formula_homoglyph_source:
                result.rejected_formula_homoglyph_source,
            }),
          });
        }
      }
    }
  }

  // ─── 6. Tier check (defense-in-depth) ──
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("sheetsMutationMeta", {
      target_spreadsheet_id_hash: spreadsheetHash,
      target_range_hash: rangeHash,
      operation: "update_values",
      policy_decision: "denied_tier",
    });
    throw new MCPError("scope_mismatch", {
      tool: "sheets_update_values",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 7. Record audit meta BEFORE SDK call (hook #11) ──
  ctx.audit.record("sheetsMutationMeta", {
    target_spreadsheet_id_hash: spreadsheetHash,
    target_range_hash: rangeHash,
    operation: "update_values",
    policy_decision: "allowed",
  });

  // ─── 8. SDK call — `valueInputOption` is RAW or USER_ENTERED (post REJECT) ──
  try {
    const sheets = sheetsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await sheets.spreadsheets.values.update({
      spreadsheetId,
      range,
      valueInputOption,
      requestBody: {
        values: args.values as Array<Array<string | number | boolean>>,
      },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "sheets_update_values", email: requireGoogle(ctx).accountId });
  }
}

/**
 * `sheets_batch_update` — WRITE tier. FIRST per-RPC ALLOWLIST for Sheets.
 *
 * 7-type positive ALLOWLIST (Q3 LOCKED) + ~47-type NEGATIVE sentinel.
 * Each request MUST have EXACTLY ONE key in the 7-type allowlist + per-type
 * sub-allowlist (handler constructs SDK request LITERALLY — no spread).
 *
 * Cell content caps (Q7 LOCKED) cumulative across all requests in the batch.
 * Check ordering cheapest-first per §8.3:
 *   Layer 4 (50-request cap) — checked FIRST (O(1))
 *   Layer 1 (per-cell 50KB)  — during iteration
 *   Layer 3 (per-batch 100KB) — accumulated during iteration
 *   Layer 2 (10K cell-count) — accumulated during iteration
 *
 * USER_ENTERED gated by formula REJECT list on every `stringValue` cell
 * (Q1 LOCKED). `formulaValue` + `errorValue` HARD-REJECTED (hook #23 N4
 * BLOCKING — closes the formula-bypass class).
 *
 * `updateSpreadsheetProperties` HARD-REJECTED (hook #3 + #16 — closes the
 * SSRF whitelist toggle `importFunctionsExternalUrlAccessAllowed`).
 *
 * `includeSpreadsheetInResponse` HARD-OMITTED (hook #15 — handler does NOT
 * accept this input key; OMISSION is the gate, matches v1.17
 * docs_modify_structured `include_document_in_response: false` precedent).
 */
export async function sheetsBatchUpdate(
  ctx: ToolContext,
  args: Record<string, unknown>,
): Promise<unknown> {
  // ─── 1. spreadsheet_id strict-parse ──────────────────────────────────────
  if (typeof args.spreadsheet_id !== "string") {
    throw new Error("sheets_batch_update: 'spreadsheet_id' must be a string");
  }
  if (!SHEETS_SPREADSHEET_ID_RE.test(args.spreadsheet_id)) {
    throw new Error(
      "sheets_batch_update: 'spreadsheet_id' must match /^[a-zA-Z0-9_-]{40,100}$/",
    );
  }
  const spreadsheetId = args.spreadsheet_id;

  // ─── 2. requests array shape ───────────────────────────────────────────
  if (!Array.isArray(args.requests)) {
    throw new Error("sheets_batch_update: 'requests' must be an array");
  }
  if (args.requests.length === 0) {
    throw new Error(
      "sheets_batch_update: 'requests' array must be non-empty",
    );
  }
  // Layer 4 cap (cheapest-first per §8.3) — request-count cap BEFORE any
  // per-request iteration. Single property access on the input array.
  if (args.requests.length > SHEETS_BATCH_UPDATE_MAX_REQUESTS) {
    throw new Error(
      `sheets_batch_update: at most ${SHEETS_BATCH_UPDATE_MAX_REQUESTS} requests per call (got ${args.requests.length})`,
    );
  }

  // ─── 3. value_input_option allowlist (Q1 LOCKED; default RAW) ──────────
  let valueInputOption: "RAW" | "USER_ENTERED" = "RAW";
  if (args.value_input_option !== undefined) {
    if (
      typeof args.value_input_option !== "string" ||
      !SHEETS_VALUE_INPUT_OPTION_ALLOWED.has(args.value_input_option)
    ) {
      throw new Error(
        "sheets_batch_update: 'value_input_option' must be one of {RAW, USER_ENTERED}",
      );
    }
    valueInputOption = args.value_input_option as "RAW" | "USER_ENTERED";
  }
  const formulaRejectEnabled = valueInputOption === "USER_ENTERED";

  // ─── 4. Per-request validation + per-type sub-allowlist construction ──
  // Build the SDK requests array LITERALLY (no spread, no pass-through).
  // Each request constructed key-by-key against the per-type sub-allowlist.
  // Cell content caps accumulated cumulatively per §8.3 (Layer 1/2/3).
  const sdkRequests: Array<Record<string, unknown>> = [];
  const requestTypes: string[] = [];
  let totalCellWrites = 0;
  let totalCells = 0;
  let totalBytes = 0;
  const spreadsheetHash = sha256Hex(spreadsheetId);

  // Track a denied_formula_rejected throw with audit-before-throw semantics.
  // Iteration may throw partway through; outer catch wires the audit row.
  let denialFn: string | undefined;
  // v1.32 Phase 2 — forensic homoglyph source bytes captured alongside the
  // rejected function name; PRESENCE-as-signal (undefined for ASCII attacks).
  let denialHomoglyphSource: string | undefined;
  // v1.41 — nested-smuggle discriminator captured alongside the rejected
  // function name; PRESENCE-as-signal (undefined ⇒ direct STEP 4 attack).
  let denialNested: true | undefined;

  const errPrefix = (i: number, t: string) => `sheets_batch_update.requests[${i}].${t}`;

  for (let i = 0; i < args.requests.length; i++) {
    const req = args.requests[i];
    if (typeof req !== "object" || req === null || Array.isArray(req)) {
      throw new Error(
        `sheets_batch_update: requests[${i}] must be an object`,
      );
    }
    const keys = Object.keys(req as Record<string, unknown>);
    if (keys.length !== 1) {
      // Hook #20 P5 / handler-side single-key gate. Mirror v1.17
      // docs_modify_structured per-request single-key gate.
      throw new Error(
        `sheets_batch_update: requests[${i}] must have EXACTLY ONE key (got ${keys.length}) — multi-key smuggle defense`,
      );
    }
    const type = keys[0]!;
    // hook #2 + hook #18 — positive ALLOWLIST is LOAD-BEARING; NEGATIVE
    // sentinel is the snapshot regression. Google adding a 53rd request
    // type → handler auto-rejects.
    if (!SHEETS_BATCH_UPDATE_ALLOWED_TYPES.has(type)) {
      throw new Error(
        `sheets_batch_update: requests[${i}] type '${type}' not in allowlist {addSheet, deleteSheet, updateSheetProperties, repeatCell, updateCells, mergeCells, unmergeCells}`,
      );
    }
    requestTypes.push(type);
    const body = (req as Record<string, unknown>)[type];
    if (typeof body !== "object" || body === null || Array.isArray(body)) {
      throw new Error(
        `${errPrefix(i, type)} must be an object`,
      );
    }
    const bodyObj = body as Record<string, unknown>;

    // ─── 4a. Per-type sub-allowlist construction ──────────────────────────
    if (type === "addSheet") {
      // P2 tightened — cross-tool symmetry with v1.20 sheets_create.sheets[]
      // (hook #22 + Risk 8). Only {properties: {title}} accepted.
      const props = bodyObj.properties;
      if (typeof props !== "object" || props === null || Array.isArray(props)) {
        throw new Error(
          `${errPrefix(i, type)}.properties must be an object {title}`,
        );
      }
      const title = (props as Record<string, unknown>).title;
      if (typeof title !== "string") {
        throw new Error(
          `${errPrefix(i, type)}.properties.title must be a string`,
        );
      }
      if (title.trim().length === 0) {
        throw new Error(
          `${errPrefix(i, type)}.properties.title must be non-empty after trim`,
        );
      }
      if (Buffer.byteLength(title, "utf-8") > 256) {
        throw new Error(
          `${errPrefix(i, type)}.properties.title exceeds 256 bytes`,
        );
      }
      sdkRequests.push({ addSheet: { properties: { title } } });
    } else if (type === "deleteSheet") {
      const sheetId = bodyObj.sheetId;
      if (typeof sheetId !== "number" || !Number.isInteger(sheetId)) {
        throw new Error(
          `${errPrefix(i, type)}.sheetId must be an integer`,
        );
      }
      sdkRequests.push({ deleteSheet: { sheetId } });
    } else if (type === "updateSheetProperties") {
      const props = bodyObj.properties;
      if (typeof props !== "object" || props === null || Array.isArray(props)) {
        throw new Error(
          `${errPrefix(i, type)}.properties must be an object`,
        );
      }
      const propsObj = props as Record<string, unknown>;
      const literalProps: Record<string, unknown> = {};
      // sheetId REQUIRED (target identifier)
      const sheetId = propsObj.sheetId;
      if (typeof sheetId !== "number" || !Number.isInteger(sheetId)) {
        throw new Error(
          `${errPrefix(i, type)}.properties.sheetId must be an integer`,
        );
      }
      literalProps.sheetId = sheetId;
      // title OPTIONAL
      if (propsObj.title !== undefined) {
        if (typeof propsObj.title !== "string") {
          throw new Error(
            `${errPrefix(i, type)}.properties.title must be a string`,
          );
        }
        if (Buffer.byteLength(propsObj.title, "utf-8") > 256) {
          throw new Error(
            `${errPrefix(i, type)}.properties.title exceeds 256 bytes`,
          );
        }
        literalProps.title = propsObj.title;
      }
      // hidden OPTIONAL
      if (propsObj.hidden !== undefined) {
        if (typeof propsObj.hidden !== "boolean") {
          throw new Error(
            `${errPrefix(i, type)}.properties.hidden must be a boolean`,
          );
        }
        literalProps.hidden = propsObj.hidden;
      }
      // Reject any other property key (cross-tool symmetry with addSheet)
      for (const k of Object.keys(propsObj)) {
        if (k !== "sheetId" && k !== "title" && k !== "hidden") {
          throw new Error(
            `${errPrefix(i, type)}.properties.${k} not in allowlist {sheetId, title, hidden}`,
          );
        }
      }
      // FieldMask validation (hook #19 P4) — CLEAR-via-mask side-effect
      // closed by per-component allowlist
      parseAndValidateFieldMask(
        bodyObj.fields,
        SHEETS_UPDATE_SHEET_PROPERTIES_FIELDS_ALLOWED,
        errPrefix(i, type),
      );
      sdkRequests.push({
        updateSheetProperties: {
          properties: literalProps,
          fields: bodyObj.fields as string,
        },
      });
    } else if (type === "repeatCell") {
      // range REQUIRED — v1.25 Phase 3 GridRange sub-allowlist (5-key
      // {sheetId?, startRowIndex?, endRowIndex?, startColumnIndex?,
      // endColumnIndex?}; integer-type pin + literal-construct return).
      const validatedRange = validateGridRange(
        bodyObj.range,
        `${errPrefix(i, type)}.range`,
      );
      // cell REQUIRED
      const cellObj = bodyObj.cell;
      if (
        typeof cellObj !== "object" ||
        cellObj === null ||
        Array.isArray(cellObj)
      ) {
        throw new Error(
          `${errPrefix(i, type)}.cell must be an object`,
        );
      }
      const cellRec = cellObj as Record<string, unknown>;
      const literalCell: Record<string, unknown> = {};
      // Optional userEnteredValue (3-key allowlist; hook #23 BLOCKING)
      if (cellRec.userEnteredValue !== undefined) {
        const v = validateUserEnteredValue(
          cellRec.userEnteredValue,
          `${errPrefix(i, type)}.cell`,
          formulaRejectEnabled,
        );
        if ("rejectedFunction" in v) {
          denialFn = v.rejectedFunction;
          // v1.32 Phase 2 — capture forensic source bytes (undefined for ASCII).
          denialHomoglyphSource = v.rejectedHomoglyphSource;
          // v1.41 — capture nested-smuggle discriminator (undefined for direct).
          denialNested = v.rejectedNested;
          break;
        }
        literalCell.userEnteredValue = v.value;
        // Cell counting (every cell touched counts toward layer-2/3 caps)
        if (v.isString && v.stringContent !== undefined) {
          const cb = Buffer.byteLength(v.stringContent, "utf-8");
          if (cb > SHEETS_CELL_MAX_BYTES) {
            throw new Error(
              `${errPrefix(i, type)}.cell.userEnteredValue.stringValue exceeds ${SHEETS_CELL_MAX_BYTES} bytes (per-cell cap)`,
            );
          }
          totalBytes += cb;
          if (totalBytes > SHEETS_BATCH_MAX_BYTES) {
            throw new Error(
              `sheets_batch_update: total batch payload exceeds ${SHEETS_BATCH_MAX_BYTES} bytes (cumulative across requests)`,
            );
          }
        }
        totalCells++;
        totalCellWrites++;
        if (totalCells > SHEETS_MAX_CELLS_PER_CALL) {
          throw new Error(
            `sheets_batch_update: cell count exceeds ${SHEETS_MAX_CELLS_PER_CALL} (cumulative across requests)`,
          );
        }
      }
      // Optional userEnteredFormat (5-sub-key allowlist; §2.2.Z)
      if (cellRec.userEnteredFormat !== undefined) {
        literalCell.userEnteredFormat = validateUserEnteredFormat(
          cellRec.userEnteredFormat,
          `${errPrefix(i, type)}.cell`,
        );
      }
      // Reject other cell keys
      for (const k of Object.keys(cellRec)) {
        if (k !== "userEnteredValue" && k !== "userEnteredFormat") {
          throw new Error(
            `${errPrefix(i, type)}.cell.${k} not in allowlist {userEnteredValue, userEnteredFormat}`,
          );
        }
      }
      // FieldMask validation (hook #19 P4)
      parseAndValidateFieldMask(
        bodyObj.fields,
        SHEETS_CELL_FIELDS_ALLOWED,
        errPrefix(i, type),
      );
      sdkRequests.push({
        repeatCell: {
          range: validatedRange,
          cell: literalCell,
          fields: bodyObj.fields as string,
        },
      });
    } else if (type === "updateCells") {
      // P8 range/start mutex — EXACTLY ONE of range OR start required
      const hasRange = bodyObj.range !== undefined;
      const hasStart = bodyObj.start !== undefined;
      if (hasRange === hasStart) {
        throw new Error(
          `${errPrefix(i, type)} must supply EXACTLY ONE of 'range' (GridRange) OR 'start' (GridCoordinate) — got ${hasRange && hasStart ? "both" : "neither"}`,
        );
      }
      // v1.25 Phase 3 — GridRange / GridCoordinate sub-allowlist on the
      // XOR branches (5-key GridRange OR 3-key GridCoordinate; integer-type
      // pin + literal-construct return).
      let rangeOrStart: { range?: unknown; start?: unknown };
      if (hasRange) {
        rangeOrStart = {
          range: validateGridRange(
            bodyObj.range,
            `${errPrefix(i, type)}.range`,
          ),
        };
      } else {
        rangeOrStart = {
          start: validateGridCoordinate(
            bodyObj.start,
            `${errPrefix(i, type)}.start`,
          ),
        };
      }
      // rows REQUIRED — array of {values: [{userEnteredValue?, userEnteredFormat?}]}
      const rows = bodyObj.rows;
      if (!Array.isArray(rows)) {
        throw new Error(
          `${errPrefix(i, type)}.rows must be an array`,
        );
      }
      const literalRows: Array<{ values: Array<Record<string, unknown>> }> = [];
      for (let r = 0; r < rows.length; r++) {
        const row = rows[r];
        if (typeof row !== "object" || row === null || Array.isArray(row)) {
          throw new Error(
            `${errPrefix(i, type)}.rows[${r}] must be an object {values: []}`,
          );
        }
        const valuesArr = (row as Record<string, unknown>).values;
        if (!Array.isArray(valuesArr)) {
          throw new Error(
            `${errPrefix(i, type)}.rows[${r}].values must be an array`,
          );
        }
        const literalValues: Array<Record<string, unknown>> = [];
        for (let c = 0; c < valuesArr.length; c++) {
          const cellPrefix = `${errPrefix(i, type)}.rows[${r}].values[${c}]`;
          const cellRec = valuesArr[c];
          if (
            typeof cellRec !== "object" ||
            cellRec === null ||
            Array.isArray(cellRec)
          ) {
            throw new Error(`${cellPrefix} must be an object`);
          }
          const cellObj = cellRec as Record<string, unknown>;
          const literalCell: Record<string, unknown> = {};
          if (cellObj.userEnteredValue !== undefined) {
            const v = validateUserEnteredValue(
              cellObj.userEnteredValue,
              cellPrefix,
              formulaRejectEnabled,
            );
            if ("rejectedFunction" in v) {
              denialFn = v.rejectedFunction;
              // v1.32 Phase 2 — capture forensic source bytes (undefined for ASCII).
              denialHomoglyphSource = v.rejectedHomoglyphSource;
              // v1.41 — capture nested-smuggle discriminator (undefined for direct).
              denialNested = v.rejectedNested;
              break;
            }
            literalCell.userEnteredValue = v.value;
            // Cell content caps
            if (v.isString && v.stringContent !== undefined) {
              const cb = Buffer.byteLength(v.stringContent, "utf-8");
              if (cb > SHEETS_CELL_MAX_BYTES) {
                throw new Error(
                  `${cellPrefix}.userEnteredValue.stringValue exceeds ${SHEETS_CELL_MAX_BYTES} bytes (per-cell cap)`,
                );
              }
              totalBytes += cb;
              if (totalBytes > SHEETS_BATCH_MAX_BYTES) {
                throw new Error(
                  `sheets_batch_update: total batch payload exceeds ${SHEETS_BATCH_MAX_BYTES} bytes (cumulative across requests)`,
                );
              }
            }
            totalCells++;
            totalCellWrites++;
            if (totalCells > SHEETS_MAX_CELLS_PER_CALL) {
              throw new Error(
                `sheets_batch_update: cell count exceeds ${SHEETS_MAX_CELLS_PER_CALL} (cumulative across requests)`,
              );
            }
          }
          if (cellObj.userEnteredFormat !== undefined) {
            literalCell.userEnteredFormat = validateUserEnteredFormat(
              cellObj.userEnteredFormat,
              cellPrefix,
            );
          }
          for (const k of Object.keys(cellObj)) {
            if (k !== "userEnteredValue" && k !== "userEnteredFormat") {
              throw new Error(
                `${cellPrefix}.${k} not in allowlist {userEnteredValue, userEnteredFormat}`,
              );
            }
          }
          literalValues.push(literalCell);
        }
        if (denialFn !== undefined) break;
        literalRows.push({ values: literalValues });
      }
      if (denialFn !== undefined) break;
      // FieldMask validation (hook #19 P4)
      parseAndValidateFieldMask(
        bodyObj.fields,
        SHEETS_CELL_FIELDS_ALLOWED,
        errPrefix(i, type),
      );
      sdkRequests.push({
        updateCells: {
          ...rangeOrStart,
          rows: literalRows,
          fields: bodyObj.fields as string,
        },
      });
    } else if (type === "mergeCells") {
      // v1.25 Phase 3 — GridRange sub-allowlist.
      const validatedRange = validateGridRange(
        bodyObj.range,
        `${errPrefix(i, type)}.range`,
      );
      const literalMerge: Record<string, unknown> = {
        range: validatedRange,
      };
      if (bodyObj.mergeType !== undefined) {
        if (
          bodyObj.mergeType !== "MERGE_ALL" &&
          bodyObj.mergeType !== "MERGE_COLUMNS" &&
          bodyObj.mergeType !== "MERGE_ROWS"
        ) {
          throw new Error(
            `${errPrefix(i, type)}.mergeType must be one of {MERGE_ALL, MERGE_COLUMNS, MERGE_ROWS}`,
          );
        }
        literalMerge.mergeType = bodyObj.mergeType;
      }
      sdkRequests.push({ mergeCells: literalMerge });
    } else if (type === "unmergeCells") {
      // v1.25 Phase 3 — GridRange sub-allowlist.
      const validatedRange = validateGridRange(
        bodyObj.range,
        `${errPrefix(i, type)}.range`,
      );
      sdkRequests.push({
        unmergeCells: { range: validatedRange },
      });
    }
  }

  // ─── 5. Formula REJECT denial path (audit BEFORE throw) ──────────────
  // Mirror v1.17 docs_modify_structured + v1.21 sheets_update_values
  // forensic-survives-failure pattern. The denial fires when ANY cell in
  // ANY request triggers the REJECT — first match wins (rest of iteration
  // breaks out early).
  if (denialFn !== undefined) {
    ctx.audit.record("sheetsMutationMeta", {
      target_spreadsheet_id_hash: spreadsheetHash,
      operation: "batch_update",
      policy_decision: "denied_formula_rejected",
      request_types_csv: requestTypes.join(","),
      rejected_formula_function: denialFn,
      // v1.41 — nested-smuggle discriminator (Q3 order: after function,
      // before homoglyph source). ABSENT for direct STEP 4 attacks.
      ...(denialNested !== undefined && {
        rejected_formula_nested: denialNested,
      }),
      // v1.32 Phase 2 — forensic source bytes (PRESENCE-as-signal:
      // ABSENT for ASCII attacks → audit row byte-identical to v1.31).
      ...(denialHomoglyphSource !== undefined && {
        rejected_formula_homoglyph_source: denialHomoglyphSource,
      }),
    });
    throw new MCPError("formula_rejected", {
      reason: "formula_rejected",
      rejected_formula_function: denialFn,
      // v1.41 — nested-smuggle discriminator on the caller-facing error
      // (Q3 order: after function, before homoglyph). ABSENT for direct.
      ...(denialNested !== undefined && {
        rejected_formula_nested: denialNested,
      }),
      // v1.32 Phase 2 — same forensic field on the caller-facing error
      // (no PII echo; bytes are the rejected identifier, never the value).
      ...(denialHomoglyphSource !== undefined && {
        rejected_formula_homoglyph_source: denialHomoglyphSource,
      }),
    });
  }

  // ─── 6. Tier check (defense-in-depth) — audit BEFORE throw ───────────
  const tier = ctx.tier;
  if (tier === "read") {
    ctx.audit.record("sheetsMutationMeta", {
      target_spreadsheet_id_hash: spreadsheetHash,
      operation: "batch_update",
      policy_decision: "denied_tier",
      request_types_csv: requestTypes.join(","),
    });
    throw new MCPError("scope_mismatch", {
      tool: "sheets_batch_update",
      detail: "Write tools require SAFESPACE_TIER=write or higher.",
    });
  }

  // ─── 7. Record audit meta BEFORE SDK call (hook #11) ─────────────────
  // request_types_csv: caller-supplied ORDER (mirror v1.17 docsModifyMeta
  // F15 — order is forensically relevant; sorting destroys it).
  // total_cell_writes: ONLY when updateCells / repeatCell touched cells.
  // ABSENT on pure addSheet/deleteSheet/mergeCells batches (ABSENCE is
  // forensic per design §5).
  const meta: import("../../audit").SheetsMutationAuditMeta = {
    target_spreadsheet_id_hash: spreadsheetHash,
    operation: "batch_update",
    policy_decision: "allowed",
    request_types_csv: requestTypes.join(","),
  };
  if (totalCellWrites > 0) {
    meta.total_cell_writes = totalCellWrites;
  }
  ctx.audit.record("sheetsMutationMeta", meta);

  // ─── 8. SDK call — `requestBody` constructed LITERALLY ──────────────
  // includeSpreadsheetInResponse HARD-OMITTED (hook #15 — OMISSION is the
  // gate; matches v1.17 docs_modify_structured.include_document_in_response
  // pattern). Each request was constructed LITERALLY via the per-type
  // sub-allowlist above — caller's other request keys silently dropped.
  try {
    const sheets = sheetsClientFromToken(requireGoogle(ctx).getAccessToken());
    const res = await sheets.spreadsheets.batchUpdate({
      spreadsheetId,
      requestBody: { requests: sdkRequests },
    });
    return res.data;
  } catch (err) {
    throw toGoogleError(err, { tool: "sheets_batch_update", email: requireGoogle(ctx).accountId });
  }
}

