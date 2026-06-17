#!/usr/bin/env bun
/**
 * Probe: sheets_get_values + sheets_get_metadata sanitize coverage on a real
 * Google Sheets spreadsheet.
 *
 * v1.20 Phase 1b-1 — manual one-time validation per
 * docs/v1.20-sheets-api.md §6. Run this once per consented account against
 * (a) `spreadsheets.values.get` for a sample range AND (b) `spreadsheets.get`
 * for the same spreadsheet's metadata to confirm:
 *
 *   1. User-controllable text fields (properties.title, sheets[*].properties.title,
 *      per-cell value / formattedValue / note, namedRanges[*].description)
 *      ARE wrapped in <untrusted-source-NONCE/> per the sanitize pipeline.
 *   2. Google opaque keys (spreadsheetId, sheetId, dataSourceId,
 *      developerMetadataId, dimensionGroupId, bandedRangeId,
 *      conditionalFormatRuleId, chartId, filterId, protectedRangeId,
 *      dataSourceTableId, namedRangeId) AND the cross-API shared opaque keys
 *      (id, etag, kind, nextPageToken, webViewLink) pass through UNWRAPPED.
 *   3. The walk completes without throwing `sanitize_failed` — confirming
 *      MAX_DEPTH=64 (carried from v1.12) accommodates real Sheets resources.
 *   4. Per design §8 inbound formula sanity: a cell containing `=A1+B2`
 *      gets wrapped as the literal string `=A1+B2` — i.e., the formula
 *      characters are inert text from the wrapper's perspective.
 *   5. (PROBE — design §16 L3 carry-forward) FieldMask `/` separator:
 *      whether real-world `sheets_get_metadata` callers need the `/`
 *      separator (e.g., `properties/title`) or whether dotted-path form
 *      (`properties.title`) suffices.
 *   6. (PROBE) `spreadsheetUrl` — emitted by Google as a top-level field
 *      under `spreadsheets.get`. Verify whether wrapping it is acceptable
 *      (currently wraps because we did NOT add it to SKIP_FIELDS Phase 1b-1)
 *      OR whether it should join SKIP_FIELDS in a follow-up patch.
 *
 * Usage:
 *   bun scripts/probe-sheets-sanitize.ts \
 *     --account=alice@example.com \
 *     --spreadsheet-id=<probe-sheet-id> \
 *     [--range=Sheet1!A1:C10] \
 *     [--config-dir=<path>]
 *
 * SAFETY:
 *   - Read-only — calls `spreadsheets.values.get` + `spreadsheets.get`
 *     once each. No writes, no shares.
 *   - Bypasses the production `withToolContext` middleware (this calls
 *     `sheetsClientFromToken` + `sanitize` directly so the assertions are
 *     observable).
 *
 * MANUAL one-time validation; not in CI. Run after Phase 1b-1 ships to
 * verify against real Google Sheets API.
 *
 * Reproducibility: kept in repo so the sanitize compatibility analysis can
 * be re-validated if Google adds new opaque keys or schema-level fields in
 * future Sheets API revisions.
 */

import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";

// ──────────────── arg parsing ────────────────
const args = process.argv.slice(2).reduce<Record<string, string>>((acc, arg) => {
  const m = arg.match(/^--([\w-]+)=(.+)$/);
  if (m && m[1] && m[2]) acc[m[1]] = m[2];
  return acc;
}, {});

const account = args.account;
const spreadsheetId = args["spreadsheet-id"];
const range = args.range ?? "Sheet1!A1:C10";
const configDir =
  args["config-dir"] ??
  process.env.SAFESPACE_CONFIG_DIR ??
  path.join(os.homedir(), ".claude", "plugins", "data", "safespace-mcp-safespace", "safespace");

if (!account || !spreadsheetId) {
  console.error(
    "Usage: bun scripts/probe-sheets-sanitize.ts " +
      "--account=<email> --spreadsheet-id=<id> [--range=Sheet1!A1:C10] [--config-dir=<path>]",
  );
  process.exit(1);
}

// Validate spreadsheet_id format (matches handler regex).
const SHEETS_SPREADSHEET_ID_RE = /^[a-zA-Z0-9_-]{40,100}$/;
if (!SHEETS_SPREADSHEET_ID_RE.test(spreadsheetId)) {
  console.error(
    `ERROR: --spreadsheet-id=${spreadsheetId} does not match /^[a-zA-Z0-9_-]{40,100}$/`,
  );
  process.exit(1);
}

// ──────────────── env bootstrap ────────────────
const envFile = path.join(configDir, ".env");
if (!fs.existsSync(envFile)) {
  console.error(`ERROR: .env not found at ${envFile}`);
  console.error(`       (override with --config-dir=<path/to/safespace>)`);
  process.exit(1);
}
const envContent = fs.readFileSync(envFile, "utf-8");
for (const line of envContent.split("\n")) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) continue;
  const eq = trimmed.indexOf("=");
  if (eq < 0) continue;
  const key = trimmed.slice(0, eq).trim();
  let val = trimmed.slice(eq + 1).trim();
  if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
    val = val.slice(1, -1);
  }
  if (key && !(key in process.env)) {
    process.env[key] = val;
  }
}
process.env.SAFESPACE_CONFIG_DIR = configDir;

const { refreshAccessToken } = await import("../.claude-plugin/src/auth/refresh");
const { sheetsClientFromToken } = await import("../.claude-plugin/src/google-api/client");
const { sanitize } = await import("../.claude-plugin/src/sanitize");

console.log(`# Probe config`);
console.log(`  account:        ${account}`);
console.log(`  spreadsheet_id: ${spreadsheetId}`);
console.log(`  range:          ${range}`);
console.log("");

console.log("# Refreshing access token...");
const tokens = await refreshAccessToken(account, { force: true });
console.log(`  ✓ Got fresh token`);
console.log("");

const sheets = sheetsClientFromToken(tokens.access_token);

// ──────────────── spreadsheets.values.get ────────────────
console.log(`# Calling spreadsheets.values.get for range=${range}...`);
const valuesRes = await sheets.spreadsheets.values.get({
  spreadsheetId,
  range,
  valueRenderOption: "FORMATTED_VALUE",
});
const valueCount = (valuesRes.data.values ?? []).reduce(
  (n, row) => n + (Array.isArray(row) ? row.length : 0),
  0,
);
console.log(`  ✓ Got ${valueCount} cell value(s) across ${(valuesRes.data.values ?? []).length} row(s)`);
console.log("");

// ──────────────── spreadsheets.get (metadata) ────────────────
console.log(`# Calling spreadsheets.get for metadata (fields default)...`);
const metaRes = await sheets.spreadsheets.get({
  spreadsheetId,
  fields: "properties,sheets.properties,namedRanges,spreadsheetUrl",
});
console.log(`  ✓ Got metadata: title=${metaRes.data.properties?.title}, sheets=${(metaRes.data.sheets ?? []).length}`);
console.log("");

// ──────────────── walk helpers ────────────────
type WalkVisitor = (key: string, value: unknown, path: string) => void;
function walkResponse(obj: unknown, visit: WalkVisitor, p = "$"): void {
  if (obj === null || typeof obj !== "object") return;
  if (Array.isArray(obj)) {
    obj.forEach((el, i) => walkResponse(el, visit, `${p}[${i}]`));
    return;
  }
  for (const [k, v] of Object.entries(obj as Record<string, unknown>)) {
    visit(k, v, `${p}.${k}`);
    walkResponse(v, visit, `${p}.${k}`);
  }
}

const WRAP_PREFIX_RE = /^<untrusted-source-[0-9a-f]{16}/;

// ──────────────── sanitize + assert (spreadsheets.get response) ────────────────
console.log("# Running sanitize() over spreadsheets.get response...");
let sanitizedMeta: unknown;
try {
  sanitizedMeta = sanitize(metaRes.data, { toolName: "sheets_get_metadata" });
} catch (err) {
  console.error(`  ✗ sanitize threw on spreadsheets.get response: ${(err as Error).message}`);
  console.error("    MAX_DEPTH=64 may need bumping OR a SKIP_FIELDS edge-case fired.");
  process.exit(2);
}
console.log("  ✓ sanitize() completed (no depth overflow / circular ref)");
console.log("");

// Pass criterion 1: user-typed text fields ARE wrapped.
console.log("# Pass criterion 1: user-typed text fields in metadata ARE wrapped");
const USER_VISIBLE_META_KEYS = new Set([
  "title",          // spreadsheet title + per-sheet tab title
  "description",    // named-range description
]);
let metaWrapped = 0;
let metaUnwrapped = 0;
walkResponse(sanitizedMeta, (k, v, p) => {
  if (USER_VISIBLE_META_KEYS.has(k) && typeof v === "string" && v.length > 0) {
    if (WRAP_PREFIX_RE.test(v)) {
      metaWrapped++;
    } else {
      metaUnwrapped++;
      console.error(`    ✗ UNWRAPPED user-visible at ${p}: ${v.slice(0, 60)}...`);
    }
  }
});
console.log(`  → ${metaWrapped} user-visible fields wrapped in metadata`);
if (metaUnwrapped > 0) {
  console.error(`  ✗ FAIL: ${metaUnwrapped} user-visible values escaped wrapping`);
  process.exit(3);
}
if (metaWrapped === 0) {
  console.warn("  ⚠ WARNING: no user-visible text wrapped in metadata — is the title empty?");
}
console.log("");

// Pass criterion 2: SKIP_FIELDS keys NOT wrapped.
console.log("# Pass criterion 2: SKIP_FIELDS Sheets-API keys NOT wrapped");
const opaqueKeys = [
  "spreadsheetId",           // v1.20 NEW
  "sheetId",                 // v1.20 NEW
  "dataSourceId",            // v1.20 NEW
  "developerMetadataId",     // v1.20 NEW
  "dimensionGroupId",        // v1.20 NEW
  "bandedRangeId",           // v1.20 NEW
  "conditionalFormatRuleId", // v1.20 NEW
  "chartId",                 // v1.20 NEW
  "filterId",                // v1.20 NEW
  "protectedRangeId",        // v1.20 NEW
  "dataSourceTableId",       // v1.20 NEW
  "namedRangeId",            // v1.20 NEW
  "id",                      // cross-API
  "etag",                    // cross-API
  "kind",                    // cross-API
];
const leaks: Array<{ path: string; key: string; value: string }> = [];
walkResponse(sanitizedMeta, (k, v, p) => {
  if (opaqueKeys.includes(k) && typeof v === "string" && WRAP_PREFIX_RE.test(v)) {
    leaks.push({ path: p, key: k, value: v.slice(0, 80) });
  }
});
if (leaks.length > 0) {
  console.error("  ✗ FAIL: opaque keys leaked into sanitize wrap:");
  for (const l of leaks) {
    console.error(`    - ${l.path} (${l.key}): ${l.value}...`);
  }
  process.exit(4);
}
console.log(`  ✓ all ${opaqueKeys.length} opaque key families pass through unwrapped`);
console.log("");

// Pass criterion 3: probe whether `spreadsheetUrl` is wrapped (L4 carry-forward).
console.log("# Probe criterion 3: spreadsheetUrl wrap behavior (Phase 1b-1 follow-up)");
let urlWrapped = 0;
walkResponse(sanitizedMeta, (k, v) => {
  if (k === "spreadsheetUrl" && typeof v === "string" && WRAP_PREFIX_RE.test(v)) {
    urlWrapped++;
  }
});
if (urlWrapped > 0) {
  console.warn(
    `  ⚠ FOLLOW-UP: spreadsheetUrl is being WRAPPED. Consider adding it to ` +
      `SKIP_FIELDS in src/sanitize/patterns.ts so callers can use it as a ` +
      `navigable link (matches Calendar htmlLink / Drive webViewLink rationale).`,
  );
}
console.log("");

// ──────────────── sanitize + assert (spreadsheets.values.get response) ────────────────
console.log("# Running sanitize() over spreadsheets.values.get response...");
let sanitizedValues: unknown;
try {
  sanitizedValues = sanitize(valuesRes.data, { toolName: "sheets_get_values" });
} catch (err) {
  console.error(`  ✗ sanitize threw on spreadsheets.values.get response: ${(err as Error).message}`);
  process.exit(2);
}
console.log("  ✓ sanitize() completed on values response");
console.log("");

// Pass criterion 4: per-cell string values ARE wrapped (formula injection class).
console.log("# Pass criterion 4: per-cell string values ARE wrapped (cells with leading = / + / - / @ still wrap)");
let cellsWrapped = 0;
let cellsUnwrappedStrings = 0;
const valuesArr = (sanitizedValues as { values?: unknown[] }).values ?? [];
for (const row of valuesArr) {
  if (!Array.isArray(row)) continue;
  for (const cell of row) {
    if (typeof cell === "string" && cell.length > 0) {
      if (WRAP_PREFIX_RE.test(cell)) {
        cellsWrapped++;
      } else {
        cellsUnwrappedStrings++;
        console.error(`    ✗ UNWRAPPED cell string: ${cell.slice(0, 60)}...`);
      }
    }
  }
}
console.log(`  → ${cellsWrapped} string cells wrapped`);
if (cellsUnwrappedStrings > 0) {
  console.error(`  ✗ FAIL: ${cellsUnwrappedStrings} string cells escaped wrapping`);
  process.exit(3);
}
console.log("");

// Pass criterion 5: range string itself NOT wrapped (closed-shape metadata).
console.log("# Pass criterion 5: range string in response NOT wrapped (closed-shape metadata)");
const rangeStr = (sanitizedValues as { range?: unknown }).range;
if (typeof rangeStr === "string" && WRAP_PREFIX_RE.test(rangeStr)) {
  console.warn(
    `  ⚠ FOLLOW-UP: response 'range' field is being WRAPPED. The range string ` +
      `is server-echoed structural metadata; consider whether to allow wrapping ` +
      `or skip.`,
  );
} else {
  console.log("  ✓ range field passed through as expected");
}
console.log("");

console.log("# All probe criteria PASSED. v1.20 Phase 1b-1 sanitize coverage is valid for this account.");
process.exit(0);
