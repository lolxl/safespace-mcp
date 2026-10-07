// v1.91 — `safespace audit export [--format jsonl|cef] [--since YYYY-MM-DD]`:
// stream audit rows to STDOUT in a SIEM-ingestable form, one formatted line per
// row. The COMPLEMENT to v1.89 `audit verify`: verify is the integrity half (is
// the chain intact?), export is the SHIPPING half (get the rows into a SIEM).
//
// STDOUT-ONLY by design — SafeSpace does NOT open a socket to a syslog / SIEM
// host. Direct shipping would be a new egress DESTINATION (the v1.88 registry's
// "one auditable list of external hosts") plus an SSRF-shaped configurable-host
// surface, for no real gain: every SIEM already ingests a piped stream. The
// operator wires us into their own shipper instead —
//   safespace audit export --format cef   | logger -n siem.corp -P 514 -T
//   safespace audit export --format jsonl | vector        (or fluentd / filebeat)
// docs/SIEM.md documents the integration + the honest boundary.
//
// SECURITY — the line formats are injection surfaces:
//   jsonl: JSON.stringify per row → control chars / newlines are escaped by the
//          encoder, so no field can forge a second line. `row_mac` passes through
//          so the SIEM can store the chain tip (v1.89) for out-of-band anchoring.
//   cef:   CEF is line- + pipe- + `key=value`-delimited; an un-escaped newline,
//          `|`, or `=` in a field value would forge a log record / header field /
//          extension pair. cefEscapeHeader / cefEscapeExtension neutralize all
//          three (and any other C0 control byte). Only a VETTED field allowlist is
//          emitted — never a blind row dump — mirroring the recent.ts safe-field
//          discipline; `account` stays plaintext + recipient ids stay hashed,
//          exactly as audit.jsonl already stores them (export adds NO new exposure).

import { CliError, type CliIO } from "../../cli";
import { streamAuditRows, strictParseIso8601, type AuditRow } from "./reader";
// Single-source the product version for the CEF Device Version header field,
// same JSON-import pattern as server.ts's SERVER_VERSION (kills drift).
import pkg from "../../../package.json" with { type: "json" };

const PRODUCT_VERSION = pkg.version;

const USAGE =
  "usage: safespace audit export [--format jsonl|cef] [--since YYYY-MM-DD]";

// ── CEF (ArcSight Common Event Format) ──────────────────────────────────────

// Every byte that could reframe a CEF record into a forged second line:
// the C0 control set (NUL..US, incl. CR / LF / TAB), DEL (U+007F), and the
// Unicode line/paragraph separators (NEL U+0085, LS U+2028, PS U+2029) that a
// Unicode-aware syslog / CEF parser may treat as a line terminator. Built from
// a STRING so the source holds only printable ASCII — a literal control byte
// here would be mangled (or truncate the file) under the repo's Write/format
// hook. Each match collapses to a single space.
const RECORD_BREAKERS = new RegExp("[\\u0000-\\u001F\\u007F\\u0085\\u2028\\u2029]", "g");

/** Escape a CEF *header* field (pipe-delimited). Backslash first (so the
 *  escapes we introduce are not re-escaped), then the pipe delimiter, then
 *  collapse every record-breaking control / line-separator to a space. */
function cefEscapeHeader(s: string): string {
  return s
    .replace(/\\/g, "\\\\")
    .replace(/\|/g, "\\|")
    .replace(RECORD_BREAKERS, " ");
}

/** Escape a CEF *extension* value (`key=value`, space-separated). Backslash
 *  first, then `=` (the pair delimiter), then collapse every record-breaking
 *  control / line-separator to a space so it cannot truncate or reframe the
 *  record in a downstream syslog / CEF parser. */
function cefEscapeExtension(s: string): string {
  return s
    .replace(/\\/g, "\\\\")
    .replace(/=/g, "\\=")
    .replace(RECORD_BREAKERS, " ");
}

/** CEF severity (0-10), three defensible buckets:
 *   8  an explicit policy denial / formula reject — the rows an analyst pages on
 *   6  the tool call errored (non-policy)
 *   3  a normal call, or a forensic / aggregate event row (informational) */
function cefSeverity(row: AuditRow): number {
  const event = typeof row.event === "string" ? row.event : "";
  const decision = typeof row.policy_decision === "string" ? row.policy_decision : "";
  if (event.endsWith("_denied_by_policy") || /denied|rejected/.test(decision)) return 8;
  if (row.status === "error") return 6;
  return 3;
}

/** The CEF signatureId + name from the row's discriminator: a standard
 *  tool-call row carries `tool`; the 4 event shapes carry `event`. */
function cefSignature(row: AuditRow): { sig: string; name: string } {
  if (typeof row.tool === "string") return { sig: row.tool, name: "tool call" };
  if (typeof row.event === "string") return { sig: row.event, name: "audit event" };
  return { sig: "audit", name: "audit row" };
}

// Vetted audit-row field → CEF extension key. ONLY these are emitted (no blind
// dump). Hashes are stored as HMAC hex by audit.ts (safe to emit in full);
// `account` is plaintext exactly as audit.jsonl already holds it.
const CEF_FIELDS: ReadonlyArray<readonly [string, string]> = [
  ["ts", "rt"],
  ["run_id", "safespaceRunId"],
  ["tool", "safespaceTool"],
  ["account", "suser"],
  ["status", "outcome"],
  ["duration_ms", "safespaceDurationMs"],
  ["policy_decision", "safespacePolicyDecision"],
  ["event", "safespaceEvent"],
  ["error_code", "safespaceErrorCode"],
  ["refusal_reason", "safespaceRefusalReason"],
  ["tool_name_hmac", "safespaceToolNameHmac"],
  ["source", "safespaceSource"],
  ["operator", "safespaceOperator"],
  ["row_mac", "safespaceRowMac"],
  ["args_hash", "safespaceArgsHash"],
  ["target_email_hash", "safespaceTargetEmailHash"],
  ["file_id", "safespaceFileId"],
  ["share_type", "safespaceShareType"],
  ["role", "safespaceRole"],
  ["rejected_count", "safespaceRejectedCount"],
  ["total_recipients", "safespaceTotalRecipients"],
  ["rejected_formula_function", "safespaceFormulaFunction"],
  ["rejected_formula_nested", "safespaceFormulaNested"],
];

/** Build the CEF extension string from the vetted field allowlist. Only
 *  string / number / boolean values are emitted (objects / arrays are skipped
 *  defensively); every value is run through cefEscapeExtension. */
function cefExtension(row: AuditRow): string {
  const parts: string[] = [];
  for (const [field, key] of CEF_FIELDS) {
    const v = row[field];
    if (typeof v !== "string" && typeof v !== "number" && typeof v !== "boolean") continue;
    parts.push(`${key}=${cefEscapeExtension(String(v))}`);
  }
  return parts.join(" ");
}

/** One CEF record (CEF:0 header, 7 pipe fields, then the extension). */
function toCefLine(row: AuditRow): string {
  const { sig, name } = cefSignature(row);
  return (
    `CEF:0|SafeSpace|safespace-mcp|${cefEscapeHeader(PRODUCT_VERSION)}|` +
    `${cefEscapeHeader(sig)}|${cefEscapeHeader(name)}|${cefSeverity(row)}|` +
    cefExtension(row)
  );
}

// ── --since filtering ───────────────────────────────────────────────────────

/** Keep rows with `ts >= sinceMs`. A row with a missing / unparseable `ts` is
 *  KEPT (over-inclusive) — silently dropping a forensic row on a parse quirk
 *  would be the worse failure for an audit export. */
function rowOnOrAfter(row: AuditRow, sinceMs: number): boolean {
  if (typeof row.ts !== "string") return true;
  const t = Date.parse(row.ts);
  if (Number.isNaN(t)) return true;
  return t >= sinceMs;
}

export async function runAuditExport(args: string[], io: CliIO): Promise<void> {
  let format: "jsonl" | "cef" = "jsonl";
  let sinceMs: number | null = null;
  for (let i = 0; i < args.length; i++) {
    const f = args[i];
    if (f === "--format") {
      const v = args[++i];
      if (v === undefined) throw new CliError(`--format requires a value\n       ${USAGE}`);
      if (v !== "jsonl" && v !== "cef") {
        throw new CliError(`--format must be 'jsonl' or 'cef', got ${JSON.stringify(v)}\n       ${USAGE}`);
      }
      format = v;
    } else if (f === "--since") {
      const v = args[++i];
      if (v === undefined) throw new CliError(`--since requires a value\n       ${USAGE}`);
      try {
        sinceMs = strictParseIso8601(v).getTime();
      } catch (e) {
        throw new CliError(`${e instanceof Error ? e.message : String(e)}\n       ${USAGE}`);
      }
    } else {
      throw new CliError(`unknown flag: ${f}\n       ${USAGE}`);
    }
  }

  let emitted = 0;
  // Stream (O(1) memory) — audit.jsonl can be large. Malformed-line warnings go
  // to stderr via the reader sink, never polluting the stdout SIEM stream.
  for await (const row of streamAuditRows(undefined, { warn: (msg) => io.err(msg) })) {
    if (sinceMs !== null && !rowOnOrAfter(row, sinceMs)) continue;
    io.out(format === "cef" ? toCefLine(row) : JSON.stringify(row));
    emitted++;
  }
  // Nothing matched → emit nothing on stdout (clean for piping); a one-line
  // note on stderr so an interactive operator isn't confused by the silence.
  if (emitted === 0) io.err("(no audit entries to export)");
}
