// v1.18 Phase 2 — `safespace audit recent [--limit N] [--include-events] [--json]`.
//
// Tail the N most recent audit rows in human-readable form. By default
// filters out the 4 non-standard event row shapes (share_forensic /
// share_denied_by_policy / recipient_denied_by_policy / cross_account_aggregate)
// because they don't carry status / duration_ms — rendering them in the
// standard table would leave columns blank. `--include-events` opts in.
//
// sec-rev hooks addressed:
//   #4 — integer bounds on --limit (1-1000); NaN / negative / Infinity reject.
//   #5 — only specific extracted fields displayed; hash fields truncated.
//   #9 — hash truncation 12 hex + `…`, applied to BOTH table and --json modes.

import { CliError, type CliIO } from "../../cli";
import {
  collectAuditRowsBothFiles,
  truncateHash,
  type AuditRow,
  strictParseInt,
} from "./reader";

const USAGE =
  "usage: safespace audit recent [--limit N=50] [--include-events] [--json]";

interface RecentOptions {
  limit: number;
  includeEvents: boolean;
  json: boolean;
}

function parseFlags(args: string[]): RecentOptions {
  let limit = 50;
  let includeEvents = false;
  let json = false;
  for (let i = 0; i < args.length; i++) {
    const f = args[i];
    if (f === "--limit") {
      const v = args[++i];
      if (v === undefined) throw new CliError(`--limit requires a value\n       ${USAGE}`);
      try {
        limit = strictParseInt(v, "--limit", 1, 1000);
      } catch (e) {
        throw new CliError(`${e instanceof Error ? e.message : String(e)}\n       ${USAGE}`);
      }
    } else if (f === "--include-events") {
      includeEvents = true;
    } else if (f === "--json") {
      json = true;
    } else {
      throw new CliError(`unknown flag: ${f}\n       ${USAGE}`);
    }
  }
  return { limit, includeEvents, json };
}

/** Default predicate: keep ONLY standard tool-call rows (have a `status`
 *  field). The 4 event shapes (share_forensic / share_denied_by_policy /
 *  recipient_denied_by_policy / cross_account_aggregate) are excluded per
 *  sec-rev M-1. `--include-events` opts in to all. */
function defaultPredicate(row: AuditRow): boolean {
  return typeof row.status === "string";
}

/** Sec-rev hook #5 + #9 — extract ONLY display-safe fields per row. Hash
 *  fields are truncated; account is rendered as plaintext per audit.ts L11-15
 *  single-user self-use convention. */
interface DisplayRow {
  ts: string;
  tool: string;
  account: string;
  status: string;
  duration_ms: string; // string so blank ("") is a valid render for event rows
  policy_decision: string;
}

/** v1.33 (b) — escape forensic source bytes to ASCII `U+XXXX` notation for the
 *  table render. The `rejected_formula_homoglyph_source` field can contain
 *  bidi / RTL / combining / invisible codepoints; emitting them raw would break
 *  column alignment + enable terminal spoofing. JSON mode emits the raw value
 *  verbatim (machine-consumed). Source-byte-purity: no literal non-ASCII here. */
function escapeForensicCodepoints(s: string): string {
  const parts: string[] = [];
  for (const ch of s) {
    parts.push("U+" + ch.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0"));
  }
  return parts.join(" ");
}

function toDisplayRow(row: AuditRow): DisplayRow {
  const ts = typeof row.ts === "string" ? row.ts : "";
  const tool = typeof row.tool === "string" ? row.tool : "";
  const accountRaw = typeof row.account === "string" ? row.account : "";
  // Per design §2.2: account is plaintext (NOT hashed) for standard rows.
  // For event rows (cross_account_aggregate) account is undefined → blank.
  const account = accountRaw;
  const status = typeof row.status === "string" ? row.status : "";
  const durationMs =
    typeof row.duration_ms === "number" ? String(row.duration_ms) : "";
  // policy_decision: enum string OR hash for share_forensic
  // (target_email_hash) — design §2.2 sample output includes
  // `hash:a3f2c8d1e5b4…` rendering when a hash is present.
  let policyDecision = "";
  if (typeof row.policy_decision === "string") {
    policyDecision = row.policy_decision;
    // Augment with a hash hint for share-style rows so the column shows the
    // forensic pivot at a glance (design §2.2 sample).
    if (typeof row.target_email_hash === "string") {
      policyDecision = `${policyDecision} (hash:${truncateHash(row.target_email_hash)})`;
    }
    // v1.41 — nested-smuggle marker. PRESENCE-as-signal: the field is the
    // literal boolean `true` ONLY on the STEP 5 nested-wrapper REJECT path
    // (`=SUM(IMPORTRANGE(...))`); ABSENT on direct attacks. Rendered BEFORE
    // the homoglyph hint (Q3 order: structural smuggle → lexical smuggle).
    // Bare ASCII marker — cannot break column width.
    if (row.rejected_formula_nested === true) {
      policyDecision = `${policyDecision} (nested)`;
    }
    // v1.33 (b) — forensic homoglyph-source hint. NEVER emit raw bytes into
    // the aligned table: the field can contain bidi / RTL / combining /
    // invisible codepoints that break column width AND enable terminal
    // spoofing. ASCII-escape to U+XXXX; the POLICY_W slice safely truncates a
    // long hint (pure ASCII cannot break width). JSON mode emits verbatim.
    if (typeof row.rejected_formula_homoglyph_source === "string") {
      policyDecision = `${policyDecision} (homoglyph:${escapeForensicCodepoints(row.rejected_formula_homoglyph_source)})`;
    }
  }
  return {
    ts,
    tool,
    account,
    status,
    duration_ms: durationMs,
    policy_decision: policyDecision,
  };
}

/** JSON mode: same display-row shape but as structured object. Applies the
 *  SAME truncation rules (sec-rev hook #9 sentinel covers this). */
function toJsonRow(row: AuditRow): Record<string, unknown> {
  const out: Record<string, unknown> = {
    ts: row.ts,
    tool: row.tool,
    account: row.account,
    status: row.status,
    duration_ms: row.duration_ms,
  };
  if (typeof row.policy_decision === "string") {
    out.policy_decision = row.policy_decision;
  }
  // Hash fields — all truncated identically across modes per hook #9.
  for (const field of [
    "args_hash",
    "target_email_hash",
    "target_video_hash",
    "parent_comment_id_hash",
    "target_event_hash",
    "target_document_id_hash",
    "target_comment_id_hash",
    "resolved_recipient_hash",
  ] as const) {
    if (typeof row[field] === "string") {
      out[field] = truncateHash(row[field]);
    }
  }
  if (Array.isArray(row.rejected_recipient_hashes)) {
    out.rejected_recipient_hashes = (row.rejected_recipient_hashes as unknown[]).map(
      truncateHash,
    );
  }
  // Pass through non-sensitive event fields when --include-events was used.
  for (const field of [
    "event",
    "file_id",
    "share_type",
    "role",
    "expiration_iso",
    "granted_permission_id",
    "ancestors_walked",
    "rejected_count",
    "total_recipients",
    "account_count_queried",
    "account_count_succeeded",
    "account_count_failed",
    "comment_length",
    "modification_count",
    "request_types_csv",
    "total_text_replacements",
    "rsvp_response",
    "sanitize",
    // v1.33 (b) — forensic formula-reject fields, emitted VERBATIM (PRESENCE-
    // as-signal: absent on non-formula rows + on pure-ASCII REJECTs). NOT
    // hash-truncated — short post-sec-L1 256-cap + raw evidence, not a hash.
    "rejected_formula_function",
    "rejected_formula_nested",
    "rejected_formula_homoglyph_source",
    "error_code",
  ] as const) {
    if (row[field] !== undefined) {
      out[field] = row[field];
    }
  }
  return out;
}

export async function runAuditRecent(args: string[], io: CliIO): Promise<void> {
  const opts = parseFlags(args);
  const predicate = opts.includeEvents ? () => true : defaultPredicate;
  // Both chain files (audit.jsonl, then audit-cli.jsonl rows merged in by ts); with no
  // CLI file, audit.jsonl in file order — today's view.
  const rows = await collectAuditRowsBothFiles(predicate, {
    warn: (msg) => io.err(msg),
  });
  // Tail N: take the last `limit` rows — the recency view.
  const tailed = rows.slice(Math.max(0, rows.length - opts.limit));

  if (tailed.length === 0) {
    if (opts.json) io.out("[]");
    else io.out("(no audit entries)");
    return;
  }

  if (opts.json) {
    // Single line per row — readable + grep-friendly. Truncation applied
    // identically to table mode (sentinel hook #9).
    for (const { row, source } of tailed) {
      // Provenance from the FILE, on the display projection only (never the signed row).
      const out = toJsonRow(row);
      if (source === "cli") out.source_file = "cli";
      io.out(JSON.stringify(out));
    }
    return;
  }

  // Table mode. Column widths sized to common content; very long tool names
  // truncate via slice in the format helper.
  const TS_W = 24, TOOL_W = 33, ACCOUNT_W = 16, STATUS_W = 7, MS_W = 5, POLICY_W = 40;
  const formatRow = (
    ts: string, tool: string, account: string, status: string, ms: string, policy: string,
  ) =>
    `${ts.padEnd(TS_W).slice(0, TS_W)} ${tool.padEnd(TOOL_W).slice(0, TOOL_W)} ${account.padEnd(ACCOUNT_W).slice(0, ACCOUNT_W)} ${status.padEnd(STATUS_W).slice(0, STATUS_W)} ${ms.padStart(MS_W).slice(0, MS_W)} ${policy.padEnd(POLICY_W).slice(0, POLICY_W)}`;

  io.out(formatRow("ts", "tool", "account", "status", "ms", "policy"));
  for (const { row, source } of tailed) {
    const d = toDisplayRow(row);
    if (source === "cli") d.tool = `[cli] ${d.tool}`;
    // Truncate account to 16 chars for table; if it's an email, slice
    // simply, no hash here. Long emails (>16) get the suffix cut — the
    // first 16 chars are sufficient for visual scan. Hash columns elsewhere
    // already truncate at 12 chars per hook #9.
    io.out(formatRow(d.ts, d.tool, d.account, d.status, d.duration_ms, d.policy_decision));
  }
}
