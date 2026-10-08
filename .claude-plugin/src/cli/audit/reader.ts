// v1.18 Phase 2 — shared JSONL streaming reader for `safespace audit *`.
//
// Why streaming (not readFile + split): the audit.jsonl file is append-only
// and can grow large (10MB+ ceiling per design §8 Q3 before stats becomes
// slow). Loading the whole file into memory would OOM on long-running
// installs. Lines are streamed with the audit writers' own splitter (`rawLines`) —
// line-by-line, memory bounded by the longest line.
//
// Malformed-line policy (sec-rev hook #5 alignment): a broken JSON line is
// SKIPPED with a one-line stderr warning. We do NOT echo the raw line — it
// might contain hashed identifiers that should not be visible in normal
// `audit recent` output. Skipping preserves the "audit reader is read-only,
// never crashes" invariant.

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { configDir } from "../../auth/keychain";
import { auditCliPath, rawLines } from "../../audit/cli-chain";

/** Path to audit.jsonl in the active config dir. Centralized so all 4
 *  sub-subcommands read from the same place. */
export function auditFilePath(): string {
  return path.join(configDir(), "audit.jsonl");
}

/** One parsed audit row. The shape is intentionally `Record<string, unknown>`
 *  because audit.jsonl carries 5 different row shapes (standard auditEnd +
 *  4 event types) — per-sub-subcommand code narrows the row with
 *  field-presence checks (NEVER `as` casts). */
export type AuditRow = Record<string, unknown>;

/** Stderr sink for malformed-line warnings. Test-injectable so suites can
 *  capture without leaking to console. */
export interface ReaderSink {
  warn: (msg: string) => void;
}

const DEFAULT_SINK: ReaderSink = {
  warn: (msg) => console.error(msg),
};

/** Stream audit.jsonl line-by-line, yielding parsed objects.
 *
 *  Async iterator: callers can `for await (const row of streamAuditRows())`
 *  and either consume eagerly or filter+collect. O(1) memory regardless of
 *  audit.jsonl size.
 *
 *  - File missing → yields nothing (caller renders "no audit entries").
 *  - File empty → yields nothing.
 *  - Malformed line → skipped + one stderr warning per line (not per file).
 *  - Non-object JSON (array / primitive) → also skipped + warned (defensive;
 *    real audit lines are always objects).
 *
 *  NEVER returns the raw line text — only parsed object or skip. */
export async function* streamAuditRows(
  filePath: string = auditFilePath(),
  sink: ReaderSink = DEFAULT_SINK,
): AsyncGenerator<AuditRow> {
  // Pre-check: a missing file yields nothing (the stream would throw ENOENT).
  try {
    await fs.access(filePath);
  } catch {
    return;
  }

  // The audit writers' own splitter (lines end at "\r\n", "\n" or a lone "\r" only), not
  // `node:readline`: newer runtimes' readline also ends a line at U+2028 / U+2029, which
  // JSON.stringify leaves raw inside strings, so readline would cut such a row in two
  // while the writers see one row. One splitter keeps every reader and both writers
  // agreeing on the rows, whatever the runtime.
  let lineNo = 0;
  for await (const { text: raw } of rawLines(filePath)) {
    lineNo++;
    if (raw.length === 0) continue;
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      // sec hook #5: NEVER echo the raw line; reference only the line
      // number so an operator can investigate via `sed -n 'Np' audit.jsonl`.
      sink.warn(
        `[safespace audit] skipped malformed JSON at line ${lineNo}: ${e instanceof Error ? e.message : String(e)}`,
      );
      continue;
    }
    if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
      sink.warn(
        `[safespace audit] skipped non-object row at line ${lineNo}`,
      );
      continue;
    }
    yield parsed as AuditRow;
  }
}

/** Convenience helper: stream + filter + collect into an array. Use only
 *  when callers actually need random-access (e.g., `audit recent` tail-N).
 *  For aggregate counts (stats / deletes / policy-decisions) prefer the
 *  pure async iterator to avoid materializing all rows. */
export async function collectAuditRows(
  predicate: (row: AuditRow) => boolean = () => true,
  filePath: string = auditFilePath(),
  sink: ReaderSink = DEFAULT_SINK,
): Promise<AuditRow[]> {
  const out: AuditRow[] = [];
  for await (const row of streamAuditRows(filePath, sink)) {
    if (predicate(row)) out.push(row);
  }
  return out;
}

/** Which chain file a row was read from: "server" = audit.jsonl, "cli" =
 *  audit-cli.jsonl (rows written by `safespace` CLI processes). Provenance is the FILE,
 *  never a field inside the row. */
export type AuditSource = "server" | "cli";

/** True when audit-cli.jsonl exists (only then do the readers change their output). */
export async function hasCliAuditFile(): Promise<boolean> {
  try {
    await fs.access(auditCliPath());
    return true;
  } catch {
    return false;
  }
}

/** Every audit row of both chain files, each tagged with its source: audit.jsonl's rows
 *  in file order, then audit-cli.jsonl's. Streaming (O(1) memory) — for readers whose
 *  result does not depend on row order. With no CLI file it yields exactly
 *  `streamAuditRows()`. */
export async function* streamAuditSources(
  sink: ReaderSink = DEFAULT_SINK,
): AsyncGenerator<{ row: AuditRow; source: AuditSource }> {
  for await (const row of streamAuditRows(auditFilePath(), sink)) yield { row, source: "server" };
  for await (const row of streamAuditRows(auditCliPath(), sink)) yield { row, source: "cli" };
}

/** Collect matching rows of both files in time order, for `audit recent`. With no CLI
 *  file: audit.jsonl's rows in file order (today's behaviour). With one: sorted by `ts`
 *  (a string compare — toISOString is fixed-width, so it is chronological), stable
 *  (audit.jsonl first, then line order); a row without a string `ts` takes the key of
 *  the row before it in the same file. Rows are never dropped. */
export async function collectAuditRowsBothFiles(
  predicate: (row: AuditRow) => boolean,
  sink: ReaderSink = DEFAULT_SINK,
): Promise<Array<{ row: AuditRow; source: AuditSource }>> {
  if (!(await hasCliAuditFile())) {
    return (await collectAuditRows(predicate, auditFilePath(), sink)).map((row) => ({ row, source: "server" }));
  }
  const keyed: Array<{ row: AuditRow; source: AuditSource; key: string; seq: number }> = [];
  let seq = 0;
  for (const [source, file] of [["server", auditFilePath()], ["cli", auditCliPath()]] as const) {
    let key = "";
    for await (const row of streamAuditRows(file, sink)) {
      if (typeof row.ts === "string") key = row.ts;
      if (predicate(row)) keyed.push({ row, source, key, seq: seq++ });
    }
  }
  keyed.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : a.seq - b.seq));
  return keyed.map(({ row, source }) => ({ row, source }));
}

/** Truncate a hash string to 12 hex characters + ellipsis for display.
 *
 *  Per design §2.2 + sec-rev hook #9: 12 hex = 48 bits, collision-safe for
 *  visual scan within a single audit log session, NOT a forensic key.
 *  Operators who need cross-session correlation use raw `jq` on audit.jsonl.
 *
 *  Applied uniformly across BOTH table mode AND --json mode so the same
 *  truncation discipline holds regardless of output format (sentinel test
 *  in `recent.test.ts` covers both modes).
 *
 *  Returns the input verbatim if it's not a string or is already short
 *  (≤ 12 chars) — defensive against malformed rows. */
export function truncateHash(value: unknown): string {
  if (typeof value !== "string") return String(value);
  if (value.length <= 12) return value;
  return value.slice(0, 12) + "…"; // U+2026 HORIZONTAL ELLIPSIS
}

/** Strict ISO 8601 date parser. Accepts `YYYY-MM-DD` or full
 *  `YYYY-MM-DDTHH:MM:SS[.sss][Z|±HH:MM]`. Rejects anything that
 *  Date constructor would otherwise accept loosely (e.g., "yesterday",
 *  "2026/05/21", "May 21").
 *
 *  Returns the parsed Date on success. Throws on any rejection — caller
 *  wraps the throw in a CliError with the user-facing message. */
export function strictParseIso8601(s: string): Date {
  // sec-rev hook #3: strict regex — date-only OR full ISO with time. Reject
  // anything outside this shape pre-Date-constructor (Date() loosely accepts
  // "2026/05/21" and similar). Year range bounded to 4 digits.
  const re = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d{1,3})?(Z|[+-]\d{2}:\d{2})?)?$/;
  if (!re.test(s)) {
    throw new Error(
      `not a valid ISO 8601 date (expected YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS): ${JSON.stringify(s)}`,
    );
  }
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) {
    throw new Error(`not a valid ISO 8601 date: ${JSON.stringify(s)}`);
  }
  return d;
}

/** Strict integer parser for CLI flag values. Used for --limit / --threshold
 *  (NOT --window — window has unit suffix; see `parseWindow`).
 *
 *  Rejects: NaN, Infinity, negative, zero (if min=1), non-integer, value
 *  outside [min, max]. Sec-rev hook #4 — matches v1.14 max_results NaN floor
 *  + v1.16 burst-limit clamping discipline. */
export function strictParseInt(
  raw: string,
  flagName: string,
  min: number,
  max: number,
): number {
  // Number() rejects "10abc" cleanly (NaN), while parseInt("10abc") silently
  // returns 10 — Number is the correct primitive here.
  const n = Number(raw);
  if (!Number.isFinite(n) || !Number.isInteger(n)) {
    throw new Error(
      `${flagName}: expected integer, got ${JSON.stringify(raw)}`,
    );
  }
  if (n < min || n > max) {
    throw new Error(
      `${flagName}: out of range (expected ${min}-${max}, got ${n})`,
    );
  }
  return n;
}

/** Parse a window argument: `Nh` / `Nm` / `Nd`. Integer N, unit suffix one
 *  of h/m/d. Returns total milliseconds.
 *
 *  sec-rev hook #4 + design §2.2 Q4: range 1h-720h (30 days). Other units
 *  normalize to hours first then the same bound applies — 720h = 43200m =
 *  30d. Rejects `1y` / `1w` / `0h` / `1.5h` / non-integer / no-suffix per
 *  prompt examples. */
export function parseWindow(raw: string): number {
  // Strict pattern: integer + single h/m/d suffix. No decimal, no negative.
  const m = /^(\d+)([hmd])$/.exec(raw);
  if (!m) {
    throw new Error(
      `--window: expected integer + unit (h/m/d), got ${JSON.stringify(raw)}`,
    );
  }
  const n = Number(m[1]);
  if (!Number.isFinite(n) || !Number.isInteger(n) || n < 1) {
    throw new Error(`--window: integer must be ≥ 1, got ${n}`);
  }
  const unit = m[2];
  let hours: number;
  if (unit === "h") hours = n;
  else if (unit === "m") hours = n / 60;
  else /* d */ hours = n * 24;
  // Bound check against 720h cap (design §8 Q4 LOCKED).
  if (hours < 1 || hours > 720) {
    throw new Error(
      `--window: out of range (expected 1h-720h, got ${raw} = ${hours}h)`,
    );
  }
  // Always express in ms; preserve sub-hour precision for `Nm`.
  return Math.round(hours * 60 * 60 * 1000);
}
