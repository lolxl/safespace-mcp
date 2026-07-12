// v1.23 Phase 1 — `safespace audit suspicious [--window 24h] [--threshold N=3]
//                                              [--since DATE] [--limit N=1000]
//                                              [--json] [--include-events]
//                                              [--include-allowlist-denials]
//                                              [--include-burst-limits]
//                                              [--include-tier-denials]
//                                              [--include-scope-mismatch]
//                                              [--include-lookup-failures]`
//
// Surfaces prompt-injection canaries from audit.jsonl in aggregate form.
// Closes v1.22 carry-forward L-5 (`audit deletes` only buckets DESTRUCTIVE
// rows; intent signals like `denied_formula_rejected` were buried in
// `audit recent`).
//
// Default behavior: HIGH-confidence canaries ONLY
// (`denied_formula_rejected` + `denied_outbound_sanitize_rejected`),
// 24h trailing window, threshold 3, table mode.
//
// ALERT semantics (LOCKED Q3 sub-decision §4.2): if total >= threshold,
// process.exitCode = 1; otherwise = 0. CI integrators wrap with `|| true`
// to silence. Below-threshold path explicitly resets to 0 so a previous
// command in the same process (e.g., test suites that call runCli twice)
// cannot leak its exit code into this run.
//
// Q4 LOCKED — when both --window and --since provided: LATER cutoff wins
// (intersection semantics; "look at last N AND since DATE, whichever is
// more recent"). Documented in design §2.4.
//
// v1.24 Phase 1 Item 1 — CLOSED Q5 (v1.23 hardcoded-enum drift site).
// `AUDIT_META_CHANNELS` registry value shape extended in v1.24 from
// `{label, flatHash}` to `{label, flatHash, suspiciousDecisions?}` per
// design §2.1 Q2 LOCKED Option A. The per-bucket category arrays
// (HIGH_CONFIDENCE / ALLOWLIST_CATEGORIES / BURST_CATEGORIES /
// TIER_CATEGORIES) are now DERIVED from the registry at module load via
// `collectByBucket()`. WHEN A NEW POLICY DECISION ENUM VALUE IS ADDED TO
// ANY CHANNEL'S `policy_decision`, EDIT THE CHANNEL'S
// `suspiciousDecisions` IN audit.ts INSTEAD — the classifier picks it up
// automatically. SCOPE_CATEGORIES + LOOKUP_CATEGORIES stay hardcoded
// because they are top-level MCPError codes, NOT per-channel
// policy_decision values.
//
// sec-rev hooks addressed (10 in-scope from design §8):
//   #1  default-exclude noisy signal classes (HIGH only by default;
//       5 opt-in flags for MEDIUM/LOW).
//   #2  hash truncation uniform 12-hex via shared truncateHash helper.
//       (Today: aggregate counts only — no per-row hash surfaced
//       per LOCKED Q5 §5.3; hook is forward-compat for future per-row
//       diagnostic mode.)
//   #3  ALERT path sets process.exitCode = 1 (mirror `audit deletes`
//       conceptual pattern; deletes today does NOT set exitCode but
//       design §4.2 explicitly LOCKS exitCode for suspicious).
//   #4  Strict-parse on --window / --threshold / --since / --limit via
//       shared reader helpers; no new parsers.
//   #5  --include-events opt-in for the 4 non-standard event row shapes
//       (carry sec-M1 from v1.18).
//   #6  NO new audit channel (read-only over existing audit.jsonl).
//   #7  NO new error codes.
//   #8  NO handler change.
//   #9  Hardcoded enums CLOSED in v1.24 Phase 1 Item 1 — categories
//       derived from AUDIT_META_CHANNELS[].suspiciousDecisions registry
//       (Q5 closure). Error-code class (SCOPE_CATEGORIES /
//       LOOKUP_CATEGORIES) stays hardcoded — they are MCPError codes,
//       not channel policy_decision values.
//   #10 PII protection — only hash + decision + channel surfaced;
//       NEVER raw arg values / cell content / file names / URLs.
//   v1.24 Phase 1 Item 2 — `error_code` audit row stamping is now LIVE
//   (auditEnd stamps the field for MCPError throws via with-context.ts
//   capture). The 4 forward-compat safety nets (-32025 / -32026 /
//   -32004 / -32022) below NO LONGER no-op against synthetic test
//   fixtures alone — they fire against real production audit.jsonl rows.

// Import the META-CHANNEL registry from the PURE leaf, NOT the barrel — this is
// the read-side that the extraction was for: it keeps the v1.89 chain WRITER
// (audit.ts) off this CLI reader's import path.
import { AUDIT_META_CHANNELS, type SuspiciousClassification } from "../../audit/meta-channels";
import { CliError, type CliIO } from "../../cli";
import {
  parseWindow,
  streamAuditRows,
  strictParseInt,
  strictParseIso8601,
  type AuditRow,
} from "./reader";
import { renderJson, renderTable } from "./suspicious-render";

const USAGE =
  "usage: safespace audit suspicious [--window 24h] [--threshold N=3] [--since YYYY-MM-DD]\n" +
  "                                  [--limit N=1000] [--json] [--include-events]\n" +
  "                                  [--include-allowlist-denials] [--include-burst-limits]\n" +
  "                                  [--include-tier-denials] [--include-scope-mismatch]\n" +
  "                                  [--include-lookup-failures] [--include-homoglyph-attacks]\n" +
  "       ALERT exits non-zero. Wrap with `|| true` to silence for CI.";

/** v1.24 Phase 2 Item 4 — `export`ed so `./suspicious-render.ts` can type
 *  its render function parameters. NAME-only refactor: classifier owns the
 *  type; render module is a sibling consumer. */
export interface SuspiciousOptions {
  windowMs: number;
  windowRaw: string;
  threshold: number;
  since: Date | null;
  limit: number;
  json: boolean;
  includeEvents: boolean;
  includeAllowlistDenials: boolean;
  includeBurstLimits: boolean;
  includeTierDenials: boolean;
  includeScopeMismatch: boolean;
  includeLookupFailures: boolean;
  /** v1.33 (a)+(c) — opt-in homoglyph-attack breakdown of
   *  denied_formula_rejected rows (aggregate per-script counts). */
  includeHomoglyphAttacks: boolean;
}

function parseFlags(args: string[]): SuspiciousOptions {
  let windowMs = 24 * 60 * 60 * 1000;
  let windowRaw = "24h";
  let threshold = 3; // design Q3 LOCKED (distinct from `audit deletes` default 5)
  let since: Date | null = null;
  let limit = 1000;
  let json = false;
  let includeEvents = false;
  let includeAllowlistDenials = false;
  let includeBurstLimits = false;
  let includeTierDenials = false;
  let includeScopeMismatch = false;
  let includeLookupFailures = false;
  let includeHomoglyphAttacks = false;
  for (let i = 0; i < args.length; i++) {
    const f = args[i];
    if (f === "--window") {
      const v = args[++i];
      if (v === undefined) throw new CliError(`--window requires a value\n       ${USAGE}`);
      try {
        windowMs = parseWindow(v);
        windowRaw = v;
      } catch (e) {
        throw new CliError(`${e instanceof Error ? e.message : String(e)}\n       ${USAGE}`);
      }
    } else if (f === "--threshold") {
      const v = args[++i];
      if (v === undefined) throw new CliError(`--threshold requires a value\n       ${USAGE}`);
      try {
        threshold = strictParseInt(v, "--threshold", 1, 10000);
      } catch (e) {
        throw new CliError(`${e instanceof Error ? e.message : String(e)}\n       ${USAGE}`);
      }
    } else if (f === "--since") {
      const v = args[++i];
      if (v === undefined) throw new CliError(`--since requires a value\n       ${USAGE}`);
      try {
        since = strictParseIso8601(v);
      } catch (e) {
        throw new CliError(`${e instanceof Error ? e.message : String(e)}\n       ${USAGE}`);
      }
    } else if (f === "--limit") {
      const v = args[++i];
      if (v === undefined) throw new CliError(`--limit requires a value\n       ${USAGE}`);
      try {
        // --limit is forward-compat (today aggregate-only output ignores
        // it; sentinel-tested for strict-parse). 100000 upper bound mirrors
        // design §2.4.
        limit = strictParseInt(v, "--limit", 1, 100000);
      } catch (e) {
        throw new CliError(`${e instanceof Error ? e.message : String(e)}\n       ${USAGE}`);
      }
    } else if (f === "--json") {
      json = true;
    } else if (f === "--include-events") {
      includeEvents = true;
    } else if (f === "--include-allowlist-denials") {
      includeAllowlistDenials = true;
    } else if (f === "--include-burst-limits") {
      includeBurstLimits = true;
    } else if (f === "--include-tier-denials") {
      includeTierDenials = true;
    } else if (f === "--include-scope-mismatch") {
      includeScopeMismatch = true;
    } else if (f === "--include-lookup-failures") {
      includeLookupFailures = true;
    } else if (f === "--include-homoglyph-attacks") {
      includeHomoglyphAttacks = true;
    } else {
      throw new CliError(`unknown flag: ${f}\n       ${USAGE}`);
    }
  }
  return {
    windowMs,
    windowRaw,
    threshold,
    since,
    limit,
    json,
    includeEvents,
    includeAllowlistDenials,
    includeBurstLimits,
    includeTierDenials,
    includeScopeMismatch,
    includeLookupFailures,
    includeHomoglyphAttacks,
  };
}

/** Canary categories (LOCKED Q5 — hardcoded per-channel enum unions).
 *
 *  Adding a new audit-meta channel OR a new `policy_decision` enum value to an
 *  existing channel REQUIRES updating this enum + classifyRow() switch below.
 *  See sec hook #9 / Risk 2 / drift-class comment at top of file.
 *
 *  v1.24 Phase 2 Item 4 — `export`ed so `./suspicious-render.ts` can type
 *  its render function parameters. Classifier owns the type; render module
 *  is a sibling consumer (Q5 sub-decision LOCKED). */
export type Category =
  | "denied_formula_rejected"
  | "denied_outbound_sanitize_rejected"
  | "denied_no_allowlist"
  | "denied_not_in_allowlist"
  | "denied_burst_limit"
  | "denied_tier"
  // -32004 / -32022 / -32025 / -32026 — top-level MCPError code signals.
  // v1.24 Phase 1 Item 2 LIVE: auditEnd now stamps `error_code: <number>`
  // on MCPError catch-path rows (Q3 LOCKED). The 4 branches below
  // (`row.error_code === -32xxx`) fire end-to-end against production
  // audit.jsonl rows, not just synthetic test fixtures.
  | "scope_mismatch"
  | "recipient_lookup_failed"
  | "comment_burst_limit_exceeded"
  | "search_burst_limit_exceeded";

// v1.24 Phase 2 Item 4 — CATEGORY_CHANNEL map MOVED to
// `./suspicious-render.ts` (rendering-only consumer per Q5 LOCKED §2.4).
// Classifier reads nested-meta / flattened-row fields directly; never
// consulted CATEGORY_CHANNEL.

/** v1.24 Phase 1 Item 1 — collect all `policy_decision` values from the
 *  AUDIT_META_CHANNELS registry for a given confidence bucket. Used to
 *  derive the per-bucket category arrays below. Closes Q5 — adding a new
 *  channel OR a new `policy_decision` value to an existing channel
 *  requires ONE edit at the registry site (audit.ts AUDIT_META_CHANNELS),
 *  NOT one edit here + one at the audit-row write block + one at
 *  policy-decisions.ts + one at deletes.ts (the previous 4-site drift). */
function collectByBucket(bucket: keyof SuspiciousClassification): ReadonlyArray<string> {
  const out: string[] = [];
  for (const entry of Object.values(AUDIT_META_CHANNELS)) {
    // `as const satisfies …` on AUDIT_META_CHANNELS narrows each entry's
    // suspiciousDecisions to its tuple-literal shape (each channel has a
    // different subset of buckets) — TypeScript then refuses to index with
    // a generic `keyof SuspiciousClassification`. Re-narrow via a typed
    // local view to the design's generic shape contract; the `satisfies`
    // clause already guarantees runtime conformance.
    const decisions = (entry.suspiciousDecisions ?? {}) as SuspiciousClassification;
    const bucketValues = decisions[bucket];
    if (bucketValues) out.push(...bucketValues);
  }
  return out;
}

/** Confidence groupings for output rendering (mirror design §3 + §5).
 *  HIGH / MEDIUM-allowlist / MEDIUM-burst / LOW-tier derive from the
 *  AUDIT_META_CHANNELS[].suspiciousDecisions registry (v1.24 Phase 1
 *  Item 1). Type-cast `as ReadonlyArray<Category>` is safe because the
 *  registry values are constrained at audit.ts to the same string
 *  literal set — but TypeScript can't propagate the `as const` widening
 *  through `collectByBucket()`'s string[] return; a registry-string
 *  outside the Category union would still classify in `classifyRow()`
 *  but never appear in the output (filtered by the active-categories
 *  check). MEDIUM-burst adds the two MCPError code categories
 *  (comment_burst_limit_exceeded / search_burst_limit_exceeded) which
 *  are NOT channel policy_decision values. SCOPE_CATEGORIES /
 *  LOOKUP_CATEGORIES stay hardcoded — top-level MCPError codes only. */
// v1.24 Phase 2 Item 4 — bucket arrays `export`ed so
// `./suspicious-render.ts` can iterate them for output rendering.
// Classifier also reads them via `buildActiveCategories` below — both
// modules share the SAME canonical arrays.
export const HIGH_CONFIDENCE: ReadonlyArray<Category> = collectByBucket(
  "high",
) as ReadonlyArray<Category>;
export const ALLOWLIST_CATEGORIES: ReadonlyArray<Category> = collectByBucket(
  "medium_allowlist",
) as ReadonlyArray<Category>;
export const BURST_CATEGORIES: ReadonlyArray<Category> = [
  ...(collectByBucket("medium_burst") as ReadonlyArray<Category>),
  // Error-code class — top-level MCPError codes, not per-channel
  // policy_decision values. Stay hardcoded per design §2.1.
  "comment_burst_limit_exceeded",
  "search_burst_limit_exceeded",
];
export const TIER_CATEGORIES: ReadonlyArray<Category> = (() => {
  // De-dupe — `denied_tier` appears in all 6 channels' low_tier bucket,
  // but the category array surfaces it ONCE for output rendering.
  const seen = new Set(collectByBucket("low_tier"));
  return Array.from(seen) as ReadonlyArray<Category>;
})();
export const SCOPE_CATEGORIES: ReadonlyArray<Category> = ["scope_mismatch"];
export const LOOKUP_CATEGORIES: ReadonlyArray<Category> = ["recipient_lookup_failed"];

/** v1.25 Phase 1 Item 1 — single source-of-truth for the 4 safety-net
 *  MCPError codes referenced by the row-classification branches below.
 *  Sentinel test at `src/cli/audit/suspicious-literals-sentinel.test.ts`
 *  asserts each entry matches `ERROR_CODES[name].code` in `src/errors.ts`
 *  — structurally prevents the v1.23 `-32007 → -32004` bug class shipped
 *  in v1.23 Phase 1 (hardcoded literal drifted from errors.ts) caught
 *  in-flight at v1.24 Phase 1 (NEW-1 carry-forward). Drift fails the
 *  sentinel test loudly. */
export const SAFETY_NET_CODES = {
  scope_mismatch: -32004,
  recipient_lookup_failed: -32022,
  comment_burst_limit_exceeded: -32025,
  search_burst_limit_exceeded: -32026,
} as const;

/** Default predicate for the sec-M1 event-row filter — mirrors v1.18
 *  `audit recent` defaultPredicate. The 4 non-standard event row shapes
 *  (share_forensic / share_denied_by_policy / recipient_denied_by_policy /
 *  cross_account_aggregate) all lack a `status` field; standard tool-call
 *  rows always have one. */
function isStandardRow(row: AuditRow): boolean {
  return typeof row.status === "string";
}

/** Classify a row against the categories the operator has opted into.
 *  Returns null if the row does not match any active category, OR if the
 *  category matches but is NOT in the opted-in set.
 *
 *  Reads BOTH nested meta objects (`row.commentPostMeta`) AND flattened
 *  top-level `policy_decision` (audit.ts auditEnd flattens the meta onto
 *  the row payload). The flattened path is what production audit.jsonl
 *  actually carries today; the nested-object path is a forward-compat
 *  read for hypothetical future channel shapes. */
function classifyRow(row: AuditRow, opts: SuspiciousOptions): Category | null {
  // Pull policy_decision once — used by every nested + flattened branch.
  const pdTop = typeof row.policy_decision === "string" ? row.policy_decision : null;

  // ─── HIGH confidence (always-on) ────────────────────────────────────────
  // 3.1.1 denied_formula_rejected — sheetsMutationMeta channel
  // Flattened path: target_spreadsheet_id_hash + policy_decision present
  // (Q5 hardcoded — sheetsMutationMeta.policy_decision union per audit.ts).
  if (pdTop === "denied_formula_rejected") {
    return "denied_formula_rejected";
  }
  // Nested-object forward-compat (auditEnd today flattens, but be defensive)
  if (
    typeof row.sheetsMutationMeta === "object" &&
    row.sheetsMutationMeta !== null &&
    (row.sheetsMutationMeta as Record<string, unknown>).policy_decision ===
      "denied_formula_rejected"
  ) {
    return "denied_formula_rejected";
  }

  // 3.1.2 denied_outbound_sanitize_rejected — commentPostMeta channel
  // Hardcoded enum: commentPostMeta.policy_decision ∋ "denied_outbound_sanitize_rejected"
  if (pdTop === "denied_outbound_sanitize_rejected") {
    // Discriminate from calendarMutationMeta (which has the same enum
    // value RESERVED but never emitted in v1.17 Phase 1; field absence is
    // the discriminator). commentPost flattens `target_video_hash`,
    // calendarMutation flattens `target_event_hash`. Either way this is
    // the same canary class, so attribution is fine regardless.
    return "denied_outbound_sanitize_rejected";
  }
  if (
    typeof row.commentPostMeta === "object" &&
    row.commentPostMeta !== null &&
    (row.commentPostMeta as Record<string, unknown>).policy_decision ===
      "denied_outbound_sanitize_rejected"
  ) {
    return "denied_outbound_sanitize_rejected";
  }

  // ─── MEDIUM/LOW confidence (opt-in) ─────────────────────────────────────
  // 3.2 allowlist denials (commentPost only)
  if (opts.includeAllowlistDenials) {
    if (pdTop === "denied_no_allowlist") return "denied_no_allowlist";
    if (pdTop === "denied_not_in_allowlist") return "denied_not_in_allowlist";
    if (
      typeof row.commentPostMeta === "object" &&
      row.commentPostMeta !== null
    ) {
      const pd = (row.commentPostMeta as Record<string, unknown>).policy_decision;
      if (pd === "denied_no_allowlist") return "denied_no_allowlist";
      if (pd === "denied_not_in_allowlist") return "denied_not_in_allowlist";
    }
  }

  // 3.3 burst limits (commentPost meta + -32025 + -32026 error rows)
  if (opts.includeBurstLimits) {
    if (pdTop === "denied_burst_limit") return "denied_burst_limit";
    if (
      typeof row.commentPostMeta === "object" &&
      row.commentPostMeta !== null &&
      (row.commentPostMeta as Record<string, unknown>).policy_decision ===
        "denied_burst_limit"
    ) {
      return "denied_burst_limit";
    }
    // Error-code paths — design §3.3.2 + §3.3.3. v1.24 Phase 1 Item 2:
    // `auditEnd` now stamps `error_code: <number>` for MCPError catch-path
    // rows (Q3 LOCKED). These branches fire end-to-end against production
    // audit.jsonl rows. The 4 corresponding safety nets (-32025 / -32026 /
    // -32004 / -32022) below are no longer no-op forward-compat — they
    // are LIVE.
    if (row.status === "error" && typeof row.error_code === "number") {
      if (row.error_code === SAFETY_NET_CODES.comment_burst_limit_exceeded) return "comment_burst_limit_exceeded";
      if (row.error_code === SAFETY_NET_CODES.search_burst_limit_exceeded) return "search_burst_limit_exceeded";
    }
  }

  // 3.4 tier denials (cross-channel — any channel's policy_decision)
  if (opts.includeTierDenials) {
    if (pdTop === "denied_tier") return "denied_tier";
    // Nested-object forward-compat sweep across the 6 channels.
    for (const ch of [
      "commentPostMeta",
      "calendarMutationMeta",
      "docsModifyMeta",
      "commentDeleteMeta",
      "tasksMutationMeta",
      "sheetsMutationMeta",
    ] as const) {
      const m = row[ch];
      if (
        typeof m === "object" &&
        m !== null &&
        (m as Record<string, unknown>).policy_decision === "denied_tier"
      ) {
        return "denied_tier";
      }
    }
  }

  // 3.5.1 scope_mismatch — error_code SAFETY_NET_CODES.scope_mismatch (v1.25 Phase 1)
  if (opts.includeScopeMismatch) {
    if (row.status === "error" && typeof row.error_code === "number" && row.error_code === SAFETY_NET_CODES.scope_mismatch) {
      return "scope_mismatch";
    }
  }

  // 3.5.2 recipient_lookup_failed — error_code SAFETY_NET_CODES.recipient_lookup_failed (v1.25 Phase 1)
  if (opts.includeLookupFailures) {
    if (row.status === "error" && typeof row.error_code === "number" && row.error_code === SAFETY_NET_CODES.recipient_lookup_failed) {
      return "recipient_lookup_failed";
    }
  }

  return null;
}

/** Initialize per-category counters. ALL active categories start at 0 so
 *  the output explicitly says "0" for canaries that didn't fire (operator
 *  visibility — absence-of-row is itself informative). */
function buildActiveCategories(opts: SuspiciousOptions): Category[] {
  const out: Category[] = [...HIGH_CONFIDENCE];
  if (opts.includeAllowlistDenials) out.push(...ALLOWLIST_CATEGORIES);
  if (opts.includeBurstLimits) out.push(...BURST_CATEGORIES);
  if (opts.includeTierDenials) out.push(...TIER_CATEGORIES);
  if (opts.includeScopeMismatch) out.push(...SCOPE_CATEGORIES);
  if (opts.includeLookupFailures) out.push(...LOOKUP_CATEGORIES);
  return out;
}

/** v1.33 (a)+(c) — aggregate per-script breakdown of denied_formula_rejected
 *  rows. ROW counts (NOT codepoint counts); `ascii` = forensic field ABSENT
 *  (user-typo / autocomplete, LOW signal); the 4 script buckets = field
 *  PRESENT (homoglyph smuggle, HIGH signal). Aggregate-only — NEVER carries
 *  per-row source bytes (sec-rev hooks #10 + #11). */
export interface HomoglyphBreakdown {
  ascii: number;
  cyrillic: number;
  greek: number;
  bidi: number;
  invisible_other: number;
}

/** v1.33 (c) — coarse, CLI-local, range-based script classifier for the
 *  forensic `rejected_formula_homoglyph_source` field. DISPLAY-ONLY trend
 *  analytics; NOT a security gate (the field was already captured by the
 *  load-bearing src/sheets/homoglyph-normalize.ts pipeline). Deliberately does
 *  NOT import HOMOGLYPH_MAP / DEFAULT_IGNORABLE_RE from src/sheets/ — avoids a
 *  src/cli → src/sheets layering coupling (mirror v1.18 youtube-search-burst
 *  extraction rationale). Worst-case drift: a codepoint lands in
 *  `invisible_other`. Returns the DOMINANT script of the field (most
 *  codepoints; fixed tiebreak cyrillic > greek > bidi > invisible_other). */
function classifyHomoglyphScript(
  field: string,
): "cyrillic" | "greek" | "bidi" | "invisible_other" {
  let cyr = 0;
  let grk = 0;
  let bidi = 0;
  let other = 0;
  for (const ch of field) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp >= 0x0400 && cp <= 0x04ff) cyr++;
    else if (cp >= 0x0370 && cp <= 0x03ff) grk++;
    else if ((cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2066 && cp <= 0x2069)) bidi++;
    else other++;
  }
  const max = Math.max(cyr, grk, bidi, other);
  if (cyr === max) return "cyrillic";
  if (grk === max) return "greek";
  if (bidi === max) return "bidi";
  return "invisible_other";
}

/** v1.33 (a)+(c) — read the forensic homoglyph-source field off a row.
 *  Flattened top-level (production audit.jsonl) with nested sheetsMutationMeta
 *  fallback (forward-compat). Returns undefined when absent (ascii bucket). */
function readHomoglyphSource(row: AuditRow): string | undefined {
  if (typeof row.rejected_formula_homoglyph_source === "string") {
    return row.rejected_formula_homoglyph_source;
  }
  const m = row.sheetsMutationMeta;
  if (typeof m === "object" && m !== null) {
    const v = (m as Record<string, unknown>).rejected_formula_homoglyph_source;
    if (typeof v === "string") return v;
  }
  return undefined;
}

export async function runAuditSuspicious(args: string[], io: CliIO): Promise<void> {
  const opts = parseFlags(args);

  // Q4 LOCKED — intersection semantics: later cutoff wins.
  const windowCutoffMs = Date.now() - opts.windowMs;
  const sinceCutoffMs = opts.since ? opts.since.getTime() : -Infinity;
  const cutoffMs = Math.max(windowCutoffMs, sinceCutoffMs);

  const active = buildActiveCategories(opts);
  const counts = new Map<Category, number>();
  for (const c of active) counts.set(c, 0);

  // v1.33 (a)+(c) — homoglyph breakdown of denied_formula_rejected rows
  // (aggregate-only; per-script counts, NEVER per-row source bytes). Populated
  // only when --include-homoglyph-attacks is set; render emits it only under
  // the flag, so flag-OFF output is byte-identical to v1.32.
  const homoglyphBreakdown: HomoglyphBreakdown = {
    ascii: 0,
    cyrillic: 0,
    greek: 0,
    bidi: 0,
    invisible_other: 0,
  };

  for await (const row of streamAuditRows(undefined, { warn: (m) => io.err(m) })) {
    if (typeof row.ts !== "string") continue;
    const t = Date.parse(row.ts);
    if (Number.isNaN(t) || t < cutoffMs) continue;
    // sec-M1: filter the 4 non-standard event row shapes unless opted in.
    if (!opts.includeEvents && !isStandardRow(row)) continue;
    const cat = classifyRow(row, opts);
    if (cat === null) continue;
    // Defensive: a classified row whose category is not in `active` means
    // classifyRow has an inconsistent opt-in gate; skip rather than crash
    // (audit reader invariant: never crashes on row content).
    if (!counts.has(cat)) continue;
    counts.set(cat, (counts.get(cat) ?? 0) + 1);
    // v1.33 (a)+(c) — bucket denied_formula_rejected rows by homoglyph script.
    if (opts.includeHomoglyphAttacks && cat === "denied_formula_rejected") {
      const src = readHomoglyphSource(row);
      if (src === undefined) homoglyphBreakdown.ascii++;
      else homoglyphBreakdown[classifyHomoglyphScript(src)]++;
    }
  }

  // Aggregate totals — HIGH subtotal + grand total.
  let highSubtotal = 0;
  for (const c of HIGH_CONFIDENCE) highSubtotal += counts.get(c) ?? 0;
  let grandTotal = 0;
  for (const [, n] of counts) grandTotal += n;
  const alert = grandTotal >= opts.threshold;
  // sec hook #3 — explicit exit-code contract LOCKED Q3 §4.2. Reset to 0
  // on below-threshold so a prior command in the same process cannot leak
  // a non-zero exit code into this run.
  process.exitCode = alert ? 1 : 0;

  const sinceIso = new Date(cutoffMs).toISOString();

  if (opts.json) {
    renderJson(io, opts, counts, sinceIso, highSubtotal, grandTotal, alert, homoglyphBreakdown);
    return;
  }
  renderTable(io, opts, counts, sinceIso, highSubtotal, grandTotal, alert, homoglyphBreakdown);
}

// v1.24 Phase 2 Item 4 — `renderJson` + `renderTable` MOVED to
// `./suspicious-render.ts` (NAME-only refactor per Q5 LOCKED §2.4).
// `runAuditSuspicious` above imports + calls them. Output BIT-IDENTICAL
// to v1.23 pre-extraction.
