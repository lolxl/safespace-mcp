// v1.24 Phase 2 Item 4 — render module extracted from suspicious.ts.
//
// NAME-only refactor (Q5 LOCKED §2.4 extraction boundary):
//   STAYS in suspicious.ts: USAGE / SuspiciousOptions / parseFlags /
//     Category type / per-bucket category arrays (HIGH_CONFIDENCE etc.) /
//     isStandardRow / classifyRow / buildActiveCategories /
//     runAuditSuspicious orchestrator + process.exitCode contract.
//   MOVES here: CATEGORY_CHANNEL map / renderJson / renderTable.
//
// Q5 sub-decision LOCKED:
//   `Category` type STAYS in suspicious.ts (classifier owns the type
//   union) — render imports the type for parameter typing.
//   `CATEGORY_CHANNEL` MOVES here (rendering-only — no classifier
//   branch reads it).
//
// Pattern reference: v1.18 Phase 2 PR #144 `reader.ts` extraction from
// the audit CLI dispatcher (~120 LoC out of the original 631-LoC
// dispatcher).
//
// Sec-rev hooks addressed:
//   §8 #5 — NAME-only extraction; v1.23 suspicious.test.ts fixture is
//           the regression sentinel; output text BIT-IDENTICAL
//           pre/post extraction (table column widths, JSON key
//           ordering, indent levels all preserved).

import type { CliIO } from "../../cli";
import type {
  Category,
  HomoglyphBreakdown,
  SuspiciousOptions,
} from "./suspicious";
import {
  ALLOWLIST_CATEGORIES,
  BURST_CATEGORIES,
  HIGH_CONFIDENCE,
  LOOKUP_CATEGORIES,
  SCOPE_CATEGORIES,
  TIER_CATEGORIES,
} from "./suspicious";

/** Channel attribution for table/JSON output. NOT used for classification —
 *  classification reads the nested-meta object or flattened-row fields
 *  directly. Moved here in v1.24 Phase 2 Item 4 (rendering-only). */
export const CATEGORY_CHANNEL: Record<Category, string> = {
  denied_formula_rejected: "sheetsMutation",
  denied_outbound_sanitize_rejected: "commentPost",
  denied_no_allowlist: "commentPost",
  denied_not_in_allowlist: "commentPost",
  denied_burst_limit: "commentPost",
  denied_tier: "cross-channel",
  scope_mismatch: "-32004",
  recipient_lookup_failed: "-32022",
  comment_burst_limit_exceeded: "-32025",
  search_burst_limit_exceeded: "-32026",
};

/** Render aggregate counts in JSON. Mirrors design §5.2. */
export function renderJson(
  io: CliIO,
  opts: SuspiciousOptions,
  counts: Map<Category, number>,
  sinceIso: string,
  highSubtotal: number,
  grandTotal: number,
  alert: boolean,
  homoglyphBreakdown: HomoglyphBreakdown,
): void {
  const groups: Record<string, Record<string, Record<string, unknown>>> = {};
  groups.high_confidence_canaries = {};
  for (const c of HIGH_CONFIDENCE) {
    groups.high_confidence_canaries[c] = {
      count: counts.get(c) ?? 0,
      channel: CATEGORY_CHANNEL[c],
    };
  }
  if (opts.includeAllowlistDenials) {
    groups.allowlist_denials = {};
    for (const c of ALLOWLIST_CATEGORIES) {
      groups.allowlist_denials[c] = {
        count: counts.get(c) ?? 0,
        channel: CATEGORY_CHANNEL[c],
      };
    }
  }
  if (opts.includeBurstLimits) {
    groups.burst_limits = {};
    for (const c of BURST_CATEGORIES) {
      const entry: Record<string, unknown> = {
        count: counts.get(c) ?? 0,
      };
      // Error-code categories surface the error_code instead of channel.
      if (c === "comment_burst_limit_exceeded") entry.error_code = -32025;
      else if (c === "search_burst_limit_exceeded") entry.error_code = -32026;
      else entry.channel = CATEGORY_CHANNEL[c];
      groups.burst_limits[c] = entry;
    }
  }
  if (opts.includeTierDenials) {
    groups.tier_denials = {};
    for (const c of TIER_CATEGORIES) {
      groups.tier_denials[c] = {
        count: counts.get(c) ?? 0,
        channel: CATEGORY_CHANNEL[c],
      };
    }
  }
  if (opts.includeScopeMismatch) {
    groups.scope_mismatch = {};
    for (const c of SCOPE_CATEGORIES) {
      groups.scope_mismatch[c] = {
        count: counts.get(c) ?? 0,
        error_code: -32004,
      };
    }
  }
  if (opts.includeLookupFailures) {
    groups.lookup_failures = {};
    for (const c of LOOKUP_CATEGORIES) {
      groups.lookup_failures[c] = {
        count: counts.get(c) ?? 0,
        error_code: -32022,
      };
    }
  }
  io.out(
    JSON.stringify({
      window: opts.windowRaw,
      since: sinceIso,
      threshold: opts.threshold,
      alert,
      categories: groups,
      // v1.33 (a)+(c) — emitted ONLY under --include-homoglyph-attacks so
      // flag-OFF output stays byte-identical to v1.32. Aggregate per-script
      // ROW counts of denied_formula_rejected; NEVER per-row source bytes.
      ...(opts.includeHomoglyphAttacks && { homoglyph_attacks: homoglyphBreakdown }),
      totals: {
        high_confidence: highSubtotal,
        grand_total: grandTotal,
      },
    }),
  );
}

/** Render aggregate counts in operator-facing table mode. Mirrors design §5.1. */
export function renderTable(
  io: CliIO,
  opts: SuspiciousOptions,
  counts: Map<Category, number>,
  sinceIso: string,
  highSubtotal: number,
  grandTotal: number,
  alert: boolean,
  homoglyphBreakdown: HomoglyphBreakdown,
): void {
  io.out(`window: ${opts.windowRaw} (since ${sinceIso})`);
  const anyOptIn =
    opts.includeAllowlistDenials ||
    opts.includeBurstLimits ||
    opts.includeTierDenials ||
    opts.includeScopeMismatch ||
    opts.includeLookupFailures;

  if (!anyOptIn) {
    // Default (HIGH-only) compact rendering — matches §2.1 sample.
    for (const c of HIGH_CONFIDENCE) {
      io.out(
        `${c}:${" ".repeat(Math.max(1, 35 - c.length))}${counts.get(c) ?? 0}  (${CATEGORY_CHANNEL[c]})`,
      );
    }
    io.out(`total high-confidence canaries:    ${highSubtotal}`);
    io.out(`threshold:                         ${opts.threshold}`);
  } else {
    // Grouped rendering — matches §5.1 expanded sample.
    io.out("");
    io.out("high-confidence canaries:");
    for (const c of HIGH_CONFIDENCE) {
      io.out(
        `  ${c}:${" ".repeat(Math.max(1, 35 - c.length))}${counts.get(c) ?? 0}  (${CATEGORY_CHANNEL[c]})`,
      );
    }
    io.out(`  subtotal:                          ${highSubtotal}`);
    if (opts.includeAllowlistDenials) {
      io.out("");
      io.out("allowlist denials (opt-in):");
      let sub = 0;
      for (const c of ALLOWLIST_CATEGORIES) {
        const n = counts.get(c) ?? 0;
        sub += n;
        io.out(
          `  ${c}:${" ".repeat(Math.max(1, 35 - c.length))}${n}  (${CATEGORY_CHANNEL[c]})`,
        );
      }
      io.out(`  subtotal:                          ${sub}`);
    }
    if (opts.includeBurstLimits) {
      io.out("");
      io.out("burst limits (opt-in):");
      let sub = 0;
      for (const c of BURST_CATEGORIES) {
        const n = counts.get(c) ?? 0;
        sub += n;
        const suffix =
          c === "comment_burst_limit_exceeded"
            ? "(-32025)"
            : c === "search_burst_limit_exceeded"
              ? "(-32026)"
              : `(${CATEGORY_CHANNEL[c]})`;
        io.out(
          `  ${c}:${" ".repeat(Math.max(1, 35 - c.length))}${n}  ${suffix}`,
        );
      }
      io.out(`  subtotal:                          ${sub}`);
    }
    if (opts.includeTierDenials) {
      io.out("");
      io.out("tier denials (opt-in):");
      let sub = 0;
      for (const c of TIER_CATEGORIES) {
        const n = counts.get(c) ?? 0;
        sub += n;
        io.out(
          `  ${c}:${" ".repeat(Math.max(1, 35 - c.length))}${n}  (${CATEGORY_CHANNEL[c]})`,
        );
      }
      io.out(`  subtotal:                          ${sub}`);
    }
    if (opts.includeScopeMismatch) {
      io.out("");
      io.out("scope mismatch (opt-in):");
      let sub = 0;
      for (const c of SCOPE_CATEGORIES) {
        const n = counts.get(c) ?? 0;
        sub += n;
        io.out(
          `  ${c}:${" ".repeat(Math.max(1, 35 - c.length))}${n}  (-32004)`,
        );
      }
      io.out(`  subtotal:                          ${sub}`);
    }
    if (opts.includeLookupFailures) {
      io.out("");
      io.out("lookup failures (opt-in):");
      let sub = 0;
      for (const c of LOOKUP_CATEGORIES) {
        const n = counts.get(c) ?? 0;
        sub += n;
        io.out(
          `  ${c}:${" ".repeat(Math.max(1, 35 - c.length))}${n}  (-32022)`,
        );
      }
      io.out(`  subtotal:                          ${sub}`);
    }
    io.out("");
    io.out(`grand total:                        ${grandTotal}`);
    io.out(`threshold:                           ${opts.threshold}`);
  }
  // v1.33 (a)+(c) — homoglyph breakdown section (additive; only under the
  // flag, so non-flag output is byte-identical to v1.32). Works in both
  // compact + grouped modes; placed before the trailing ALERT/OK line.
  if (opts.includeHomoglyphAttacks) {
    io.out("");
    io.out("denied_formula_rejected breakdown (--include-homoglyph-attacks):");
    io.out(`  ascii (user-typo / autocomplete):  ${homoglyphBreakdown.ascii}`);
    io.out(`  cyrillic:                          ${homoglyphBreakdown.cyrillic}`);
    io.out(`  greek:                             ${homoglyphBreakdown.greek}`);
    io.out(`  bidi:                              ${homoglyphBreakdown.bidi}`);
    io.out(`  invisible_other:                   ${homoglyphBreakdown.invisible_other}`);
  }
  io.out("");
  if (alert) {
    io.out("ALERT: prompt-injection canary density at/above threshold.");
    io.out("       Review recent activity: safespace audit recent --limit 20");
  } else {
    io.out("OK: prompt-injection canary density below threshold.");
  }
}
