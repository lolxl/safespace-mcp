// v1.18 Phase 2 — `safespace audit stats [--since DATE] [--json]`.
//
// Aggregate counts grouped by tool / account / policy_decision. Streams
// audit.jsonl once, accumulates counters, prints summary. O(1) memory
// (counters only — never holds rows in memory).
//
// sec-rev hooks addressed:
//   #3 — --since strict ISO 8601 parse pre-read (CliError before file open).
//   #5 — no row content echoed; only aggregate counts + group keys.

import { CliError, type CliIO } from "../../cli";
import { strictParseIso8601, streamAuditRows } from "./reader";

const USAGE = "usage: safespace audit stats [--since YYYY-MM-DD] [--json]";

interface StatsOptions {
  since: Date | null;
  json: boolean;
}

function parseFlags(args: string[]): StatsOptions {
  let since: Date | null = null;
  let json = false;
  for (let i = 0; i < args.length; i++) {
    const f = args[i];
    if (f === "--since") {
      const v = args[++i];
      if (v === undefined) throw new CliError(`--since requires a value\n       ${USAGE}`);
      try {
        since = strictParseIso8601(v);
      } catch (e) {
        throw new CliError(
          `${e instanceof Error ? e.message : String(e)}\n       ${USAGE}`,
        );
      }
    } else if (f === "--json") {
      json = true;
    } else {
      throw new CliError(`unknown flag: ${f}\n       ${USAGE}`);
    }
  }
  return { since, json };
}

interface Counts {
  byTool: Map<string, number>;
  byAccount: Map<string, number>;
  byPolicyDecision: Map<string, number>;
  total: number;
}

function emptyCounts(): Counts {
  return {
    byTool: new Map(),
    byAccount: new Map(),
    byPolicyDecision: new Map(),
    total: 0,
  };
}

function bump(map: Map<string, number>, key: string): void {
  map.set(key, (map.get(key) ?? 0) + 1);
}

export async function runAuditStats(args: string[], io: CliIO): Promise<void> {
  const opts = parseFlags(args);
  const counts = emptyCounts();
  const sinceMs = opts.since ? opts.since.getTime() : -Infinity;

  for await (const row of streamAuditRows(undefined, { warn: (m) => io.err(m) })) {
    // --since filter: rows with no parseable ts are EXCLUDED when --since is
    // set (defensive — they can't be proven to be in the window).
    if (opts.since) {
      if (typeof row.ts !== "string") continue;
      const t = Date.parse(row.ts);
      if (Number.isNaN(t) || t < sinceMs) continue;
    }
    counts.total++;
    if (typeof row.tool === "string") bump(counts.byTool, row.tool);
    if (typeof row.account === "string") bump(counts.byAccount, row.account);
    if (typeof row.policy_decision === "string") {
      bump(counts.byPolicyDecision, row.policy_decision);
    }
  }

  if (opts.json) {
    io.out(
      JSON.stringify({
        since: opts.since ? opts.since.toISOString() : null,
        total: counts.total,
        by_tool: Object.fromEntries(counts.byTool),
        by_account: Object.fromEntries(counts.byAccount),
        by_policy_decision: Object.fromEntries(counts.byPolicyDecision),
      }),
    );
    return;
  }

  // Table mode.
  const sinceLabel = opts.since ? opts.since.toISOString() : "(all time)";
  io.out(`since: ${sinceLabel}`);
  io.out(`total rows: ${counts.total}`);
  io.out("");
  io.out("By tool:");
  printGroup(io, counts.byTool);
  io.out("");
  io.out("By account:");
  printGroup(io, counts.byAccount);
  if (counts.byPolicyDecision.size > 0) {
    io.out("");
    io.out("By policy_decision:");
    printGroup(io, counts.byPolicyDecision);
  }
}

function printGroup(io: CliIO, m: Map<string, number>): void {
  if (m.size === 0) {
    io.out("  (none)");
    return;
  }
  // Sort by count descending, then key ascending for deterministic output.
  const sorted = [...m.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  const KEY_W = 32;
  for (const [k, v] of sorted) {
    io.out(`  ${k.padEnd(KEY_W).slice(0, KEY_W)} ${String(v).padStart(6)}`);
  }
}
