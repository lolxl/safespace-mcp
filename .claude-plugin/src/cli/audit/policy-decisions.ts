// v1.18 Phase 2 — `safespace audit policy-decisions [--since DATE] [--json]`.
//
// Distribution of policy_decision values across the 4 meta channels. Drives
// allowlist-tuning ("am I getting denied a lot at the contact-lookup gate?").
//
// sec-rev hooks addressed:
//   #3 — --since strict ISO 8601 parse pre-read.
//   #5 — only aggregate counts; no row content echoed.
//
// sec-rev M-3 LOCKED: iterate the meta-channel union DYNAMICALLY from the
// AUDIT_META_CHANNELS registry. NEVER hard-code policy_decision enum values;
// the per-channel enum diverges (commentPostMeta has 6 values vs
// commentDeleteMeta with 2). Drift discipline: a 5th channel added in
// v1.19+ shows up automatically.
//
// Unknown-channel handling: if an audit row carries a policy_decision but
// NONE of the registry's channel discriminators match (e.g., future-channel
// drift), the row is bucketed under "unknown" + a stderr warning fires.

// Import the META-CHANNEL registry from the PURE leaf, NOT the barrel — keeps the
// v1.89 chain WRITER (audit.ts) off this CLI reader's import path (the edge break).
import { AUDIT_META_CHANNELS } from "../../audit/meta-channels";
import { CliError, type CliIO } from "../../cli";
import { strictParseIso8601, type AuditRow, streamAuditSources } from "./reader";

const USAGE = "usage: safespace audit policy-decisions [--since YYYY-MM-DD] [--json]";

interface PolicyDecisionsOptions {
  since: Date | null;
  json: boolean;
}

function parseFlags(args: string[]): PolicyDecisionsOptions {
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
        throw new CliError(`${e instanceof Error ? e.message : String(e)}\n       ${USAGE}`);
      }
    } else if (f === "--json") {
      json = true;
    } else {
      throw new CliError(`unknown flag: ${f}\n       ${USAGE}`);
    }
  }
  return { since, json };
}

/** Map a row to its channel label by checking each registered meta key.
 *
 *  Returns the channel label from AUDIT_META_CHANNELS, OR null if a
 *  policy_decision is present but no registered channel matches.
 *  Caller buckets nulls under "unknown" and warns once per unknown-channel
 *  decision value.
 *
 *  Channel discrimination happens BOTH via the nested meta object
 *  (`row.commentDeleteMeta`) AND via flattened hash fields (since auditEnd
 *  flattens the meta into the top-level row).
 *
 *  v1.19 Phase 2b refactor (sec-L4 drift class closure): the flattened-row
 *  branch is now driven by `AUDIT_META_CHANNELS[*].flatHash` instead of a
 *  hard-coded 4-name switch. Adding a 6th channel auto-extends both branches
 *  with NO edit here — registry is the single source of truth. */
function detectChannel(row: AuditRow): string | null {
  // (a) nested meta object pattern — exact registry key match
  for (const key of Object.keys(AUDIT_META_CHANNELS) as Array<keyof typeof AUDIT_META_CHANNELS>) {
    if (typeof row[key] === "object" && row[key] !== null) {
      return AUDIT_META_CHANNELS[key].label;
    }
  }
  // (b) flattened-field discriminator — fully registry-driven. The
  // flatHash field name is unique per channel (target_video_hash /
  // target_event_hash / target_document_id_hash / target_comment_id_hash /
  // target_tasklist_hash). PRESENCE of any one of those top-level fields
  // identifies the channel.
  for (const key of Object.keys(AUDIT_META_CHANNELS) as Array<keyof typeof AUDIT_META_CHANNELS>) {
    const { flatHash, label } = AUDIT_META_CHANNELS[key];
    if (typeof row[flatHash] === "string") return label;
  }
  return null;
}

export async function runAuditPolicyDecisions(args: string[], io: CliIO): Promise<void> {
  const opts = parseFlags(args);
  const sinceMs = opts.since ? opts.since.getTime() : -Infinity;

  // channel → policy_decision → count
  const grouped = new Map<string, Map<string, number>>();
  // Initialize all registered channels so "no occurrences" is visible.
  // v1.19 Phase 2b — registry value shape is {label, flatHash}; use .label
  // for grouping (the human-readable channel name).
  for (const entry of Object.values(AUDIT_META_CHANNELS)) {
    grouped.set(entry.label, new Map());
  }
  grouped.set("unknown", new Map()); // future-drift bucket
  const unknownChannelsWarned = new Set<string>();

  for await (const { row } of streamAuditSources({ warn: (m) => io.err(m) })) {
    if (typeof row.policy_decision !== "string") continue;
    if (opts.since) {
      if (typeof row.ts !== "string") continue;
      const t = Date.parse(row.ts);
      if (Number.isNaN(t) || t < sinceMs) continue;
    }
    const channel = detectChannel(row) ?? "unknown";
    if (channel === "unknown") {
      // sec-M3 graceful-handling: warn once per session — never echo the
      // row content (per hook #5). The decision value alone is closed-enum
      // and PII-free (e.g., "allowed"), so logging it is safe.
      if (!unknownChannelsWarned.has(row.policy_decision)) {
        unknownChannelsWarned.add(row.policy_decision);
        io.err(
          `[safespace audit] warning: policy_decision '${row.policy_decision}' on row without a recognized channel (future drift?)`,
        );
      }
    }
    const inner = grouped.get(channel)!;
    inner.set(row.policy_decision, (inner.get(row.policy_decision) ?? 0) + 1);
  }

  if (opts.json) {
    const out: Record<string, Record<string, number>> = {};
    for (const [channel, counts] of grouped) {
      // Skip "unknown" if no entries (avoids polluting output for the common case).
      if (channel === "unknown" && counts.size === 0) continue;
      out[channel] = Object.fromEntries(counts);
    }
    io.out(
      JSON.stringify({
        since: opts.since ? opts.since.toISOString() : null,
        channels: out,
      }),
    );
    return;
  }

  const sinceLabel = opts.since ? opts.since.toISOString() : "(all time)";
  io.out(`since: ${sinceLabel}`);
  // Per sec-M3 + design §2.2: iterate via registry order (NOT hard-coded).
  // v1.19 Phase 2b — registry value shape is {label, flatHash}; iterate
  // entry.label for the display name.
  for (const entry of Object.values(AUDIT_META_CHANNELS)) {
    const counts = grouped.get(entry.label)!;
    io.out("");
    io.out(`channel: ${entry.label}`);
    if (counts.size === 0) {
      io.out("  (no occurrences in window)");
      continue;
    }
    const sorted = [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    for (const [pd, n] of sorted) {
      io.out(`  ${pd.padEnd(36).slice(0, 36)} ${String(n).padStart(6)}`);
    }
  }
  // Render the unknown bucket only if it has rows (drift signal).
  const unknown = grouped.get("unknown")!;
  if (unknown.size > 0) {
    io.out("");
    io.out("channel: unknown (future drift — registry has no matching meta)");
    const sorted = [...unknown.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    for (const [pd, n] of sorted) {
      io.out(`  ${pd.padEnd(36).slice(0, 36)} ${String(n).padStart(6)}`);
    }
  }
}
