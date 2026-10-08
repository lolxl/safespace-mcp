// v1.58 F5 — `safespace audit sessions [--limit N=20] [--anomalous-only]
//            [--denial-threshold N=5] [--delete-threshold N=10]
//            [--call-threshold N=500] [--json]`.
//
// docs/v1.58-f5-session-anomaly-audit.md. Groups audit rows by the v1.58 `run_id`
// (one value per proxy process) and prints a per-SESSION summary + an anomaly
// verdict — the review an unattended overnight run needs (the existing `audit
// suspicious` groups by time WINDOW, not by agent RUN).
//
// READ-ONLY forensics: no gate, no write, no SDK call. It AGGREGATES the existing
// audit signals per-run (it invents none):
//   - denials       — status === "error" rows (a denial / SDK error)
//   - permanent-deletes — the LOCKED `classifyDestructive` discriminator (reused
//                     from ./deletes, not re-derived)
//   - tainted_source — the v1.56 F3b egress-provenance flag (row field)
//   - outbound_secret_shape — the v1.57 F3a interactive secret-shape flag (row field)
//
// NOTE (impl-time, vs design Q4): `credential_lure` is a SANITIZE-WRAP flag in the
// tool RESPONSE (the `<untrusted-source flags="…">` attribute), NOT an audit-row
// field — so it cannot be tallied from audit.jsonl. F5 swaps the planned
// "lure-read + egress" composite for the row-native `outbound_secret_shape` signal
// (and keeps tainted_source). Stamping `credential_lure` on the audit row to
// re-enable the lure composite is a documented fast-follow.
//
// sec hook #6 (mirrors deletes/suspicious): aggregate COUNTS only — never echo
// per-row content (no recipient, no secret bytes, no hash values are printed).

import { CliError, type CliIO } from "../../cli";
import { strictParseInt, type AuditRow, streamAuditSources } from "./reader";
import { classifyDestructive } from "./deletes";

const USAGE =
  "usage: safespace audit sessions [--limit N=20] [--anomalous-only]\n" +
  "                                [--denial-threshold N=5] [--delete-threshold N=10]\n" +
  "                                [--call-threshold N=500] [--json]\n" +
  "       Groups audit rows by run_id (one per proxy process). Surfaces the\n" +
  "       sessions whose aggregate shape is anomalous (the morning-review view).";

interface SessionsOptions {
  limit: number;
  anomalousOnly: boolean;
  denialThreshold: number;
  deleteThreshold: number;
  callThreshold: number;
  json: boolean;
}

function parseFlags(args: string[]): SessionsOptions {
  let limit = 20;
  let anomalousOnly = false;
  let denialThreshold = 5;
  let deleteThreshold = 10;
  let callThreshold = 500;
  let json = false;
  for (let i = 0; i < args.length; i++) {
    const f = args[i];
    const intFlag = (name: string, min: number): number => {
      const v = args[++i];
      if (v === undefined) throw new CliError(`${name} requires a value\n       ${USAGE}`);
      try {
        return strictParseInt(v, name, min, 1_000_000);
      } catch (e) {
        throw new CliError(`${e instanceof Error ? e.message : String(e)}\n       ${USAGE}`);
      }
    };
    if (f === "--limit") limit = intFlag("--limit", 1);
    else if (f === "--denial-threshold") denialThreshold = intFlag("--denial-threshold", 1);
    else if (f === "--delete-threshold") deleteThreshold = intFlag("--delete-threshold", 1);
    else if (f === "--call-threshold") callThreshold = intFlag("--call-threshold", 1);
    else if (f === "--anomalous-only") anomalousOnly = true;
    else if (f === "--json") json = true;
    else throw new CliError(`unknown flag: ${f}\n       ${USAGE}`);
  }
  return { limit, anomalousOnly, denialThreshold, deleteThreshold, callThreshold, json };
}

interface SessionAgg {
  runId: string;
  firstTs: string;
  lastTs: string;
  operators: Set<string>;
  calls: number;
  denials: number;
  deletes: number;
  taintedSource: number;
  outboundSecret: number;
}

type Confidence = "HIGH" | "MEDIUM" | "NONE";

interface SessionVerdict {
  confidence: Confidence;
  reasons: string[];
}

/** Anomaly verdict from a session's aggregate shape (reuses the suspicious.ts
 *  HIGH / MEDIUM vocabulary). HIGH = a direct exfil / destruction signal;
 *  MEDIUM = a spike (denials / call volume). A session is "anomalous" when the
 *  confidence is not NONE. Forensics only — a verdict is a REVIEW PROMPT, never
 *  a block. */
function verdictFor(s: SessionAgg, o: SessionsOptions): SessionVerdict {
  const reasons: string[] = [];
  let high = false;
  let medium = false;
  if (s.taintedSource > 0) {
    high = true;
    reasons.push(`tainted-source egress ×${s.taintedSource}`);
  }
  if (s.outboundSecret > 0) {
    high = true;
    reasons.push(`outbound secret-shape ×${s.outboundSecret}`);
  }
  if (s.deletes >= o.deleteThreshold) {
    high = true;
    reasons.push(`permanent-delete volume ${s.deletes} (≥${o.deleteThreshold})`);
  }
  if (s.denials >= o.denialThreshold) {
    medium = true;
    reasons.push(`denial spike ${s.denials} (≥${o.denialThreshold})`);
  }
  if (s.calls >= o.callThreshold) {
    medium = true;
    reasons.push(`call volume ${s.calls} (≥${o.callThreshold})`);
  }
  const confidence: Confidence = high ? "HIGH" : medium ? "MEDIUM" : "NONE";
  return { confidence, reasons };
}

function aggregate(row: AuditRow, sessions: Map<string, SessionAgg>): void {
  // Pre-v1.58 rows have no run_id — bucket them under a clearly-labelled key so
  // they are visible (not silently dropped) but distinct from real sessions.
  const runId = typeof row.run_id === "string" && row.run_id.length > 0 ? row.run_id : "(no run_id)";
  let s = sessions.get(runId);
  if (s === undefined) {
    s = {
      runId,
      firstTs: "",
      lastTs: "",
      operators: new Set(),
      calls: 0,
      denials: 0,
      deletes: 0,
      taintedSource: 0,
      outboundSecret: 0,
    };
    sessions.set(runId, s);
  }
  s.calls++;
  const ts = typeof row.ts === "string" ? row.ts : "";
  if (ts.length > 0) {
    if (s.firstTs === "" || ts < s.firstTs) s.firstTs = ts;
    if (s.lastTs === "" || ts > s.lastTs) s.lastTs = ts;
  }
  if (typeof row.operator === "string" && row.operator.length > 0) s.operators.add(row.operator);
  if (row.status === "error") s.denials++;
  if (classifyDestructive(row) !== null) s.deletes++;
  if (row.tainted_source === true) s.taintedSource++;
  if (typeof row.outbound_secret_shape === "string") s.outboundSecret++;
}

export async function runAuditSessions(args: string[], io: CliIO): Promise<void> {
  const opts = parseFlags(args);
  const sessions = new Map<string, SessionAgg>();
  for await (const { row } of streamAuditSources({ warn: (m) => io.err(m) })) {
    aggregate(row, sessions);
  }

  // Most-recent-first (by last activity), then cap to --limit.
  let list = [...sessions.values()].map((s) => ({ s, v: verdictFor(s, opts) }));
  list.sort((a, b) => (a.s.lastTs < b.s.lastTs ? 1 : a.s.lastTs > b.s.lastTs ? -1 : 0));
  // The FULL anomalous count — derived from the already-verdicted `list` BEFORE
  // the --anomalous-only filter shrinks it (reuses each verdict; never re-runs
  // verdictFor, so the count cannot drift from the per-session verdicts shown).
  const anomalousTotal = list.filter((e) => e.v.confidence !== "NONE").length;
  if (opts.anomalousOnly) list = list.filter((e) => e.v.confidence !== "NONE");
  const shown = list.slice(0, opts.limit);

  if (opts.json) {
    // sec hook #6: aggregate counts + the verdict only — never per-row content.
    io.out(
      JSON.stringify({
        total_sessions: sessions.size,
        anomalous_sessions: anomalousTotal,
        sessions: shown.map((e) => ({
          run_id: e.s.runId,
          first_ts: e.s.firstTs,
          last_ts: e.s.lastTs,
          operators: [...e.s.operators],
          calls: e.s.calls,
          denials: e.s.denials,
          permanent_deletes: e.s.deletes,
          tainted_source: e.s.taintedSource,
          outbound_secret_shape: e.s.outboundSecret,
          verdict: e.v.confidence,
          reasons: e.v.reasons,
        })),
      }),
    );
    return;
  }

  io.out(`sessions: ${sessions.size} total, ${anomalousTotal} anomalous` + (opts.anomalousOnly ? " (showing anomalous only)" : ""));
  io.out("");
  for (const { s, v } of shown) {
    const ops = s.operators.size > 0 ? [...s.operators].join(",") : "(none)";
    io.out(`run ${s.runId}  ${s.firstTs || "?"} .. ${s.lastTs || "?"}  operator: ${ops}`);
    io.out(
      `  calls: ${s.calls}  denials: ${s.denials}  permanent-deletes: ${s.deletes}` +
        `  tainted_source: ${s.taintedSource}  outbound_secret_shape: ${s.outboundSecret}`,
    );
    if (v.confidence !== "NONE") {
      io.out(`  ⚠ ${v.confidence}: ${v.reasons.join("; ")}`);
    }
    io.out("");
  }
  if (shown.length === 0) {
    io.out(opts.anomalousOnly ? "OK: no anomalous sessions." : "no sessions found.");
  }
}
