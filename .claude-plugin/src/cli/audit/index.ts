// v1.18 Phase 2 — `safespace audit` dispatcher. Parses the sub-subcommand
// (recent / stats / deletes / policy-decisions / suspicious) and delegates.
// Mirrors the pattern used by `whitelist` / `recipient` sub-subcommand
// dispatchers in the same directory.
//
// v1.23 Phase 1 — added `suspicious` (5th sub-subcommand) per design
// docs/v1.23-audit-suspicious.md. Closes v1.22 carry-forward L-5 (intent
// signals like `denied_formula_rejected` previously invisible to density
// alerts).

import { CliError, type CliIO } from "../../cli";
import { runAuditDeletes } from "./deletes";
import { runAuditExport } from "./export";
import { runAuditPolicyDecisions } from "./policy-decisions";
import { runAuditRecent } from "./recent";
import { runAuditSessions } from "./sessions";
import { runAuditStats } from "./stats";
import { runAuditSuspicious } from "./suspicious";
import { runAuditVerify } from "./verify";

const USAGE =
  "usage: safespace audit <recent|stats|deletes|policy-decisions|suspicious|sessions|verify|export> [flags]\n" +
  "       safespace audit recent [--limit N=50] [--include-events] [--json]\n" +
  "       safespace audit stats [--since YYYY-MM-DD] [--json]\n" +
  "       safespace audit deletes [--window 24h] [--threshold N=5] [--json]\n" +
  "       safespace audit policy-decisions [--since YYYY-MM-DD] [--json]\n" +
  "       safespace audit suspicious [--window 24h] [--threshold N=3] [--since DATE]\n" +
  "                                  [--limit N=1000] [--json] [--include-events]\n" +
  "                                  [--include-allowlist-denials] [--include-burst-limits]\n" +
  "                                  [--include-tier-denials] [--include-scope-mismatch]\n" +
  "                                  [--include-lookup-failures] [--include-homoglyph-attacks]\n" +
  "       safespace audit sessions [--limit N=20] [--anomalous-only] [--json]\n" +
  "                                [--denial-threshold N=5] [--delete-threshold N=10]\n" +
  "                                [--call-threshold N=500]\n" +
  "       safespace audit verify [--json]\n" +
  "       safespace audit export [--format jsonl|cef] [--since YYYY-MM-DD]";

export async function runAuditCmd(rest: string[], io: CliIO): Promise<void> {
  const [sub, ...args] = rest;
  if (!sub) throw new CliError(USAGE);
  if (sub === "recent") return runAuditRecent(args, io);
  if (sub === "stats") return runAuditStats(args, io);
  if (sub === "deletes") return runAuditDeletes(args, io);
  if (sub === "policy-decisions") return runAuditPolicyDecisions(args, io);
  if (sub === "suspicious") return runAuditSuspicious(args, io);
  if (sub === "sessions") return runAuditSessions(args, io);
  if (sub === "verify") return runAuditVerify(args, io);
  if (sub === "export") return runAuditExport(args, io);
  throw new CliError(`unknown audit subcommand: ${sub}\n       ${USAGE}`);
}
