// v1.18 Phase 2 — `safespace audit deletes [--window 24h] [--threshold N=5] [--json]`.
//
// Density alert: count destructive events in trailing window and ALERT if
// the count meets/exceeds the threshold. Implements CLAUDE.md L236 v1.18
// hook NEW-5.
//
// Destructive event discriminator (LOCKED per sec-rev M-2 in design §2.2 +
// v1.19 Phase 2b sec-H2):
//   (1) commentDeleteMeta exists AND policy_decision === "deleted" AND status === "ok"
//   (2) calendarMutationMeta exists AND tool === "calendar_delete_event" AND status === "ok"
//   (3) tasksMutationMeta exists AND operation === "delete" AND status === "ok"
//       (v1.19 Phase 2b — sec-M3 LOCKED uses `operation === "delete"` NOT
//       `policy_decision === "deleted"`; policy_decision stays binary
//       allowed|denied_tier for tasksMutationMeta. INTENTIONALLY divergent
//       from v1.17 commentDeleteMeta.)
//   (4) playlistMutationMeta exists AND operation === "playlist_delete" AND
//       status === "ok" (v1.49 — YouTube has NO playlist trash; permanent.
//       Same operation-discriminator pattern as (3). The sibling
//       playlist_item_remove is RECOVERABLE (re-insert) and is NOT counted.)
//
// Tier-denied attempts (policy_decision === "denied_tier" with status === "error")
// audit the ATTEMPT but no deletion occurred — EXCLUDED to prevent
// false-positive ALERT inflation.
//
// v1.24 Phase 2 Item 3 — ALERT path sets process.exitCode = 1; OK path
// explicitly resets to 0. Mirrors v1.23 `audit suspicious` Q3 LOCK (Q4
// LOCKED §2.3) — restores parity across the two density-alert
// subcommands. CI integrators that relied on exit-0-on-ALERT must wrap
// with `|| true` to silence. Below-threshold explicit reset to 0
// defends against prior-command leakage in the same process (test
// suites that call runCli multiple times in one process).
//
// sec-rev hooks addressed:
//   #2 — density threshold default 5/24h (overridable via --threshold + --window).
//   #4 — --window / --threshold integer + bounds checks pre-read.
//   #4 (v1.24) — exit-code parity with `audit suspicious`; documented
//                as v1.23 contract extension (ALERT stdout line was
//                already a signal — CI grep should already handle it).
//   #6 — aggregate counts ONLY; NEVER echo per-row content.

import { CliError, type CliIO } from "../../cli";
import {
  parseWindow,
  strictParseInt,
  streamAuditRows,
  type AuditRow,
} from "./reader";

const USAGE =
  "usage: safespace audit deletes [--window 24h] [--threshold N=5] [--json]\n" +
  "       ALERT exits non-zero. Wrap with `|| true` to silence for CI.";

interface DeletesOptions {
  /** Window in milliseconds. */
  windowMs: number;
  /** Human-readable window string (e.g., "24h") for display. */
  windowRaw: string;
  threshold: number;
  json: boolean;
}

function parseFlags(args: string[]): DeletesOptions {
  let windowMs = 24 * 60 * 60 * 1000;
  let windowRaw = "24h";
  let threshold = 5;
  let json = false;
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
    } else if (f === "--json") {
      json = true;
    } else {
      throw new CliError(`unknown flag: ${f}\n       ${USAGE}`);
    }
  }
  return { windowMs, windowRaw, threshold, json };
}

/** sec-rev M-2 LOCKED discriminator (+ v1.19 Phase 2b sec-H2 extension).
 *  Returns the destructive-event category string OR null if the row is NOT
 *  a destructive event. Tier-denied attempts return null (status === "error"
 *  never matches the AND clauses). v1.58 F5 — `export`ed so `audit sessions`
 *  reuses the SAME locked discriminator for its per-session permanent-delete
 *  tally (one classifier, cannot drift). */
export function classifyDestructive(
  row: AuditRow,
):
  | "youtube_comment_delete"
  | "calendar_delete_event"
  | "tasks_delete"
  | "youtube_playlist_delete"
  | null {
  if (row.status !== "ok") return null; // tier-denied / SDK-error rows excluded
  // (1) YouTube comment delete
  if (
    typeof row.commentDeleteMeta === "object" &&
    row.commentDeleteMeta !== null &&
    (row.commentDeleteMeta as Record<string, unknown>).policy_decision === "deleted"
  ) {
    return "youtube_comment_delete";
  }
  // Some audit rows flatten commentDeleteMeta fields onto the top row
  // (see audit.ts auditEnd § Phase 3) — recognize via target_comment_id_hash
  // + policy_decision === "deleted" as a fallback discriminator.
  if (
    typeof row.target_comment_id_hash === "string" &&
    row.policy_decision === "deleted"
  ) {
    return "youtube_comment_delete";
  }
  // (2) Calendar delete event
  if (
    typeof row.calendarMutationMeta === "object" &&
    row.calendarMutationMeta !== null &&
    row.tool === "calendar_delete_event"
  ) {
    return "calendar_delete_event";
  }
  // Flattened-row fallback for calendarMutationMeta — discriminate by tool
  // name (event_id hash is not unique to delete; update/respond also have it).
  if (
    typeof row.target_event_hash === "string" &&
    row.tool === "calendar_delete_event"
  ) {
    return "calendar_delete_event";
  }
  // (3) v1.19 Phase 2b — Tasks delete (PERMANENTLY destructive; Google
  // Tasks has NO trash). sec-M3 LOCKED: discriminate by `operation === "delete"`
  // NOT `policy_decision === "deleted"` (tasksMutationMeta.policy_decision is
  // binary "allowed" | "denied_tier"). Without this 3rd branch, tasks_delete
  // rows ESCAPE the density alert entirely — incompatible with the
  // recovery-impossibility posture per design §11 Risk 1.
  if (
    typeof row.tasksMutationMeta === "object" &&
    row.tasksMutationMeta !== null &&
    (row.tasksMutationMeta as Record<string, unknown>).operation === "delete"
  ) {
    return "tasks_delete";
  }
  // Flattened-row fallback for tasksMutationMeta — discriminate by
  // operation==="delete" + tool name. target_tasklist_hash alone is NOT
  // a delete-specific signal (create / update rows also have it); we MUST
  // use `operation` AND the tool name to avoid false positives on create
  // / update rows.
  if (
    typeof row.target_tasklist_hash === "string" &&
    row.operation === "delete" &&
    row.tool === "tasks_delete"
  ) {
    return "tasks_delete";
  }
  // (4) v1.49 — YouTube playlist delete (PERMANENTLY destructive; YouTube has
  // NO playlist trash, asymmetric with Drive's 30-day trash). Mirror the
  // tasks_delete sec-M3 discriminator: match `operation === "playlist_delete"`
  // NOT `policy_decision` (playlistMutationMeta.policy_decision is binary
  // "allowed" | "denied_tier"). The sibling `playlist_item_remove` is
  // RECOVERABLE (re-insert the video) so it is deliberately NOT classified
  // destructive — exactly like tasks_clear / tasks_move. Without this branch a
  // permanent playlist delete would ESCAPE the density alert entirely.
  if (
    typeof row.playlistMutationMeta === "object" &&
    row.playlistMutationMeta !== null &&
    (row.playlistMutationMeta as Record<string, unknown>).operation ===
      "playlist_delete"
  ) {
    return "youtube_playlist_delete";
  }
  // Flattened-row fallback for playlistMutationMeta — discriminate by
  // operation==="playlist_delete" + tool name. target_playlist_hash alone is
  // NOT a delete-specific signal (create / update / insert / item_remove rows
  // also carry it); require `operation` AND the tool name to avoid false
  // positives on the non-destructive playlist rows.
  if (
    typeof row.target_playlist_hash === "string" &&
    row.operation === "playlist_delete" &&
    row.tool === "youtube_playlist_delete"
  ) {
    return "youtube_playlist_delete";
  }
  return null;
}

export async function runAuditDeletes(args: string[], io: CliIO): Promise<void> {
  const opts = parseFlags(args);
  const cutoffMs = Date.now() - opts.windowMs;

  let countYoutube = 0;
  let countCalendar = 0;
  let countTasks = 0;
  let countPlaylist = 0;

  for await (const row of streamAuditRows(undefined, { warn: (m) => io.err(m) })) {
    if (typeof row.ts !== "string") continue;
    const t = Date.parse(row.ts);
    if (Number.isNaN(t) || t < cutoffMs) continue;
    const cat = classifyDestructive(row);
    if (cat === "youtube_comment_delete") countYoutube++;
    else if (cat === "calendar_delete_event") countCalendar++;
    else if (cat === "tasks_delete") countTasks++;
    else if (cat === "youtube_playlist_delete") countPlaylist++;
  }
  const total = countYoutube + countCalendar + countTasks + countPlaylist;
  const alert = total >= opts.threshold;
  // v1.24 Phase 2 Item 3 — explicit exit-code contract (mirror
  // suspicious.ts:471 / v1.23 Q3 LOCK). Reset to 0 on OK so a prior
  // command in the same process cannot leak a non-zero exit code into
  // this run. Documented in USAGE: "ALERT exits non-zero. Wrap with
  // `|| true` to silence for CI."
  process.exitCode = alert ? 1 : 0;
  const since = new Date(cutoffMs).toISOString();

  if (opts.json) {
    // sec hook #6: aggregate counts only — NEVER individual rows.
    io.out(
      JSON.stringify({
        window: opts.windowRaw,
        since,
        youtube_comment_delete: countYoutube,
        calendar_delete_event: countCalendar,
        tasks_delete: countTasks,
        youtube_playlist_delete: countPlaylist,
        total,
        threshold: opts.threshold,
        alert,
      }),
    );
    return;
  }

  io.out(`window: ${opts.windowRaw} (since ${since})`);
  io.out(`youtube_comment_delete:  ${countYoutube}`);
  io.out(`calendar_delete_event:   ${countCalendar}`);
  io.out(`tasks_delete:            ${countTasks}`);
  io.out(`youtube_playlist_delete: ${countPlaylist}`);
  io.out(`total destructive:       ${total}`);
  io.out(`threshold:               ${opts.threshold}`);
  io.out("");
  if (alert) {
    io.out("ALERT: destructive event density at/above threshold.");
    io.out("       Review recent activity: safespace audit recent --limit 20");
  } else {
    io.out("OK: destructive event density below threshold.");
  }
}
