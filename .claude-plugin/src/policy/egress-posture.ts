// v1.87 — per-connector egress/access allowlist posture (for `doctor --posture`).
//
// Enumerates every policy allowlist that bounds what the agent can reach or send,
// classifying each into one of three EFFECTIVE states for the operator to verify:
//   - restricted — N entries allowlisted (the intended hardened state)
//   - deny-all   — nothing permitted (an off→DENY list unset, or an off→ALLOW list
//                  unset under autonomous mode → both safe / inert)
//   - OPEN       — an off→ALLOW list unset while INTERACTIVE → unrestricted egress;
//                  the one warn-worthy posture finding (set the allowlist, or
//                  enable SAFESPACE_AUTONOMOUS to flip it deny-by-default)
//
// NO-PII-ECHO (the load-bearing invariant): rows carry COUNTS + posture words only,
// NEVER the allowlist CONTENTS (emails / repos / channel ids / roots / hosts). Each
// connector's `summarize*` helper already returns counts-not-values; this module
// only ever reads `.kind` and a count off them.
//
// The autonomous flip is applied UNIFORMLY here at the posture layer (off→ALLOW +
// unset is deny-all iff autonomous), from each allowlist's STATIC default posture +
// one isAutonomousMode() read — so this module does not depend on whether a given
// connector folds autonomous inside its state builder vs its gate.

import { isAutonomousMode } from "./autonomous-mode";
import { getAllowlistState, summarizeAllowlist } from "./recipient-allowlist";
import {
  getTasksDeleteAllowlistState,
  summarizeTasksDeleteAllowlist,
} from "./tasks-delete-targets";
import {
  getCommentTargetAllowlistState,
  summarizeCommentTargetAllowlist,
} from "./youtube-comment-targets";
import {
  getVideoTargetAllowlistState,
  summarizeVideoTargetAllowlist,
} from "./youtube-video-targets";
import { lineAllowlistSummary } from "./line-recipient-allowlist";
import { telegramAllowlistSummary } from "./telegram-recipient-allowlist";
import { discordAllowlistSummary } from "./discord-recipient-allowlist";
import { slackAllowlistSummary } from "./slack-recipient-allowlist";
import { mattermostAllowlistSummary } from "./mattermost-recipient-allowlist";
import {
  getGithubWriteAllowlistState,
  summarizeGithubWriteAllowlist,
} from "./github-write-targets";
import {
  getGithubMergeAllowlistState,
  summarizeGithubMergeAllowlist,
} from "./github-merge-targets";
import {
  getGithubApproveAllowlistState,
  summarizeGithubApproveAllowlist,
} from "./github-approve-targets";
import { fsRootsSummary } from "./fs-gate";
import { webfetchAllowlistSummary } from "./url-gate";

export type EgressStatus = "pass" | "warn";

export interface EgressRow {
  /** A connector label — NOT a secret (a fixed display name). */
  readonly connector: string;
  readonly status: EgressStatus;
  /** Counts + posture words only — NEVER the allowlist contents. */
  readonly detail: string;
}

/** Default "off" posture of an allowlist: off→ALLOW (presence tightens) vs
 *  off→DENY (presence loosens — a public/destructive surface). */
export type DefaultPosture = "allow" | "deny";

/** Pure classifier — the single source of the restricted / deny-all / OPEN rule.
 *  Exported for direct unit testing (no env / no cache). `count` is read ONLY when
 *  `configured` is true (every summary helper returns count 0 when unset anyway). */
export function classifyEgress(
  connector: string,
  configured: boolean,
  count: number,
  posture: DefaultPosture,
  autonomous: boolean,
): EgressRow {
  if (configured) {
    return {
      connector,
      status: "pass",
      detail: `restricted — ${count} ${count === 1 ? "entry" : "entries"} allowlisted`,
    };
  }
  // Unset. An off→DENY list is deny-all by construction; an off→ALLOW list is
  // deny-all only under autonomous mode, otherwise wide OPEN.
  if (posture === "deny") {
    return {
      connector,
      status: "pass",
      detail: "deny-all (unset → nothing permitted until you list targets)",
    };
  }
  return autonomous
    ? {
        connector,
        status: "pass",
        detail: "deny-all (unset + autonomous → nothing permitted)",
      }
    : {
        connector,
        status: "warn",
        detail:
          "OPEN (unset + interactive → unrestricted; set the allowlist or enable SAFESPACE_AUTONOMOUS)",
      };
}

/** Enumerate every egress/access allowlist's effective posture. Reads env (live)
 *  + each connector's count-only summary; never the allowlist contents. */
export async function evaluateEgressPosture(): Promise<EgressRow[]> {
  const auto = isAutonomousMode();
  // recipient alone is async (its state resolves the operator's self-send accounts);
  // every other connector's state read is synchronous.
  const recipient = summarizeAllowlist(await getAllowlistState());
  const tasksDelete = summarizeTasksDeleteAllowlist(getTasksDeleteAllowlistState());
  const ytComment = summarizeCommentTargetAllowlist(getCommentTargetAllowlistState());
  const ytVideo = summarizeVideoTargetAllowlist(getVideoTargetAllowlistState());
  const line = lineAllowlistSummary();
  const telegram = telegramAllowlistSummary();
  const discord = discordAllowlistSummary();
  const slack = slackAllowlistSummary();
  const mattermost = mattermostAllowlistSummary();
  const ghWrite = summarizeGithubWriteAllowlist(getGithubWriteAllowlistState());
  const ghMerge = summarizeGithubMergeAllowlist(getGithubMergeAllowlistState());
  const ghApprove = summarizeGithubApproveAllowlist(getGithubApproveAllowlistState());
  const fsRoots = fsRootsSummary();
  const webfetch = webfetchAllowlistSummary();

  return [
    classifyEgress(
      "recipient (gmail · drive)",
      recipient.kind === "active",
      recipient.allow_count + recipient.extra_count,
      "allow",
      auto,
    ),
    classifyEgress("tasks-delete", tasksDelete.kind === "active", tasksDelete.count, "allow", auto),
    classifyEgress("youtube-comment", ytComment.kind === "active", ytComment.count, "deny", auto),
    classifyEgress("youtube-video", ytVideo.kind === "active", ytVideo.count, "deny", auto),
    classifyEgress("line", line.kind === "active", line.id_count, "allow", auto),
    classifyEgress("telegram", telegram.kind === "active", telegram.id_count, "allow", auto),
    classifyEgress("discord", discord.kind === "active", discord.id_count, "allow", auto),
    classifyEgress("slack", slack.kind === "active", slack.id_count, "allow", auto),
    classifyEgress("mattermost", mattermost.kind === "active", mattermost.id_count, "allow", auto),
    classifyEgress("github-write", ghWrite.kind === "active", ghWrite.count, "deny", auto),
    classifyEgress("github-merge", ghMerge.kind === "active", ghMerge.count, "deny", auto),
    classifyEgress("github-approve", ghApprove.kind === "active", ghApprove.count, "deny", auto),
    classifyEgress("fs-read", fsRoots.kind === "active", fsRoots.count, "deny", auto),
    classifyEgress("web-fetch", webfetch.kind === "active", webfetch.count, "allow", auto),
  ];
}
