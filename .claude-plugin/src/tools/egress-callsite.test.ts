// Egress call-site sentinel — the machine-checked "classified external-reaching
// tool ⇒ its handler actually CALLS its gate" invariant.
//
// WHY THIS EXISTS: egress-coverage.test.ts pins every write/share tool into a
// classification bucket (CENTRALIZED_EGRESS / HANDLER_GATED_EXTERNAL /
// OWN_DATA_WRITE). That is necessary but not sufficient — a tool can sit in
// CENTRALIZED_EGRESS with direction:"outbound-write" while its handler never
// invokes enforce*EgressGates (the R7 trap one level deeper: "looks gated in
// the registry, ships with zero call-site protection").
//
// This sentinel closes that gap with a static call-site check: for every
// centrally-classified (and handler-gated-external) tool, the handler source
// must contain a call-shaped match of its gate function name(s). Import-only
// references do not count. Dependency-free (node:fs / node:path); no AST.
//
// Single source of truth for the sets: egress-coverage.sets.ts (shared with
// the coverage partition sentinel).

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { CENTRALIZED_EGRESS, HANDLER_GATED_EXTERNAL } from "./egress-coverage.sets";

/** Handler path is relative to `.claude-plugin/src/`. gates = exact centralized
 *  (or bespoke) gate function name(s) the handler must call (call-shaped, not
 *  merely imported). Derived by reading each handler's live call sites. */
const GATE_TABLE: Record<string, { handlerFile: string; gates: string[] }> = {
  // ── CENTRALIZED_EGRESS (tools/egress.ts) ──────────────────────────────
  gmail_send: {
    handlerFile: "tools/handlers/gmail.ts",
    gates: ["enforceEgressGates"],
  },
  gmail_create_draft: {
    handlerFile: "tools/handlers/gmail.ts",
    gates: ["enforceEgressGates"],
  },
  line_push_message: {
    handlerFile: "tools/handlers/line.ts",
    gates: ["enforceLineEgressGates"],
  },
  telegram_send_message: {
    handlerFile: "tools/handlers/telegram.ts",
    gates: ["enforceTelegramEgressGates"],
  },
  discord_send_message: {
    handlerFile: "tools/handlers/discord.ts",
    gates: ["enforceDiscordEgressGates"],
  },
  slack_send_message: {
    handlerFile: "tools/handlers/slack.ts",
    gates: ["enforceSlackEgressGates"],
  },
  mattermost_send_message: {
    handlerFile: "tools/handlers/mattermost.ts",
    gates: ["enforceMattermostEgressGates"],
  },
  github_create_issue: {
    handlerFile: "tools/handlers/github.ts",
    gates: ["enforceGithubWriteEgressGates"],
  },
  github_create_issue_comment: {
    handlerFile: "tools/handlers/github.ts",
    gates: ["enforceGithubWriteEgressGates"],
  },
  github_update_issue: {
    handlerFile: "tools/handlers/github.ts",
    gates: ["enforceGithubWriteEgressGates"],
  },
  github_create_pull_request: {
    handlerFile: "tools/handlers/github.ts",
    gates: ["enforceGithubWriteEgressGates"],
  },
  github_merge_pull_request: {
    handlerFile: "tools/handlers/github.ts",
    gates: ["enforceGithubMergeEgressGates"],
  },
  github_create_pull_request_review: {
    handlerFile: "tools/handlers/github.ts",
    gates: ["enforceGithubReviewEgressGates"],
  },
  github_set_issue_labels: {
    handlerFile: "tools/handlers/github.ts",
    gates: ["enforceGithubWriteEgressGates"],
  },
  notion_create_page: {
    handlerFile: "tools/handlers/notion.ts",
    gates: ["enforceNotionWriteEgressGates"],
  },
  notion_append_blocks: {
    handlerFile: "tools/handlers/notion.ts",
    gates: ["enforceNotionWriteEgressGates"],
  },
  notion_update_page: {
    handlerFile: "tools/handlers/notion.ts",
    gates: ["enforceNotionWriteEgressGates"],
  },
  x_post_create: {
    handlerFile: "tools/handlers/x.ts",
    gates: ["enforceXPostEgressGates"],
  },

  // ── HANDLER_GATED_EXTERNAL (bespoke in-handler gates) ─────────────────
  // drive_share_file: whitelist ancestor walk + (share_type=user) recipient allowlist
  drive_share_file: {
    handlerFile: "tools/handlers/drive.ts",
    gates: ["checkShareAllowed", "isRecipientAllowed"],
  },
  // youtube comment-writes: default-deny target allowlist + burst + outbound sanitize
  youtube_video_comment_post: {
    handlerFile: "tools/handlers/youtube.ts",
    gates: ["isCommentTargetAllowed", "checkCommentBurst", "outboundSanitize"],
  },
  youtube_comment_reply: {
    handlerFile: "tools/handlers/youtube.ts",
    gates: ["isCommentTargetAllowed", "checkCommentBurst", "outboundSanitize"],
  },
  // youtube_video_update: default-deny video allowlist + per-field outbound sanitize + F3a
  youtube_video_update: {
    handlerFile: "tools/handlers/youtube.ts",
    gates: ["isVideoTargetAllowed", "outboundSanitize", "enforceOutboundSecret"],
  },
};

/** `.claude-plugin/src/` — handler paths in GATE_TABLE are relative to here. */
const SRC_ROOT = join(import.meta.dir, "..");

/** Call-shaped match: word-boundary gate name followed by optional whitespace
 *  and an opening paren. Import-only references (no call) do not match. */
function callShaped(gateName: string): RegExp {
  return new RegExp(String.raw`\b${gateName}\s*\(`);
}

describe("egress call-site sentinel — every classified external tool calls its gate", () => {
  test("every CENTRALIZED_EGRESS tool has a GATE_TABLE entry", () => {
    const missing = [...CENTRALIZED_EGRESS].filter((t) => !(t in GATE_TABLE));
    expect(missing).toEqual([]);
  });

  test("every GATE_TABLE key is in CENTRALIZED_EGRESS ∪ HANDLER_GATED_EXTERNAL", () => {
    const allowed = new Set([...CENTRALIZED_EGRESS, ...HANDLER_GATED_EXTERNAL]);
    const extras = Object.keys(GATE_TABLE).filter((t) => !allowed.has(t));
    expect(extras).toEqual([]);
  });

  test("every HANDLER_GATED_EXTERNAL tool has a GATE_TABLE entry", () => {
    const missing = [...HANDLER_GATED_EXTERNAL].filter((t) => !(t in GATE_TABLE));
    expect(missing).toEqual([]);
  });

  test("each GATE_TABLE entry's handler source calls every listed gate (call-shaped)", () => {
    // Cache file contents so multi-tool handlers (github.ts, gmail.ts, …) are
    // read once. Miss message names tool + file + missing gate.
    const fileCache = new Map<string, string>();
    const failures: string[] = [];

    for (const [tool, { handlerFile, gates }] of Object.entries(GATE_TABLE)) {
      let src = fileCache.get(handlerFile);
      if (src === undefined) {
        const abs = join(SRC_ROOT, handlerFile);
        src = readFileSync(abs, "utf8");
        fileCache.set(handlerFile, src);
      }
      for (const gate of gates) {
        if (!callShaped(gate).test(src)) {
          failures.push(
            `${tool}: handler ${handlerFile} is missing a call-site for ${gate} (expected /\\b${gate}\\s*\\(/)`,
          );
        }
      }
    }

    expect(failures).toEqual([]);
  });
});
