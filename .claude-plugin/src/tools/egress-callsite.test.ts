// Egress call-site sentinel — the machine-checked "classified external-reaching
// tool ⇒ its gate is actually CALLED" invariant: by the descriptor for a
// PIPELINE_EGRESS tool, by the handler for a HANDLER_GATED_EXTERNAL one.
//
// WHY THIS EXISTS: egress-coverage.test.ts pins every write/share tool into a
// classification bucket (PIPELINE_EGRESS / HANDLER_GATED_EXTERNAL /
// OWN_DATA_WRITE). That is necessary but not sufficient — a tool can sit in a
// gated bucket while its gate is never called (the R7 trap one level deeper:
// "looks gated in the registry, ships with zero call-site protection").
//
// This sentinel closes that gap with a static call-site check: for every
// HANDLER_GATED_EXTERNAL tool, the handler source must contain a call-shaped
// match of its gate function name(s). Import-only references do not count.
// Dependency-free (node:fs / node:path); no AST.
//
// B6.1 wave A1 — PIPELINE_EGRESS tools invert the rule: their gate is fired by
// the tool's choke point (withNonOAuthContext for the service-token sends,
// withToolContext for the OAuth writes) via the registry def's egress descriptor, so the
// DESCRIPTOR module (tools/egress-pipeline.ts) must contain the call-shaped gate
// match, the HANDLER must NOT (anti-double-fire), and the def must carry the
// descriptor (asserted via TOOL_REGISTRY). See the pipeline describe block below.
//
// Single source of truth for the sets: egress-coverage.sets.ts (shared with
// the coverage partition sentinel).

import { describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { HANDLER_GATED_EXTERNAL, PIPELINE_EGRESS } from "./egress-coverage.sets";
import { TOOL_REGISTRY } from "./registry";

/** Handler path is relative to `.claude-plugin/src/`. gates = exact bespoke gate
 *  function name(s) the handler must call (call-shaped, not merely imported).
 *  Derived by reading each handler's live call sites. The handler-called
 *  `tools/egress.ts` gates all moved to PIPELINE_TABLE below (B6.1 wave A). */
const GATE_TABLE: Record<string, { handlerFile: string; gates: string[] }> = {
  // ── HANDLER_GATED_EXTERNAL (bespoke in-handler gates) ─────────────────
  // drive_share_file: whitelist ancestor walk + (share_type=user) recipient allowlist
  drive_share_file: {
    handlerFile: "tools/handlers/drive.ts",
    gates: ["checkShareAllowed", "isRecipientAllowed", "requireSendApproval"],
  },
  // forms_publish: the SAME anyone-link path (Form id = Drive file id) via the shared
  // whitelist helper (which itself calls checkShareAllowed in drive.ts) + send-approval
  forms_publish: {
    handlerFile: "tools/handlers/forms.ts",
    gates: ["enforceDriveShareWhitelist", "requireSendApproval"],
  },
  // B6.1 wave A2b — the 3 YouTube public-surface writes MIGRATED to PIPELINE_TABLE
  // below (their gate blocks became composite wrappers fired by the choke point).
};

/** B6.1 wave A1 (A2a adds x_post_create) — the PIPELINE_EGRESS tools: the gate is
 *  fired by the tool's choke point (withNonOAuthContext for the service-token
 *  sends; withToolContext for the OAuth writes) via the registry def's egress
 *  descriptor (tools/egress-pipeline.ts), NOT by the handler. `wrapper` = the
 *  centralized gate function the DESCRIPTOR must call (call-shaped in
 *  egress-pipeline.ts) and the HANDLER must NOT call (anti-double-fire — a double
 *  fire would double requireSendApproval + the denial audit rows). Completeness of
 *  the wiring itself is asserted via TOOL_REGISTRY (the def carries `egress`),
 *  not by grep. */
const PIPELINE_TABLE: Record<string, { handlerFile: string; wrapper: string }> = {
  line_push_message: {
    handlerFile: "tools/handlers/line.ts",
    wrapper: "enforceLineEgressGates",
  },
  telegram_send_message: {
    handlerFile: "tools/handlers/telegram.ts",
    wrapper: "enforceTelegramEgressGates",
  },
  discord_send_message: {
    handlerFile: "tools/handlers/discord.ts",
    wrapper: "enforceDiscordEgressGates",
  },
  slack_send_message: {
    handlerFile: "tools/handlers/slack.ts",
    wrapper: "enforceSlackEgressGates",
  },
  mattermost_send_message: {
    handlerFile: "tools/handlers/mattermost.ts",
    wrapper: "enforceMattermostEgressGates",
  },
  x_post_create: {
    handlerFile: "tools/handlers/x.ts",
    wrapper: "enforceXPostEgressGates",
  },
  // B6.1 wave A2b — the 3 YouTube public-surface writes. comment_post + comment_reply
  // share the comment wrapper (distinct `tool` literals in the descriptors); the
  // handler must NOT call either wrapper (anti-double-fire).
  youtube_video_comment_post: {
    handlerFile: "tools/handlers/youtube.ts",
    wrapper: "enforceYoutubeCommentEgressGates",
  },
  youtube_comment_reply: {
    handlerFile: "tools/handlers/youtube.ts",
    wrapper: "enforceYoutubeCommentEgressGates",
  },
  youtube_video_update: {
    handlerFile: "tools/handlers/youtube.ts",
    wrapper: "enforceYoutubeVideoUpdateEgressGates",
  },
  // B6.1 wave A3+D — the 2 gmail compose writes. Both share the compose wrapper
  // (distinct `tool` literals in the descriptors); the handler must NOT call it
  // (anti-double-fire).
  gmail_send: {
    handlerFile: "tools/handlers/gmail.ts",
    wrapper: "enforceGmailComposeEgressGates",
  },
  gmail_create_draft: {
    handlerFile: "tools/handlers/gmail.ts",
    wrapper: "enforceGmailComposeEgressGates",
  },
  // B6.1 wave A (github sweep) — the 7 github writes. CHECK-ONLY gates; the descriptor
  // (egress-pipeline.ts) calls the wrapper, the handler must NOT (anti-double-fire). Several
  // tools share enforceGithubWriteEgressGates (the descriptor calls it once per tool).
  github_create_issue: {
    handlerFile: "tools/handlers/github.ts",
    wrapper: "enforceGithubWriteEgressGates",
  },
  github_create_issue_comment: {
    handlerFile: "tools/handlers/github.ts",
    wrapper: "enforceGithubWriteEgressGates",
  },
  github_update_issue: {
    handlerFile: "tools/handlers/github.ts",
    wrapper: "enforceGithubWriteEgressGates",
  },
  github_create_pull_request: {
    handlerFile: "tools/handlers/github.ts",
    wrapper: "enforceGithubWriteEgressGates",
  },
  github_merge_pull_request: {
    handlerFile: "tools/handlers/github.ts",
    wrapper: "enforceGithubMergeEgressGates",
  },
  github_create_pull_request_review: {
    handlerFile: "tools/handlers/github.ts",
    wrapper: "enforceGithubReviewEgressGates",
  },
  github_set_issue_labels: {
    handlerFile: "tools/handlers/github.ts",
    wrapper: "enforceGithubWriteEgressGates",
  },
  // B6.1 wave A (notion sweep) — the 3 notion writes. CHECK-ONLY gates (model B: F3a only).
  notion_create_page: {
    handlerFile: "tools/handlers/notion.ts",
    wrapper: "enforceNotionWriteEgressGates",
  },
  notion_append_blocks: {
    handlerFile: "tools/handlers/notion.ts",
    wrapper: "enforceNotionWriteEgressGates",
  },
  notion_update_page: {
    handlerFile: "tools/handlers/notion.ts",
    wrapper: "enforceNotionWriteEgressGates",
  },
};

/** `.claude-plugin/src/` — handler paths in GATE_TABLE are relative to here. */
const SRC_ROOT = join(import.meta.dir, "..");

/** Call-shaped match: word-boundary gate name followed by optional whitespace
 *  and an opening paren. Import-only references (no call) do not match. */
function callShaped(gateName: string): RegExp {
  return new RegExp(String.raw`\b${gateName}\s*\(`);
}

describe("pipeline egress call-site sentinel (B6.1 wave A1) — descriptor-fired, never handler-fired", () => {
  test("PIPELINE_TABLE keys are EXACTLY the PIPELINE_EGRESS set", () => {
    expect(Object.keys(PIPELINE_TABLE).sort()).toEqual([...PIPELINE_EGRESS].sort());
  });

  test("(a) tools/egress-pipeline.ts calls every PIPELINE_EGRESS tool's gate wrapper (call-shaped)", () => {
    const src = readFileSync(join(SRC_ROOT, "tools/egress-pipeline.ts"), "utf8");
    const failures: string[] = [];
    for (const [tool, { wrapper }] of Object.entries(PIPELINE_TABLE)) {
      if (!callShaped(wrapper).test(src)) {
        failures.push(
          `${tool}: tools/egress-pipeline.ts is missing a call-site for ${wrapper} (expected /\\b${wrapper}\\s*\\(/)`,
        );
      }
    }
    expect(failures).toEqual([]);
  });

  test("(b) no PIPELINE_EGRESS handler calls its gate wrapper (anti-double-fire)", () => {
    // The pipeline fires the gate; a handler-level call would DOUBLE-fire it
    // (doubling requireSendApproval + the denial audit rows). Import-only or
    // non-call mentions do not match (call-shaped regex).
    const failures: string[] = [];
    for (const [tool, { handlerFile, wrapper }] of Object.entries(PIPELINE_TABLE)) {
      const src = readFileSync(join(SRC_ROOT, handlerFile), "utf8");
      if (callShaped(wrapper).test(src)) {
        failures.push(
          `${tool}: handler ${handlerFile} contains a call-shaped ${wrapper} — the pipeline already fires it (double fire)`,
        );
      }
    }
    expect(failures).toEqual([]);
  });

  test("(c) every PIPELINE_EGRESS registry def carries the egress descriptor (via TOOL_REGISTRY, not grep)", () => {
    const missing = [...PIPELINE_EGRESS].filter(
      (t) => TOOL_REGISTRY[t]?.egress === undefined,
    );
    expect(missing).toEqual([]);
    // And the inverse: no tool OUTSIDE the set carries a descriptor — the set is
    // the single source of truth for what is pipeline-fired.
    const extras = Object.entries(TOOL_REGISTRY)
      .filter(([name, def]) => def.egress !== undefined && !PIPELINE_EGRESS.has(name))
      .map(([name]) => name);
    expect(extras).toEqual([]);
  });
});

describe("egress call-site sentinel — every classified external tool calls its gate", () => {
  test("every GATE_TABLE key is in HANDLER_GATED_EXTERNAL", () => {
    const extras = Object.keys(GATE_TABLE).filter((t) => !HANDLER_GATED_EXTERNAL.has(t));
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
