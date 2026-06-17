// Egress-coverage sentinel — the machine-checked "external-reaching write ⇒
// gated" invariant (the R7 forcing function).
//
// WHY THIS EXISTS (thesis §6.1 / R7): the envelope's egress protection is the
// one part that is NOT applied by a single central choke point. tier + sanitize
// + audit + burst run universally inside the 3 choke points (with-context /
// with-nonoauth-context / with-all-accounts), but the recipient / public-surface
// gates live per-tool — 8 tools go through the centralized `tools/egress.ts`
// gate, while drive_share_file + the two YouTube comment-write tools carry their
// own bespoke handler gates. So a future connector tool that reaches an external
// party (a new "send" / "post" / "share") can be added at min_tier:write and ship
// with ZERO egress protection while *looking* protected — the exact R7 trap.
//
// This sentinel removes the "looks protected" ambiguity by forcing EVERY
// write/share tool to be classified into exactly one bucket. A newly-added
// write/share tool that nobody classified is an orphan → this test FAILS → it
// cannot merge until its author answers "does this reach an external party, and
// if so where is its gate?". The maintenance cost of adding a name below IS the
// forcing function.
//
// This is a test-only invariant (no runtime behavior). It composes with the two
// adjacent registry sentinels: the v1.64-B0 `direction:"outbound-write"` set
// (registry.test.ts) and the v1.52-F1 `cross_account ⇒ min_tier:read` set.

import { describe, expect, test } from "bun:test";
import { TOOL_REGISTRY } from "./registry";

// ── Bucket 1: CENTRALIZED_EGRESS ──────────────────────────────────────────────
// Reaches an external party AND is gated by `tools/egress.ts` (the F3a
// secret-shape scan + a recipient / target allowlist). This set MUST stay
// identical to the `direction:"outbound-write"` label set — the cross-check
// below pins that, so the two can never drift apart.
//   gmail_send / gmail_create_draft  → enforceEgressGates  (recipient + secret)
//   line_push_message                → enforceLineEgressGates
//   telegram_send_message            → enforceTelegramEgressGates
//   discord_send_message             → enforceDiscordEgressGates
//   slack_send_message               → enforceSlackEgressGates
//   mattermost_send_message          → enforceMattermostEgressGates (self-hosted; the
//                                        configured-host pin lives in the client)
//   github_create_issue / _comment / update_issue / create_pull_request
//                                    → enforceGithubWriteEgressGates
//   github_merge_pull_request         → enforceGithubMergeEgressGates (SEPARATE
//                                        default-deny merge allowlist; IRREVERSIBLE)
//   github_create_pull_request_review → enforceGithubReviewEgressGates (EVENT-CONDITIONAL:
//                                        APPROVE → SEPARATE default-deny approve allowlist;
//                                        COMMENT / REQUEST_CHANGES → the write allowlist)
//   notion_create_page / _append_blocks / _update_page
//                                    → enforceNotionWriteEgressGates (model B: F3a
//                                       secret-shape, NO target allowlist)
const CENTRALIZED_EGRESS: ReadonlySet<string> = new Set([
  "gmail_send",
  "gmail_create_draft",
  "line_push_message",
  "telegram_send_message",
  "discord_send_message",
  "slack_send_message",
  "mattermost_send_message",
  "github_create_issue",
  "github_create_issue_comment",
  "github_update_issue",
  "github_create_pull_request",
  "github_merge_pull_request",
  "github_create_pull_request_review",
  "github_set_issue_labels",
  "notion_create_page",
  "notion_append_blocks",
  "notion_update_page",
]);

// ── Bucket 2: HANDLER_GATED_EXTERNAL ──────────────────────────────────────────
// Reaches an external party but is gated by BESPOKE handler logic outside
// tools/egress.ts (these gates predate the egress centralization and have
// per-tool signatures that don't fit the gmail-style recipient+secret shape).
// Each entry names where its gate lives — a reviewer can verify it is live.
//   drive_share_file           → policy/drive-whitelist (checkShareAllowed, both
//                                 share_type values) + policy/recipient-allowlist
//                                 (isRecipientAllowed on share_type=user); both
//                                 fail-closed.  [handlers/drive.ts]
//   youtube_video_comment_post → public-surface 4-gate: outbound-sanitize REJECT
//   youtube_comment_reply        (sanitize/outbound) + policy/youtube-comment-
//                                 targets (default-deny allowlist) + policy/
//                                 youtube-comment-burst.  [handlers/youtube.ts]
//   youtube_video_update       → public-surface: outbound-sanitize REJECT per field
//                                 (sanitize/outbound) + policy/youtube-video-targets
//                                 (default-deny allowlist) + F3a secret-shape
//                                 (egress.enforceOutboundSecret).  [handlers/youtube.ts]
const HANDLER_GATED_EXTERNAL: ReadonlySet<string> = new Set([
  "drive_share_file",
  "youtube_video_comment_post",
  "youtube_comment_reply",
  "youtube_video_update",
]);

// ── Bucket 3: OWN_DATA_WRITE ──────────────────────────────────────────────────
// Writes to the caller's OWN data with NO external recipient — the egress gate
// does not apply (tier + per-source sanitize + audit + F1 burst is the floor;
// some carry their own inbound/structure gates: sheets formula-reject, slides/
// forms SSRF-exclusion, gmail filter `forward` reject + batch TRASH/SPAM block,
// tasks-delete target allowlist, calendar `sendUpdates="none"` so attendees get
// NO invite email). A tool only belongs here if it cannot deliver agent-authored
// content to a third party.
const OWN_DATA_WRITE: ReadonlySet<string> = new Set([
  // calendar — own calendar; attendees never emailed (sendUpdates="none")
  "calendar_create_event",
  "calendar_update_event",
  "calendar_delete_event",
  "calendar_respond",
  // contacts — own address book
  "contacts_create",
  "contacts_update",
  // docs — own documents
  "docs_create",
  "docs_append_text",
  "docs_modify_structured",
  // drive — own files (sharing is drive_share_file, bucket 2)
  "drive_create_folder",
  "drive_move_file",
  "drive_create_file",
  "drive_copy_file",
  "drive_rename_file",
  // forms — own forms (forms_create = bare form, no item payload; the
  // SSRF-exclusion deep-gate is on forms_modify's item requests)
  "forms_create",
  "forms_modify",
  // gmail — own mailbox (filter forward rejected; batch TRASH/SPAM blocked)
  "gmail_create_label",
  "gmail_modify_message",
  "gmail_modify_messages_batch",
  "gmail_delete_draft",
  "gmail_create_filter",
  "gmail_delete_filter",
  // sheets — own spreadsheets (inbound formula-reject)
  "sheets_create",
  "sheets_update_values",
  "sheets_batch_update",
  "sheets_append_values",
  // slides — own presentations (SSRF-exclusion on modify)
  "slides_create",
  "slides_modify",
  // tasks — own task lists (tasks_delete target allowlist)
  "tasks_create",
  "tasks_update",
  "tasks_delete",
  "tasks_move",
  "tasks_clear",
  // youtube — removes/own-channel actions; no agent-authored content reaches a
  // third party. (youtube_playlist_update can set a playlist public, but a
  // playlist holds only video references — no agent text is delivered; the
  // public posting surfaces are youtube_video_comment_post / _comment_reply,
  // bucket 2.)
  "youtube_comment_delete",
  "youtube_playlist_create",
  "youtube_playlist_update",
  "youtube_playlist_item_insert",
  "youtube_playlist_item_remove",
  "youtube_playlist_delete",
]);

/** Every write/share tool in the registry — the universe the partition covers.
 *  read-tier tools (no mutation) and cross_account `_all` tools (pinned
 *  min_tier:read by the F1 sentinel) are out of scope by construction. */
const allWriteShare = Object.entries(TOOL_REGISTRY)
  .filter(([, def]) => def.min_tier === "write" || def.min_tier === "share")
  .map(([name]) => name);

describe("egress-coverage sentinel — every write/share tool is classified", () => {
  test("the 3 buckets are pairwise disjoint (no tool double-classified)", () => {
    const overlap = (a: ReadonlySet<string>, b: ReadonlySet<string>) =>
      [...a].filter((x) => b.has(x));
    expect(overlap(CENTRALIZED_EGRESS, HANDLER_GATED_EXTERNAL)).toEqual([]);
    expect(overlap(CENTRALIZED_EGRESS, OWN_DATA_WRITE)).toEqual([]);
    expect(overlap(HANDLER_GATED_EXTERNAL, OWN_DATA_WRITE)).toEqual([]);
  });

  test("EVERY write/share tool is classified — a new tool is an orphan until gated", () => {
    const classified = new Set([
      ...CENTRALIZED_EGRESS,
      ...HANDLER_GATED_EXTERNAL,
      ...OWN_DATA_WRITE,
    ]);
    // Orphan: a write/share tool nobody put in a bucket. If this fires for a new
    // tool, decide whether it reaches an external party — if so, gate it and add
    // it to CENTRALIZED_EGRESS (preferred) or HANDLER_GATED_EXTERNAL; if it only
    // writes the caller's own data, add it to OWN_DATA_WRITE.
    const unclassified = allWriteShare.filter((t) => !classified.has(t));
    expect(unclassified).toEqual([]);
    // Stale: a name in a bucket that is no longer a write/share tool (renamed or
    // removed) — keep the buckets honest.
    const stale = [...classified].filter((t) => !allWriteShare.includes(t));
    expect(stale).toEqual([]);
  });

  test("CENTRALIZED_EGRESS is EXACTLY the direction:'outbound-write' label set", () => {
    // The label and the gated set must never drift: a tool labeled outbound-write
    // that is not centrally gated (or vice-versa) is the R7 hole this prevents.
    const labelled = Object.entries(TOOL_REGISTRY)
      .filter(([, def]) => def.direction === "outbound-write")
      .map(([name]) => name)
      .sort();
    expect(labelled).toEqual([...CENTRALIZED_EGRESS].sort());
  });

  test("no HANDLER_GATED_EXTERNAL tool carries the outbound-write label", () => {
    // These are gated in-handler, NOT via egress.ts. Labeling one outbound-write
    // would falsely claim centralized coverage (and, post-B6.1, route it through
    // a pipeline-fired gate whose shape it doesn't match).
    for (const t of HANDLER_GATED_EXTERNAL) {
      expect(TOOL_REGISTRY[t]?.direction).toBeUndefined();
    }
  });
});
