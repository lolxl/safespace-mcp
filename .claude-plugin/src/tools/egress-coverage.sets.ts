// Egress-coverage classification sets — the single source of truth shared by
// egress-coverage.test.ts (the write/share partition sentinel) and
// egress-callsite.test.ts (the call-site binding sentinel).
//
// Keep this module free of test/runtime side effects: pure data only. A new
// external-reaching write tool must be added here AND wired to its gate; the
// two sentinels then cross-check membership + call-site presence.

// ── Bucket 1: PIPELINE_EGRESS (B6.1 wave A1; A2a adds x_post_create) ──────────
// The only bucket for gates in `tools/egress.ts`: the former handler-called
// bucket (CENTRALIZED_EGRESS, the B3 posture) emptied in B6.1 wave A and was
// removed. A new external-reaching write goes here (descriptor-carried,
// choke-point-fired) or, for a bespoke gate, into HANDLER_GATED_EXTERNAL.
// Reaches an external party AND is gated by `tools/egress.ts`, but the gate is
// PIPELINE-FIRED: the tool's registry def carries an egress descriptor
// (tools/egress-pipeline.ts) and the tool's choke point (withNonOAuthContext for
// the service-token sends; withToolContext for every OAuth write — gmail, GitHub,
// Notion, X, YouTube) fires
// extract → gate BEFORE the handler runs. The handler must NOT call the gate
// itself (anti-double-fire — a double fire would double requireSendApproval + the
// denial audit rows); the call-site sentinel (egress-callsite.test.ts) enforces
// both directions, and the coverage sentinel pins PIPELINE_EGRESS == the
// outbound-write label set.
//   line_push_message       → enforceLineEgressGates       (via lineEgressDescriptor)
//   telegram_send_message   → enforceTelegramEgressGates   (via telegramEgressDescriptor)
//   discord_send_message    → enforceDiscordEgressGates    (via discordEgressDescriptor)
//   slack_send_message      → enforceSlackEgressGates      (via slackEgressDescriptor;
//                              gate input = the RAW text, escaping is wire-only)
//   mattermost_send_message → enforceMattermostEgressGates (via mattermostEgressDescriptor;
//                              self-hosted; the configured-host pin lives in the client)
//   x_post_create           → enforceXPostEgressGates      (via xPostEgressDescriptor;
//                              TRANSFORMING: the gate RETURNS the sanitized text →
//                              ctx.egress; OAuth-routed, fired by withToolContext)
//   youtube_video_comment_post / youtube_comment_reply
//                           → enforceYoutubeCommentEgressGates (B6.1 wave A2b; shared
//                              wrapper, distinct `tool` literals; TRANSFORMING: allowlist
//                              → burst pre-check → outboundSanitize; OAuth-routed)
//   youtube_video_update    → enforceYoutubeVideoUpdateEgressGates (B6.1 wave A2b;
//                              TRANSFORMING per-FIELD: allowlist → per-field
//                              outboundSanitize → F3a secret-shape; OAuth-routed)
//   gmail_send / gmail_create_draft
//                           → enforceGmailComposeEgressGates (B6.1 wave A3+D; shared
//                              wrapper, distinct `tool` literals; TRANSFORMING: header
//                              gates → contact-lookup resolution [gmail_send, via
//                              source.resolveRecipients] → recipient/secret/tainted
//                              gates → supervised-send approval; RETURNS the RESOLVED
//                              shape; OAuth-routed, fired by withToolContext)
//   github_create_issue / _comment / update_issue / create_pull_request / set_issue_labels
//                           → enforceGithubWriteEgressGates (B6.1 wave A; CHECK-ONLY —
//                              default-deny write allowlist + F3a secret-shape; the gate
//                              returns void, the handler wires its own vetted args)
//   github_merge_pull_request → enforceGithubMergeEgressGates (B6.1 wave A; CHECK-ONLY;
//                              SEPARATE default-deny merge allowlist; IRREVERSIBLE)
//   github_create_pull_request_review → enforceGithubReviewEgressGates (B6.1 wave A;
//                              CHECK-ONLY; EVENT-CONDITIONAL: APPROVE → approve allowlist,
//                              COMMENT / REQUEST_CHANGES → write allowlist; `event` rides the shape)
//   notion_create_page / _append_blocks / _update_page
//                           → enforceNotionWriteEgressGates (B6.1 wave A; CHECK-ONLY; model
//                              B: F3a secret-shape, NO target allowlist; notion_create_page's
//                              extract covers the page-, database- and data-source-parent gate inputs; the two
//                              data-source READ tools are inbound-read and NOT in this set)
export const PIPELINE_EGRESS: ReadonlySet<string> = new Set([
  "line_push_message",
  "telegram_send_message",
  "discord_send_message",
  "slack_send_message",
  "mattermost_send_message",
  "x_post_create",
  "youtube_video_comment_post",
  "youtube_comment_reply",
  "youtube_video_update",
  "gmail_send",
  "gmail_create_draft",
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
//   forms_publish              → the SAME anyone-link path (a Form id IS a Drive file
//                                 id): handler tier re-check → enforceDriveShareWhitelist
//                                 (policy/drive-whitelist, fail-closed) → requireSendApproval
//                                 → setPublishSettings.  [handlers/forms.ts]
// (B6.1 wave A2b — the 3 YouTube public-surface writes MIGRATED to PIPELINE_EGRESS:
//  their bespoke handler gate blocks became the composite wrappers
//  enforceYoutubeCommentEgressGates / enforceYoutubeVideoUpdateEgressGates in
//  tools/egress.ts, fired by withToolContext via each tool's egress descriptor.)
export const HANDLER_GATED_EXTERNAL: ReadonlySet<string> = new Set([
  "drive_share_file",
  "forms_publish",
]);

// ── Bucket 3: OWN_DATA_WRITE ──────────────────────────────────────────────────
// Writes to the caller's OWN data with NO external recipient — the egress gate
// does not apply (tier + per-source sanitize + audit + F1 burst is the floor;
// some carry their own inbound/structure gates: sheets formula-reject, slides/
// forms SSRF-exclusion, gmail filter `forward` reject + batch TRASH/SPAM block,
// tasks-delete target allowlist, calendar `sendUpdates="none"` so attendees get
// NO invite email). A tool only belongs here if it cannot deliver agent-authored
// content to a third party.
export const OWN_DATA_WRITE: ReadonlySet<string> = new Set([
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
  // drive — own files (sharing is drive_share_file, bucket 2; trash/delete carry the
  // drive-delete target allowlist)
  "drive_create_folder",
  "drive_move_file",
  "drive_create_file",
  "drive_copy_file",
  "drive_rename_file",
  "drive_trash_file",
  "drive_delete_file",
  // forms — own forms (forms_create = bare form, no item payload; the
  // SSRF-exclusion deep-gate is on forms_modify's item requests).
  // forms_unpublish only REVOKES exposure (recovery action, like drive_unshare_file;
  // forms_publish is the outbound share, in HANDLER_GATED_EXTERNAL).
  "forms_create",
  "forms_modify",
  "forms_unpublish",
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
  // in PIPELINE_EGRESS.)
  "youtube_comment_delete",
  "youtube_playlist_create",
  "youtube_playlist_update",
  "youtube_playlist_item_insert",
  "youtube_playlist_item_remove",
  "youtube_playlist_delete",
]);
