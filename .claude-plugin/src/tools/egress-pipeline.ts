// B6.1 wave A1 — the PIPELINE-FIRED egress descriptors for the 5 class-B
// service-token send tools (line / telegram / discord / slack / mattermost).
// B6.1 wave A2a — extended to the TRANSFORMING gate case + the first OAuth-routed
// pipeline tool (x_post_create).
//
// BEFORE A1 the composite egress gate (tools/egress.ts) was HANDLER-CALLED (the B3
// posture): each send handler had to remember to invoke its enforce<X>EgressGates
// wrapper before the network call — enforced only by the static call-site sentinel
// (prevention) + the post-handler runtime tripwire (detection AFTER the egress
// already happened). A1 makes the enforcement PIPELINE-OWNED: the tool's registry
// def carries an {@link EgressDescriptor}, and the choke point (withNonOAuthContext
// for the service-token sends; withToolContext for the OAuth writes) fires
// extract → gate BEFORE the handler runs, so a drifted handler can no longer skip
// the gate — the choke point owns it.
//
// SINGLE-SOURCE VALIDATION: each descriptor's `extract` calls the SAME exported
// validator the handler itself calls (validate<X>SendArgs / validateXPostArgs in
// the handler file), so the two call sites can never drift. In production the
// handler re-validates already-validated args — pure, cheap, identical result
// (defense-in-depth + the handler unit-test surface).
//
// BYTE-IDENTICAL GATE INPUT: each `gate` passes its wrapper the exact object shape
// the pre-A1 handler passed — recipient id + the RAW body text (slack included: the
// gate always ran on the RAW text; escapeSlackText is wire-only, applied later in
// the handler). Rejection order and messages are unchanged: resolveCredential
// (no_token) still precedes extract; extract throws the tool's own plain-Error
// validation messages; gate throws -32035 / -32019 exactly as before.
//
// TRANSFORMING GATES (A2a): a gate may RETURN a transformed shape — x_post_create's
// gate returns the outboundSanitize'd text. The choke point stores the return on
// `ctx.egress`; the handler MUST put THAT (via {@link requireEgressResult}), not its
// own recomputation, on the wire — the gate's return value is the vetted bytes (no
// TOCTOU between what the gate scanned and what egresses). The 5 A1 service-token
// gates keep returning void (their handlers pass the same raw args the gate
// already scanned) — zero behavior change.
//
// The gate WRAPPERS themselves are UNCHANGED (tools/egress.ts): they still set
// ctx.egressGateFired first, so the choke point's post-handler tripwire keeps
// holding as a residual backstop. The handlers must NOT call the gate (a double
// fire would double requireSendApproval + the denial audit rows) — the call-site
// sentinel (egress-callsite.test.ts) enforces both directions.

import { MCPError } from "../errors";
import {
  enforceDiscordEgressGates,
  enforceGithubMergeEgressGates,
  enforceGithubReviewEgressGates,
  enforceGithubWriteEgressGates,
  enforceGmailComposeEgressGates,
  enforceLineEgressGates,
  enforceMattermostEgressGates,
  enforceNotionWriteEgressGates,
  enforceSlackEgressGates,
  enforceTelegramEgressGates,
  enforceXPostEgressGates,
  enforceYoutubeCommentEgressGates,
  enforceYoutubeVideoUpdateEgressGates,
} from "./egress";
import { validateDiscordSendArgs } from "./handlers/discord";
import {
  validateGithubCreateIssueArgs,
  validateGithubCreateIssueCommentArgs,
  validateGithubCreatePullRequestArgs,
  validateGithubMergePullRequestArgs,
  validateGithubReviewArgs,
  validateGithubSetIssueLabelsArgs,
  validateGithubUpdateIssueArgs,
} from "./handlers/github";
import { validateGmailCreateDraftArgs, validateGmailSendArgs } from "./handlers/gmail";
import { validateLineSendArgs } from "./handlers/line";
import { validateMattermostSendArgs } from "./handlers/mattermost";
import {
  prepareNotionCreatePage,
  prepareNotionUpdatePage,
  validateNotionAppendBlocksArgs,
} from "./handlers/notion";
import { requireX } from "./handlers/shared";
import { validateSlackSendArgs } from "./handlers/slack";
import { validateTelegramSendArgs } from "./handlers/telegram";
import { validateXPostArgs } from "./handlers/x";
import {
  validateYoutubeCommentPostArgs,
  validateYoutubeCommentReplyArgs,
  validateYoutubeVideoUpdateArgs,
} from "./handlers/youtube";
import type { RecipientResolver } from "./source";
import type {
  EgressShape,
  GithubWriteEgressShape,
  GmailComposeEgressShape,
  NotionWriteEgressShape,
  ServiceTokenEgressShape,
  ToolContext,
  XPostEgressShape,
  YoutubeCommentEgressShape,
  YoutubeVideoUpdateEgressShape,
} from "./types";

// B6.1 wave A2a — the shape types RELOCATED to tools/types.ts (the leaf, so
// ToolContext.egress can carry the union without a type cycle); re-exported here
// so A1 importers stay valid.
export type {
  EgressShape,
  GithubWriteEgressShape,
  GmailComposeEgressShape,
  NotionWriteEgressShape,
  ServiceTokenEgressShape,
  XPostEgressShape,
  YoutubeCommentEgressShape,
  YoutubeVideoUpdateEgressShape,
} from "./types";

/** A pipeline-fired egress descriptor. When a ToolDef carries one, the tool's
 *  choke point (with-nonoauth-context.ts for the service-token sends;
 *  with-context.ts for the OAuth writes) fires extract → gate BEFORE the handler
 *  runs; the handler must NOT call the gate itself (the call-site sentinel
 *  enforces both directions). `S` is the tool's egress shape — descriptors are
 *  declared with their concrete shape; the registry stores the default
 *  (union-typed) view. */
export interface EgressDescriptor<S extends EgressShape = EgressShape> {
  /** Validate + extract the egress fields from raw args (throws the tool's own
   *  plain-Error validation messages via the handler's exported validator). */
  extract(args: Record<string, unknown>): S;
  /** Fire the tool's composite egress gate (sets ctx.egressGateFired; throws on
   *  denial). A TRANSFORMING gate returns the transformed shape (stored on
   *  `ctx.egress` by the OAuth choke point only — the handler wires THAT); a void return
   *  means the handler's own args are already the vetted bytes (the A1 posture).
   *
   *  B6.1 wave A3+D — OPTIONAL third arg `resolveRecipients`: the OAuth choke point
   *  (with-context.ts) passes `source.resolveRecipients` so the gmail gate can resolve
   *  a recipient name→email (People API) BEFORE the allowlist runs; every other
   *  descriptor's gate ignores it (fewer-param functions are assignable). INVARIANT:
   *  a gate's audit/approval side effects MUST run AFTER any network sub-step, so the
   *  choke point's gate-stage 401-retry can re-fire the whole gate on a resolve 401
   *  with no double side effect. The existing (non-gmail) gates have NO network
   *  sub-step → the 401-retry path is inert for them. */
  gate(ctx: ToolContext, shape: S, resolveRecipients?: RecipientResolver): Promise<S | void>;
}

/** B6.1 wave A2a — the handler-side narrow for a TRANSFORMING pipeline tool:
 *  returns the gate's transformed result the choke point stored on `ctx.egress`.
 *  Absence is type-unreachable in production (the choke point always fires the
 *  descriptor before the handler); kept to catch a direct handler invocation that
 *  bypassed the pipeline — fail loud, never recompute the egress bytes locally.
 *  Mirrors the repo's narrow style (requireOAuth / requireServiceToken):
 *  stable MCPError, no internal detail leaked. */
export function requireEgressResult<K extends EgressShape["kind"]>(
  ctx: ToolContext,
  // A2b sec-rev — the caller's EXPECTED shape kind. EgressShape carries a runtime
  // `kind` discriminant (the Credential.kind pattern, tools/types.ts), so a future
  // descriptor mis-wiring (the pipeline stored a DIFFERENT tool's shape) fails LOUD
  // here instead of silently returning the wrong variant (e.g. `.body` = undefined
  // on a video-update shape). Absence AND mismatch throw the same stable MCPError;
  // the kinds are never echoed (no internal detail leaked).
  expected: K,
): Extract<EgressShape, { kind: K }> {
  const egress = ctx.egress;
  if (egress === undefined || egress.kind !== expected) {
    throw new MCPError("internal_routing_error", { reason: "invariant_violation" });
  }
  // Runtime-guarded by the discriminant check above (TS cannot narrow a generic
  // comparison, so the assertion carries what the guard just proved).
  return egress as Extract<EgressShape, { kind: K }>;
}

/** line_push_message — recipient `to`, body `text`. */
export const lineEgressDescriptor: EgressDescriptor<ServiceTokenEgressShape> = {
  extract(args) {
    const { to, text } = validateLineSendArgs(args);
    return { kind: "service-token", recipient: to, body: text };
  },
  gate(ctx, shape) {
    return enforceLineEgressGates(ctx, {
      tool: "line_push_message",
      to: shape.recipient,
      body: shape.body,
    });
  },
};

/** telegram_send_message — recipient `chat_id`, body `text`. */
export const telegramEgressDescriptor: EgressDescriptor<ServiceTokenEgressShape> = {
  extract(args) {
    const { chat_id, text } = validateTelegramSendArgs(args);
    return { kind: "service-token", recipient: chat_id, body: text };
  },
  gate(ctx, shape) {
    return enforceTelegramEgressGates(ctx, {
      tool: "telegram_send_message",
      chat_id: shape.recipient,
      body: shape.body,
    });
  },
};

/** discord_send_message — recipient `channel_id`, body `content`. */
export const discordEgressDescriptor: EgressDescriptor<ServiceTokenEgressShape> = {
  extract(args) {
    const { channel_id, content } = validateDiscordSendArgs(args);
    return { kind: "service-token", recipient: channel_id, body: content };
  },
  gate(ctx, shape) {
    return enforceDiscordEgressGates(ctx, {
      tool: "discord_send_message",
      channel_id: shape.recipient,
      body: shape.body,
    });
  },
};

/** slack_send_message — recipient `channel`, body `text`. The body is the RAW text
 *  (the pre-A1 gate input, pinned by egress-pipeline.test.ts); escapeSlackText is
 *  wire-only and stays in the handler. */
export const slackEgressDescriptor: EgressDescriptor<ServiceTokenEgressShape> = {
  extract(args) {
    const { channel, text } = validateSlackSendArgs(args);
    return { kind: "service-token", recipient: channel, body: text };
  },
  gate(ctx, shape) {
    return enforceSlackEgressGates(ctx, {
      tool: "slack_send_message",
      channel: shape.recipient,
      body: shape.body,
    });
  },
};

/** mattermost_send_message — recipient `channel_id`, body `message`. */
export const mattermostEgressDescriptor: EgressDescriptor<ServiceTokenEgressShape> = {
  extract(args) {
    const { channel_id, message } = validateMattermostSendArgs(args);
    return { kind: "service-token", recipient: channel_id, body: message };
  },
  gate(ctx, shape) {
    return enforceMattermostEgressGates(ctx, {
      tool: "mattermost_send_message",
      channel_id: shape.recipient,
      body: shape.body,
    });
  },
};

/** B6.1 wave A2a — x_post_create: the FIRST transforming + OAuth-routed descriptor
 *  (fired by withToolContext, not withNonOAuthContext). `extract` runs the SAME
 *  exported validator the handler re-runs (non-empty + weighted-280, messages
 *  verbatim). `gate` resolves the posting account from the ctx's oauth credential
 *  exactly as the pre-A2a handler did (requireX — the cross-provider narrow), fires
 *  the UNCHANGED composite wrapper (allowlist → F3a → outboundSanitize, tools/
 *  egress.ts) and RETURNS the sanitized text: the choke point stores it on
 *  `ctx.egress`, and the handler puts THAT on the wire (requireEgressResult). */
export const xPostEgressDescriptor: EgressDescriptor<XPostEgressShape> = {
  extract(args) {
    const { text } = validateXPostArgs(args);
    return { kind: "x-post", body: text };
  },
  async gate(ctx, shape) {
    const cred = requireX(ctx);
    const sanitized = await enforceXPostEgressGates(ctx, cred.accountId, shape.body);
    return { kind: "x-post", body: sanitized };
  },
};

/** B6.1 wave A2b — youtube_video_comment_post: TRANSFORMING, OAuth-routed (fired by
 *  withToolContext). `extract` runs the SAME exported validator the handler re-runs
 *  (video_id / text / optional channel_id — messages verbatim). `gate` fires the
 *  shared comment wrapper (allowlist → burst pre-check → outboundSanitize) and RETURNS
 *  the sanitized text on ctx.egress; the handler wires THAT (requireEgressResult). */
export const youtubeCommentPostEgressDescriptor: EgressDescriptor<YoutubeCommentEgressShape> = {
  extract(args) {
    const { videoId, text } = validateYoutubeCommentPostArgs(args);
    return { kind: "youtube-comment", videoId, body: text };
  },
  async gate(ctx, shape) {
    const sanitized = await enforceYoutubeCommentEgressGates(ctx, {
      tool: "youtube_video_comment_post",
      videoId: shape.videoId,
      body: shape.body,
    });
    return { kind: "youtube-comment", videoId: shape.videoId, body: sanitized };
  },
};

/** B6.1 wave A2b — youtube_comment_reply: same shape/gate as comment_post, distinct
 *  `tool` literal. `parentCommentId` rides the extracted shape so the shared wrapper's
 *  DENIAL rows keep `parent_comment_id_hash` (reply-only). */
export const youtubeCommentReplyEgressDescriptor: EgressDescriptor<YoutubeCommentEgressShape> = {
  extract(args) {
    const { parentCommentId, videoId, text } = validateYoutubeCommentReplyArgs(args);
    return { kind: "youtube-comment", videoId, body: text, parentCommentId };
  },
  async gate(ctx, shape) {
    const sanitized = await enforceYoutubeCommentEgressGates(ctx, {
      tool: "youtube_comment_reply",
      videoId: shape.videoId,
      body: shape.body,
      parentCommentId: shape.parentCommentId,
    });
    return { kind: "youtube-comment", videoId: shape.videoId, body: sanitized };
  },
};

/** B6.1 wave A2b — youtube_video_update: TRANSFORMING per-FIELD gate (title /
 *  description? / tags?). `extract` runs the handler's validator (category_id is
 *  validated + returned but NOT part of the egress shape — the handler reads it
 *  directly). `gate` fires the video wrapper (allowlist → per-field sanitize → F3a
 *  secret) and RETURNS the per-field-sanitized shape on ctx.egress. */
export const youtubeVideoUpdateEgressDescriptor: EgressDescriptor<YoutubeVideoUpdateEgressShape> = {
  extract(args) {
    const { videoId, title, description, tags } = validateYoutubeVideoUpdateArgs(args);
    return {
      kind: "youtube-video-update",
      videoId,
      title,
      ...(description !== undefined ? { description } : {}),
      ...(tags !== undefined ? { tags } : {}),
    };
  },
  async gate(ctx, shape) {
    return enforceYoutubeVideoUpdateEgressGates(ctx, shape);
  },
};

/** B6.1 wave A3+D — gmail_send: TRANSFORMING, OAuth-routed (fired by withToolContext).
 *  `extract` runs the SAME exported validator the handler re-runs (type-then-presence,
 *  messages verbatim) → the RAW compose shape. `gate` fires the shared compose wrapper
 *  (header gates → contact-lookup resolution via `resolveRecipients` → recipient/secret/
 *  tainted gates → supervised-send approval) and RETURNS the shape with `resolved`
 *  populated (the contact-resolved recipients); the handler wires THAT off ctx.egress. */
export const gmailSendEgressDescriptor: EgressDescriptor<GmailComposeEgressShape> = {
  extract(args) {
    const { to, subject, body, cc, bcc } = validateGmailSendArgs(args);
    return { kind: "gmail-compose", tool: "gmail_send", to, cc, bcc, subject, body };
  },
  async gate(ctx, shape, resolveRecipients) {
    return enforceGmailComposeEgressGates(ctx, shape, resolveRecipients);
  },
};

/** B6.1 wave A3+D — gmail_create_draft: same shape/gate as gmail_send, distinct `tool`
 *  literal. A draft is literal-only (D3 — no contact resolution) and is NOT in
 *  APPROVAL_GATED_SENDS, so the compose wrapper skips resolution + approval for it; the
 *  RETURNED `resolved` carries the parsed literal arrays. `resolveRecipients` is passed
 *  through uniformly (the wrapper's tool discriminant ignores it for the draft). */
export const gmailCreateDraftEgressDescriptor: EgressDescriptor<GmailComposeEgressShape> = {
  extract(args) {
    const { to, subject, body, cc, bcc } = validateGmailCreateDraftArgs(args);
    return { kind: "gmail-compose", tool: "gmail_create_draft", to, cc, bcc, subject, body };
  },
  async gate(ctx, shape, resolveRecipients) {
    return enforceGmailComposeEgressGates(ctx, shape, resolveRecipients);
  },
};

/* ── B6.1 wave A (github sweep) — the 7 GitHub write descriptors. CHECK-ONLY (the gate
 * returns void): the handler's own already-validated args are the vetted bytes, so it does
 * NOT read ctx.egress. Each `extract` runs the SAME exported validator the handler re-runs
 * and maps to the gate's `body` (the combined agent text the F3a secret-shape scan sees,
 * reproduced verbatim from the pre-A handler assembly). Each `gate` fires the UNCHANGED
 * composite wrapper (tools/egress.ts). All OAuth-routed → fired by withToolContext. ── */

/** github_create_issue — default-deny write allowlist + F3a on `title(\nbody)`. */
export const githubCreateIssueEgressDescriptor: EgressDescriptor<GithubWriteEgressShape> = {
  extract(args) {
    const { owner, repo, title, body } = validateGithubCreateIssueArgs(args);
    return {
      kind: "github-write",
      tool: "github_create_issue",
      owner,
      repo,
      body: body === undefined ? title : `${title}\n${body}`,
    };
  },
  async gate(ctx, shape) {
    enforceGithubWriteEgressGates(ctx, {
      tool: "github_create_issue",
      owner: shape.owner,
      repo: shape.repo,
      body: shape.body,
    });
  },
};

/** github_create_issue_comment — write allowlist + F3a on the comment `body`. */
export const githubCreateIssueCommentEgressDescriptor: EgressDescriptor<GithubWriteEgressShape> = {
  extract(args) {
    const { owner, repo, body } = validateGithubCreateIssueCommentArgs(args);
    return { kind: "github-write", tool: "github_create_issue_comment", owner, repo, body };
  },
  async gate(ctx, shape) {
    enforceGithubWriteEgressGates(ctx, {
      tool: "github_create_issue_comment",
      owner: shape.owner,
      repo: shape.repo,
      body: shape.body,
    });
  },
};

/** github_update_issue — write allowlist + F3a on `[title, body].join("\n")` (target check
 *  runs even for a state-only update: extract's combined body is "" then). */
export const githubUpdateIssueEgressDescriptor: EgressDescriptor<GithubWriteEgressShape> = {
  extract(args) {
    const { owner, repo, title, body } = validateGithubUpdateIssueArgs(args);
    return {
      kind: "github-write",
      tool: "github_update_issue",
      owner,
      repo,
      body: [title, body].filter((t): t is string => t !== undefined).join("\n"),
    };
  },
  async gate(ctx, shape) {
    enforceGithubWriteEgressGates(ctx, {
      tool: "github_update_issue",
      owner: shape.owner,
      repo: shape.repo,
      body: shape.body,
    });
  },
};

/** github_create_pull_request — write allowlist + F3a on `title(\nbody)` (head/base are
 *  refs, not secret-bearing prose → excluded from the scan, as pre-A). */
export const githubCreatePullRequestEgressDescriptor: EgressDescriptor<GithubWriteEgressShape> = {
  extract(args) {
    const { owner, repo, title, body } = validateGithubCreatePullRequestArgs(args);
    return {
      kind: "github-write",
      tool: "github_create_pull_request",
      owner,
      repo,
      body: body === undefined ? title : `${title}\n${body}`,
    };
  },
  async gate(ctx, shape) {
    enforceGithubWriteEgressGates(ctx, {
      tool: "github_create_pull_request",
      owner: shape.owner,
      repo: shape.repo,
      body: shape.body,
    });
  },
};

/** github_merge_pull_request — SEPARATE default-deny MERGE allowlist + F3a on the
 *  merge-commit text (`[commit_title, commit_message].join("\n")`, "" when auto-generated). */
export const githubMergePullRequestEgressDescriptor: EgressDescriptor<GithubWriteEgressShape> = {
  extract(args) {
    const { owner, repo, commitTitle, commitMessage } = validateGithubMergePullRequestArgs(args);
    return {
      kind: "github-write",
      tool: "github_merge_pull_request",
      owner,
      repo,
      body: [commitTitle, commitMessage].filter((t): t is string => t !== undefined).join("\n"),
    };
  },
  async gate(ctx, shape) {
    enforceGithubMergeEgressGates(ctx, {
      tool: "github_merge_pull_request",
      owner: shape.owner,
      repo: shape.repo,
      body: shape.body,
    });
  },
};

/** github_create_pull_request_review — EVENT-CONDITIONAL: APPROVE → approve allowlist, else
 *  → write allowlist; + F3a on the review `body` ("" for a bare APPROVE). `event` rides the
 *  shape (present for this tool only); the gate always receives it (extract sets it). */
export const githubCreatePullRequestReviewEgressDescriptor: EgressDescriptor<GithubWriteEgressShape> =
  {
    extract(args) {
      const { owner, repo, event, body } = validateGithubReviewArgs(args);
      return {
        kind: "github-write",
        tool: "github_create_pull_request_review",
        owner,
        repo,
        body: body ?? "",
        event,
      };
    },
    async gate(ctx, shape) {
      enforceGithubReviewEgressGates(ctx, {
        tool: "github_create_pull_request_review",
        // extract always sets `event` for this tool → non-null by construction.
        event: shape.event!,
        owner: shape.owner,
        repo: shape.repo,
        body: shape.body,
      });
    },
  };

/** github_set_issue_labels — write allowlist + F3a on `labels.join("\n")` (a label name is
 *  agent-authored text that can create a new repo label). SOURCE: the descriptor calls the
 *  WRITE gate (not a separate labels allowlist). */
export const githubSetIssueLabelsEgressDescriptor: EgressDescriptor<GithubWriteEgressShape> = {
  extract(args) {
    const { owner, repo, rawLabels } = validateGithubSetIssueLabelsArgs(args);
    return { kind: "github-write", tool: "github_set_issue_labels", owner, repo, body: rawLabels.join("\n") };
  },
  async gate(ctx, shape) {
    enforceGithubWriteEgressGates(ctx, {
      tool: "github_set_issue_labels",
      owner: shape.owner,
      repo: shape.repo,
      body: shape.body,
    });
  },
};

/* ── B6.1 wave A (notion sweep) — the 3 Notion write descriptors. CHECK-ONLY (model B:
 * F3a secret-shape only, NO target allowlist). Each `extract` runs the SAME exported
 * prepare/validate helper the handler re-runs and takes its `egressBody` (the combined
 * agent text the secret-shape scan sees; for notion_create_page it covers BOTH the
 * page-parent and db-parent branches — the two pre-A gate call sites). OAuth-routed. ── */

/** notion_create_page — F3a on the page-parent `title(\ntext)` OR the db-parent
 *  buildNotionProperties scan join (prepareNotionCreatePage picks the branch). */
export const notionCreatePageEgressDescriptor: EgressDescriptor<NotionWriteEgressShape> = {
  extract(args) {
    return { kind: "notion-write", tool: "notion_create_page", body: prepareNotionCreatePage(args).egressBody };
  },
  async gate(ctx, shape) {
    enforceNotionWriteEgressGates(ctx, { tool: "notion_create_page", body: shape.body });
  },
};

/** notion_append_blocks — F3a on the RAW appended `text`. */
export const notionAppendBlocksEgressDescriptor: EgressDescriptor<NotionWriteEgressShape> = {
  extract(args) {
    const { text } = validateNotionAppendBlocksArgs(args);
    return { kind: "notion-write", tool: "notion_append_blocks", body: text };
  },
  async gate(ctx, shape) {
    enforceNotionWriteEgressGates(ctx, { tool: "notion_append_blocks", body: shape.body });
  },
};

/** notion_update_page — F3a on the combined RAW agent strings (properties scan + title;
 *  "" for an archive-only call). */
export const notionUpdatePageEgressDescriptor: EgressDescriptor<NotionWriteEgressShape> = {
  extract(args) {
    return { kind: "notion-write", tool: "notion_update_page", body: prepareNotionUpdatePage(args).egressBody };
  },
  async gate(ctx, shape) {
    enforceNotionWriteEgressGates(ctx, { tool: "notion_update_page", body: shape.body });
  },
};
