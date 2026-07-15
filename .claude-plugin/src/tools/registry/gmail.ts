// Gmail tool definitions — extracted verbatim from the former
// monolithic src/tools/registry.ts TOOL_REGISTRY (mechanical per-API split).
// Assembled in original key order by ./index.ts.

import type { ToolDef } from "./types";
import * as handlers from "../handlers";
import {
  gmailCreateDraftEgressDescriptor,
  gmailSendEgressDescriptor,
} from "../egress-pipeline";
import {
  GMAIL_READONLY,
  GMAIL_LABELS,
  GMAIL_MODIFY,
  GMAIL_SEND,
  GMAIL_SETTINGS_BASIC,
} from "./scopes";

export const gmailTools: Record<string, ToolDef> = {
  gmail_search: {
    name: "gmail_search",
    description:
      "Search Gmail messages in the active account. Returns ID list only (id + threadId per match, plus nextPageToken and resultSizeEstimate). Use gmail_get_message for body/snippet/subject/from. Uses Gmail search syntax.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Gmail search syntax, e.g. 'from:foo@example.com subject:invoice'",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 50,
          default: 10,
          description: "Maximum number of messages to return (capped at 50).",
        },
      },
      required: ["query"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_READONLY],
    handler: handlers.gmailSearch,
    min_tier: "read",
  },
  gmail_list_labels: {
    name: "gmail_list_labels",
    description:
      "List all labels in the active Gmail account — system labels (INBOX, SENT, UNREAD, IMPORTANT, STARRED, etc.) plus user-created labels. Returns labels[{id, name, type, messageListVisibility?, labelListVisibility?, messagesTotal?, ...}]. Use to discover label ids before gmail_modify_message, or to map a human label name (e.g. 'procurement') to its id (e.g. 'Label_123'). System labels use uppercase ALL-CAPS ids; user labels use 'Label_<digits>'.",
    inputSchema: {
      type: "object",
      properties: {
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: [],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_LABELS],
    handler: handlers.gmailListLabels,
    min_tier: "read",
  },
  gmail_create_label: {
    name: "gmail_create_label",
    description:
      "Create a new user-defined Gmail label in the active account (WRITE OPERATION, but undoable — labels can be deleted via Gmail UI). ALWAYS ask the user for explicit confirmation before calling this tool. Idempotent: if a label with the same exact name (case-sensitive) already exists, returns it without creating a duplicate. POLICY BLOCK: name cannot match a system label (INBOX/SENT/UNREAD/IMPORTANT/STARRED/DRAFT/TRASH/SPAM/CHAT, case-insensitive) and cannot start with `CATEGORY_` (reserved for Gmail's inbox categories). Name is trimmed before send, must be 1-225 UTF-8 bytes after trim, and must not contain CR/LF/NUL/NEL/U+2028/U+2029. Returns the Label resource {id, name, type, labelListVisibility, messageListVisibility, ...}. Use gmail_list_labels first to check what already exists.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Display name for the label (1-225 bytes after trim). Nesting is by Gmail UI convention only — 'foo/bar' renders as a child of 'foo' in the web UI, but Gmail treats the full string as one flat name.",
        },
        label_list_visibility: {
          type: "string",
          enum: ["labelShow", "labelShowIfUnread", "labelHide"],
          default: "labelShow",
          description: "Whether the label appears in the left-side label list. Default labelShow.",
        },
        message_list_visibility: {
          type: "string",
          enum: ["show", "hide"],
          default: "show",
          description: "Whether the label chip appears next to messages in the message list. Default show.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["name"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_LABELS],
    handler: handlers.gmailCreateLabel,
    min_tier: "write",
  },
  gmail_get_message: {
    name: "gmail_get_message",
    description:
      "Fetch a Gmail message by id. Returns headers (From/Subject/To/Date as payload.headers[{name,value}]), snippet, full payload (mimeType, body.data base64url-encoded, parts for multipart), labelIds, internalDate, historyId. Use after gmail_search.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Message id from gmail_search (e.g. '19de5a8c628b9010').",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["id"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_READONLY],
    handler: handlers.gmailGetMessage,
    min_tier: "read",
  },
  gmail_modify_message: {
    name: "gmail_modify_message",
    description:
      "Add or remove labels on a Gmail message (WRITE OPERATION, but undoable — labels can be flipped back). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share) in the proxy environment. Common uses: mark as read by removing UNREAD, apply a user label by id (use gmail_list_labels first to find ids), star a message via addLabelIds:['STARRED']. POLICY BLOCK: addLabelIds CANNOT contain TRASH or SPAM — use Gmail's web UI for destructive triage (TRASH auto-deletes after 30 days; SPAM trains Gmail's classifier). REMOVING TRASH/SPAM is allowed (un-trash / un-spam are recovery actions). Max 10 ids per array (add and remove counted independently). At least one of addLabelIds / removeLabelIds must be non-empty.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Gmail message id (16+ lowercase hex chars, e.g. '19de5a8c628b9010'). Get from gmail_search.",
        },
        addLabelIds: {
          type: "array",
          items: { type: "string" },
          maxItems: 10,
          description: "Label ids to add. Cannot include TRASH or SPAM (use Gmail UI for those). Max 10.",
        },
        removeLabelIds: {
          type: "array",
          items: { type: "string" },
          maxItems: 10,
          description: "Label ids to remove. TRASH / SPAM removal IS allowed (un-trash / un-spam). Max 10.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["id"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_MODIFY],
    handler: handlers.gmailModifyMessage,
    min_tier: "write",
  },
  gmail_modify_messages_batch: {
    name: "gmail_modify_messages_batch",
    description:
      "Apply the SAME label change to UP TO 100 Gmail messages in a single API call (WRITE OPERATION, but undoable — labels can be flipped back). HIGHER blast radius than gmail_modify_message: ALWAYS ask the user for explicit confirmation INCLUDING the count of messages and the exact label changes BEFORE calling this tool. Requires SAFESPACE_TIER=write (or share) in the proxy environment. Use this instead of N parallel gmail_modify_message calls when applying the same label change to many messages (e.g. archiving a search result set, bulk-marking as read). POLICY BLOCK: addLabelIds CANNOT contain TRASH or SPAM (same rule as gmail_modify_message). REMOVING TRASH/SPAM is allowed (un-trash / un-spam are recovery actions). Per-call limits: ids 1-100, addLabelIds 0-10, removeLabelIds 0-10, at least one of add/remove non-empty. Duplicate ids are de-duplicated locally before send. On success returns {success: true, modified_count: N, duplicates_dropped: K}.",
    inputSchema: {
      type: "object",
      properties: {
        ids: {
          type: "array",
          items: { type: "string" },
          minItems: 1,
          maxItems: 100,
          description: "Gmail message ids to modify (1-100). Each must be 16+ lowercase hex chars. Get from gmail_search.",
        },
        addLabelIds: {
          type: "array",
          items: { type: "string" },
          maxItems: 10,
          description: "Label ids to add to every message in ids[]. Cannot include TRASH or SPAM (use Gmail UI for those). Max 10.",
        },
        removeLabelIds: {
          type: "array",
          items: { type: "string" },
          maxItems: 10,
          description: "Label ids to remove from every message in ids[]. TRASH / SPAM removal IS allowed. Max 10.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["ids"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_MODIFY],
    handler: handlers.gmailModifyMessagesBatch,
    min_tier: "write",
  },
  gmail_send: {
    name: "gmail_send",
    description:
      "Send a Gmail message AS the active account (WRITE OPERATION, irreversible — email cannot be unsent). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share) in the proxy environment. Plain text body only (no HTML, no attachments). `to`, `cc`, and `bcc` may each contain comma-separated addresses; combined recipient count (to+cc+bcc) is capped at 10. CR/LF/NUL/NEL/U+2028/U+2029 in `to`, `cc`, `bcc`, or `subject` is rejected (header injection prevention). Subject must be ASCII. Body capped at 1 MB. Recipients across to+cc+bcc are gated by SAFESPACE_RECIPIENT_ALLOW (v2.2) when set — all-or-nothing. Bcc recipients are delivered to but stripped from the message headers per RFC 5322 §3.6.3. Every send produces one audit JSONL line.",
    inputSchema: {
      type: "object",
      properties: {
        to: {
          type: "string",
          description: "Recipient email(s), comma-separated. No CR/LF allowed.",
        },
        cc: {
          type: "string",
          description: "Optional Cc recipient(s), comma-separated. Counts against the combined 10-recipient cap. No CR/LF allowed.",
        },
        bcc: {
          type: "string",
          description: "Optional Bcc recipient(s), comma-separated. Delivered to but stripped from message headers per RFC 5322 §3.6.3. Counts against the combined 10-recipient cap. No CR/LF allowed.",
        },
        subject: {
          type: "string",
          description: "Plain ASCII subject line. No CR/LF allowed.",
        },
        body: {
          type: "string",
          description: "Plain text body (UTF-8). Multi-line is fine.",
        },
        account_id: {
          type: "string",
          description: "Email of the sending account; defaults to the most recently used account.",
        },
      },
      required: ["to", "subject", "body"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_SEND],
    handler: handlers.gmailSend,
    min_tier: "write",
    // v1.64 Phase B (B0) — outbound egress surface: sends agent-authored mail
    // to recipients outside the user's own account. The label keys the choke
    // point's egress tripwire + (B6.1 wave A3+D) the PIPELINE-FIRED gate.
    direction: "outbound-write",
    // B6.1 wave A3+D — pipeline-fired TRANSFORMING egress: withToolContext runs
    // the descriptor (extract → gate, resolving recipients via
    // source.resolveRecipients) BEFORE the handler and stores the RESOLVED shape on
    // ctx.egress; the handler wires that (requireEgressResult), never re-fires the gate.
    egress: gmailSendEgressDescriptor,
  },
  gmail_create_draft: {
    name: "gmail_create_draft",
    description:
      "Compose a Gmail DRAFT in the active account (WRITE OPERATION, but does NOT send — the message is saved under DRAFT and no email leaves). Use this to prepare a reply or new message for the user to review and send themselves from Gmail. ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). Plain text body only (no HTML, no attachments). `to`, `cc`, `bcc`, `subject`, and `body` are ALL optional, but at least one of `to`/`subject`/`body` must be non-empty (no empty drafts). `to`/`cc`/`bcc` may each contain comma-separated addresses; combined recipient count is capped at 10 and each must be a literal email address (no name lookup). CR/LF/NUL/NEL/U+2028/U+2029 in `to`/`cc`/`bcc`/`subject` is rejected (header injection prevention). Subject must be ASCII. Body capped at 1 MB. Recipients across to+cc+bcc are gated by SAFESPACE_RECIPIENT_ALLOW (v2.2) when set — all-or-nothing, identical to gmail_send (a draft is a latent send). Returns the Draft resource {id, message:{id, threadId, labelIds:[DRAFT], ...}}.",
    inputSchema: {
      type: "object",
      properties: {
        to: {
          type: "string",
          description: "Optional recipient email(s), comma-separated. Literal emails only. No CR/LF allowed.",
        },
        cc: {
          type: "string",
          description: "Optional Cc recipient(s), comma-separated. Counts against the combined 10-recipient cap. No CR/LF allowed.",
        },
        bcc: {
          type: "string",
          description: "Optional Bcc recipient(s), comma-separated. Counts against the combined 10-recipient cap. No CR/LF allowed.",
        },
        subject: {
          type: "string",
          description: "Optional plain ASCII subject line. No CR/LF allowed.",
        },
        body: {
          type: "string",
          description: "Optional plain text body (UTF-8). Multi-line is fine.",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: [],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_MODIFY],
    handler: handlers.gmailCreateDraft,
    min_tier: "write",
    // v1.64 Phase B (B0) — outbound egress surface: a draft is a latent send
    // (same recipient gate as gmail_send). Labeled outbound-write so the choke
    // point's egress tripwire + (B6.1 wave A3+D) the PIPELINE-FIRED gate cover it.
    direction: "outbound-write",
    // B6.1 wave A3+D — pipeline-fired TRANSFORMING egress, same wrapper as gmail_send
    // (draft is literal-only + not approval-gated; the wrapper's tool discriminant
    // handles the difference). Handler wires the RESOLVED shape off ctx.egress.
    egress: gmailCreateDraftEgressDescriptor,
  },
  gmail_list_drafts: {
    name: "gmail_list_drafts",
    description:
      "List drafts in the active Gmail account. Returns drafts[{id, message:{id, threadId}}] plus nextPageToken and resultSizeEstimate — ID list only. Use gmail_get_draft for a draft's subject/body/recipients.",
    inputSchema: {
      type: "object",
      properties: {
        max_results: {
          type: "integer",
          minimum: 1,
          maximum: 50,
          default: 10,
          description: "Maximum number of drafts to return (capped at 50).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: [],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_READONLY],
    handler: handlers.gmailListDrafts,
    min_tier: "read",
  },
  gmail_get_draft: {
    name: "gmail_get_draft",
    description:
      "Fetch a Gmail draft by id. Returns {id, message:{...}} where message is the full payload (headers From/To/Subject as payload.headers[{name,value}], snippet, body.data base64url-encoded, parts for multipart, labelIds). Use after gmail_list_drafts.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Draft id from gmail_list_drafts (e.g. 'r-1234567890').",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["id"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_READONLY],
    handler: handlers.gmailGetDraft,
    min_tier: "read",
  },
  gmail_delete_draft: {
    name: "gmail_delete_draft",
    description:
      "Permanently delete a Gmail draft by id (WRITE OPERATION, IRREVERSIBLE — drafts bypass Trash and cannot be recovered). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). Only affects the draft itself; nothing is sent. Returns {success: true, id}.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Draft id from gmail_list_drafts (e.g. 'r-1234567890').",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["id"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_MODIFY],
    handler: handlers.gmailDeleteDraft,
    min_tier: "write",
  },
  gmail_get_thread: {
    name: "gmail_get_thread",
    description:
      "Fetch a whole Gmail conversation (thread) by id as a LIGHTWEIGHT index. Returns {id, historyId, messages:[{id, threadId, labelIds, snippet, payload:{headers:[{name,value}], mimeType, parts:[{partId, mimeType, filename, body:{attachmentId, size}}]}}]} — format=metadata, so each message carries headers (From/To/Subject/Date) + snippet but NO body.data (keeps the response bounded for long threads). To read a specific message's full body, use gmail_get_message with that message id. To download an attachment, use gmail_get_attachment with the message id + the part's body.attachmentId. Get the thread id from gmail_search (each match carries threadId).",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Thread id (e.g. '18c9a1b2c3d4e5f6'); from gmail_search's threadId field.",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["id"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_READONLY],
    handler: handlers.gmailGetThread,
    min_tier: "read",
  },
  gmail_get_attachment: {
    name: "gmail_get_attachment",
    description:
      "Download ONE attachment from a Gmail message (READ OPERATION). Provide message_id and attachment_id — both come from a prior gmail_get_message (or gmail_get_thread) payload: walk payload.parts[*]; each attachment part has a filename plus body.attachmentId + body.size. Returns {size, data} where data is the base64url-encoded attachment bytes (decode client-side; NOT decoded proxy-side). SIZE CAP: attachments larger than 5 MB are REJECTED with file_too_large (-32007) — check the part's body.size first and use the Gmail web UI for large files. Binary content (PDF/image/zip) is returned as-is; the proxy does not interpret it.",
    inputSchema: {
      type: "object",
      properties: {
        message_id: {
          type: "string",
          description: "The Gmail message id that owns the attachment (from gmail_search / gmail_get_message).",
        },
        attachment_id: {
          type: "string",
          description: "The attachment id from the message payload (payload.parts[*].body.attachmentId).",
        },
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: ["message_id", "attachment_id"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_READONLY],
    handler: handlers.gmailGetAttachment,
    min_tier: "read",
  },
  gmail_list_filters: {
    name: "gmail_list_filters",
    description:
      "List all message filters in the active Gmail account (READ OPERATION). Returns {filter:[{id, criteria:{from?,to?,subject?,query?,negatedQuery?,hasAttachment?,excludeChats?,size?,sizeComparison?}, action:{addLabelIds?,removeLabelIds?,forward?}}]}. Use the returned filter `id` with gmail_delete_filter. NOTE: filters created outside SafeSpace (e.g. in the Gmail web UI) may carry a `forward` action — SafeSpace surfaces it on read but will NEVER create one.",
    inputSchema: {
      type: "object",
      properties: {
        account_id: {
          type: "string",
          description: "Email of the account to query; defaults to the most recently used account.",
        },
      },
      required: [],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_SETTINGS_BASIC],
    handler: handlers.gmailListFilters,
    min_tier: "read",
  },
  gmail_create_filter: {
    name: "gmail_create_filter",
    description:
      "Create a Gmail message filter that auto-applies label changes to matching incoming mail (WRITE OPERATION, but recoverable — delete + recreate via gmail_delete_filter; Gmail has no update-filter endpoint). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). Provide `criteria` (which messages match — at least one of from/to/subject/query/negatedQuery/hasAttachment/excludeChats/size/sizeComparison) and `action` (what to do — at least one of addLabelIds / removeLabelIds). POLICY BLOCKS: (1) the `forward` action is NOT permitted (a forwarding filter is a persistent exfiltration channel) — it is rejected even if supplied. (2) addLabelIds CANNOT contain TRASH or SPAM (a silent auto-delete / auto-spam rule) — same rule as gmail_modify_message. Ordinary label add/remove IS allowed, including removeLabelIds:['INBOX'] (auto-archive) and removeLabelIds:['UNREAD'] (auto-mark-read) — the real 'auto-organize inbox' use case. Per-side label cap 10. Use gmail_list_labels to find label ids first. Returns the created Filter {id, criteria, action}.",
    inputSchema: {
      type: "object",
      properties: {
        criteria: {
          type: "object",
          description: "Match predicate — which incoming messages this filter applies to. At least one field required (an empty criteria would match ALL mail).",
          properties: {
            from: { type: "string", description: "Sender display name or email address." },
            to: { type: "string", description: "Recipient (to/cc/bcc) display name or email; local-part matches too." },
            subject: { type: "string", description: "Case-insensitive phrase in the subject." },
            query: { type: "string", description: "Gmail search query (same syntax as the search box)." },
            negatedQuery: { type: "string", description: "Only match messages NOT matching this Gmail query." },
            hasAttachment: { type: "boolean", description: "Match only messages with an attachment." },
            excludeChats: { type: "boolean", description: "Exclude chat messages." },
            size: { type: "integer", minimum: 0, description: "RFC822 message size in bytes, compared per sizeComparison." },
            sizeComparison: {
              type: "string",
              enum: ["smaller", "larger", "unspecified"],
              description: "How `size` is compared.",
            },
          },
          additionalProperties: false,
        },
        action: {
          type: "object",
          description: "What to do with matching messages. At least one of addLabelIds / removeLabelIds. The `forward` action is intentionally NOT accepted.",
          properties: {
            addLabelIds: {
              type: "array",
              items: { type: "string" },
              maxItems: 10,
              description: "Label ids to add. Cannot include TRASH or SPAM. Max 10. Get ids from gmail_list_labels.",
            },
            removeLabelIds: {
              type: "array",
              items: { type: "string" },
              maxItems: 10,
              description: "Label ids to remove. INBOX (archive) / UNREAD (mark read) allowed. Max 10.",
            },
          },
          additionalProperties: false,
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["criteria", "action"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_SETTINGS_BASIC],
    handler: handlers.gmailCreateFilter,
    min_tier: "write",
  },
  gmail_delete_filter: {
    name: "gmail_delete_filter",
    description:
      "Delete a Gmail message filter by id (WRITE OPERATION, but recoverable — recreate via gmail_create_filter). ALWAYS ask the user for explicit confirmation before calling this tool. Requires SAFESPACE_TIER=write (or share). Only removes the filter rule; no mail is touched. Get the filter id from gmail_list_filters. Returns {success: true, id}.",
    inputSchema: {
      type: "object",
      properties: {
        id: {
          type: "string",
          description: "Filter id from gmail_list_filters (e.g. 'ANe1Bmj...').",
        },
        account_id: {
          type: "string",
          description: "Email of the account; defaults to the most recently used account.",
        },
      },
      required: ["id"],
      additionalProperties: false,
    },
    requiredScopes: [GMAIL_SETTINGS_BASIC],
    handler: handlers.gmailDeleteFilter,
    min_tier: "write",
  },
};
