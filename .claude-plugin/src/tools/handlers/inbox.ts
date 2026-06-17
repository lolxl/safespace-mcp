// v1.102 (W0) — the inbox_read handler. Reads the durable webhook inbox (populated by
// the listener) and returns a curated page; the choke point (withNonOAuthContext) then
// sanitize-WRAPS sender_name + text via the `webhook` Source skipFields. Credential is
// {kind:"none"} (a local-store read; the signing secret is listener infra, not a tool
// credential), so this handler never touches a token/account — `ctx` is unused.
//
// docs/v1.102-webhook-listener.md §5.5 + §4.2.

import { MCPError } from "../../errors";
import { inboxPath, readInbox, type InboxReadResult } from "../../webhook/inbox-store";
import type { WebhookProvider } from "../../webhook/types";
import type { ToolContext } from "../types";

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 100;

function clampLimit(v: unknown): number {
  if (typeof v === "number" && Number.isInteger(v) && v >= 1) return Math.min(v, MAX_LIMIT);
  return DEFAULT_LIMIT;
}

/** Test seams (default to the real store + clock). */
export interface InboxReadDeps {
  read?: (file: string, provider: WebhookProvider, afterSeq: number, limit: number, now: number) => Promise<InboxReadResult>;
  now?: () => number;
  inboxFile?: string;
}

export async function inboxRead(
  _ctx: ToolContext,
  args: Record<string, unknown>,
  deps: InboxReadDeps = {},
): Promise<unknown> {
  const read = deps.read ?? readInbox;
  const now = deps.now ?? (() => Date.now());
  const file = deps.inboxFile ?? inboxPath();
  // The inputSchema enum restricts `provider` to the wired set (W0: slack). An unknown
  // value would simply match no rows (readInbox filters by provider) → empty, never a crash.
  const provider = args.provider as WebhookProvider;
  const afterSeq =
    typeof args.after_seq === "number" && Number.isInteger(args.after_seq) && args.after_seq >= 0
      ? args.after_seq
      : 0;
  const limit = clampLimit(args.limit);

  let result: InboxReadResult;
  try {
    result = await read(file, provider, afterSeq, limit, now());
  } catch (e) {
    // A corrupt / unreadable store → fail-loud throw → a closed-set MCPError (no content
    // echoed). The NonOAuth choke point does not run source.mapError (B6.1), so the
    // handler maps it here, mirroring web_fetch / fs_read.
    if (e instanceof MCPError) throw e;
    throw new MCPError("inbox_read_failed", { reason: "store_unavailable" });
  }

  return {
    provider,
    messages: result.messages.map((r) => ({
      seq: r.seq,
      event_id: r.event_id,
      received_at: r.received_at,
      provider_message_id: r.msg.provider_message_id,
      ts: r.msg.ts,
      sender_id: r.msg.sender_id,
      sender_name: r.msg.sender_name,
      channel_id: r.msg.channel_id,
      text: r.msg.text,
    })),
    max_seq: result.max_seq,
    oldest_seq: result.oldest_seq,
  };
}
