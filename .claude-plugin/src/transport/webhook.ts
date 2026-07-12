// v1.102 (W0) — the inbound webhook listener: SafeSpace's first public,
// untrusted-remote-caller surface. A SEPARATE `node:http` server from the MCP
// transport (its own port + bind, its own request handler — no shared router, so a
// routing bug can never expose `/mcp` on the public port). Verify → persist → ACK.
//
// docs/v1.102-webhook-listener.md §3 + §5.1:
//   - `POST /webhook/<provider>` ONLY; the <provider> segment is validated against the
//     CLOSED enabled set before any work (path-traversal guard, security MISSED-1).
//   - Body read is BYTE-bounded (actual bytes, not Content-Length) — a chunked body
//     with a forged Content-Length cannot truncate-bypass (security MISSED-2).
//   - The signing secret is read PER REQUEST (never cached) → clear/rotate bites now.
//   - PERSIST-BEFORE-ACK: a persist failure returns 500 (NOT 200) so the provider
//     retries; dedup absorbs the retry → no message lost (§3).
//   - A bad/absent signature → 401; a verified-but-malformed → 400; a dedup hit → 200
//     (an intentional provider ACK — never "corrected" to a 4xx). Rejects are counted
//     into a 60 s window and audited counts-only (no body/source/event-id leak).

import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server as HttpServer,
} from "node:http";
import type { AddressInfo } from "node:net";
import { ENV_WEBHOOK_BIND, ENV_WEBHOOK_PORT } from "../config";
import { auditWebhookReceiptEvent, auditWebhookRejectedEvent } from "../audit";
import { appendInboxMessage, inboxPath, type InboxAppend } from "../webhook/inbox-store";
import { readWebhookSigningSecret } from "../auth/webhook-secret-store";
import { handleSlackWebhook } from "../webhook/verify/slack";
import { handleLineWebhook } from "../webhook/verify/line";
import { rejectHttpStatus, type WebhookProvider, type WebhookResult } from "../webhook/types";

/** Default bind — LOOPBACK. NEVER 0.0.0.0; a public bind must be the operator's
 *  explicit `SAFESPACE_WEBHOOK_BIND` choice fronted by a TLS proxy. */
export const DEFAULT_WEBHOOK_BIND = "127.0.0.1";
/** Body cap — mirrors the MCP transport's 4 MB. Webhook payloads are small. */
const MAX_BODY_BYTES = 4 * 1024 * 1024;
/** Rolling window for the counts-only rejected audit (security MED-3). */
const REJECT_WINDOW_MS = 60_000;

/** A verify function: raw bytes + headers + the per-request secret + now(ms) → result.
 *  The SINGLE registry of WIRED providers (W0: slack). The route validator + the
 *  fail-loud secret check both derive the enabled set from this — adding LINE (W1) is a
 *  one-line add here + a skipFields/verify module. */
type Verifier = (raw: Buffer, headers: IncomingMessage["headers"], secret: string, nowMs: number) => WebhookResult;
const VERIFIERS: Partial<Record<WebhookProvider, Verifier>> = {
  slack: handleSlackWebhook,
  line: handleLineWebhook,
};

/** The providers wired in this build (the enabled set). */
export function enabledWebhookProviders(): WebhookProvider[] {
  return Object.keys(VERIFIERS) as WebhookProvider[];
}

// ── config resolution (mirrors transport/http.ts) ──────────────────────────

/** True iff the webhook listener is enabled (its port is set). Read LIVE. */
export function webhookEnabled(): boolean {
  const p = process.env[ENV_WEBHOOK_PORT];
  return p != null && p !== "";
}

/** The configured webhook bind (default loopback; never defaults to 0.0.0.0). */
export function webhookBind(): string {
  return process.env[ENV_WEBHOOK_BIND] || DEFAULT_WEBHOOK_BIND;
}

/** Resolve the listener config from env (production path; fail-loud on a bad port). */
export function resolveWebhookConfigFromEnv(): { port: number; bind: string } {
  const portRaw = process.env[ENV_WEBHOOK_PORT];
  const port = portRaw != null && portRaw !== "" ? Number(portRaw) : NaN;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(
      `[safespace] ${ENV_WEBHOOK_PORT} must be an integer port 1-65535 to enable the webhook listener (got ${portRaw ?? "unset"})`,
    );
  }
  return { port, bind: webhookBind() };
}

/** Fail-loud (bootstrap): a public listener with NO verification key is the worst
 *  failure mode (security HIGH-2). When the listener is enabled, EVERY enabled
 *  provider's signing secret must be present, or we refuse to start (naming the
 *  missing ones). Async (reads the SecretBackend). */
export async function enforceWebhookSecretsPresent(
  hasSecret: (p: WebhookProvider) => Promise<boolean> = async (p) =>
    (await readWebhookSigningSecret(p)) !== null,
): Promise<void> {
  // Probe every enabled provider's secret in parallel (independent SecretBackend
  // reads, no ordering dependency), then derive `missing` by filtering in
  // provider order — same result + same reported order as the sequential loop.
  const providers = enabledWebhookProviders();
  const present = await Promise.all(providers.map((p) => hasSecret(p)));
  const missing = providers.filter((_, i) => !present[i]);
  if (missing.length > 0) {
    throw new Error(
      `${ENV_WEBHOOK_PORT} is set but no signing secret is configured for: ${missing.join(", ")}. ` +
        `Set it with 'safespace webhook set-secret <provider>' (or the SAFESPACE_<PROVIDER>_WEBHOOK_SECRET env) ` +
        "before starting — refusing to serve an unverifiable public listener.",
    );
  }
}

// ── request handling ───────────────────────────────────────────────────────

class BodyTooLargeError extends Error {}

/** Collect the request body up to maxBytes (counting ACTUAL bytes, not Content-Length).
 *  Resolves a Buffer; rejects BodyTooLargeError on oversize (draining the rest so the
 *  413 reaches the client cleanly). */
function readRawBody(req: IncomingMessage, maxBytes: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    let aborted = false;
    req.on("data", (chunk: Buffer) => {
      if (aborted) return;
      size += chunk.length;
      if (size > maxBytes) {
        aborted = true;
        reject(new BodyTooLargeError());
        req.resume();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => {
      if (!aborted) resolve(Buffer.concat(chunks));
    });
    req.on("error", reject);
  });
}

/** Extract a KNOWN provider from `/webhook/<provider>` (exact two-segment path), or
 *  null. The closed-set check (not the architectural separation alone) is the
 *  path-traversal guard. */
function providerFromPath(pathname: string, enabled: readonly WebhookProvider[]): WebhookProvider | null {
  const parts = pathname.split("/").filter((s) => s.length > 0);
  if (parts.length !== 2 || parts[0] !== "webhook") return null;
  const p = parts[1]!;
  return (enabled as readonly string[]).includes(p) ? (p as WebhookProvider) : null;
}

/** Injectable seams so the listener is unit-testable without a real SecretBackend /
 *  store / clock. Production passes none → the real impls. */
export interface WebhookListenerConfig {
  readonly port: number;
  readonly bind: string;
  readonly readSecret?: (p: WebhookProvider) => Promise<string | null>;
  readonly persist?: (input: InboxAppend, now: number) => Promise<{ deduped: boolean }>;
  readonly auditReceipt?: (provider: WebhookProvider, eventId: string, persisted: boolean) => void;
  readonly auditRejected?: (provider: WebhookProvider, count: number) => void;
  readonly now?: () => number;
}

export interface WebhookHandle {
  readonly port: number;
  close(): Promise<void>;
}

export async function startWebhookListener(config: WebhookListenerConfig): Promise<WebhookHandle> {
  const enabled = enabledWebhookProviders();
  const now = config.now ?? (() => Date.now());
  const readSecret = config.readSecret ?? readWebhookSigningSecret;
  const persist =
    config.persist ?? ((input: InboxAppend, n: number) => appendInboxMessage(inboxPath(), input, n));
  const auditReceipt =
    config.auditReceipt ??
    ((provider: WebhookProvider, eventId: string, persisted: boolean) =>
      void auditWebhookReceiptEvent({ provider, event_id: eventId, persisted }));
  const auditRejected =
    config.auditRejected ??
    ((provider: WebhookProvider, count: number) => void auditWebhookRejectedEvent(provider, count));

  // Per-provider rolling reject window: aggregate rejects, emit ONE counts-only audit
  // line per 60 s (so a forged flood can't fill the log). Each record builds a NEW
  // window object (no in-place Map mutation). The TAIL count of a window that never
  // sees a following reject is flushed on close() (below) so a finite burst that stops
  // mid-window is not silently dropped (review MED-1 / LOW-1).
  const rejectWindows = new Map<WebhookProvider, { start: number; count: number }>();
  const recordReject = (provider: WebhookProvider, t: number): void => {
    const w = rejectWindows.get(provider);
    if (w && t - w.start >= REJECT_WINDOW_MS) {
      // The window elapsed: emit its accumulated count, then OPEN a fresh window that
      // contains THIS reject (so every reject is counted exactly once).
      auditRejected(provider, w.count);
      rejectWindows.set(provider, { start: t, count: 1 });
    } else if (w) {
      rejectWindows.set(provider, { start: w.start, count: w.count + 1 });
    } else {
      rejectWindows.set(provider, { start: t, count: 1 });
    }
  };
  // Emit any un-flushed window counts (the tail of a finite burst). Called on close().
  const flushRejectWindows = (): void => {
    for (const [provider, w] of rejectWindows) {
      if (w.count > 0) auditRejected(provider, w.count);
    }
    rejectWindows.clear();
  };

  const httpServer: HttpServer = createHttpServer(async (req, res) => {
    try {
      if (req.method !== "POST") {
        res.writeHead(405, { Allow: "POST" }).end();
        return;
      }
      const url = new URL(req.url ?? "/", `http://${config.bind}`);
      const provider = providerFromPath(url.pathname, enabled);
      if (!provider) {
        res.writeHead(404).end();
        return;
      }
      let raw: Buffer;
      try {
        raw = await readRawBody(req, MAX_BODY_BYTES);
      } catch (e) {
        res.writeHead(e instanceof BodyTooLargeError ? 413 : 400).end();
        return;
      }
      // Per-request secret resolution (never cached) → clear/rotate bites now.
      const secret = await readSecret(provider);
      if (secret == null) {
        // No key to verify against (cleared at runtime) → fail closed, count it.
        recordReject(provider, now());
        res.writeHead(401).end();
        return;
      }
      const verify = VERIFIERS[provider]!;
      const result = verify(raw, req.headers, secret, now());

      if (result.kind === "reject") {
        recordReject(provider, now());
        res.writeHead(rejectHttpStatus(result.reason)).end();
        return;
      }
      if (result.kind === "challenge") {
        // Echo the validated challenge ONLY; never persist/sanitize/audit.
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end(result.challenge);
        return;
      }
      // result.kind === "messages": persist EACH before ack (an empty list = verified,
      // nothing to store → 200). A persist failure → 500 (NOT 200) so the provider
      // retries the WHOLE batch; dedup makes the already-persisted ones idempotent
      // (so a mid-batch failure never double-stores). One POST can carry N events (LINE).
      for (const m of result.messages) {
        let persisted = false;
        try {
          const r = await persist({ provider, event_id: m.event_id, msg: m.msg }, now());
          persisted = !r.deduped;
        } catch (e) {
          console.error(`[safespace] webhook persist failed: ${e instanceof Error ? e.message : String(e)}`);
          res.writeHead(500).end();
          return;
        }
        auditReceipt(provider, m.event_id, persisted);
      }
      res.writeHead(200).end();
    } catch {
      // Defensive: a handler throw never leaks a stack to the wire.
      if (!res.headersSent) res.writeHead(500).end();
    }
  });

  await new Promise<void>((resolve) => httpServer.listen(config.port, config.bind, resolve));
  const port = (httpServer.address() as AddressInfo).port;
  // stderr — never stdout. bind+port are not secret; no secret/body echoed.
  const note =
    config.bind === "0.0.0.0" || config.bind === "::"
      ? "all-interfaces — front it with your own TLS proxy (see SAFESPACE_TLS_TERMINATED)"
      : "bind a private/proxied interface — NEVER expose plaintext publicly";
  console.error(
    `[safespace] inbound webhook listener on http://${config.bind}:${port}/webhook/<provider> (providers: ${enabled.join(", ")}; signature-verified; ${note})`,
  );

  return {
    port,
    close: () => {
      flushRejectWindows(); // emit the tail reject-count before shutting down
      return new Promise<void>((resolve, reject) =>
        httpServer.close((err) =>
          err && (err as NodeJS.ErrnoException).code !== "ERR_SERVER_NOT_RUNNING" ? reject(err) : resolve(),
        ),
      );
    },
  };
}
