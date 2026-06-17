// v1.74 — Model B PR-2b: Tailscale WhoIs connection identity.
//
// On the tailnet, an inbound connection ALREADY carries a verified identity: its
// peer IP is the WireGuard tunnel source, which Tailscale binds 1:1 to a logged-in
// user+device. We read that identity from the LOCAL `tailscaled` daemon's LocalAPI
// (`GET /localapi/v0/whois?addr=<peerIP:port>` over its unix socket) — NOT from any
// client-supplied header (docs/v1.74-model-b-operator-auth.md §4.1).
//
// NON-FORGEABLE: a tailnet member cannot present another member's 100.x address;
// the login comes from the daemon keyed on the verified peer IP. (Honest limit §5.2:
// Tailscale authenticates the DEVICE, not each request — the app-layer envelope
// stays mandatory.)
//
// FAIL-CLOSED: any error (socket missing, timeout, non-200, unparseable, tagged
// node, no LoginName) → `null` = "no verified identity" → the transport refuses the
// session (default-deny §4.2). The function NEVER throws and NEVER echoes the socket
// path or the raw daemon response.

import { request as httpRequest } from "node:http";
import { ENV_TAILSCALE_SOCKET } from "../config";

/** Standard Linux path for the tailscaled LocalAPI unix socket (the Model B host
 *  is a Linux container per docs/model-b-deployment.md §5.3). Overridable via
 *  `SAFESPACE_TAILSCALE_SOCKET`. */
const DEFAULT_SOCKET = "/run/tailscale/tailscaled.sock";
const WHOIS_TIMEOUT_MS = 3000;
const MAX_WHOIS_BYTES = 64 * 1024;

/** The injectable network call — returns the parsed LocalAPI whois JSON (or null on
 *  any failure). Separated from parsing so the pure extractor can be unit-tested and
 *  tests can inject a fake daemon response. */
export type RawWhois = (peerAddr: string) => Promise<unknown>;

export interface WhoisDeps {
  rawWhoisImpl?: RawWhois;
}

/** Extract the verified login from a LocalAPI whois response. Pure. Returns null
 *  unless the response is a well-formed object carrying a non-empty
 *  `UserProfile.LoginName` for a REAL user — a `tagged-devices` node (a tagged /
 *  shared machine, not a human) has no operator identity and is rejected. */
export function loginFromWhoisResponse(resp: unknown): string | null {
  if (resp == null || typeof resp !== "object") return null;
  const profile = (resp as { UserProfile?: unknown }).UserProfile;
  if (profile == null || typeof profile !== "object") return null;
  const login = (profile as { LoginName?: unknown }).LoginName;
  if (typeof login !== "string" || login.length === 0) return null;
  // Tagged/shared nodes report this sentinel — no human operator behind them.
  if (login === "tagged-devices") return null;
  return login;
}

/** Resolve the verified tailnet login for a connection's peer address, or null
 *  (fail-closed). `peerAddr` is the connection's remote `ip:port`. */
export async function tailscaleWhois(
  peerAddr: string,
  deps: WhoisDeps = {},
): Promise<string | null> {
  const raw = deps.rawWhoisImpl ?? defaultRawWhois;
  let resp: unknown;
  try {
    resp = await raw(peerAddr);
  } catch {
    return null; // fail-closed: no identity → default-deny
  }
  return loginFromWhoisResponse(resp);
}

/** Real LocalAPI call over the tailscaled unix socket. Never throws (resolves null
 *  on every failure path) and never surfaces the socket path or response bytes. */
function defaultRawWhois(peerAddr: string): Promise<unknown> {
  const socketPath = process.env[ENV_TAILSCALE_SOCKET] || DEFAULT_SOCKET;
  return new Promise((resolve) => {
    const req = httpRequest(
      {
        socketPath,
        path: `/localapi/v0/whois?addr=${encodeURIComponent(peerAddr)}`,
        method: "GET",
        // The LocalAPI requires this fixed Host over the unix socket.
        headers: { Host: "local-tailscaled.sock" },
        timeout: WHOIS_TIMEOUT_MS,
      },
      (res) => {
        if (res.statusCode !== 200) {
          res.resume();
          resolve(null);
          return;
        }
        const chunks: Buffer[] = [];
        let size = 0;
        res.on("data", (c: Buffer) => {
          size += c.length;
          if (size > MAX_WHOIS_BYTES) {
            req.destroy(); // abort the request too (consistency with the timeout path)
            res.destroy();
            resolve(null);
            return;
          }
          chunks.push(c);
        });
        res.on("end", () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
          } catch {
            resolve(null);
          }
        });
        res.on("error", () => resolve(null));
      },
    );
    req.on("timeout", () => {
      req.destroy();
      resolve(null);
    });
    req.on("error", () => resolve(null)); // socket missing / refused → null (deny)
    req.end();
  });
}
