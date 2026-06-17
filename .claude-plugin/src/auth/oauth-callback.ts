// v1.70 (G3) — the provider-agnostic loopback OAuth callback server.
//
// Extracted VERBATIM from auth/consent.ts (where it served the Google
// authorization-code flow since DESIGN.md §Next Steps Step 2). GitHub is
// SafeSpace's 2nd OAuth source (a GitHub OAuth App, same authorization-code +
// loopback-redirect shape), so the callback server is shared rather than forked:
// both auth/consent.ts (Google) and auth/github/consent.ts (GitHub) bind a
// 127.0.0.1 server on an ephemeral port, hand its `/callback` URL to the provider
// as the redirect_uri, and await the single `?code=…&state=…` (or `?error=…`)
// redirect the browser delivers.
//
// SECURITY (carried over from the Google sec-review, NEW-1 / state-CSRF):
//   - 127.0.0.1-bound only (never 0.0.0.0) — not reachable off-host.
//   - the `state` CSRF token is verified before the code is accepted.
//   - user-controlled `error` text is logged to the rejecting Error but NEVER
//     reflected into the HTTP response body.
//   - non-/callback paths 404; missing code / state mismatch reject + 4xx.

import * as http from "node:http";

export interface CallbackResult {
  readonly code: string;
}

export interface CallbackServer {
  /** The loopback redirect_uri to hand the OAuth provider. */
  readonly url: string;
  /** Resolves with the authorization code once the browser hits /callback with a
   *  matching state; rejects on ?error= / state mismatch / missing code. */
  readonly await: Promise<CallbackResult>;
  /** Tear the server down (always call in a finally). */
  stop(): void;
}

/** Start a single-shot 127.0.0.1 callback server bound to an ephemeral port.
 *  `expectedState` is the CSRF token the caller embedded in the authorize URL;
 *  a redirect whose `state` does not match is rejected (possible CSRF).
 *
 *  Async because `node:http` assigns the ephemeral port asynchronously (the port is
 *  not known until the `listening` event fires) — the returned `url` carries that port,
 *  so the caller must await it before building the redirect_uri. */
export function startCallbackServer(expectedState: string): Promise<CallbackServer> {
  let resolveCb!: (r: CallbackResult) => void;
  let rejectCb!: (e: Error) => void;
  const promise = new Promise<CallbackResult>((res, rej) => { resolveCb = res; rejectCb = rej; });

  const server = http.createServer((req, res) => {
    // SECURITY: in node:http `req.url` is PATH-ONLY (e.g. "/callback?code=…"), not a
    // full URL — a base is REQUIRED or `new URL` throws. The base host is irrelevant
    // (only pathname + searchParams are read).
    const u = new URL(req.url ?? "/", "http://127.0.0.1");
    if (u.pathname !== "/callback") { res.writeHead(404).end("not found"); return; }

    const error = u.searchParams.get("error");
    if (error) {
      // The provider's `error` is a fixed lowercase-underscore enum
      // (access_denied / redirect_uri_mismatch / …). Sanitize before embedding
      // it in the thrown Error so a crafted loopback redirect can't inject
      // arbitrary text into the CLI's error output (it is already never
      // reflected into the HTTP response body — security-review NEW-1 + G3 L2).
      const safe = /^[a-z_]{1,64}$/.test(error) ? error : "denied";
      rejectCb(new Error(`oauth_denied: ${safe}`));
      res.writeHead(200).end("Authorization was denied. You may close this tab.");
      return;
    }
    const state = u.searchParams.get("state");
    const code = u.searchParams.get("code");
    if (state !== expectedState) {
      rejectCb(new Error("state_mismatch"));
      res.writeHead(400).end("State mismatch — possible CSRF. You may close this tab.");
      return;
    }
    if (!code) {
      rejectCb(new Error("no_code"));
      res.writeHead(400).end("Missing code. You may close this tab.");
      return;
    }
    resolveCb({ code });
    res.writeHead(200).end("Consent received. You may close this tab.");
  });

  return new Promise<CallbackServer>((resolveServer, rejectServer) => {
    server.on("error", rejectServer); // bind failure (e.g. loopback unavailable)
    // SECURITY: bind EXPLICITLY to 127.0.0.1 — omitting the host makes node:http listen
    // on 0.0.0.0, exposing the OAuth callback to the local network (review S1).
    server.listen(0, "127.0.0.1", () => {
      const addr = server.address();
      const port = typeof addr === "object" && addr !== null ? addr.port : 0;
      resolveServer({
        url: `http://127.0.0.1:${port}/callback`,
        await: promise,
        stop: () => {
          // node:http's close() only stops NEW connections and waits for in-flight ones
          // to drain; a keep-alive client socket (e.g. fetch) would keep the process
          // alive forever. Force-destroy open sockets — the equivalent of Bun.serve's
          // stop(true) — so this single-shot server releases the event loop immediately.
          server.closeAllConnections();
          server.close();
        },
      });
    });
  });
}
