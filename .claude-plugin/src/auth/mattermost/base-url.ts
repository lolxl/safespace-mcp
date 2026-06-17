// v1.107 — Mattermost SELF-HOSTED server base URL resolver.
//
// Mattermost is the FIRST service-token connector whose host is NOT a fixed constant:
// it is self-hosted, so the server URL is per-deployment. The OWNER configures it once
// via `SAFESPACE_MATTERMOST_SERVER_URL` (CONFIG, not a secret — the bot token is the
// secret, stored separately in the SecretBackend). This module is the ONE place that
// reads + validates that URL, so every layer (client / handlers / egress backstop)
// derives the base URL and the pinned host from the same source.
//
// VALIDATION (at load, cached):
//   - require `https://` — the bot token rides an Authorization header; http would
//     expose it in transit. (Front an http-only internal server with TLS.)
//   - must parse + carry a hostname.
//   - PRIVATE / internal / tailnet hosts are ALLOWED — a self-hosted Mattermost is
//     legitimately on an internal network, and this host is OWNER-set ONCE, NOT
//     agent-controlled (so it is NOT the web-fetch SSRF threat model where the agent
//     supplies an arbitrary per-call URL). We do NOT apply the url-gate private-IP block.
//   - normalized to origin + path (drops query/fragment, strips trailing slash) so a
//     subpath deployment (`https://example.com/mattermost`) works and the API root is
//     stable: handlers build `${baseUrl}/api/v4/...`.
//
// FAIL-CLOSED: unset / non-https / unparseable → null. The require* accessor throws
// `mattermost_api_failed{no_server_url}`, and `mattermostConfiguredHost()` returns null
// so `assertEgressHost(host, "mattermost")` blocks ALL Mattermost egress until the URL
// is configured.

import { ENV_MATTERMOST_SERVER_URL } from "../../config";
import { MCPError } from "../../errors";

export interface MattermostServer {
  /** Normalized base URL (origin + subpath, no trailing slash) — the API-root prefix. */
  readonly baseUrl: string;
  /** Lowercased hostname (no port) — the value `assertEgressHost` pins against. */
  readonly host: string;
}

let cached: MattermostServer | null | undefined;
let warned = false;

function warnOnce(reason: string): void {
  if (warned) return;
  warned = true;
  console.error(
    `[safespace] WARNING: SAFESPACE_MATTERMOST_SERVER_URL ${reason} — the Mattermost ` +
      `connector is disabled (all Mattermost egress is blocked) until it is set to a ` +
      `valid https:// server URL.`,
  );
}

function compute(): MattermostServer | null {
  const raw = process.env[ENV_MATTERMOST_SERVER_URL];
  if (raw == null || raw.trim() === "") return null;
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    warnOnce("is not a valid URL");
    return null;
  }
  if (url.protocol !== "https:") {
    warnOnce("must use https:// (the bot token rides an Authorization header)");
    return null;
  }
  if (url.hostname === "") {
    warnOnce("has no host");
    return null;
  }
  // origin = scheme://host[:port]; pathname keeps a subpath deployment; drop the rest.
  const baseUrl = (url.origin + url.pathname).replace(/\/+$/, "");
  return { baseUrl, host: url.hostname.toLowerCase() };
}

/** The configured server (cached), or null when unset / invalid (fail-closed). */
export function getMattermostServer(): MattermostServer | null {
  if (cached === undefined) cached = compute();
  return cached;
}

/** The normalized base URL, or throw `mattermost_api_failed{no_server_url}`. */
export function requireMattermostBaseUrl(): string {
  const s = getMattermostServer();
  if (s === null) {
    throw new MCPError("mattermost_api_failed", { reason: "no_server_url" });
  }
  return s.baseUrl;
}

/** The lowercased configured host for the egress backstop, or null (→ blocks egress). */
export function mattermostConfiguredHost(): string | null {
  return getMattermostServer()?.host ?? null;
}

/** Test-only: drop the cached parse + warn flag so a test can flip the env. */
export function __resetMattermostServerForTests(): void {
  cached = undefined;
  warned = false;
}
