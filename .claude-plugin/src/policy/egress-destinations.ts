// v1.88 — the centralized egress-DESTINATION registry: the ONE auditable place
// listing every external host SafeSpace's OWN process connects to (NOT what the
// agent sends — the v1.87 `doctor --posture` egress enumeration covers that; this
// is the complementary "SafeSpace → provider" direction).
//
// WHY: before v1.88 each connector hardcoded its provider host inline (api.line.me
// in line.ts, api.github.com in github/client.ts, …) — scattered across 5+ files,
// with no single place to answer "where does SafeSpace actually connect." This
// registry is that single source, surfaced by `doctor --posture`.
//
// HONEST BOUNDARY (mirrors v1.86 SOLE-EGRESS — enforce where you own the socket,
// declare where you don't):
//   - ENFORCED connectors (github / notion / line / telegram / discord) use a raw
//     `fetch`/`node:https` SafeSpace controls → `assertEgressHost` is wired into
//     their fetch chokepoints, so an outbound call to a host NOT registered for that
//     connector is BLOCKED (a backstop against a connector bug or a path-injection
//     host escape — e.g. a path turning `api.github.com` into `…@evil.com`).
//   - DECLARED connectors (google-workspace / web-fetch) reach hosts SafeSpace
//     CANNOT gate at this layer: the googleapis SDK owns its gaxios socket (not
//     interceptable without forking the SDK), and web-fetch is intentionally a
//     DYNAMIC user host gated per-call by the SSRF `policy/url-gate.ts`. They are
//     listed for auditability but NOT enforced here — saying so honestly rather
//     than pretending to a guarantee we can't make.
//
// This is a FIXED code registry, not a user-configurable allowlist: the provider
// hosts are constants of the connectors, not a per-deployment policy. (A corporate
// egress proxy / mirror is a network-layer concern — SOLE-EGRESS Layer 2 — not an
// app-layer override.)

import { MCPError } from "../errors";
import { mattermostConfiguredHost } from "../auth/mattermost/base-url";

// v1.107 — "configured" joins enforced/declared. A SELF-HOSTED connector (Mattermost)
// has a per-DEPLOYMENT host, so it can't be a fixed registry constant — but it is still
// SafeSpace-socket-owned, so it IS enforced, against the OWNER-configured host (parsed
// once from SAFESPACE_MATTERMOST_SERVER_URL). This is the honest exception to the
// "FIXED code registry" rule above: the host is config, not an agent-supplied per-call
// URL (that is web-fetch's `declared` SSRF case), so the path-injection backstop holds.
export type EgressEnforcement = "enforced" | "declared" | "configured";

/** The closed set of connector ids — a structural key into the registry, NOT a
 *  free-form label. Typing `assertEgressHost`'s `connector` to this catches a
 *  miskeyed wiring site at COMPILE time (an untyped typo would otherwise silently
 *  fail-closed and block the connector at runtime). A new connector is added here
 *  and to EGRESS_DESTINATIONS together. */
export type ConnectorId =
  | "github"
  | "notion"
  | "line"
  | "telegram"
  | "discord"
  | "slack"
  | "mattermost"
  | "google-workspace"
  | "web-fetch";

export interface EgressDestination {
  /** The connector id (matches the `*_api_failed` connector + the registry key). */
  readonly connector: ConnectorId;
  /** The external host(s) SafeSpace connects to for this connector (lowercased). */
  readonly hosts: readonly string[];
  readonly enforcement: EgressEnforcement;
  /** A one-line operator-facing note (esp. WHY a `declared` host can't be enforced). */
  readonly note?: string;
}

/** The registry. ENFORCED hosts are runtime-checked at the connector's fetch
 *  chokepoint; DECLARED hosts are audit-listed only (SafeSpace can't gate them). */
export const EGRESS_DESTINATIONS: readonly EgressDestination[] = [
  { connector: "github", hosts: ["api.github.com"], enforcement: "enforced" },
  { connector: "notion", hosts: ["api.notion.com"], enforcement: "enforced" },
  { connector: "line", hosts: ["api.line.me"], enforcement: "enforced" },
  { connector: "telegram", hosts: ["api.telegram.org"], enforcement: "enforced" },
  { connector: "discord", hosts: ["discord.com"], enforcement: "enforced" },
  { connector: "slack", hosts: ["slack.com"], enforcement: "enforced" },
  {
    connector: "mattermost",
    // Self-hosted: the real host is your SAFESPACE_MATTERMOST_SERVER_URL. This static
    // entry can't hold the per-install value; assertEgressHost pins the live configured
    // host at runtime (enforcement: "configured" — enforced, just not a fixed constant).
    hosts: ["(configured: SAFESPACE_MATTERMOST_SERVER_URL)"],
    enforcement: "configured",
    note: "self-hosted — egress is pinned to your configured server host at runtime; unset → all Mattermost egress blocked",
  },
  {
    connector: "google-workspace",
    // `*.googleapis.com` is a DOCUMENTATION glob (this entry is `declared` → never
    // enters the enforced match set); it is not evaluated as a wildcard anywhere.
    hosts: ["oauth2.googleapis.com", "accounts.google.com", "*.googleapis.com"],
    enforcement: "declared",
    note: "the googleapis SDK owns its gaxios socket — not interceptable at this layer without forking the SDK",
  },
  {
    connector: "web-fetch",
    hosts: ["(dynamic — user-supplied URL)"],
    enforcement: "declared",
    note: "intentionally dynamic; gated per-call by the SSRF url-gate (private-IP block + IP-pin), not this fixed registry",
  },
];

/** The enforced host set, indexed by connector (built once). */
const ENFORCED_HOSTS_BY_CONNECTOR: ReadonlyMap<string, ReadonlySet<string>> = new Map(
  EGRESS_DESTINATIONS.filter((d) => d.enforcement === "enforced").map((d) => [
    d.connector,
    new Set(d.hosts.map((h) => h.toLowerCase())),
  ]),
);

/** Backstop assertion for a SafeSpace-OWNED outbound fetch: the final destination
 *  `hostname` MUST be a registered enforced host for `connector`. Throws -32047
 *  otherwise — echoing ONLY the hostname (NEVER the full URL, which can hold a token,
 *  e.g. Telegram's bot token in the path; `new URL(...).hostname` strips path/query).
 *  No-op for a registered host (the normal path).
 *
 *  Catches: a connector handler bug that builds the wrong host, and a path-injection
 *  that escapes the host (`https://api.github.com@evil.com/…` → hostname `evil.com`).
 *  Pass the already-parsed `URL.hostname` (the caller has the URL anyway). */
export function assertEgressHost(hostname: string, connector: ConnectorId): void {
  const host = hostname.toLowerCase();
  // v1.107 — the "configured" connector(s): the enforced host is read LIVE from config
  // (not the fixed map). mattermostConfiguredHost() is null when the server URL is unset
  // or invalid → fail-closed (every host mismatches → blocked). The path-injection
  // backstop is preserved: the request host must equal the owner's configured host.
  if (connector === "mattermost") {
    const configured = mattermostConfiguredHost();
    if (configured === null || configured !== host) {
      throw new MCPError("egress_destination_blocked", { host });
    }
    return;
  }
  const allowed = ENFORCED_HOSTS_BY_CONNECTOR.get(connector);
  if (allowed === undefined || !allowed.has(host)) {
    // Echo the NORMALIZED (lowercased) host — consistent with the registry, and a
    // fixed known value (never a token: callers pass `new URL(...).hostname`, which
    // strips any token-bearing path/userinfo).
    throw new MCPError("egress_destination_blocked", { host });
  }
}
