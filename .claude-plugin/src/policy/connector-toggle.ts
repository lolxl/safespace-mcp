// v1.127 — `SAFESPACE_CONNECTORS`: the SECOND EXPOSURE AXIS.
//
// WHAT IT IS (read this before "fixing" anything below). SafeSpace already has one
// exposure axis: the tier (`tier.ts`), which filters `tools/list` and is re-checked
// at `tools/call`. This adds an ORTHOGONAL, PROCESS-GLOBAL second axis — a set of
// connector tokens — enforced at the SAME two choke points. The two INTERSECT: a
// tool ships only if it passes BOTH. Narrowing-only, by construction — listing a
// token can never carry a tool past its `min_tier`.
//
// It is NOT merely a display filter, and the honest framing matters: because
// `server.ts` re-checks it at `tools/call`, an operator setting
// `SAFESPACE_CONNECTORS=gmail` really does prevent the agent from invoking a GitHub
// tool. Operators WILL rely on that. So the non-coverage must be stated as loudly:
//
//   - `safespace exec` (cli.ts) resolves TOOL_REGISTRY directly and calls
//     `withToolContext` — it passes neither the tier gate nor this one. That is
//     deliberate: a local operator at their own shell is not the threat model, and
//     gating `exec` would obstruct the operator's own recovery path.
//   - It does NOT reduce the OAuth scope union. `computeScopeUnion`
//     (tools/registry/index.ts) unions `requiredScopes` over the WHOLE registry, so
//     `SAFESPACE_CONNECTORS=gmail` still consents to Drive / YouTube / Sheets / …
//     The token this deployment holds is unchanged; only the agent's reach through
//     SafeSpace is narrowed. Feeding the connector set into the scope union is a
//     separate, larger change (deliberately deferred — see docs/CARRY-FORWARD.md).
//   - It does NOT stop the INBOUND WEBHOOK LISTENER. `proxy.ts` starts the public
//     `node:http` listener on `webhookEnabled()` (SAFESPACE_WEBHOOK_PORT) alone.
//     Omitting the `webhook` token hides `inbox_read` from the agent and refuses it
//     at tools/call — but SafeSpace still binds the socket, still accepts signed
//     Slack/LINE callbacks, and still persists that third-party content to the
//     durable inbox. This is the widest of the four gaps because it is SafeSpace's
//     ONLY unsolicited public surface: "the webhook connector is off" is FALSE. To
//     actually stop it, unset SAFESPACE_WEBHOOK_PORT. (Not an exfil path — the
//     agent cannot read the inbox — but it is a listening socket the operator
//     believes is closed.)
//   - It does NOT stop the CONTACTS connector being exercised INTERNALLY. The
//     People-API name→email lookup is a Source strategy (`resolveRecipients`,
//     tools/source.ts) and is also called directly by calendar.ts; none consult
//     this axis. With `SAFESPACE_CONNECTORS=gmail,calendar` plus the separate
//     `SAFESPACE_RECIPIENT_ALLOW_CONTACTS=true` opt-in, a name-shaped recipient
//     still queries the address book. The 5 `contacts_*` TOOLS are correctly
//     hidden and blocked, so the agent cannot browse contacts; bounded further by
//     that opt-in defaulting off.
//
// The rule behind all four: this axis gates the AGENT'S TOOL SURFACE. It does not
// gate the operator's own CLI, the OAuth consent breadth, inbound listeners, or
// internal helper calls between connectors. Anything outside `server.ts`'s two
// request handlers is out of its reach BY CONSTRUCTION, not by oversight.
//
// The motivating cost is context, not security: a non-lazy MCP client (Codex, Grok,
// Antigravity, Cursor — docs/CLIENTS.md) pays the full ~52k tokens of tool schemas
// on every session, and google-workspace alone is ~39k of it. Claude Code defers
// tool schemas and does not pay this.
//
// ── TWO DELIBERATE DEVIATIONS FROM REPO CONVENTION ────────────────────────────
//
// 1. UNSET = ALLOW-ALL, not deny-by-default. Every other env allowlist here
//    (recipient / github-write / youtube-comment / x-post / fs-roots …) is a
//    default-deny EGRESS gate, where "unset" failing closed costs at most some
//    blocked sends. This axis fails the other way: unset-means-deny would silently
//    strip all 130 tools from every existing install on upgrade. `tier.ts` names
//    that direction outright — "silent capability loss is the only outcome with an
//    actually dangerous failure mode". Do not "harmonize" this to deny-default.
//
// 2. NO `_EXTRA` OVERLAY. The family-5 `X` + `X_EXTRA` pairs exist because those are
//    persistent security policy in `.env` that occasionally needs a shell-only,
//    non-persistent WIDENING for one session. This axis inverts both properties: it
//    is per-client config (each client's `mcpServers` entry carries its own `env`
//    block), and a "widening overlay" on a narrowing intersection is incoherent.
//
// ── HOW A TOOL MAPS TO A TOKEN ────────────────────────────────────────────────
//
// Non-google tools: the token IS `ToolDef.source`. Google tools (which omit
// `source`) map by NAME PREFIX to one of 10 sub-services — because google-workspace
// is a single `source` worth ~39k tokens, and an all-or-nothing switch on the
// flagship connector is a useless knob. That prefix contract is IMPLICIT in 85 tool
// names, so it is enforced two ways:
//   - at test time, `connector-toggle.test.ts` asserts EVERY implemented tool maps
//     to exactly one token, and that the constants below equal the live `SOURCES`
//     registry — adding `chat_send` with no token turns the suite red;
//   - at runtime, an UNMAPPED tool is treated as ALWAYS ENABLED (never filtered).
//     Fail-safe, so a mapping gap can never make a tool silently unreachable in
//     every configuration — the failure surfaces in CI, not in an operator's log.
// New connector? Add its token here and to the docs/ADDING-A-CONNECTOR.md checklist.
import { ENV_CONNECTORS } from "../config";
import type { ToolDef } from "../tools/registry/types";

/** The 10 google-workspace sub-services, keyed by tool-name prefix. Kept as a
 *  literal (not derived) so this module stays import-cheap and cycle-free; the
 *  sentinel test binds it to the live registry. */
export const GOOGLE_SUBSERVICE_TOKENS: readonly string[] = [
  "calendar",
  "contacts",
  "docs",
  "drive",
  "forms",
  "gmail",
  "sheets",
  "slides",
  "tasks",
  "youtube",
];

/** The non-google connector tokens — one per `SOURCES` entry in tools/source.ts
 *  other than google-workspace. The sentinel test asserts set-equality with it. */
export const NON_GOOGLE_CONNECTOR_TOKENS: readonly string[] = [
  "discord",
  "fs-read",
  "github",
  "line",
  "mattermost",
  "notion",
  "slack",
  "telegram",
  "web-fetch",
  "webhook",
  "x",
];

/** The google-workspace umbrella token — an ALIAS that expands to all 10
 *  sub-services. Accepted on input, never a per-tool token. */
export const GOOGLE_ALIAS = "google-workspace";

/** Every token an operator may write in `SAFESPACE_CONNECTORS`, sorted — this is
 *  the list the bootstrap error message prints. */
export const CONNECTOR_TOKENS: readonly string[] = [
  ...GOOGLE_SUBSERVICE_TOKENS,
  ...NON_GOOGLE_CONNECTOR_TOKENS,
  GOOGLE_ALIAS,
].sort();

const GOOGLE_SUBSERVICE_SET: ReadonlySet<string> = new Set(GOOGLE_SUBSERVICE_TOKENS);
const VALID_TOKENS: ReadonlySet<string> = new Set(CONNECTOR_TOKENS);

/** Normalize one operator-written token: trim, lowercase, and fold `_` → `-` so
 *  `web_fetch` / `fs_read` (the shapes a user reads off a TOOL NAME) are accepted
 *  as the hyphenated connector ids they actually are. */
function normalizeToken(raw: string): string {
  return raw.trim().toLowerCase().replace(/_/g, "-");
}

/** The token a tool belongs to, or `undefined` when the tool maps to none (a new
 *  google service whose prefix is not yet listed). `undefined` means ALWAYS
 *  ENABLED at the choke points — see the fail-safe note in the header. */
export function connectorTokenFor(def: Pick<ToolDef, "name" | "source">): string | undefined {
  if (def.source !== undefined && def.source !== GOOGLE_ALIAS) return def.source;
  // google-workspace (the `source`-omitted default): map by name prefix.
  const prefix = def.name.split("_")[0] ?? "";
  return GOOGLE_SUBSERVICE_SET.has(prefix) ? prefix : undefined;
}

export interface ParsedConnectors {
  /** Enabled per-tool tokens, alias already expanded. */
  tokens: ReadonlySet<string>;
  /** Operator-written tokens that match nothing — the bootstrap refusal reason. */
  unknown: readonly string[];
}

/** Parse a raw `SAFESPACE_CONNECTORS` value. Pure — no env read, no I/O. */
export function parseConnectors(raw: string): ParsedConnectors {
  const tokens = new Set<string>();
  const unknown: string[] = [];
  for (const part of raw.split(",")) {
    const tok = normalizeToken(part);
    if (tok === "") continue; // tolerate trailing / doubled commas
    if (!VALID_TOKENS.has(tok)) {
      unknown.push(tok);
      continue;
    }
    if (tok === GOOGLE_ALIAS) {
      for (const s of GOOGLE_SUBSERVICE_TOKENS) tokens.add(s);
    } else {
      tokens.add(tok);
    }
  }
  return { tokens, unknown };
}

/** The enabled token set, or `null` for "unset → every connector on" (the default,
 *  byte-identical to v1.126).
 *
 *  Reads env on EVERY call, exactly like `currentTier()`. This is deliberate and
 *  load-bearing: `bun test` runs all test files in ONE process with ONE module
 *  cache, so a module-load `const` here would let whichever test file imports
 *  `server.ts` first freeze the connector config for the entire suite — green
 *  locally, order-dependent in CI. `server.ts` keeps its projection memoized by
 *  keying the cache on `connectorSelectionKey()`.
 *
 *  Unknown tokens are IGNORED here rather than thrown: `validateConnectors()`
 *  already refused to start the process on them, and ignoring can only ever
 *  narrow — never over-expose. */
export function resolveEnabledConnectors(): ReadonlySet<string> | null {
  const raw = process.env[ENV_CONNECTORS];
  if (raw === undefined || raw.trim() === "") return null;
  return parseConnectors(raw).tokens;
}

/** True if this tool's connector is enabled. Unset env → always true. */
export function isConnectorEnabled(def: Pick<ToolDef, "name" | "source">): boolean {
  const enabled = resolveEnabledConnectors();
  if (enabled === null) return true;
  const token = connectorTokenFor(def);
  if (token === undefined) return true; // fail-safe: unmapped tool is never hidden
  return enabled.has(token);
}

/** A stable cache key for the current selection — `"*"` when unset. Sorted so two
 *  env spellings of the same set share one memoized projection. */
export function connectorSelectionKey(): string {
  const enabled = resolveEnabledConnectors();
  return enabled === null ? "*" : [...enabled].sort().join(",");
}

/** Render the unrecognized tokens for the refusal message: DEDUPED and length-
 *  CAPPED. The refusal echoes operator-written env content to stderr, which the MCP
 *  client persists in its server log — a different retention domain than `.env`. An
 *  operator who fat-fingers a long paste (or a secret) into SAFESPACE_CONNECTORS
 *  should not have the whole value copied there. Enough survives to identify the
 *  typo, which is the message's only job. */
function summarizeUnknown(unknown: readonly string[]): string {
  const deduped = [...new Set(unknown)];
  const shown = deduped.slice(0, 5).map((t) => (t.length > 40 ? `${t.slice(0, 40)}…` : t));
  const rest = deduped.length - shown.length;
  return rest > 0 ? `${shown.join(", ")} (+${rest} more)` : shown.join(", ");
}

/** BOOTSTRAP GUARD (fail-loud). Throws on any unrecognized token, naming the
 *  offenders and printing every valid token — the error message IS the doc, the
 *  same posture as `tier.ts`'s LEGACY_FLAG_ERROR.
 *
 *  Call this from `proxy.ts`'s startup sequence, NEVER at module evaluation: a
 *  throw during `import` surfaces to an MCP client as a bare "server disconnected"
 *  with no message, and would make `server.ts` unimportable by any test that has
 *  not pre-set the env. */
export function validateConnectors(): void {
  const raw = process.env[ENV_CONNECTORS];
  if (raw === undefined) return;
  if (raw.trim() === "") {
    // The ONE input where this axis fails OPEN: `SAFESPACE_CONNECTORS=" "` (a
    // compose file or heredoc whose variable failed to interpolate) is
    // indistinguishable from unset and yields the full surface. Refusing to start
    // would be the dangerous direction (deviation 1 above), so warn instead of
    // throwing — the operator gets told, and the safe default still holds.
    console.error(
      `[safespace] ${ENV_CONNECTORS} is set but empty — treating as unset (every ` +
        `connector exposed). If you meant to restrict the tool surface, name at ` +
        `least one connector token.`,
    );
    return;
  }
  const { tokens, unknown } = parseConnectors(raw);
  if (unknown.length > 0) {
    throw new Error(
      `${ENV_CONNECTORS} contains unrecognized connector token(s): ${summarizeUnknown(unknown)}. ` +
        `Valid tokens: ${CONNECTOR_TOKENS.join(", ")}. ` +
        `("${GOOGLE_ALIAS}" is an alias for all 10 Google sub-services; unset the ` +
        `variable entirely to expose every connector.)`,
    );
  }
  if (tokens.size === 0) {
    throw new Error(
      `${ENV_CONNECTORS} is set but selects no connector. Unset it to expose every ` +
        `connector, or name at least one of: ${CONNECTOR_TOKENS.join(", ")}.`,
    );
  }
}

/** One-line `doctor` value describing the axis. Token names are fixed public
 *  identifiers (never PII), so echoing them is safe — unlike the egress rows,
 *  which carry counts only. */
export function connectorPostureValue(): string {
  const enabled = resolveEnabledConnectors();
  if (enabled === null) {
    return `all connectors exposed (${ENV_CONNECTORS} unset — the default)`;
  }
  return `restricted to ${enabled.size} of ${CONNECTOR_TOKENS.length - 1}: ${[...enabled].sort().join(", ")}`;
}
