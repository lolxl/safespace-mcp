// The MCP server DEFINITION — `createMcpServer()` builds a fresh `Server` with
// the tier-filtered `tools/list` + the `tools/call` dispatch. Extracted from
// proxy.ts (v1.73, Model B PR-1) so it can be:
//   - connected to a StdioServerTransport once (stdio mode = Model A), or
//   - instantiated PER SESSION by the Streamable HTTP transport (transport/http.ts),
//   - imported by tests WITHOUT triggering proxy.ts's startup side effects.
//
// The handlers are VERBATIM from the pre-v1.73 proxy.ts — moving them into a
// factory changes no behavior (the stdio path builds one server exactly as before).
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { MCPError } from "./errors";
import { tierSatisfies, type Tier } from "./tier";
import { connectorSelectionKey, isConnectorEnabled } from "./policy/connector-toggle";
import { EnvOperatorResolver, type OperatorResolver } from "./identity/operator-context";
import { IMPLEMENTED_TOOLS, TOOL_REGISTRY } from "./tools/registry";
import { sourceFor } from "./tools/source";
import { withToolContext } from "./tools/with-context";
import { withNonOAuthContext } from "./tools/with-nonoauth-context";
import type { CrossAccountSentinel } from "./tools/types";
// Derive SERVER_VERSION from package.json — single-source-of-truth, kills the
// drift class (issue #115). resolveJsonModule + Bun's native JSON import handle
// this at compile + runtime. (proxy/server-version regression-lock: server.test.ts.)
import pkg from "../package.json" with { type: "json" };

const SERVER_NAME = "safespace-mcp";
const SERVER_VERSION = pkg.version;

// Cold-path: the tools/list projection is a PURE function of (tier, connector
// selection), yet the handler re-walked all of TOOL_REGISTRY + re-allocated the
// projected array on EVERY request (wasteful under HTTP polling). Memoize the
// projection — iterating Object.values in registry order so the on-wire
// TOOL_ORDER stays byte-identical — and the handler becomes a keyed lookup.
//
// v1.127: the cache is keyed on tier AND `connectorSelectionKey()` rather than
// precomputed for the 3 tiers at module load. That is deliberate. Reading
// SAFESPACE_CONNECTORS once at module load would be correct in production (env is
// fixed for the process lifetime) but WRONG under test: `bun test` runs every test
// file in one process with one module cache, so whichever file imported this module
// first would freeze the connector selection for the whole suite. Both inputs are
// therefore resolved per request — the same freshness contract tier already had —
// and only the projection is memoized. Treat the cached arrays as read-only; the
// SDK serializes them without mutation (same shared-reference convention as the
// inputSchema objects, which were already shared via def.inputSchema).
const IMPLEMENTED_DEFS = Object.values(TOOL_REGISTRY).filter((def) =>
  IMPLEMENTED_TOOLS.has(def.name),
);
const TOOLS_CACHE = new Map<
  string,
  Array<{ name: string; description: string; inputSchema: Record<string, unknown> }>
>();

function toolsFor(tier: Tier): Array<{
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
}> {
  const key = `${tier}|${connectorSelectionKey()}`;
  let tools = TOOLS_CACHE.get(key);
  if (tools === undefined) {
    tools = IMPLEMENTED_DEFS.filter(
      (def) => tierSatisfies(tier, def.min_tier) && isConnectorEnabled(def),
    ).map((def) => ({
      name: def.name,
      description: def.description,
      inputSchema: def.inputSchema,
    }));
    TOOLS_CACHE.set(key, tools);
  }
  return tools;
}

function renderMcpError(err: MCPError): {
  content: Array<{ type: "text"; text: string }>;
  isError: true;
} {
  const json = err.toJsonRpc();
  const recovery = typeof json.data.recovery === "string" ? json.data.recovery : "";
  return {
    content: [{ type: "text", text: `Error (${json.message}): ${recovery}` }],
    isError: true,
  };
}

/** Build a fresh MCP `Server` with SafeSpace's tier-filtered tool surface +
 *  envelope dispatch. Called ONCE for stdio (Model A) and PER SESSION for the
 *  Streamable HTTP transport (v1.73). Stateless across calls — all per-call state
 *  (tier, account, audit) is resolved inside the handlers / choke points. */
export function createMcpServer(
  // v1.74 PR-2a — the operator-identity resolver for THIS server instance.
  // Default = Model A (env-backed); `resolve()` is called PER request (never
  // snapshot) so a long-lived stdio process honors env exactly as before. The
  // Streamable HTTP transport (PR-2b) will construct one server PER SESSION with a
  // ConnectionOperatorResolver bound to that session's verified connection — the
  // single seam that makes the server multi-operator without any handler change.
  operator: OperatorResolver = new EnvOperatorResolver(),
): Server {
  const server = new Server(
    { name: SERVER_NAME, version: SERVER_VERSION },
    { capabilities: { tools: {} } },
  );

  // v2.0: tools/list filtered by current tier. Claude never sees tools above
  // the current tier, so it never tries to call them — this is the structural
  // defense replacing v1.x's three kill switches. Per-tool runtime tier check
  // in CallTool below is defense-in-depth against speculative calls from a
  // cached tool list (where Claude saw the tool at a higher tier earlier in
  // the session, then the operator lowered the tier without restarting).
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    // v1.74 PR-2a — filter by THIS operator's tier (was the process-global
    // currentTier()). Model A default re-reads env per request → byte-identical.
    // The tier resolve stays per-request; only the projection is memoized
    // (keyed on tier + connector selection), so freshness is unchanged.
    const tier = operator.resolve().tier;
    return { tools: toolsFor(tier) };
  });

  server.setRequestHandler(CallToolRequestSchema, async (req) => {
    const def = TOOL_REGISTRY[req.params.name];
    // Reject tools not in IMPLEMENTED_TOOLS BEFORE entering withToolContext —
    // otherwise a speculative tools/call (e.g. from a cached tool list) would
    // burn an accounts.json read + token refresh just to reach the error.
    if (!def || !IMPLEMENTED_TOOLS.has(req.params.name)) {
      return renderMcpError(new MCPError("tool_not_found", { name: req.params.name }));
    }

    // v2.0 defense-in-depth: even if Claude has the tool cached from a higher
    // tier earlier in the session, the call must still match current tier.
    // Surface `tool_not_found` (same shape as unknown tool) rather than a
    // distinct error code — semantically the tool *is* not available right
    // now, and exposing a "tier insufficient" hint would leak tier state to
    // a potentially adversarial caller.
    // v1.74 PR-2a — resolve the operator context ONCE per call (replaces the
    // process-global currentTier() here AND inside the choke points; threaded into
    // both the tier re-check and the dispatch below). Model A default re-reads env
    // per call → byte-identical; PR-2b supplies a per-session resolver.
    const op = operator.resolve();
    if (!tierSatisfies(op.tier, def.min_tier)) {
      return renderMcpError(new MCPError("tool_not_found", { name: req.params.name }));
    }

    // v1.127 — the SECOND exposure axis (policy/connector-toggle.ts), re-checked
    // here for exactly the reason the tier re-check above exists: the tools/list
    // filter is ADVISORY to the client. A caller holding a tool list cached from a
    // wider configuration — or an injected agent that simply knows the tool names —
    // can call anything. Without this the axis would be cosmetic. Collapses into the
    // SAME `tool_not_found` as the unknown-tool and tier-blocked branches, so it
    // adds no distinguishability (no config-state oracle).
    if (!isConnectorEnabled(def)) {
      return renderMcpError(new MCPError("tool_not_found", { name: req.params.name }));
    }

    try {
      let result: unknown;
      if (def.cross_account) {
        // v1.14 Phase 1: cross-account tools bypass `withToolContext` (they
        // don't have a single resolved account — they fan out across all
        // consented accounts via `withAllAccounts` inside the handler). The
        // handler shim ignores `ctx`; we pass a sentinel so the handler
        // signature remains uniform. Audit / sanitize / refresh are owned
        // by `withAllAccounts` per design §5.
        const SENTINEL_CTX: CrossAccountSentinel = Object.freeze({
          // v1.64 Phase B (B6 — D12): the cross-account handler shim DROPS `ctx`
          // entirely (the `_all` handlers take `(args, deps)` and `withAllAccounts`
          // owns per-account resolve / refresh / scope / sanitize / audit), so this
          // credential is never read. B2 oauth-wrapped a `<cross-account>` placeholder
          // here; B6 makes it the HONEST `{kind:"none"}` — the path has no single
          // resolved OAuth account. (`requireOAuth(ctx)` would throw on this, by
          // design: no google-workspace single-account handler ever runs on the
          // sentinel — the shim routes straight to `withAllAccounts`.)
          credential: { kind: "none" as const },
          // v1.38 BLOCKER 3: ToolContext.tier is now required. Cross-account tools
          // are all min_tier:read and branch on tier nowhere, but the field must be
          // present; carry the resolved operator tier (v1.74 PR-2a: op.tier, ===
          // currentTier() under Model A — the same source the proxy gates above
          // used to admit this call).
          tier: op.tier,
          // v1.64 Phase B (B1): ToolContext.audit is now required. Cross-account
          // tools record NO per-account meta through `ctx` — `withAllAccounts`
          // owns the per-account audit rows + the outer aggregate (design §5) — so
          // the sentinel carries a NO-OP sink.
          audit: { record() {} },
          // v1.74 PR-2c — the per-operator identity the `_all` fan-out needs, riding
          // the widened sentinel (the shim drops `ctx`, so this is the only channel):
          // the operator id for the inner audit rows + the allowedAccounts confinement
          // set (both null under Model A → byte-identical).
          operator: op.operatorId,
          allowedAccounts: op.allowedAccounts,
        });
        result = await def.handler(
          SENTINEL_CTX,
          (req.params.arguments ?? {}) as Record<string, unknown>,
        );
      } else if (sourceFor(def).authModel !== "oauth") {
        // v1.65 Phase C — NON-OAUTH connectors: keyless (web-fetch, authModel
        // "none") + service-token (LINE OA v1.66, Telegram Bot v1.68; authModel
        // "service-token"). This
        // single dispatch-site read of the Source's authModel (beside the
        // `def.cross_account` route above) picks the non-OAuth choke point: no Google
        // account resolution, no scope check, no token refresh, no 401 retry. The
        // choke point dispatches credential resolution through the source's
        // `resolveCredential`/`authorize` strategies polymorphically (v1.66). The
        // OAuth `withToolContext` path is unchanged.
        result = await withNonOAuthContext(
          req.params.name,
          (req.params.arguments ?? {}) as Record<string, unknown>,
          def.handler,
          op,
        );
      } else {
        result = await withToolContext(
          req.params.name,
          (req.params.arguments ?? {}) as Record<string, unknown>,
          def.handler,
          // `op` is the trailing param; deps/opts take their {} defaults here (the
          // production path injects neither). The two {} placeholders are the price
          // of a trailing-default seam — code-rev MEDIUM: revisit the signature
          // ergonomics in PR-2b when per-session resolvers add more call sites
          // (fold into a single options object; NOT into `opts`, which is reserved
          // for behavior flags like skipSanitize, not identity).
          {},
          {},
          op,
        );
      }
      return {
        content: [{ type: "text", text: JSON.stringify(result, null, 2) }],
      };
    } catch (err) {
      if (err instanceof MCPError) return renderMcpError(err);
      throw err;
    }
  });

  return server;
}
