// The MCP server DEFINITION — `createMcpServer()` builds a fresh `Server` with
// the tier-filtered `tools/list` + the `tools/call` dispatch. Kept apart from
// proxy.ts so tests can import it without triggering the startup side effects.
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import {
  auditEnd,
  hashUnknownToolName,
  UNKNOWN_TOOL_LABEL,
  type RefusalReason,
} from "./audit";
import { MCPError } from "./errors";
import { tierSatisfies, type Tier } from "./tier";
import { connectorSelectionKey, isConnectorEnabled } from "./policy/connector-toggle";
import {
  EnvOperatorResolver,
  type OperatorResolver,
} from "./identity/operator-context";
import type { ToolDef } from "./tools/registry/types";
import { IMPLEMENTED_TOOLS, TOOL_REGISTRY } from "./tools/registry";
import { sourceFor } from "./tools/source";
import { dispatchTool, hashArgs } from "./tools/dispatch";
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

/** Refuse a call at the dispatch boundary with the uniform `tool_not_found`, and
 *  write its terminal audit row (these refusals never reach a choke point, so
 *  without this they left no row). The reason lives on the row only; the client
 *  response is identical for all three reasons. A name not in the registry is
 *  caller-supplied, so it is logged as an HMAC, never raw. */
async function refuseToolNotFound(
  name: string,
  args: Record<string, unknown>,
  reason: RefusalReason,
  def: ToolDef | undefined,
): Promise<ReturnType<typeof renderMcpError>> {
  const err = new MCPError("tool_not_found", { name });
  // A registry name is trusted (logged raw); anything else came from the caller.
  const known = def !== undefined;
  // Awaited (auditEnd never throws) so the row is on disk before the reply.
  await auditEnd({
    tool: known ? name : UNKNOWN_TOOL_LABEL,
    source: known ? sourceFor(def).id : "unknown",
    email: null,
    argsHash: hashArgs(args),
    status: "error",
    durationMs: 0,
    errorCode: err.code,
    refusalReason: reason,
    toolNameHmac: known ? undefined : await hashUnknownToolName(name).catch(() => undefined),
  });
  return renderMcpError(err);
}

/** Build a fresh MCP `Server` with SafeSpace's tier-filtered tool surface +
 *  envelope dispatch. Stateless across calls — all per-call state
 *  (tier, account, audit) is resolved inside the handlers / choke points. */
export function createMcpServer(
  // Env-backed by default; `resolve()` runs PER request (never a snapshot), so a
  // long-lived stdio process honors env changes. Tests inject a fixed resolver.
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
    // Own keys only: the registry is a plain object, so `constructor` / `__proto__`
    // / `toString` would otherwise resolve to inherited properties.
    const def = Object.hasOwn(TOOL_REGISTRY, req.params.name)
      ? TOOL_REGISTRY[req.params.name]
      : undefined;
    // Reject tools not in IMPLEMENTED_TOOLS BEFORE entering withToolContext —
    // otherwise a speculative tools/call (e.g. from a cached tool list) would
    // burn an accounts.json read + token refresh just to reach the error.
    // Resolved once so the tier checks below read one value. The resolver does not
    // throw (env-backed).
    const op = operator.resolve();
    const args = (req.params.arguments ?? {}) as Record<string, unknown>;
    if (!def || !IMPLEMENTED_TOOLS.has(req.params.name)) {
      return refuseToolNotFound(req.params.name, args, "unknown", def);
    }

    // v2.0 defense-in-depth: even if Claude has the tool cached from a higher
    // tier earlier in the session, the call must still match current tier.
    // Surface `tool_not_found` (same shape as unknown tool) rather than a
    // distinct error code — semantically the tool *is* not available right
    // now, and exposing a "tier insufficient" hint would leak tier state to
    // a potentially adversarial caller.
    if (!tierSatisfies(op.tier, def.min_tier)) {
      return refuseToolNotFound(req.params.name, args, "tier_hidden", def);
    }

    // v1.127 — the SECOND exposure axis (policy/connector-toggle.ts), re-checked
    // here for exactly the reason the tier re-check above exists: the tools/list
    // filter is ADVISORY to the client. A caller holding a tool list cached from a
    // wider configuration — or an injected agent that simply knows the tool names —
    // can call anything. Without this the axis would be cosmetic. Collapses into the
    // SAME `tool_not_found` as the unknown-tool and tier-blocked branches, so it
    // adds no distinguishability (no config-state oracle).
    if (!isConnectorEnabled(def)) {
      return refuseToolNotFound(req.params.name, args, "connector_hidden", def);
    }

    try {
      const result = await dispatchTool(req.params.name, args, def, op);
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
