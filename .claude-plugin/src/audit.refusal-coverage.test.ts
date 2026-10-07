// Every MCP tool call leaves exactly one terminal audit row — including the calls
// that never reach a choke point (dispatch-boundary tool_not_found refusals) and
// the ones that fail before a choke point's audited region (OAuth pre-flight,
// cross-account pre-fan-out).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { UNKNOWN_TOOL_LABEL } from "./audit";
import { MCPError } from "./errors";
import type { OperatorContext, OperatorResolver } from "./identity/operator-context";
import { createMcpServer } from "./server";
import type { Tier } from "./tier";
import { withAllAccounts } from "./tools/with-all-accounts";
import { _resetLastUsedForTests, withToolContext } from "./tools/with-context";

const SAVED = ["SAFESPACE_CONFIG_DIR", "SAFESPACE_CONNECTORS", "SAFESPACE_TIER"] as const;
let saved: Record<string, string | undefined> = {};
let tmpDir = "";

beforeEach(async () => {
  saved = Object.fromEntries(SAVED.map((k) => [k, process.env[k]]));
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-refusal-audit-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  delete process.env.SAFESPACE_CONNECTORS;
  _resetLastUsedForTests();
});

afterEach(async () => {
  for (const k of SAVED) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  _resetLastUsedForTests();
  await fs.rm(tmpDir, { recursive: true, force: true });
});

async function auditRows(): Promise<Array<Record<string, unknown>>> {
  // auditEnd is fire-and-forget; let the append flush.
  await new Promise((r) => setTimeout(r, 30));
  let content = "";
  try {
    content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
  } catch {
    return [];
  }
  return content.split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));
}

function resolverAt(tier: Tier): OperatorResolver {
  const op: OperatorContext = { tier };
  return { resolve: () => op };
}

async function callTool(
  resolver: OperatorResolver,
  name: string,
  args: Record<string, unknown> = {},
): Promise<{ isError?: boolean; content: unknown }> {
  const server = createMcpServer(resolver);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "refusal-audit-test", version: "1.0.0" });
  await client.connect(clientTransport);
  try {
    return (await client.callTool({ name, arguments: args })) as {
      isError?: boolean;
      content: unknown;
    };
  } finally {
    await client.close();
  }
}

const TOOL_NOT_FOUND = new MCPError("tool_not_found").code;

describe("dispatch-boundary refusals write one terminal row", () => {
  test("unknown tool: row is labelled, the caller-supplied name is HMAC'd and never written raw", async () => {
    const secretLookingName = "probe_sk-live-THIS-MUST-NOT-BE-LOGGED";
    const res = await callTool(resolverAt("share"), secretLookingName);
    expect(res.isError).toBe(true);

    const rows = await auditRows();
    expect(rows).toHaveLength(1);
    const row = rows[0]!;
    expect(row.tool).toBe(UNKNOWN_TOOL_LABEL);
    expect(row.status).toBe("error");
    expect(row.error_code).toBe(TOOL_NOT_FOUND);
    expect(row.refusal_reason).toBe("unknown");
    expect(row.tool_name_hmac).toMatch(/^[0-9a-f]{64}$/);
    expect(row.account).toBeNull();

    const raw = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(raw).not.toContain("THIS-MUST-NOT-BE-LOGGED");
  });

  test("names inherited from Object.prototype are unknown, not registry tools", async () => {
    for (const name of ["constructor", "__proto__", "toString", "hasOwnProperty"]) {
      await callTool(resolverAt("share"), name);
    }
    const rows = await auditRows();
    expect(rows).toHaveLength(4);
    for (const row of rows) {
      expect(row.tool).toBe(UNKNOWN_TOOL_LABEL);
      expect(row.source).toBe("unknown");
      expect(row.tool_name_hmac).toMatch(/^[0-9a-f]{64}$/);
    }
  });

  test("tier-hidden tool: registry name logged raw with reason tier_hidden", async () => {
    await callTool(resolverAt("read"), "gmail_send", { to: "x@example.com" });
    const rows = await auditRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tool).toBe("gmail_send");
    expect(rows[0]!.refusal_reason).toBe("tier_hidden");
    expect(rows[0]!.error_code).toBe(TOOL_NOT_FOUND);
    expect(rows[0]!.tool_name_hmac).toBeUndefined();
  });

  test("connector-hidden tool: reason connector_hidden", async () => {
    process.env.SAFESPACE_CONNECTORS = "github";
    await callTool(resolverAt("share"), "gmail_search", { query: "x" });
    const rows = await auditRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tool).toBe("gmail_search");
    expect(rows[0]!.refusal_reason).toBe("connector_hidden");
  });

  test("the client sees the same response for all three reasons (no tier/connector oracle)", async () => {
    const unknown = await callTool(resolverAt("read"), "no_such_tool");
    const tierHidden = await callTool(resolverAt("read"), "gmail_send");
    process.env.SAFESPACE_CONNECTORS = "github";
    const connectorHidden = await callTool(resolverAt("share"), "gmail_search");
    expect(tierHidden).toEqual(unknown);
    expect(connectorHidden).toEqual(unknown);
    // One row per refusal; also lets the appends land before the tmp dir is removed.
    expect(await auditRows()).toHaveLength(3);
  });
});

describe("OAuth pre-flight failure writes one terminal row", () => {
  test("account_not_found before the audited try → exactly one error row", async () => {
    let thrown: unknown;
    try {
      await withToolContext(
        "gmail_search",
        { query: "x", account_id: "nobody@example.com" },
        async () => ({ ok: true }),
        { loadIndexImpl: async () => ({ version: 2, accounts: [] }) },
      );
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(MCPError);
    const code = (thrown as MCPError).code;

    // The row is written before the rejection, so it is on disk with no flush delay
    // (a CLI caller may exit as soon as the call rejects).
    const immediate = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    expect(immediate.trim().split("\n")).toHaveLength(1);

    const rows = await auditRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tool).toBe("gmail_search");
    expect(rows[0]!.status).toBe("error");
    expect(rows[0]!.error_code).toBe(code);
    expect(rows[0]!.account).toBeNull();
  });
});

describe("cross-account pre-fan-out failure writes one terminal row", () => {
  test("malformed `accounts` entry → one error row, no aggregate row", async () => {
    const inner: Array<Record<string, unknown>> = [];
    const outer: Array<Record<string, unknown>> = [];
    let thrown: unknown;
    try {
      await withAllAccounts(
        "gmail_search_all",
        {},
        async () => ({}),
        { accounts: ["not an email"] },
        {
          loadIndexImpl: async () => ({ accounts: [] }),
          auditEndImpl: async (ctx) => {
            inner.push({ ...ctx });
          },
          auditAggregateImpl: async (ctx) => {
            outer.push({ ...ctx });
          },
        },
      );
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect(inner).toHaveLength(1);
    expect(inner[0]!.status).toBe("error");
    expect(inner[0]!.email).toBeNull();
    expect(inner[0]!.tool).toBe("gmail_search_all");
    expect(outer).toHaveLength(0);
  });
});

describe("cross-account handler failure before fan-out writes one terminal row", () => {
  test("gmail_search_all without a query → one error row (the handler threw before withAllAccounts)", async () => {
    // A plain Error from the handler surfaces as a protocol error (pre-existing).
    await expect(callTool(resolverAt("share"), "gmail_search_all", {})).rejects.toThrow(/query/);
    const rows = await auditRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tool).toBe("gmail_search_all");
    expect(rows[0]!.status).toBe("error");
    expect(rows[0]!.account).toBeNull();
  });

  test("a failure withAllAccounts already logged is not logged again", async () => {
    // A malformed `accounts` entry fails inside withAllAccounts' pre-fan-out phase,
    // which writes the row; the server wrapper must not add a second one.
    await expect(
      callTool(resolverAt("share"), "gmail_search_all", { query: "x", accounts: ["not an email"] }),
    ).rejects.toThrow(/accounts/);
    const rows = await auditRows();
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tool).toBe("gmail_search_all");
  });
});
