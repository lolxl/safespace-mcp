import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "../server";
import { IMPLEMENTED_TOOLS, TOOL_REGISTRY } from "../tools/registry";
import { sourceFor } from "../tools/source";
import type { OperatorContext, OperatorResolver } from "../identity/operator-context";
import type { Tier } from "../tier";
import {
  CONNECTOR_TOKENS,
  GOOGLE_ALIAS,
  GOOGLE_SUBSERVICE_TOKENS,
  NON_GOOGLE_CONNECTOR_TOKENS,
  connectorPostureValue,
  connectorSelectionKey,
  connectorTokenFor,
  isConnectorEnabled,
  parseConnectors,
  resolveEnabledConnectors,
  validateConnectors,
} from "./connector-toggle";

const ENV = "SAFESPACE_CONNECTORS";
const TIER = "SAFESPACE_TIER";
let savedConnectors: string | undefined;
let savedTier: string | undefined;
beforeEach(() => {
  savedConnectors = process.env[ENV];
  savedTier = process.env[TIER];
  delete process.env[ENV];
});
afterEach(() => {
  if (savedConnectors === undefined) delete process.env[ENV];
  else process.env[ENV] = savedConnectors;
  if (savedTier === undefined) delete process.env[TIER];
  else process.env[TIER] = savedTier;
});

const implementedDefs = Object.values(TOOL_REGISTRY).filter((d) => IMPLEMENTED_TOOLS.has(d.name));

function fixedResolver(tier: Tier): OperatorResolver {
  const op: OperatorContext = { tier };
  return { resolve: () => op };
}

async function listToolNames(tier: Tier): Promise<string[]> {
  const server = createMcpServer(fixedResolver(tier));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "v1.127-connector-toggle-test", version: "1.0.0" });
  await client.connect(clientTransport);
  try {
    return (await client.listTools()).tools.map((t) => t.name);
  } finally {
    await client.close();
  }
}

async function callTool(tier: Tier, name: string): Promise<string> {
  const server = createMcpServer(fixedResolver(tier));
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "v1.127-connector-toggle-test", version: "1.0.0" });
  await client.connect(clientTransport);
  try {
    const res = (await client.callTool({ name, arguments: {} })) as {
      content?: Array<{ type: string; text: string }>;
    };
    return res.content?.[0]?.text ?? "";
  } finally {
    await client.close();
  }
}

// ───────────────────────────────────────────────────────────────────────────────
// SENTINELS — the token map is an IMPLICIT contract over 130 tool names. These are
// the tests that turn a future mapping gap RED instead of shipping it silently.
// ───────────────────────────────────────────────────────────────────────────────
describe("v1.127 sentinels — the token map is bound to the live registry", () => {
  test("EVERY implemented tool maps to exactly one connector token", () => {
    const unmapped = implementedDefs
      .filter((d) => connectorTokenFor(d) === undefined)
      .map((d) => d.name);
    // A new Google service (chat_send, meet_list, …) lands here. Fix = add its
    // prefix to GOOGLE_SUBSERVICE_TOKENS + docs/ADDING-A-CONNECTOR.md, NOT a skip.
    expect(unmapped).toEqual([]);
    for (const d of implementedDefs) {
      expect(CONNECTOR_TOKENS).toContain(connectorTokenFor(d)!);
    }
  });

  test("the non-google tokens are exactly the non-google SOURCES ids", () => {
    // Direction 1 — every registered source has a token.
    const registered = new Set(
      implementedDefs.map((d) => d.source ?? GOOGLE_ALIAS).filter((s) => s !== GOOGLE_ALIAS),
    );
    expect([...registered].sort()).toEqual([...NON_GOOGLE_CONNECTOR_TOKENS].sort());
    // Direction 2 — every token resolves in tools/source.ts (which throws on an
    // unknown id), so a renamed source id cannot leave a dangling token here.
    for (const tok of NON_GOOGLE_CONNECTOR_TOKENS) {
      expect(() => sourceFor({ source: tok })).not.toThrow();
    }
  });

  test("the google sub-service tokens are exactly the distinct google tool-name prefixes", () => {
    const prefixes = new Set(
      implementedDefs
        .filter((d) => d.source === undefined || d.source === GOOGLE_ALIAS)
        .map((d) => d.name.split("_")[0]!),
    );
    expect([...prefixes].sort()).toEqual([...GOOGLE_SUBSERVICE_TOKENS].sort());
  });

  test("all 21 tokens are pairwise distinct and sorted", () => {
    expect(new Set(CONNECTOR_TOKENS).size).toBe(CONNECTOR_TOKENS.length);
    expect(CONNECTOR_TOKENS.length).toBe(21);
    expect([...CONNECTOR_TOKENS]).toEqual([...CONNECTOR_TOKENS].sort());
  });
});

// ───────────────────────────────────────────────────────────────────────────────
describe("v1.127 parsing", () => {
  test("alias expands to all 10 google sub-services and nothing else", () => {
    const { tokens, unknown } = parseConnectors(GOOGLE_ALIAS);
    expect(unknown).toEqual([]);
    expect([...tokens].sort()).toEqual([...GOOGLE_SUBSERVICE_TOKENS].sort());
    expect(tokens.has(GOOGLE_ALIAS)).toBe(false); // the alias is never a per-tool token
  });

  test("underscores fold to hyphens — `web_fetch` / `fs_read` are accepted", () => {
    // The shapes an operator reads off a TOOL NAME must not be a startup failure.
    const { tokens, unknown } = parseConnectors("web_fetch, fs_read");
    expect(unknown).toEqual([]);
    expect([...tokens].sort()).toEqual(["fs-read", "web-fetch"]);
  });

  test("case, surrounding whitespace, and empty segments are tolerated", () => {
    const { tokens, unknown } = parseConnectors(" GMail , ,github,, ");
    expect(unknown).toEqual([]);
    expect([...tokens].sort()).toEqual(["github", "gmail"]);
  });

  test("unknown tokens are collected, not silently dropped", () => {
    const { tokens, unknown } = parseConnectors("gmail,gcal,slak");
    expect([...tokens]).toEqual(["gmail"]);
    expect(unknown).toEqual(["gcal", "slak"]);
  });
});

describe("v1.127 bootstrap guard (fail-loud)", () => {
  test("proxy.ts calls validateConnectors before the F6 token check (unknown-token diagnosis first)", () => {
    const src = readFileSync(join(import.meta.dir, "../proxy.ts"), "utf8");
    const iValidate = src.indexOf("validateConnectors()");
    const iF6 = src.indexOf("enforceAutonomousTokenStorage()");
    expect(iValidate).toBeGreaterThan(-1);
    expect(iF6).toBeGreaterThan(-1);
    expect(iValidate).toBeLessThan(iF6);
  });

  test("unset → no-op", () => {
    expect(() => validateConnectors()).not.toThrow();
    process.env[ENV] = "   ";
    expect(() => validateConnectors()).not.toThrow();
  });

  test("a typo throws, naming the offender AND printing every valid token", () => {
    process.env[ENV] = "gmail,gcal";
    let msg = "";
    try {
      validateConnectors();
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e);
    }
    expect(msg).toContain("gcal");
    // The error message IS the doc (tier.ts LEGACY_FLAG_ERROR posture).
    for (const tok of CONNECTOR_TOKENS) expect(msg).toContain(tok);
  });

  test("a non-empty value that selects nothing throws rather than serving zero tools", () => {
    // The split is deliberate: truly empty / whitespace-only == unset == all on
    // (covered above), but a value the operator actually TYPED which resolves to
    // no connector is a mistake — refuse to start rather than serve an empty
    // tools/list they would then debug for an hour.
    process.env[ENV] = " , ,";
    expect(() => validateConnectors()).toThrow(/selects no connector/);
  });

  test("a valid set passes", () => {
    process.env[ENV] = "gmail,calendar,github";
    expect(() => validateConnectors()).not.toThrow();
  });

  test("the refusal DEDUPES and LENGTH-CAPS the echoed operator input", () => {
    // The message reaches the client's server log — a different retention domain
    // than .env. A fat-fingered long paste (or secret) must not be copied whole.
    const long = "z".repeat(500);
    process.env[ENV] = `${long},bogus,bogus,bogus`;
    let msg = "";
    try {
      validateConnectors();
    } catch (e) {
      msg = e instanceof Error ? e.message : String(e);
    }
    expect(msg).not.toContain(long); // never the full value
    expect(msg).toContain("…"); // truncated
    expect(msg.match(/bogus/g)?.length).toBe(1); // deduped, not repeated 3×
  });

  test("set-but-empty warns instead of silently exposing everything", () => {
    // The one input where the axis fails OPEN. Refusing to start would be the
    // dangerous direction, so it must WARN and keep the safe default.
    const errs: string[] = [];
    const orig = console.error;
    console.error = (...a: unknown[]) => void errs.push(a.join(" "));
    try {
      process.env[ENV] = "   ";
      expect(() => validateConnectors()).not.toThrow();
    } finally {
      console.error = orig;
    }
    expect(errs.join("\n")).toContain("set but empty");
    expect(resolveEnabledConnectors()).toBeNull(); // still all-on
  });
});

describe("v1.127 resolution + fail-safe", () => {
  test("unset (and whitespace-only) → null = every connector on", () => {
    expect(resolveEnabledConnectors()).toBeNull();
    expect(connectorSelectionKey()).toBe("*");
    process.env[ENV] = "  ";
    expect(resolveEnabledConnectors()).toBeNull();
  });

  test("an UNMAPPED tool is always enabled (fail-safe, never silently unreachable)", () => {
    process.env[ENV] = "github";
    // Simulates a future google service with no token yet.
    expect(isConnectorEnabled({ name: "chat_send", source: undefined })).toBe(true);
    expect(connectorTokenFor({ name: "chat_send", source: undefined })).toBeUndefined();
  });

  test("the selection key is order-insensitive so two spellings share one cache entry", () => {
    process.env[ENV] = "github,gmail";
    const a = connectorSelectionKey();
    process.env[ENV] = "gmail,github";
    expect(connectorSelectionKey()).toBe(a);
  });

  test("the posture line echoes token names (fixed identifiers, never PII)", () => {
    expect(connectorPostureValue()).toContain("all connectors exposed");
    process.env[ENV] = "gmail";
    expect(connectorPostureValue()).toContain("gmail");
  });

  test("the retired webhook token is now an unknown connector", () => {
    process.env[ENV] = "gmail,WEBHOOK";
    expect(() => validateConnectors()).toThrow(/"webhook" is retired: the inbound webhook listener/);
  });
});

// ───────────────────────────────────────────────────────────────────────────────
// BEHAVIORAL — through a real in-memory MCP client.
// ───────────────────────────────────────────────────────────────────────────────
describe("v1.127 tools/list", () => {
  test("UNSET exposes every connector — 70 / 129 / 135 tools, registry order", async () => {
    expect((await listToolNames("read")).length).toBe(70);
    expect((await listToolNames("write")).length).toBe(129);
    const share = await listToolNames("share");
    expect(share.length).toBe(135);
    expect(share).toEqual(
      implementedDefs.map((d) => d.name), // registry order preserved on the wire
    );
  });

  test("a narrowed set exposes only that connector's tools", async () => {
    process.env[ENV] = "gmail,calendar";
    const names = await listToolNames("share");
    expect(names.length).toBeGreaterThan(0);
    expect(names.every((n) => n.startsWith("gmail_") || n.startsWith("calendar_"))).toBe(true);
    expect(names).toContain("gmail_send");
    expect(names).not.toContain("github_list_repos");
    expect(names).not.toContain("youtube_search");
  });

  test("the alias exposes all of google-workspace and no other connector", async () => {
    process.env[ENV] = GOOGLE_ALIAS;
    const names = await listToolNames("share");
    expect(names.length).toBe(89);
    expect(names).not.toContain("github_list_repos");
  });

  test("NARROWING-ONLY: the connector axis can never carry a tool past its tier", async () => {
    // gmail_send is write-tier. Naming `gmail` at read tier must not expose it.
    process.env[ENV] = "gmail";
    const read = await listToolNames("read");
    expect(read).toContain("gmail_search");
    expect(read).not.toContain("gmail_send");
    // Formally: for every tier, the narrowed list is a SUBSET of the unset list.
    for (const tier of ["read", "write", "share"] as const) {
      const narrowed = await listToolNames(tier);
      delete process.env[ENV];
      const full = await listToolNames(tier);
      process.env[ENV] = "gmail";
      expect(full).toEqual(expect.arrayContaining(narrowed));
    }
  });

  test("env changes are honored across calls — the cache is keyed, not frozen", async () => {
    // The module-cache hazard: `bun test` shares ONE process across all test files,
    // so a module-load snapshot of the env would make this suite order-dependent.
    process.env[ENV] = "github";
    const a = await listToolNames("share");
    process.env[ENV] = "notion";
    const b = await listToolNames("share");
    delete process.env[ENV];
    const c = await listToolNames("share");
    process.env[ENV] = "github";
    const d = await listToolNames("share");

    expect(a.every((n) => n.startsWith("github_"))).toBe(true);
    expect(b.every((n) => n.startsWith("notion_"))).toBe(true);
    expect(c.length).toBe(135);
    expect(d).toEqual(a); // re-selecting the first set returns the same projection
  });
});

describe("v1.127 tools/call re-check", () => {
  test("a disabled connector's tool is not callable even with a cached tool list", async () => {
    // The whole point of the call-time check: tools/list is ADVISORY to the client.
    process.env[ENV] = "gmail";
    const text = await callTool("share", "github_list_repos");
    expect(text).toContain("tool_not_found");
  });

  test("no new oracle — a disabled tool is indistinguishable from an unknown one", async () => {
    process.env[ENV] = "gmail";
    const disabled = await callTool("share", "github_list_repos");
    const unknown = await callTool("share", "totally_made_up_tool");
    // Same error code + same shape; only the echoed caller-supplied name differs.
    expect(disabled.replace("github_list_repos", "X")).toBe(
      unknown.replace("totally_made_up_tool", "X"),
    );
  });

  test("an ENABLED connector's tool still reaches the handler (not blanket-blocked)", async () => {
    process.env[ENV] = "gmail";
    const text = await callTool("share", "gmail_search");
    // No account is consented in the test env, so it fails FURTHER IN — the point is
    // that it does NOT fail with tool_not_found at the connector gate.
    expect(text).not.toContain("tool_not_found");
  });
});
