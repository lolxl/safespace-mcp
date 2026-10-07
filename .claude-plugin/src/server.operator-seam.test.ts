import { afterEach, beforeEach, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createMcpServer } from "./server";
import type { OperatorContext, OperatorResolver } from "./identity/operator-context";
import type { Tier } from "./tier";

// v1.74 PR-2a — behavioral proof that the OperatorContext seam is REAL: the
// tier-filtered tools/list reads the per-server RESOLVER's tier, NOT the
// process-global $SAFESPACE_TIER. This is the single property that makes the
// future per-session Model-B server (PR-2b) able to show operator A a different
// tool surface than operator B from ONE process — and the property that proves
// the default still mirrors env (Model A byte-identical).

function fixedResolver(tier: Tier): OperatorResolver {
  const op: OperatorContext = { tier };
  return { resolve: () => op };
}

/** Connect an in-memory MCP client to a server built with `resolver` (or the
 *  default env resolver when omitted) and return the visible tool names. */
async function listToolNames(resolver?: OperatorResolver): Promise<string[]> {
  const server = resolver ? createMcpServer(resolver) : createMcpServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "v1.74-seam-test", version: "1.0.0" });
  await client.connect(clientTransport);
  try {
    const { tools } = await client.listTools();
    return tools.map((t) => t.name);
  } finally {
    await client.close();
  }
}

const TIER = "SAFESPACE_TIER";
let savedTier: string | undefined;
beforeEach(() => {
  savedTier = process.env[TIER];
});
afterEach(() => {
  if (savedTier === undefined) delete process.env[TIER];
  else process.env[TIER] = savedTier;
});

test("a read-tier resolver hides write tools EVEN when $SAFESPACE_TIER=share", async () => {
  // The global says "share" (everything visible); the resolver says "read".
  // tools/list must obey the RESOLVER — gmail_send (write) is hidden.
  process.env[TIER] = "share";
  const names = await listToolNames(fixedResolver("read"));
  expect(names).toContain("gmail_search"); // read tool — visible
  expect(names).not.toContain("gmail_send"); // write tool — hidden by the resolver
  expect(names).not.toContain("drive_share_file"); // share tool — hidden
});

test("a share-tier resolver shows write/share tools EVEN when $SAFESPACE_TIER=read", async () => {
  // The mirror: the resolver can WIDEN past the global (a Model-B operator whose
  // registry tier is higher than the host's env default). Proves the filter is
  // sourced from the resolver, not max(resolver, env) or the global.
  process.env[TIER] = "read";
  const names = await listToolNames(fixedResolver("share"));
  expect(names).toContain("gmail_send");
  expect(names).toContain("drive_share_file");
});

test("the DEFAULT (no resolver) still reads $SAFESPACE_TIER — Model A byte-identical", async () => {
  process.env[TIER] = "read";
  const readNames = await listToolNames();
  expect(readNames).toContain("gmail_search");
  expect(readNames).not.toContain("gmail_send");

  process.env[TIER] = "write";
  const writeNames = await listToolNames();
  expect(writeNames).toContain("gmail_send");
});
