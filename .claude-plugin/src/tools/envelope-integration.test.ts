// Envelope-composition integration (arch-review F7): table-driven cases drive the
// PRODUCTION path createMcpServer → tools/call → choke point → REAL registered
// handler per connector class. Asserts the composed envelope (MCP error render,
// inbound sanitize wrap, audit rows) — not the fetchImpl-injected handler unit path.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { __resetChainState } from "../audit";
import { writeActive } from "../auth/active";
import { saveIndex } from "../auth/keychain";
import { _resetTokenCacheForTests } from "../auth/refresh";
import { __resetServiceTokenBackendForTests } from "../auth/service-token-store";
import { __resetBackendForTests, setToken } from "../auth/token-store";
import { createMcpServer } from "../server";
import { _resetLastUsedForTests } from "./with-context";

const ENV_KEYS = [
  "SAFESPACE_TIER",
  "SAFESPACE_CONFIG_DIR",
  "SAFESPACE_SECRET_BACKEND",
  "SAFESPACE_TELEGRAM_BOT_TOKEN",
  "SAFESPACE_TELEGRAM_RECIPIENT_ALLOW",
  "SAFESPACE_TELEGRAM_RECIPIENT_ALLOW_EXTRA",
  "SAFESPACE_AUTONOMOUS",
  "GOOGLE_CLIENT_ID",
  "GOOGLE_CLIENT_SECRET",
] as const;

const GMAIL_LABELS = "https://www.googleapis.com/auth/gmail.labels";
const MARKER = "ENVELOPE_MARKER_untrusted_text_xyz";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};

function resetSingletons(): void {
  __resetChainState();
  __resetServiceTokenBackendForTests();
  __resetBackendForTests();
  _resetTokenCacheForTests();
  _resetLastUsedForTests();
}

beforeEach(async () => {
  for (const k of ENV_KEYS) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-envelope-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file";
  delete process.env.SAFESPACE_TELEGRAM_BOT_TOKEN;
  delete process.env.SAFESPACE_TELEGRAM_RECIPIENT_ALLOW;
  delete process.env.SAFESPACE_TELEGRAM_RECIPIENT_ALLOW_EXTRA;
  delete process.env.SAFESPACE_AUTONOMOUS;
  process.env.GOOGLE_CLIENT_ID = "fake-client-id";
  process.env.GOOGLE_CLIENT_SECRET = "fake-client-secret";
  resetSingletons();
});

afterEach(async () => {
  for (const k of ENV_KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k];
  }
  resetSingletons();
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

async function readAuditRows(): Promise<Array<Record<string, unknown>>> {
  await new Promise((r) => setTimeout(r, 30));
  try {
    const content = await fs.readFile(path.join(tmpDir, "audit.jsonl"), "utf8");
    return content.split("\n").filter(Boolean).map((l) => JSON.parse(l));
  } catch {
    return [];
  }
}

async function callThroughServer(
  name: string,
  args: Record<string, unknown>,
): Promise<{ isError: boolean; text: string }> {
  const server = createMcpServer();
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: "envelope-integration", version: "1.0.0" });
  await client.connect(clientTransport);
  try {
    const result = await client.callTool({ name, arguments: args });
    const blocks = (result.content ?? []) as Array<{ text?: string }>;
    return {
      isError: result.isError === true,
      text: blocks.map((b) => b.text ?? "").join("\n"),
    };
  } finally {
    await client.close();
  }
}

async function seedGoogleAccount(): Promise<void> {
  const { setGaxiosHandler, resetGaxiosHandler } = await import(
    "../google-api/test-utils"
  );
  resetGaxiosHandler();
  setGaxiosHandler(async () => ({
    data: {
      labels: [
        { id: "INBOX", name: "INBOX", type: "system" },
        { id: "Label_99", name: MARKER, type: "user" },
      ],
    },
    status: 200,
  }));
  await saveIndex({
    version: 2,
    accounts: [
      {
        email: "alice@example.com",
        scopes: [GMAIL_LABELS],
        added_at: "2026-05-15T00:00:00.000Z",
        last_used_at: null,
      },
    ],
  });
  await setToken(
    "alice@example.com",
    JSON.stringify({
      refresh_token: "rt",
      access_token: "access-token-for-envelope-test",
      expires_at: Date.now() + 30 * 60_000,
      scopes: [GMAIL_LABELS],
      obtained_at: Date.now(),
    }),
  );
  await writeActive("alice@example.com");
}

type EnvelopeCase = {
  id: string;
  tier: "read" | "share";
  tool: string;
  args: Record<string, unknown>;
  setup?: () => Promise<void>;
  expectError: boolean;
  textIncludes: string[];
  audit: { tool: string; status: "ok" | "error"; errorCode?: number };
};

const CASES: EnvelopeCase[] = [
  {
    // Class-B: resolveCredential no_token BEFORE egress/network.
    id: "class-B telegram_send_message deny (no token)",
    tier: "share",
    tool: "telegram_send_message",
    args: { chat_id: "123456789", text: "hello" },
    expectError: true,
    textIncludes: ["telegram_api_failed"],
    audit: { tool: "telegram_send_message", status: "error", errorCode: -32039 },
  },
  {
    // Class-C: SSRF gate denies metadata IP locally (no network).
    id: "class-C web_fetch deny (metadata IP)",
    tier: "read",
    tool: "web_fetch",
    args: { url: "http://169.254.169.254/" },
    expectError: true,
    textIncludes: ["url_blocked_by_policy"],
    audit: { tool: "web_fetch", status: "error", errorCode: -32036 },
  },
  {
    // Class-A: FileBackend-seeded account + gaxios mock → sanitize through choke point.
    id: "class-A gmail_list_labels sanitize wrap",
    tier: "read",
    tool: "gmail_list_labels",
    args: { account_id: "alice@example.com" },
    setup: seedGoogleAccount,
    expectError: false,
    textIncludes: ["untrusted-source-", MARKER],
    audit: { tool: "gmail_list_labels", status: "ok" },
  },
];

describe("envelope composition via createMcpServer → callTool (per connector class)", () => {
  for (const c of CASES) {
    test(c.id, async () => {
      process.env.SAFESPACE_TIER = c.tier;
      resetSingletons();

      // Guard: deny paths must never hit the network; class-A uses gaxios mock.
      const fetchCalls: string[] = [];
      const realFetch = globalThis.fetch;
      globalThis.fetch = (async (input: Parameters<typeof fetch>[0]) => {
        const url =
          typeof input === "string"
            ? input
            : input instanceof URL
              ? input.href
              : input.url;
        fetchCalls.push(url);
        throw new Error(`envelope-integration: unexpected fetch to ${url}`);
      }) as unknown as typeof fetch;

      try {
        if (c.setup) await c.setup();
        const result = await callThroughServer(c.tool, c.args);
        expect(result.isError).toBe(c.expectError);
        for (const s of c.textIncludes) expect(result.text).toContain(s);
        if (c.expectError) expect(fetchCalls).toEqual([]);

        const rows = await readAuditRows();
        const row = rows.find((r) => r.tool === c.audit.tool);
        expect(row, `audit row for ${c.audit.tool}`).toBeDefined();
        expect(row!.status).toBe(c.audit.status);
        if (c.audit.errorCode !== undefined) {
          expect(row!.error_code).toBe(c.audit.errorCode);
        } else {
          expect(row!.error_code).toBeUndefined();
        }
      } finally {
        globalThis.fetch = realFetch;
      }
    });
  }
});
