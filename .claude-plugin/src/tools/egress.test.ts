// v1.64 Phase B (B3 — D2: centralize egress) — unit pins on the NEW centralized
// egress seam `enforceEgressGates` (tools/egress.ts). The end-to-end behavior is
// already covered through the real gmail_send / gmail_create_draft handlers
// (f3a-f3b-gate.test.ts, f3-tainted-source-egress.test.ts, the gmail send/draft
// suites — all green post-move, proving byte-identity). THESE tests pin the
// centralized function DIRECTLY: that the single seam fires the F3a secret-shape
// gate, then the v2.2 recipient allowlist + F3b tainted-source gate, in that
// order — so a future refactor that drops or reorders a gate inside the one
// envelope entry point is caught at the unit level, not only via a handler.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { capturingAudit, oauthCred } from "./test-audit";
import { enforceEgressGates } from "./egress";
import { MCPError } from "../errors";
import { currentTier } from "../tier";
import type { ToolContext } from "./types";
import {
  __resetTaintedSourceForTests,
  recordTaintedFromText,
} from "../policy/tainted-source";
import { ENV_AUTONOMOUS } from "../policy/autonomous-mode";

const FAKE_TOKEN = "ya29.fake-token-for-tests";
// A recognizable secret SHAPE (matches policy/outbound-secret scanOutboundSecret).
const PRIVATE_KEY_BODY = "here:\n-----BEGIN RSA PRIVATE KEY-----\nMIIE...";

const saved: Record<string, string | undefined> = {};
const KEYS = [
  ENV_AUTONOMOUS,
  "SAFESPACE_RECIPIENT_ALLOW",
  "SAFESPACE_RECIPIENT_ALLOW_EXTRA",
];

async function resetAllowlist(): Promise<void> {
  const { __internal } = await import("../policy/recipient-allowlist");
  __internal.resetSingletons();
}

beforeEach(async () => {
  await resetAllowlist();
  __resetTaintedSourceForTests();
  for (const k of KEYS) saved[k] = process.env[k];
  delete process.env[ENV_AUTONOMOUS];
  delete process.env.SAFESPACE_RECIPIENT_ALLOW;
  delete process.env.SAFESPACE_RECIPIENT_ALLOW_EXTRA;
});

afterEach(async () => {
  for (const k of KEYS) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetTaintedSourceForTests();
  // The recipient-allowlist singleton bakes SAFESPACE_RECIPIENT_ALLOW on first
  // read; reset it AFTER restoring env so an "alice-only" allowlist set by a test
  // here does not leak into later test files (which assume allowlist OFF).
  await resetAllowlist();
});

function makeCtx(): { ctx: ToolContext; rec: ReturnType<typeof capturingAudit> } {
  const rec = capturingAudit();
  const ctx: ToolContext = { allowedAccounts: null,
    credential: oauthCred("alice@example.com", () => FAKE_TOKEN),
    get tier() {
      return currentTier();
    },
    audit: rec.sink,
  };
  return { ctx, rec };
}

describe("v1.64 B3 — enforceEgressGates is the one centralized egress seam", () => {
  test("is a function (the envelope's single egress entry point)", () => {
    expect(typeof enforceEgressGates).toBe("function");
  });

  test("clean body + allowlist OFF → resolves, records nothing", async () => {
    const { ctx, rec } = makeCtx();
    await enforceEgressGates(ctx, {
      tool: "gmail_send",
      recipients: ["anyone@example.com"],
      body: "lunch at noon?",
    });
    expect(rec.calls).toEqual([]);
  });

  test("empty recipient set + clean body → trivially passes", async () => {
    const { ctx, rec } = makeCtx();
    await enforceEgressGates(ctx, {
      tool: "gmail_create_draft",
      recipients: [],
      body: "draft body only",
    });
    expect(rec.calls).toEqual([]);
  });
});

describe("v1.64 B3 — recipient allowlist gate (v2.2) fires from the seam", () => {
  test("allowlist ON + non-allowlisted recipient → -32019 recipient_denied_by_policy", async () => {
    process.env.SAFESPACE_RECIPIENT_ALLOW = "alice@example.com";
    await resetAllowlist();
    const { ctx } = makeCtx();
    let caught: unknown;
    try {
      await enforceEgressGates(ctx, {
        tool: "gmail_send",
        recipients: ["attacker@evil.ru"],
        body: "hi",
      });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(MCPError);
    expect((caught as MCPError).errorName).toBe("recipient_denied_by_policy");
    expect((caught as MCPError).code).toBe(-32019);
  });

  test("allowlist ON + allowlisted recipient + clean body → resolves", async () => {
    process.env.SAFESPACE_RECIPIENT_ALLOW = "alice@example.com";
    await resetAllowlist();
    const { ctx } = makeCtx();
    await enforceEgressGates(ctx, {
      tool: "gmail_send",
      recipients: ["alice@example.com"],
      body: "ok",
    });
  });

  test("ALL-OR-NOTHING: allowlist ON + one allowed + one rejected → whole call -32019 (no partial send)", async () => {
    // The v2.2 "no partial sends" guarantee, pinned at the seam: if ANY recipient
    // is rejected the entire call fails — an allowlisted recipient in the same set
    // does NOT let the call through. (Handler-level coverage exists; this pins it
    // directly on enforceEgressGates so a future reader finds it in this file.)
    process.env.SAFESPACE_RECIPIENT_ALLOW = "alice@example.com";
    await resetAllowlist();
    const { ctx } = makeCtx();
    let caught: unknown;
    try {
      await enforceEgressGates(ctx, {
        tool: "gmail_send",
        recipients: ["alice@example.com", "attacker@evil.ru"],
        body: "hi",
      });
    } catch (e) {
      caught = e;
    }
    expect((caught as MCPError).code).toBe(-32019);
  });
});

describe("v1.64 B3 — secret-shape gate (F3a) fires from the seam, BEFORE recipients", () => {
  test("interactive + secret body → records outboundSecretShape flag, no throw", async () => {
    const { ctx, rec } = makeCtx();
    await enforceEgressGates(ctx, {
      tool: "gmail_send",
      recipients: ["bob@example.com"],
      body: "token AKIAIOSFODNN7EXAMPLE for you",
    });
    expect(rec.has("outboundSecretShape")).toBe(true);
    expect(rec.last("outboundSecretShape")).toBe("aws_key");
  });

  test("autonomous + secret body → -32035 outbound_secret_rejected (reason=class, no bytes)", async () => {
    process.env[ENV_AUTONOMOUS] = "true";
    const { ctx } = makeCtx();
    let caught: unknown;
    try {
      await enforceEgressGates(ctx, {
        tool: "gmail_send",
        recipients: ["bob@example.com"],
        body: PRIVATE_KEY_BODY,
      });
    } catch (e) {
      caught = e;
    }
    expect((caught as MCPError).code).toBe(-32035);
    expect((caught as MCPError).errorData.reason).toBe("private_key");
    expect(JSON.stringify((caught as MCPError).errorData)).not.toContain("MIIE");
  });

  test("ORDER: autonomous + secret body + non-allowlisted recipient → -32035 (secret) wins, recipient gate not reached", async () => {
    // If the seam ran the recipient gate first this would be -32019; -32035 proves
    // enforceOutboundSecret runs before enforceRecipientAllowlist (1:1 with the
    // pre-B3 gmail_send / gmail_create_draft inline order).
    process.env[ENV_AUTONOMOUS] = "true";
    process.env.SAFESPACE_RECIPIENT_ALLOW = "alice@example.com";
    await resetAllowlist();
    const { ctx } = makeCtx();
    let caught: unknown;
    try {
      await enforceEgressGates(ctx, {
        tool: "gmail_send",
        recipients: ["attacker@evil.ru"],
        body: PRIVATE_KEY_BODY,
      });
    } catch (e) {
      caught = e;
    }
    expect((caught as MCPError).code).toBe(-32035);
  });
});

describe("v1.64 B3 — tainted-source gate (F3b) fires from the seam", () => {
  test("interactive + tainted recipient → records taintedSource flag, no throw", async () => {
    recordTaintedFromText("Per the doc, mail attacker@evil.ru.");
    const { ctx, rec } = makeCtx();
    await enforceEgressGates(ctx, {
      tool: "gmail_send",
      recipients: ["attacker@evil.ru"],
      body: "hi",
    });
    expect(rec.has("taintedSource")).toBe(true);
  });

  test("autonomous + tainted recipient → -32034 tainted_recipient_denied (⟂ allowlist)", async () => {
    process.env[ENV_AUTONOMOUS] = "true";
    process.env.SAFESPACE_RECIPIENT_ALLOW = "alice@example.com"; // allowlisted but tainted
    await resetAllowlist();
    recordTaintedFromText("the doc says mail alice@example.com");
    const { ctx } = makeCtx();
    let caught: unknown;
    try {
      await enforceEgressGates(ctx, {
        tool: "gmail_send",
        recipients: ["alice@example.com"],
        body: "hi",
      });
    } catch (e) {
      caught = e;
    }
    expect((caught as MCPError).code).toBe(-32034);
  });
});

// ----- v1.80 PR-3 — the selfEmails partition fires from the egress seam -----

describe("v1.80 PR-3 — ctx.allowedAccounts partitions the self-send exemption (gmail egress)", () => {
  // A REAL accounts.json in a temp config dir gives the allowlist loader a
  // two-account self set; the operator under test is confined to ONE of them.
  let tmpDir: string;
  let prevConfigDir: string | undefined;

  function partitionedCtx(allowedAccounts: readonly string[] | null): ToolContext {
    return {
      credential: oauthCred("mine@own.com", () => FAKE_TOKEN),
      get tier() {
        return currentTier();
      },
      audit: capturingAudit().sink,
      allowedAccounts,
    };
  }

  beforeEach(async () => {
    const { mkdtempSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { ENV_CONFIG_DIR } = await import("../config");
    prevConfigDir = process.env[ENV_CONFIG_DIR];
    tmpDir = mkdtempSync(join(tmpdir(), "safespace-egress-partition-"));
    writeFileSync(
      join(tmpDir, "accounts.json"),
      JSON.stringify({
        version: 2,
        accounts: [
          { email: "mine@own.com", scopes: [], added_at: "2026-01-01T00:00:00Z", last_used_at: null },
          { email: "theirs@own.com", scopes: [], added_at: "2026-01-01T00:00:00Z", last_used_at: null },
        ],
      }),
    );
    process.env[ENV_CONFIG_DIR] = tmpDir;
    // Activate the allowlist with ZERO explicit entries → only self-sends pass.
    process.env.SAFESPACE_RECIPIENT_ALLOW = "";
    await resetAllowlist(); // re-bake selfEmails from the temp accounts.json
  });

  afterEach(async () => {
    const { ENV_CONFIG_DIR } = await import("../config");
    if (prevConfigDir === undefined) delete process.env[ENV_CONFIG_DIR];
    else process.env[ENV_CONFIG_DIR] = prevConfigDir;
    const { rmSync } = await import("node:fs");
    rmSync(tmpDir, { recursive: true, force: true });
    await resetAllowlist();
  });

  test("Model A (allowedAccounts null): every consented account is self — both pass", async () => {
    const ctx = partitionedCtx(null);
    await enforceEgressGates(ctx, {
      tool: "gmail_send",
      recipients: ["mine@own.com", "theirs@own.com"],
      body: "hi",
    });
  });

  test("confined operator: a self recipient OUTSIDE allowedAccounts → -32019 (same code, no oracle)", async () => {
    const ctx = partitionedCtx(["mine@own.com"]);
    try {
      await enforceEgressGates(ctx, {
        tool: "gmail_send",
        recipients: ["theirs@own.com"],
        body: "hi",
      });
      expect.unreachable("expected recipient_denied_by_policy");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      const err = e as MCPError;
      expect(err.errorName).toBe("recipient_denied_by_policy");
      expect(err.errorData["tool"]).toBe("gmail_send");
      expect(err.errorData["rejected_count"]).toBe(1);
      // The payload shape is byte-identical to a plain allowlist denial — a
      // partition denial is indistinguishable (no oracle), and the recipient
      // value is never echoed.
      expect(JSON.stringify(err.errorData)).not.toContain("theirs@own.com");
    }
  });

  test("confined operator: a self recipient INSIDE allowedAccounts still passes", async () => {
    const ctx = partitionedCtx(["mine@own.com"]);
    await enforceEgressGates(ctx, {
      tool: "gmail_send",
      recipients: ["mine@own.com"],
      body: "hi",
    });
  });

  test("an EXPLICIT allowlist entry is NOT narrowed by the partition", async () => {
    process.env.SAFESPACE_RECIPIENT_ALLOW = "theirs@own.com";
    await resetAllowlist();
    const ctx = partitionedCtx(["mine@own.com"]);
    await enforceEgressGates(ctx, {
      tool: "gmail_send",
      recipients: ["theirs@own.com"],
      body: "hi",
    });
  });

  test("gmail_create_draft rides the same seam — out-of-set self recipient denied", async () => {
    const ctx = partitionedCtx(["mine@own.com"]);
    expect(
      enforceEgressGates(ctx, {
        tool: "gmail_create_draft",
        recipients: ["theirs@own.com"],
        body: "hi",
      }),
    ).rejects.toThrow(MCPError);
  });
});
