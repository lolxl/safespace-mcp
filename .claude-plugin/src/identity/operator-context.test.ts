import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ConnectionOperatorResolver,
  EnvOperatorResolver,
  envOperatorContext,
  type OperatorContext,
} from "./operator-context";

// v1.74 PR-2a — the Model-A EnvOperatorResolver: the degenerate-case resolver that
// reproduces today's three process-global env reads (operator id + tier;
// allowedAccounts null). These tests pin (1) it reads the right env, (2) it is
// resolved PER CALL — never a snapshot — so the env-mutation contract the choke
// points rely on survives, and (3) the Model-A defaults (null operator,
// no-restriction accounts) that keep the whole arc byte-identical.

const OP = "SAFESPACE_OPERATOR_ID";
const TIER = "SAFESPACE_TIER";

let savedOperator: string | undefined;
let savedTier: string | undefined;

beforeEach(() => {
  savedOperator = process.env[OP];
  savedTier = process.env[TIER];
  delete process.env[OP];
  delete process.env[TIER];
});

afterEach(() => {
  if (savedOperator === undefined) delete process.env[OP];
  else process.env[OP] = savedOperator;
  if (savedTier === undefined) delete process.env[TIER];
  else process.env[TIER] = savedTier;
});

describe("EnvOperatorResolver.resolve()", () => {
  test("reads $SAFESPACE_OPERATOR_ID + $SAFESPACE_TIER; allowedAccounts is null", () => {
    process.env[OP] = "alice";
    process.env[TIER] = "write";
    const op = new EnvOperatorResolver().resolve();
    expect(op.operatorId).toBe("alice");
    expect(op.tier).toBe("write");
    expect(op.allowedAccounts).toBeNull();
  });

  test("Model-A single-user defaults: operatorId null, tier read, accounts null", () => {
    // Neither env var set → the byte-identical-to-today single-user shape.
    const op = new EnvOperatorResolver().resolve();
    expect(op.operatorId).toBeNull();
    expect(op.tier).toBe("read");
    expect(op.allowedAccounts).toBeNull();
  });

  test("a malformed operator id drops to null (reuses isValidOperatorId)", () => {
    process.env[OP] = "has spaces / and slashes"; // fails ^[A-Za-z0-9_.-]{1,64}$
    expect(new EnvOperatorResolver().resolve().operatorId).toBeNull();
  });

  test("an invalid tier falls back to read (fail-safe, reuses currentTier)", () => {
    process.env[TIER] = "superuser";
    expect(new EnvOperatorResolver().resolve().tier).toBe("read");
  });

  test("resolve() is PER CALL — env mutation between calls is honored (NO snapshot)", () => {
    const resolver = new EnvOperatorResolver();
    process.env[OP] = "alice";
    process.env[TIER] = "read";
    const first = resolver.resolve();
    // Mutate env on the SAME resolver instance — a snapshot-at-construction
    // implementation would miss this; the per-call read must see it.
    process.env[OP] = "bob";
    process.env[TIER] = "share";
    const second = resolver.resolve();
    expect(first.operatorId).toBe("alice");
    expect(first.tier).toBe("read");
    expect(second.operatorId).toBe("bob");
    expect(second.tier).toBe("share");
  });
});

describe("envOperatorContext()", () => {
  test("is the EnvOperatorResolver context (the choke-point default)", () => {
    process.env[OP] = "carol";
    process.env[TIER] = "share";
    const op: OperatorContext = envOperatorContext();
    expect(op).toEqual({ operatorId: "carol", tier: "share", allowedAccounts: null });
  });

  test("re-reads env on each call (default param must not freeze)", () => {
    process.env[TIER] = "read";
    expect(envOperatorContext().tier).toBe("read");
    process.env[TIER] = "write";
    expect(envOperatorContext().tier).toBe("write");
  });
});

describe("ConnectionOperatorResolver (Model B — PR-2b; supplier-based v1.80)", () => {
  test("resolve() returns the supplier's context, ignoring env", () => {
    // The transport resolves the connection identity (WhoIs → registry) and binds
    // a SUPPLIER of the session's current context; env must not leak in.
    process.env[OP] = "envguy";
    process.env[TIER] = "read";
    const ctx: OperatorContext = {
      operatorId: "alice",
      tier: "share",
      allowedAccounts: ["alice@gmail.com"],
    };
    const resolver = new ConnectionOperatorResolver(() => ctx);
    expect(resolver.resolve()).toBe(ctx); // same reference
    expect(resolver.resolve()).toEqual(ctx); // stable across calls
  });

  test("v1.80 — resolve() observes a supplier swap (registry hot-reload policy change)", () => {
    // The transport refreshes the session record's context per request; the
    // resolver must read the CURRENT value, not a constructor-time snapshot.
    let current: OperatorContext = {
      operatorId: "alice",
      tier: "share",
      allowedAccounts: ["alice@gmail.com"],
    };
    const resolver = new ConnectionOperatorResolver(() => current);
    expect(resolver.resolve().tier).toBe("share");
    current = { operatorId: "alice", tier: "read", allowedAccounts: [] };
    expect(resolver.resolve().tier).toBe("read");
    expect(resolver.resolve().allowedAccounts).toEqual([]);
  });
});
