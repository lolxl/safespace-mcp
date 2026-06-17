import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  type AllowlistState,
  __internal,
  buildAllowlistState,
  ENV_ALLOW,
  ENV_ALLOW_EXTRA,
  getAllowlistState,
  isRecipientAllowed,
  parseAllowlistTokens,
  summarizeAllowlist,
} from "./recipient-allowlist";
import { ENV_AUTONOMOUS } from "./autonomous-mode";

const ENV_KEYS = [ENV_ALLOW, ENV_ALLOW_EXTRA] as const;
let envBackup: Record<string, string | undefined>;

beforeEach(() => {
  envBackup = {};
  for (const k of ENV_KEYS) {
    envBackup[k] = process.env[k];
    delete process.env[k];
  }
  __internal.resetSingletons();
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (envBackup[k] === undefined) delete process.env[k];
    else process.env[k] = envBackup[k];
  }
  __internal.resetSingletons();
});

// ----- parseAllowlistTokens -----

describe("parseAllowlistTokens", () => {
  test("undefined input → empty result", () => {
    const r = parseAllowlistTokens(undefined);
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toHaveLength(0);
  });

  test("empty string → empty result", () => {
    const r = parseAllowlistTokens("");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toHaveLength(0);
  });

  test("single exact email parses", () => {
    const r = parseAllowlistTokens("alice@client.com");
    expect(r.ok).toEqual([{ kind: "email", localpart: "alice", domain: "client.com" }]);
    expect(r.rejected).toHaveLength(0);
  });

  test("single domain pattern parses", () => {
    const r = parseAllowlistTokens("@client.com");
    expect(r.ok).toEqual([{ kind: "domain", domain: "client.com" }]);
  });

  test("domain lowercased on parse", () => {
    const r = parseAllowlistTokens("alice@CLIENT.com, @VENDOR.ORG");
    expect(r.ok[0]).toEqual({ kind: "email", localpart: "alice", domain: "client.com" });
    expect(r.ok[1]).toEqual({ kind: "domain", domain: "vendor.org" });
  });

  test("localpart case preserved on parse", () => {
    const r = parseAllowlistTokens("Alice.WONDER@client.com");
    expect(r.ok[0]).toEqual({
      kind: "email",
      localpart: "Alice.WONDER",
      domain: "client.com",
    });
  });

  test("bare domain (no @) rejected", () => {
    const r = parseAllowlistTokens("client.com");
    expect(r.ok).toHaveLength(0);
    expect(r.rejected).toEqual(["client.com"]);
  });

  test("mixed valid + rejected tokens — partial success", () => {
    const r = parseAllowlistTokens("@ok.com, bad-no-tld, alice@valid.org, BARE.com");
    expect(r.ok).toHaveLength(2);
    expect(r.rejected).toEqual(["bad-no-tld", "BARE.com"]);
  });

  test("whitespace tolerated around tokens", () => {
    const r = parseAllowlistTokens("  @a.com  ,   bob@b.com   ");
    expect(r.ok).toHaveLength(2);
  });

  test("trailing/multiple commas tolerated", () => {
    const r = parseAllowlistTokens(",@a.com,,,bob@b.com,");
    expect(r.ok).toHaveLength(2);
  });

  test("token with @ but invalid shape rejected", () => {
    const r = parseAllowlistTokens("@nope");
    expect(r.rejected).toContain("@nope");
    expect(r.ok).toHaveLength(0);
  });
});

// ----- isRecipientAllowed -----

describe("isRecipientAllowed", () => {
  test("state.kind=off → always true (policy off)", () => {
    const state: AllowlistState = { kind: "off" };
    expect(isRecipientAllowed("anyone@anywhere.com", state)).toBe(true);
  });

  test("state.kind=active + empty union + non-self → false (default-deny)", () => {
    const state: AllowlistState = {
      kind: "active",
      allow: [],
      extra: [],
      selfEmails: new Set(),
    };
    expect(isRecipientAllowed("alice@example.com", state)).toBe(false);
  });

  test("self-send implicit-allow even when union empty", () => {
    const state: AllowlistState = {
      kind: "active",
      allow: [],
      extra: [],
      selfEmails: new Set(["me@own.com"]),
    };
    expect(isRecipientAllowed("me@own.com", state)).toBe(true);
  });

  test("self-send exact-match — case-preserving", () => {
    const state: AllowlistState = {
      kind: "active",
      allow: [],
      extra: [],
      selfEmails: new Set(["Me@Own.com"]),
    };
    expect(isRecipientAllowed("Me@Own.com", state)).toBe(true);
    // Different case in either side → no match (we don't auto-fold for self)
    expect(isRecipientAllowed("me@own.com", state)).toBe(false);
  });

  test("exact email entry matches recipient", () => {
    const state = buildAllowlistState("alice@client.com", undefined, new Set());
    expect(isRecipientAllowed("alice@client.com", state)).toBe(true);
    expect(isRecipientAllowed("bob@client.com", state)).toBe(false);
  });

  test("domain entry matches any localpart at that domain", () => {
    const state = buildAllowlistState("@client.com", undefined, new Set());
    expect(isRecipientAllowed("alice@client.com", state)).toBe(true);
    expect(isRecipientAllowed("bob@client.com", state)).toBe(true);
    expect(isRecipientAllowed("anyone@OTHER.com", state)).toBe(false);
  });

  test("domain match is case-insensitive on domain part", () => {
    const state = buildAllowlistState("@client.com", undefined, new Set());
    expect(isRecipientAllowed("alice@CLIENT.com", state)).toBe(true);
    expect(isRecipientAllowed("bob@ClIeNt.CoM", state)).toBe(true);
  });

  test("exact-email match is case-sensitive on localpart", () => {
    const state = buildAllowlistState("alice@client.com", undefined, new Set());
    expect(isRecipientAllowed("alice@client.com", state)).toBe(true);
    // Different localpart case → no match
    expect(isRecipientAllowed("Alice@client.com", state)).toBe(false);
    expect(isRecipientAllowed("ALICE@client.com", state)).toBe(false);
  });

  test("EXTRA entries union with ALLOW", () => {
    const state = buildAllowlistState("@own.com", "alice@new-client.com", new Set());
    expect(isRecipientAllowed("anyone@own.com", state)).toBe(true);
    expect(isRecipientAllowed("alice@new-client.com", state)).toBe(true);
    expect(isRecipientAllowed("attacker@evil.com", state)).toBe(false);
  });

  test("malformed recipient (no @) → false", () => {
    const state = buildAllowlistState("@client.com", undefined, new Set());
    expect(isRecipientAllowed("nope-no-at-sign", state)).toBe(false);
  });

  test("malformed recipient (@ at start) → false", () => {
    const state = buildAllowlistState("@client.com", undefined, new Set());
    expect(isRecipientAllowed("@client.com", state)).toBe(false);
  });

  test("malformed recipient (@ at end) → false", () => {
    const state = buildAllowlistState("@client.com", undefined, new Set());
    expect(isRecipientAllowed("alice@", state)).toBe(false);
  });

  test("empty string recipient → false", () => {
    const state = buildAllowlistState("@client.com", undefined, new Set());
    expect(isRecipientAllowed("", state)).toBe(false);
  });
});

// ----- buildAllowlistState -----

describe("buildAllowlistState", () => {
  test("both env undefined → kind=off", () => {
    const state = buildAllowlistState(undefined, undefined, new Set());
    expect(state.kind).toBe("off");
  });

  test("ALLOW set to empty string → kind=active with empty union (default-deny)", () => {
    const state = buildAllowlistState("", undefined, new Set());
    expect(state.kind).toBe("active");
    if (state.kind === "active") {
      expect(state.allow).toHaveLength(0);
      expect(state.extra).toHaveLength(0);
    }
  });

  test("ALLOW unset but EXTRA set → kind=active (default-deny base + extras)", () => {
    const state = buildAllowlistState(undefined, "@adhoc.com", new Set());
    expect(state.kind).toBe("active");
    if (state.kind === "active") {
      expect(state.allow).toHaveLength(0);
      expect(state.extra).toHaveLength(1);
    }
  });

  test("self-emails defensively copied (caller can't mutate state)", () => {
    const original = new Set(["a@b.com"]);
    const state = buildAllowlistState("@c.com", undefined, original);
    original.add("d@e.com");
    if (state.kind === "active") {
      expect(state.selfEmails.has("d@e.com")).toBe(false);
    }
  });
});

// ----- summarizeAllowlist -----

describe("summarizeAllowlist", () => {
  test("off-state summary is all zeros", () => {
    const s = summarizeAllowlist({ kind: "off" });
    expect(s.kind).toBe("off");
    expect(s.allow_count).toBe(0);
    expect(s.self_implicit_count).toBe(0);
  });

  test("active-state summary categorizes counts correctly", () => {
    const state = buildAllowlistState(
      "@a.com, alice@b.com, @c.com",
      "extra@d.com",
      new Set(["self@me.com", "self2@me.com"]),
    );
    const s = summarizeAllowlist(state);
    expect(s.kind).toBe("active");
    expect(s.allow_count).toBe(3);
    expect(s.allow_domain_count).toBe(2);
    expect(s.allow_email_count).toBe(1);
    expect(s.extra_count).toBe(1);
    expect(s.extra_email_count).toBe(1);
    expect(s.self_implicit_count).toBe(2);
  });

  test("summary contains NO entry values (sec-rev invariant)", () => {
    const state = buildAllowlistState(
      "SECRET-CANARY@secret.com, @SECRET-CANARY-DOMAIN.com",
      "EXTRA-CANARY@x.com",
      new Set(["SELF-CANARY@me.com"]),
    );
    const s = summarizeAllowlist(state);
    const serialized = JSON.stringify(s);
    expect(serialized).not.toContain("SECRET-CANARY");
    expect(serialized).not.toContain("EXTRA-CANARY");
    expect(serialized).not.toContain("SELF-CANARY");
  });
});

// ----- getAllowlistState singleton -----

describe("getAllowlistState", () => {
  test("returns off when env unset (default)", async () => {
    const state = await getAllowlistState();
    expect(state.kind).toBe("off");
  });

  test("returns active when ALLOW set in process.env", async () => {
    process.env[ENV_ALLOW] = "@client.com";
    __internal.resetSingletons();
    const state = await getAllowlistState();
    expect(state.kind).toBe("active");
  });

  test("returns active when ALLOW empty string (explicit default-deny)", async () => {
    process.env[ENV_ALLOW] = "";
    __internal.resetSingletons();
    const state = await getAllowlistState();
    expect(state.kind).toBe("active");
  });

  test("singleton — second call returns same promise", async () => {
    process.env[ENV_ALLOW] = "@a.com";
    __internal.resetSingletons();
    const p1 = getAllowlistState();
    const p2 = getAllowlistState();
    expect(p1).toBe(p2);
  });

  test("resetSingletons forces reload (env change pickup)", async () => {
    process.env[ENV_ALLOW] = "@first.com";
    __internal.resetSingletons();
    const state1 = await getAllowlistState();
    process.env[ENV_ALLOW] = "@second.com";
    // Without reset, cached state1 still has @first.com only.
    const stillCached = await getAllowlistState();
    expect(stillCached).toBe(state1);
    // After reset, second load picks up new env.
    __internal.resetSingletons();
    const state2 = await getAllowlistState();
    if (state2.kind === "active") {
      const domains = state2.allow
        .filter((e) => e.kind === "domain")
        .map((e) => (e as { kind: "domain"; domain: string }).domain);
      expect(domains).toContain("second.com");
    }
  });
});

// ----- sec-rev PR-A MEDIUM mitigations (verified at PR-B integration) -----

describe("sec-rev mitigations", () => {
  test("MEDIUM #2: warn log fires when EXTRA set but ALLOW unset", async () => {
    process.env[ENV_ALLOW_EXTRA] = "@adhoc.com";
    // ENV_ALLOW intentionally unset
    __internal.resetSingletons();

    const messages: string[] = [];
    const orig = console.error;
    console.error = (...args: unknown[]) => {
      messages.push(args.map((a) => String(a)).join(" "));
    };

    try {
      await getAllowlistState();
    } finally {
      console.error = orig;
    }

    const warned = messages.some((m) =>
      m.includes("SAFESPACE_RECIPIENT_ALLOW_EXTRA is set but"),
    );
    expect(warned).toBe(true);
  });

  test("MEDIUM #2: warn log does NOT fire when both ALLOW and EXTRA set", async () => {
    process.env[ENV_ALLOW] = "@global.com";
    process.env[ENV_ALLOW_EXTRA] = "@adhoc.com";
    __internal.resetSingletons();

    const messages: string[] = [];
    const orig = console.error;
    console.error = (...args: unknown[]) => {
      messages.push(args.map((a) => String(a)).join(" "));
    };

    try {
      await getAllowlistState();
    } finally {
      console.error = orig;
    }

    const warned = messages.some((m) =>
      m.includes("SAFESPACE_RECIPIENT_ALLOW_EXTRA is set but"),
    );
    expect(warned).toBe(false);
  });

  test("MEDIUM #2: warn log does NOT fire when only ALLOW set (normal case)", async () => {
    process.env[ENV_ALLOW] = "@global.com";
    __internal.resetSingletons();

    const messages: string[] = [];
    const orig = console.error;
    console.error = (...args: unknown[]) => {
      messages.push(args.map((a) => String(a)).join(" "));
    };

    try {
      await getAllowlistState();
    } finally {
      console.error = orig;
    }

    const warned = messages.some((m) =>
      m.includes("SAFESPACE_RECIPIENT_ALLOW_EXTRA is set but"),
    );
    expect(warned).toBe(false);
  });

  test("MEDIUM #1: summarize never exposes parser-rejected tokens", () => {
    // Rejected tokens (bare domain) must not appear anywhere in the summary
    // output — they're held only in ParseResult.rejected which the public
    // summary API does not surface.
    const stateWithRejected = buildAllowlistState(
      "REJECTED-CANARY.com, @ok.com, REJECTED-CANARY-2.com",
      undefined,
      new Set(),
    );
    const summary = summarizeAllowlist(stateWithRejected);
    const serialized = JSON.stringify(summary);
    expect(serialized).not.toContain("REJECTED-CANARY");
    // Sanity: the one valid token did get counted.
    if (stateWithRejected.kind === "active") {
      expect(stateWithRejected.allow).toHaveLength(1);
    }
  });
});

// ----- integration: env semantic round-trip -----

describe("env-driven state semantics (parallels SAFESPACE_TIER)", () => {
  test("EXTRA-set-via-process.env behaves same as EXTRA-set-via-build-arg (sec-rev DX invariant)", () => {
    // Both paths must produce structurally identical states. The wizard
    // writes ALLOW to .env; users use EXTRA at shell. Both must compose.
    const direct = buildAllowlistState("@global.com", "@adhoc.com", new Set(["me@own.com"]));
    process.env[ENV_ALLOW] = "@global.com";
    process.env[ENV_ALLOW_EXTRA] = "@adhoc.com";
    const viaEnv = buildAllowlistState(
      process.env[ENV_ALLOW],
      process.env[ENV_ALLOW_EXTRA],
      new Set(["me@own.com"]),
    );
    expect(direct.kind).toBe(viaEnv.kind);
    if (direct.kind === "active" && viaEnv.kind === "active") {
      expect(direct.allow).toEqual(viaEnv.allow);
      expect(direct.extra).toEqual(viaEnv.extra);
      expect(direct.selfEmails.size).toBe(viaEnv.selfEmails.size);
    }
  });

  test("compliance-hold scenario: SAFESPACE_RECIPIENT_ALLOW=legal@x.com replaces global", () => {
    const baselineState = buildAllowlistState(
      "@my-company.com, @vendor.com",
      undefined,
      new Set(),
    );
    expect(isRecipientAllowed("anyone@my-company.com", baselineState)).toBe(true);

    // Compliance hold: only legal@ allowed today.
    const overrideState = buildAllowlistState(
      "legal@my-company.com",
      undefined,
      new Set(),
    );
    expect(isRecipientAllowed("anyone@my-company.com", overrideState)).toBe(false);
    expect(isRecipientAllowed("legal@my-company.com", overrideState)).toBe(true);
  });

  test("explicit empty SAFESPACE_RECIPIENT_ALLOW + EXTRA: only EXTRA + self allowed", () => {
    const state = buildAllowlistState("", "@temp.com", new Set(["me@own.com"]));
    expect(isRecipientAllowed("anyone@temp.com", state)).toBe(true);
    expect(isRecipientAllowed("me@own.com", state)).toBe(true);
    expect(isRecipientAllowed("anyone@anywhere.com", state)).toBe(false);
  });
});

// ───────────────── v1.53 F2 — autonomous/strict mode flip ─────────────────
describe("buildAllowlistState — v1.53 F2 autonomous flip", () => {
  const ENV_AUTO = ENV_AUTONOMOUS;
  let autoBackup: string | undefined;
  beforeEach(() => {
    autoBackup = process.env[ENV_AUTO];
    delete process.env[ENV_AUTO];
    __internal.resetSingletons();
  });
  afterEach(() => {
    if (autoBackup === undefined) delete process.env[ENV_AUTO];
    else process.env[ENV_AUTO] = autoBackup;
    __internal.resetSingletons();
  });

  test("autonomous=false + both env undefined → off (byte-identical to today)", () => {
    expect(buildAllowlistState(undefined, undefined, new Set(["me@own.com"]))).toEqual({
      kind: "off",
    });
  });

  test("autonomous=true + both env undefined → active-empty: external denied, self allowed", () => {
    const state = buildAllowlistState(undefined, undefined, new Set(["me@own.com"]), true);
    expect(state.kind).toBe("active");
    expect(isRecipientAllowed("stranger@elsewhere.com", state)).toBe(false);
    expect(isRecipientAllowed("me@own.com", state)).toBe(true); // self-send still allowed
  });

  test("autonomous=true still honors an explicit allowlist entry", () => {
    const state = buildAllowlistState("@client.com", undefined, new Set(), true);
    expect(isRecipientAllowed("bob@client.com", state)).toBe(true);
    expect(isRecipientAllowed("bob@other.com", state)).toBe(false);
  });

  test("loader wiring: SAFESPACE_AUTONOMOUS=true makes getAllowlistState() active (flag is read)", async () => {
    // Pins the loadAllowlistFromEnvAndDisk → isAutonomousMode() wiring. Drop
    // the arg and the state would be "off" (allow-all) despite the flag.
    process.env[ENV_AUTO] = "true";
    const state = await getAllowlistState();
    expect(state.kind).toBe("active");
    expect(isRecipientAllowed("stranger@elsewhere.com", state)).toBe(false);
  });

  test("loader wiring: a typo'd flag ('True') leaves getAllowlistState() off (allow-all)", async () => {
    process.env[ENV_AUTO] = "True";
    const state = await getAllowlistState();
    expect(state.kind).toBe("off");
  });
});

// ----- v1.80 PR-3 — the selfEmails partition (confineSelfTo) -----

describe("v1.80 PR-3 — isRecipientAllowed confineSelfTo (the selfEmails partition)", () => {
  // A deployment that consented two accounts; the calling operator is confined
  // (Model B allowedAccounts) to just ONE of them.
  const TWO_SELF: AllowlistState = {
    kind: "active",
    allow: [],
    extra: [],
    selfEmails: new Set(["mine@own.com", "theirs@own.com"]),
  };

  test("default (null) is byte-identical to the 2-arg form — every self email allowed", () => {
    expect(isRecipientAllowed("mine@own.com", TWO_SELF)).toBe(true);
    expect(isRecipientAllowed("theirs@own.com", TWO_SELF)).toBe(true);
    expect(isRecipientAllowed("mine@own.com", TWO_SELF, null)).toBe(true);
    expect(isRecipientAllowed("theirs@own.com", TWO_SELF, null)).toBe(true);
  });

  test("confined: a self email INSIDE the operator's set stays implicitly allowed", () => {
    expect(isRecipientAllowed("mine@own.com", TWO_SELF, new Set(["mine@own.com"]))).toBe(true);
  });

  test("confined: a self email OUTSIDE the operator's set is DENIED (the PR-2c gap closed)", () => {
    // Pre-v1.80: operator A (confined to mine@) could still send to theirs@
    // because the GLOBAL self set exempted it from the allowlist.
    expect(isRecipientAllowed("theirs@own.com", TWO_SELF, new Set(["mine@own.com"]))).toBe(false);
  });

  test("an EMPTY confinement set = zero self exemption (a no-accounts operator)", () => {
    expect(isRecipientAllowed("mine@own.com", TWO_SELF, new Set())).toBe(false);
    expect(isRecipientAllowed("theirs@own.com", TWO_SELF, new Set())).toBe(false);
  });

  test("the partition NEVER narrows the explicit allow/extra entries (membership ⟂ provenance)", () => {
    // theirs@own.com is BOTH a self email and an explicit allow entry; the
    // confinement only kills the self route — the explicit entry still admits it.
    const state = buildAllowlistState(
      "theirs@own.com",
      undefined,
      new Set(["mine@own.com", "theirs@own.com"]),
    );
    expect(isRecipientAllowed("theirs@own.com", state, new Set(["mine@own.com"]))).toBe(true);
    // Same via the EXTRA layer.
    const stateExtra = buildAllowlistState(
      "",
      "theirs@own.com",
      new Set(["mine@own.com", "theirs@own.com"]),
    );
    expect(isRecipientAllowed("theirs@own.com", stateExtra, new Set(["mine@own.com"]))).toBe(true);
  });

  test("an off-state allowlist is unaffected by confinement (policy off = allow)", () => {
    const off: AllowlistState = { kind: "off" };
    expect(isRecipientAllowed("anyone@anywhere.com", off, new Set())).toBe(true);
  });

  test("a non-self, non-allowlisted recipient is denied the same way regardless of confinement (no oracle)", () => {
    expect(isRecipientAllowed("stranger@elsewhere.com", TWO_SELF)).toBe(false);
    expect(isRecipientAllowed("stranger@elsewhere.com", TWO_SELF, new Set(["mine@own.com"]))).toBe(false);
  });
});
