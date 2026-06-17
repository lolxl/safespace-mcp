// v1.64 Phase B (B2 — Credential union, D3b) unit tests.
//
// Pins the discriminated-union narrowing (`requireOAuth`) + the getter-not-field
// security property the codebase relies on (review #2 — JSON.stringify cannot
// leak the bearer token). The INTEGRATION of the oauth credential into
// withToolContext (resolve account → refresh → 401 force-refresh retry) is
// covered by with-context.test.ts, which now reads `requireOAuth(ctx).accountId` /
// `.getAccessToken()`; this file pins the union + helper in isolation.

import { describe, expect, test } from "bun:test";
import { requireGithub, requireGoogle, requireOAuth } from "./handlers/shared";
import type { Credential, ToolContext } from "./types";
import { NOOP_AUDIT, oauthCred } from "./test-audit";

type OAuthCred = Extract<Credential, { kind: "oauth" }>;

function ctxWith(credential: Credential): ToolContext {
  return { allowedAccounts: null, credential, tier: "read", audit: NOOP_AUDIT };
}

describe("Credential union + requireOAuth (B2)", () => {
  test("requireOAuth narrows an oauth credential → accountId + LIVE token getter", () => {
    let token = "tok-1";
    const ctx = ctxWith({
      kind: "oauth",
      provider: "google",
      accountId: "alice@example.com",
      getAccessToken: () => token,
    });
    const cred = requireOAuth(ctx);
    expect(cred.kind).toBe("oauth");
    expect(cred.accountId).toBe("alice@example.com");
    expect(cred.getAccessToken()).toBe("tok-1");
    // The getter reads live state — mirrors with-context.ts reassigning
    // `tokenSet` on a 401 force-refresh under the same closure, so a handler
    // re-invoked after refresh sees the NEW token (byte-identical to the
    // pre-B2 `ctx.getAccessToken` field semantics).
    token = "tok-2";
    expect(cred.getAccessToken()).toBe("tok-2");
  });

  test("requireOAuth throws on a non-oauth credential (R6 — no fabricated email/token)", () => {
    expect(() => requireOAuth(ctxWith({ kind: "none" }))).toThrow(
      /requires an OAuth credential/,
    );
    expect(() =>
      requireOAuth(ctxWith({ kind: "service-token", token: () => "t" })),
    ).toThrow(/requires an OAuth credential/);
  });

  test("the bearer token is a GETTER, not a serializable field (review #2)", () => {
    const oauthCtx = ctxWith({
      kind: "oauth",
      provider: "google",
      accountId: "alice@example.com",
      getAccessToken: () => "ya29.OAUTH_SECRET",
    });
    // JSON.stringify drops functions → an accidental ToolContext / Credential
    // serialization (logging, audit, JSON-RPC error data) cannot leak the token.
    expect(JSON.stringify(oauthCtx)).not.toContain("ya29.OAUTH_SECRET");
    expect(JSON.stringify(oauthCtx.credential)).not.toContain("ya29.OAUTH_SECRET");

    // Same property for the (not-yet-wired) service-token variant: `token` is a
    // getter, so the Phase-C connector inherits the no-token-at-rest guarantee.
    const svcCred: Credential = { kind: "service-token", token: () => "bot:SECRET" };
    expect(JSON.stringify(svcCred)).not.toContain("bot:SECRET");
  });

  test("oauthCred test helper builds the oauth variant", () => {
    const c = oauthCred("bob@example.com", () => "tok");
    expect(c).toMatchObject({ kind: "oauth", provider: "google", accountId: "bob@example.com" });
    expect((c as OAuthCred).getAccessToken()).toBe("tok");
  });
});

describe("requireGoogle / requireGithub — the cross-provider-token backstop (v1.70 G2, thesis R8)", () => {
  const googleCred: Credential = {
    kind: "oauth", provider: "google", accountId: "alice@example.com", getAccessToken: () => "g",
  };
  const githubCred: Credential = {
    kind: "oauth", provider: "github", accountId: "octocat", getAccessToken: () => "gh",
  };

  test("requireGoogle returns a google oauth credential", () => {
    const c = requireGoogle(ctxWith(googleCred));
    expect(c.provider).toBe("google");
    expect(c.accountId).toBe("alice@example.com");
  });

  test("requireGoogle THROWS on a github credential — a GitHub bearer can never reach a googleapis handler", () => {
    expect(() => requireGoogle(ctxWith(githubCred))).toThrow(/received a 'github'/);
  });

  test("requireGithub returns a github oauth credential", () => {
    const c = requireGithub(ctxWith(githubCred));
    expect(c.provider).toBe("github");
    expect(c.accountId).toBe("octocat");
  });

  test("requireGithub THROWS on a google credential", () => {
    expect(() => requireGithub(ctxWith(googleCred))).toThrow(/received a 'google'/);
  });

  test("both still throw on a non-oauth credential (the base requireOAuth guard fires first)", () => {
    expect(() => requireGoogle(ctxWith({ kind: "none" }))).toThrow(/requires an OAuth credential/);
    expect(() =>
      requireGithub(ctxWith({ kind: "service-token", token: () => "t" })),
    ).toThrow(/requires an OAuth credential/);
  });
});
