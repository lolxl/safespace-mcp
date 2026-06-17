/**
 * Tests for `getAuthClient` + `withGoogleApi` — the googleapis OAuth2Client
 * factory and the 401-retry wrapper.
 *
 * Uses the existing `RefreshDeps` DI seam in `../auth/refresh.ts` to inject
 * fake Keychain + fetch implementations. NO real Keychain access, NO real
 * Google OAuth endpoint calls. For withGoogleApi tests, uses the gaxios
 * mock via test-utils to simulate 401 / 403 / other API responses.
 */

import {
  setGaxiosHandler,
  resetGaxiosHandler,
  makeGaxiosError,
} from "./test-utils";
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import { getAuthClient, type AuthDeps } from "./auth";
import { MCPError } from "../errors";

const FAKE_EMAIL = "spike@example.com";
const FAKE_CLIENT_ID = "1234567890-fake.apps.googleusercontent.com";
const FAKE_CLIENT_SECRET = "GOCSPX-fake-secret";

function freshTokenJson(): string {
  return JSON.stringify({
    refresh_token: "1//rt_fake",
    access_token: "ya29.fake-at",
    expires_at: Date.now() + 60 * 60 * 1000, // 1 hour
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    obtained_at: Date.now(),
  });
}

function expiredTokenJson(): string {
  return JSON.stringify({
    refresh_token: "1//rt_fake",
    access_token: "ya29.expired-at",
    expires_at: Date.now() - 60 * 1000, // 1 minute ago
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    obtained_at: Date.now() - 60 * 60 * 1000,
  });
}

describe("getAuthClient", () => {
  let prevClientId: string | undefined;
  let prevClientSecret: string | undefined;

  beforeEach(() => {
    prevClientId = process.env.GOOGLE_CLIENT_ID;
    prevClientSecret = process.env.GOOGLE_CLIENT_SECRET;
    process.env.GOOGLE_CLIENT_ID = FAKE_CLIENT_ID;
    process.env.GOOGLE_CLIENT_SECRET = FAKE_CLIENT_SECRET;
  });

  afterEach(() => {
    if (prevClientId === undefined) delete process.env.GOOGLE_CLIENT_ID;
    else process.env.GOOGLE_CLIENT_ID = prevClientId;
    if (prevClientSecret === undefined) delete process.env.GOOGLE_CLIENT_SECRET;
    else process.env.GOOGLE_CLIENT_SECRET = prevClientSecret;
  });

  test("happy path — returns OAuth2Client with credentials set", async () => {
    const deps: AuthDeps = {
      getToken: async () => freshTokenJson(),
    };
    const oauth = await getAuthClient(FAKE_EMAIL, deps);
    const creds = oauth.credentials;
    expect(creds.access_token).toBe("ya29.fake-at");
    expect(creds.refresh_token).toBe("1//rt_fake");
    expect(creds.token_type).toBe("Bearer");
    expect(creds.scope).toBe("https://www.googleapis.com/auth/gmail.readonly");
    expect(typeof creds.expiry_date).toBe("number");
  });

  test("missing GOOGLE_CLIENT_ID → throws explicit error", async () => {
    delete process.env.GOOGLE_CLIENT_ID;
    const deps: AuthDeps = {
      getToken: async () => freshTokenJson(),
    };
    await expect(getAuthClient(FAKE_EMAIL, deps)).rejects.toThrow(
      /GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables required/,
    );
  });

  test("missing GOOGLE_CLIENT_SECRET → throws explicit error", async () => {
    delete process.env.GOOGLE_CLIENT_SECRET;
    const deps: AuthDeps = {
      getToken: async () => freshTokenJson(),
    };
    await expect(getAuthClient(FAKE_EMAIL, deps)).rejects.toThrow(
      /GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables required/,
    );
  });

  test("account_not_found from refresh propagates", async () => {
    const deps: AuthDeps = {
      getToken: async () => null, // simulate keychain miss
    };
    try {
      await getAuthClient(FAKE_EMAIL, deps);
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("account_not_found");
      expect((e as MCPError).errorData).toEqual({ email: FAKE_EMAIL });
    }
  });

  test("refresh_token_invalid from refresh propagates", async () => {
    const deps: AuthDeps = {
      getToken: async () => expiredTokenJson(),
      setToken: async () => {},
      deleteToken: async () => {},
      removeAccount: async () => {},
      fetchImpl: (async () =>
        new Response(JSON.stringify({ error: "invalid_grant" }), {
          status: 400,
          headers: { "Content-Type": "application/json" },
        })) as unknown as typeof fetch,
    };
    try {
      await getAuthClient(FAKE_EMAIL, deps);
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("refresh_token_invalid");
    }
  });

  test("expired token triggers refresh, new access_token reflected on client", async () => {
    let writeBackCount = 0;
    let writtenJson = "";
    const deps: AuthDeps = {
      getToken: async () => expiredTokenJson(),
      setToken: async (_email, json) => {
        writeBackCount++;
        writtenJson = json;
      },
      deleteToken: async () => {},
      removeAccount: async () => {},
      fetchImpl: (async () =>
        new Response(
          JSON.stringify({
            access_token: "ya29.refreshed-at",
            expires_in: 3600,
            scope: "https://www.googleapis.com/auth/gmail.readonly",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        )) as unknown as typeof fetch,
    };
    const oauth = await getAuthClient(FAKE_EMAIL, deps);
    expect(oauth.credentials.access_token).toBe("ya29.refreshed-at");
    expect(writeBackCount).toBe(1);
    const parsed = JSON.parse(writtenJson);
    expect(parsed.access_token).toBe("ya29.refreshed-at");
  });

  test("force: true bypasses skip-when-valid cache", async () => {
    let refreshCount = 0;
    const deps: AuthDeps = {
      getToken: async () => freshTokenJson(),
      setToken: async () => {},
      deleteToken: async () => {},
      removeAccount: async () => {},
      fetchImpl: (async () => {
        refreshCount++;
        return new Response(
          JSON.stringify({
            access_token: "ya29.forced-at",
            expires_in: 3600,
            scope: "https://www.googleapis.com/auth/gmail.readonly",
          }),
          {
            status: 200,
            headers: { "Content-Type": "application/json" },
          },
        );
      }) as unknown as typeof fetch,
      force: true,
    };
    const oauth = await getAuthClient(FAKE_EMAIL, deps);
    expect(refreshCount).toBe(1);
    expect(oauth.credentials.access_token).toBe("ya29.forced-at");
  });

  test("without force, fresh token skips refresh entirely", async () => {
    let refreshCount = 0;
    const deps: AuthDeps = {
      getToken: async () => freshTokenJson(),
      setToken: async () => {},
      fetchImpl: (async () => {
        refreshCount++;
        return new Response("{}", { status: 200 });
      }) as unknown as typeof fetch,
    };
    const oauth = await getAuthClient(FAKE_EMAIL, deps);
    expect(refreshCount).toBe(0); // skip-when-valid kicked in
    expect(oauth.credentials.access_token).toBe("ya29.fake-at");
  });

  test("scopes joined with single space (OAuth2Client format)", async () => {
    const deps: AuthDeps = {
      getToken: async () =>
        JSON.stringify({
          refresh_token: "1//rt_fake",
          access_token: "ya29.fake-at",
          expires_at: Date.now() + 60 * 60 * 1000,
          scopes: [
            "https://www.googleapis.com/auth/gmail.readonly",
            "https://www.googleapis.com/auth/drive.readonly",
            "openid",
          ],
          obtained_at: Date.now(),
        }),
    };
    const oauth = await getAuthClient(FAKE_EMAIL, deps);
    expect(oauth.credentials.scope).toBe(
      "https://www.googleapis.com/auth/gmail.readonly https://www.googleapis.com/auth/drive.readonly openid",
    );
  });
});

describe("withGoogleApi — 401 retry wrapper", () => {
  let prevClientId: string | undefined;
  let prevClientSecret: string | undefined;

  function freshTokenDeps(): AuthDeps {
    return {
      getToken: async () => freshTokenJson(),
    };
  }

  beforeEach(() => {
    prevClientId = process.env.GOOGLE_CLIENT_ID;
    prevClientSecret = process.env.GOOGLE_CLIENT_SECRET;
    process.env.GOOGLE_CLIENT_ID = FAKE_CLIENT_ID;
    process.env.GOOGLE_CLIENT_SECRET = FAKE_CLIENT_SECRET;
    resetGaxiosHandler();
  });

  afterEach(() => {
    if (prevClientId === undefined) delete process.env.GOOGLE_CLIENT_ID;
    else process.env.GOOGLE_CLIENT_ID = prevClientId;
    if (prevClientSecret === undefined) delete process.env.GOOGLE_CLIENT_SECRET;
    else process.env.GOOGLE_CLIENT_SECRET = prevClientSecret;
    resetGaxiosHandler();
  });

  test("happy path — fn succeeds on first attempt, no retry", async () => {
    let fnCalls = 0;
    setGaxiosHandler(async () => ({ data: { labels: [{ id: "L1", name: "Label1" }] }, status: 200 }));

    const { withGoogleApi } = await import("./auth");
    const result = await withGoogleApi(
      FAKE_EMAIL,
      "test_tool",
      async (auth) => {
        fnCalls++;
        // Use the auth client to make a real (mocked) API call so gaxios runs.
        const { google } = await import("googleapis");
        const gmail = google.gmail({ version: "v1", auth });
        return (await gmail.users.labels.list({ userId: "me" })).data;
      },
      freshTokenDeps(),
    );

    expect(result).toEqual({ labels: [{ id: "L1", name: "Label1" }] });
    expect(fnCalls).toBe(1);
  });

  test("401 on first attempt → force refresh → retry once → succeeds", async () => {
    let fnCalls = 0;
    let refreshCalls = 0;
    setGaxiosHandler(async () => {
      fnCalls++;
      if (fnCalls === 1) {
        throw makeGaxiosError({ status: 401, errorMessage: "Token expired" });
      }
      return { data: { labels: [{ id: "RECOVERED", name: "Recovered" }] }, status: 200 };
    });

    const deps: AuthDeps = {
      getToken: async () => freshTokenJson(),
      setToken: async () => {},
      deleteToken: async () => {},
      removeAccount: async () => {},
      fetchImpl: (async () => {
        refreshCalls++;
        return new Response(
          JSON.stringify({
            access_token: "ya29.refreshed-after-401",
            expires_in: 3600,
            scope: "https://www.googleapis.com/auth/gmail.readonly",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }) as unknown as typeof fetch,
    };

    const { withGoogleApi } = await import("./auth");
    const result = await withGoogleApi(
      FAKE_EMAIL,
      "test_tool",
      async (auth) => {
        const { google } = await import("googleapis");
        const gmail = google.gmail({ version: "v1", auth });
        return (await gmail.users.labels.list({ userId: "me" })).data;
      },
      deps,
    );

    expect(result).toEqual({ labels: [{ id: "RECOVERED", name: "Recovered" }] });
    expect(fnCalls).toBe(2); // initial + retry
    expect(refreshCalls).toBe(1); // exactly one force refresh between attempts
  });

  test("403 (non-401) → mapped via mapGoogleError → does NOT retry", async () => {
    let fnCalls = 0;
    setGaxiosHandler(async () => {
      fnCalls++;
      throw makeGaxiosError({
        status: 403,
        errorStatus: "PERMISSION_DENIED",
        errors: [{ reason: "insufficientPermissions" }],
      });
    });

    const { withGoogleApi } = await import("./auth");
    try {
      await withGoogleApi(
        FAKE_EMAIL,
        "test_tool",
        async (auth) => {
          const { google } = await import("googleapis");
          const gmail = google.gmail({ version: "v1", auth });
          return (await gmail.users.labels.list({ userId: "me" })).data;
        },
        freshTokenDeps(),
      );
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("scope_mismatch");
    }
    expect(fnCalls).toBe(1); // no retry on non-401
  });

  test("401 on retry too → propagates final error via mapGoogleError", async () => {
    let fnCalls = 0;
    setGaxiosHandler(async () => {
      fnCalls++;
      throw makeGaxiosError({ status: 401, errorMessage: "Still expired" });
    });

    const deps: AuthDeps = {
      getToken: async () => freshTokenJson(),
      setToken: async () => {},
      deleteToken: async () => {},
      removeAccount: async () => {},
      fetchImpl: (async () =>
        new Response(
          JSON.stringify({
            access_token: "ya29.refreshed-still-bad",
            expires_in: 3600,
            scope: "https://www.googleapis.com/auth/gmail.readonly",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        )) as unknown as typeof fetch,
    };

    const { withGoogleApi } = await import("./auth");
    try {
      await withGoogleApi(
        FAKE_EMAIL,
        "stuck_tool",
        async (auth) => {
          const { google } = await import("googleapis");
          const gmail = google.gmail({ version: "v1", auth });
          return (await gmail.users.labels.list({ userId: "me" })).data;
        },
        deps,
      );
      throw new Error("expected throw");
    } catch (e) {
      // mapGoogleError maps 401 → Error("google_api_unauthorized_<tool>")
      expect((e as Error).message).toContain("google_api_unauthorized_stuck_tool");
    }
    expect(fnCalls).toBe(2); // initial + one retry, then propagate
  });
});
