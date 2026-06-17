/**
 * Tests for `getGmailClient` / `getDriveClient` — the googleapis SDK factories.
 *
 * Uses the gaxios mock from `./test-utils` to verify that:
 *   - The factories return SDK clients backed by `getAuthClient`'s OAuth2Client
 *   - API calls actually dispatch through the mocked transport
 *   - Auth failures (account_not_found, etc.) propagate without invoking gaxios
 *
 * IMPORTANT: googleapis caches gaxios at module load. To ensure our mock
 * is in place BEFORE googleapis resolves gaxios, we (a) import test-utils
 * first (its top-level `mock.module` call runs), and (b) dynamically import
 * `./client` INSIDE each test, AFTER setGaxiosHandler is configured.
 */

// Step 1: install the gaxios mock at module load (top-level mock.module in
// test-utils.ts runs when this import is evaluated).
import {
  setGaxiosHandler,
  resetGaxiosHandler,
} from "./test-utils";
import { describe, test, expect, beforeEach, afterEach } from "bun:test";
import type { AuthDeps } from "./auth";
import { MCPError } from "../errors";

const FAKE_EMAIL = "client-test@example.com";
const FAKE_CLIENT_ID = "1234567890-fake.apps.googleusercontent.com";
const FAKE_CLIENT_SECRET = "GOCSPX-fake-secret";

function freshTokenDeps(): AuthDeps {
  return {
    getToken: async () =>
      JSON.stringify({
        refresh_token: "1//rt_fake",
        access_token: "ya29.fake-at",
        expires_at: Date.now() + 60 * 60 * 1000,
        scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
        obtained_at: Date.now(),
      }),
  };
}

describe("client factories", () => {
  let prevClientId: string | undefined;
  let prevClientSecret: string | undefined;

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

  test("getGmailClient returns a Gmail v1 client that dispatches through gaxios mock", async () => {
    setGaxiosHandler(async (opts) => {
      expect(opts.url).toContain("/gmail/v1/users/me/labels");
      return {
        data: { labels: [{ id: "MOCK1", name: "MockLabel" }] },
        status: 200,
      };
    });

    // Dynamic import — guarantees `./client` (and transitively googleapis +
    // gaxios) loads AFTER test-utils' mock.module has been registered AND
    // beforeEach has configured the handler.
    const { getGmailClient } = await import("./client");
    const gmail = await getGmailClient(FAKE_EMAIL, freshTokenDeps());
    const res = await gmail.users.labels.list({ userId: "me" });
    expect(res.data.labels).toEqual([{ id: "MOCK1", name: "MockLabel" }]);
  });

  test("getDriveClient returns a Drive v3 client that dispatches through gaxios mock", async () => {
    setGaxiosHandler(async (opts) => {
      expect(opts.url).toContain("/drive/v3/files");
      return {
        data: { files: [{ id: "FILE1", name: "Doc.pdf", mimeType: "application/pdf" }] },
        status: 200,
      };
    });

    const { getDriveClient } = await import("./client");
    const drive = await getDriveClient(FAKE_EMAIL, freshTokenDeps());
    const res = await drive.files.list({ pageSize: 1 });
    expect(res.data.files).toEqual([
      { id: "FILE1", name: "Doc.pdf", mimeType: "application/pdf" },
    ]);
  });

  test("auth failure (account_not_found) propagates before gaxios is invoked", async () => {
    let handlerCalled = false;
    setGaxiosHandler(() => {
      handlerCalled = true;
      return { data: {}, status: 200 };
    });

    const deps: AuthDeps = {
      getToken: async () => null, // keychain miss
    };

    const { getGmailClient } = await import("./client");
    try {
      await getGmailClient(FAKE_EMAIL, deps);
      throw new Error("expected throw");
    } catch (e) {
      expect(e).toBeInstanceOf(MCPError);
      expect((e as MCPError).errorName).toBe("account_not_found");
    }
    expect(handlerCalled).toBe(false); // never reached the transport layer
  });

  test("multiple clients use independent OAuth2Client instances", async () => {
    let labelsCalls = 0;
    let filesCalls = 0;
    setGaxiosHandler(async (opts) => {
      if (opts.url?.includes("/labels")) {
        labelsCalls++;
        return { data: { labels: [] }, status: 200 };
      }
      if (opts.url?.includes("/files")) {
        filesCalls++;
        return { data: { files: [] }, status: 200 };
      }
      return { data: {}, status: 200 };
    });

    const { getGmailClient, getDriveClient } = await import("./client");
    const gmail = await getGmailClient(FAKE_EMAIL, freshTokenDeps());
    const drive = await getDriveClient(FAKE_EMAIL, freshTokenDeps());

    await gmail.users.labels.list({ userId: "me" });
    await drive.files.list({ pageSize: 1 });

    expect(labelsCalls).toBe(1);
    expect(filesCalls).toBe(1);
  });

  test("getGmailClient forwards force:true through AuthDeps", async () => {
    let refreshCount = 0;
    const deps: AuthDeps = {
      getToken: async () =>
        JSON.stringify({
          refresh_token: "1//rt_fake",
          access_token: "ya29.fake-at",
          expires_at: Date.now() + 60 * 60 * 1000, // fresh
          scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
          obtained_at: Date.now(),
        }),
      setToken: async () => {},
      deleteToken: async () => {},
      removeAccount: async () => {},
      fetchImpl: (async () => {
        refreshCount++;
        return new Response(
          JSON.stringify({
            access_token: "ya29.forced",
            expires_in: 3600,
            scope: "https://www.googleapis.com/auth/gmail.readonly",
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }) as unknown as typeof fetch,
      force: true, // force refresh even though cached token is fresh
    };
    setGaxiosHandler(async () => ({ data: { labels: [] }, status: 200 }));

    const { getGmailClient } = await import("./client");
    await getGmailClient(FAKE_EMAIL, deps);
    expect(refreshCount).toBe(1); // force kicked in
  });
});
