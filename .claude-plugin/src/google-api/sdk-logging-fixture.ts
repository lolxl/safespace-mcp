// Subprocess fixture for sdk-logging.test.ts — NOT a test file.
//
// Drives the REAL google-auth-library / googleapis interceptors (no gaxios mock)
// with only the network replaced by an in-memory `fetch` that returns SENTINEL
// credential / user-data bodies. The parent runs it with
// GOOGLE_SDK_NODE_LOGGING=* and asserts no sentinel reaches stdout/stderr.
//
// Imports are DYNAMIC and go through the production modules (auth/consent.ts,
// google-api/client.ts) so the logging guard is exercised exactly where
// production loads the libraries; this file never imports the guard itself.
//
// Usage: bun run sdk-logging-fixture.ts token_exchange | api_call
// Prints one sentinel-free JSON line: {"ok":true,"scenario":...}

export const SENTINEL_ACCESS = "SENTINEL-ACCESS-TOKEN-7f3a";
export const SENTINEL_REFRESH = "SENTINEL-REFRESH-TOKEN-9c1d";
export const SENTINEL_ID = "SENTINEL-ID-TOKEN-2b8e";
export const SENTINEL_USERDATA = "SENTINEL-USER-DATA-4e6f";

const json = (body: unknown): Response =>
  new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });

globalThis.fetch = (async (input: unknown) => {
  const url = String(input);
  if (url.includes("oauth2.googleapis.com/token")) {
    return json({
      access_token: SENTINEL_ACCESS,
      refresh_token: SENTINEL_REFRESH,
      id_token: SENTINEL_ID,
      expires_in: 3599,
      token_type: "Bearer",
      scope: "openid",
    });
  }
  return json({ id: "1FileAAAAAAAAAAAAAAAAAA", name: SENTINEL_USERDATA, mimeType: "text/plain" });
}) as typeof fetch;

const scenario = process.argv[2];
try {
  if (scenario === "token_exchange") {
    await import("../auth/consent"); // production loader of google-auth-library
    const { OAuth2Client } = await import("google-auth-library");
    const oauth = new OAuth2Client({ clientId: "cid", clientSecret: "csecret", redirectUri: "http://127.0.0.1/cb" });
    const { tokens } = await oauth.getToken({ code: "code", codeVerifier: "v".repeat(43) });
    if (tokens.access_token !== SENTINEL_ACCESS) throw new Error("token exchange did not return the sentinel");
  } else if (scenario === "consent") {
    // Real consent(): must refuse BEFORE any network / browser step when SDK
    // logging was requested but could not be disabled.
    const { consent } = await import("../auth/consent");
    await consent("alice@example.com");
  } else if (scenario === "api_call") {
    const { driveClientFromToken } = await import("./client"); // lazy googleapis
    const res = await driveClientFromToken(SENTINEL_ACCESS).files.get({ fileId: "1FileAAAAAAAAAAAAAAAAAA" });
    if (res.data.name !== SENTINEL_USERDATA) throw new Error("api call did not return the sentinel");
  } else {
    throw new Error(`unknown scenario ${scenario}`);
  }
  console.log(JSON.stringify({ ok: true, scenario }));
} catch (err) {
  console.log(JSON.stringify({ ok: false, scenario, error: String((err as Error)?.message ?? err) }));
  process.exitCode = 1;
}
