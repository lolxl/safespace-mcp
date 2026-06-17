// v1.70 (G3) — the extracted shared loopback callback server. These tests are NEW
// coverage for the module that was module-private inside consent.ts (where it was
// only exercised transitively by the Google consent flow); the Google consent.test.ts
// D2 path still proves the consent.ts re-point is behavior-preserving.

import { afterEach, describe, expect, test } from "bun:test";
import { startCallbackServer, type CallbackServer } from "./oauth-callback";

// Track for teardown; tests use a non-null local `s` so control-flow narrowing
// survives `await` suspension points.
let active: CallbackServer | null = null;
async function start(state: string): Promise<CallbackServer> {
  active = await startCallbackServer(state);
  return active;
}

afterEach(() => {
  active?.stop();
  active = null;
});

describe("startCallbackServer", () => {
  test("binds 127.0.0.1 on an ephemeral port with a /callback path", async () => {
    const s = await start("state-1");
    expect(s.url).toMatch(/^http:\/\/127\.0\.0\.1:\d+\/callback$/);
  });

  test("resolves with the code when state matches", async () => {
    const s = await start("st-ok");
    const resp = await fetch(`${s.url}?code=abc123&state=st-ok`);
    expect(resp.status).toBe(200);
    expect(await s.await).toEqual({ code: "abc123" });
  });

  // Capture the server promise's rejection as a VALUE the moment the server
  // starts (so it's never momentarily unhandled when the request triggers it,
  // and we don't depend on the `expect().rejects` matcher's await timing).
  function captureRejection(s: CallbackServer): Promise<Error> {
    return s.await.then(
      () => { throw new Error("expected the callback to reject, but it resolved"); },
      (e: Error) => e,
    );
  }

  test("rejects on state mismatch (CSRF guard), returns 400", async () => {
    const s = await start("expected");
    const settled = captureRejection(s);
    const resp = await fetch(`${s.url}?code=abc&state=attacker`);
    expect(resp.status).toBe(400);
    expect((await settled).message).toMatch(/state_mismatch/);
  });

  test("rejects on ?error=, reflecting it into NEITHER the body NOR the Error message", async () => {
    const s = await start("st");
    const settled = captureRejection(s);
    const resp = await fetch(`${s.url}?error=access_denied<script>`);
    expect(resp.status).toBe(200);
    const body = await resp.text();
    expect(body).not.toContain("access_denied");
    expect(body).not.toContain("<script>");
    // A malformed/injected error value is genericized in the thrown message too,
    // so it can't leak attacker-controlled text into the CLI's error output.
    const msg = (await settled).message;
    expect(msg).toMatch(/oauth_denied/);
    expect(msg).not.toContain("<script>");
  });

  test("a well-formed provider error code passes through to the Error message", async () => {
    const s = await start("st");
    const settled = captureRejection(s);
    await fetch(`${s.url}?error=access_denied`);
    expect((await settled).message).toBe("oauth_denied: access_denied");
  });

  test("rejects when code is missing (state ok), returns 400", async () => {
    const s = await start("st");
    const settled = captureRejection(s);
    const resp = await fetch(`${s.url}?state=st`);
    expect(resp.status).toBe(400);
    expect((await settled).message).toMatch(/no_code/);
  });

  test("non-/callback path → 404", async () => {
    const s = await start("st");
    const resp = await fetch(`http://127.0.0.1:${new URL(s.url).port}/other`);
    expect(resp.status).toBe(404);
  });
});
