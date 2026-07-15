// Shared streaming byte-cap for the hardened READ clients (auth/{notion,github,slack}/client.ts).
//
// B6.1-B — part of the client-layer error-mapping contract (a cap breach surfaces as
// the CALLING client's `*_api_failed{api_error}`): src/auth/http/connector-error-contract.ts.
//
// Each of those clients performs an authenticated request that RETURNS the parsed JSON (unlike
// the outbound write core tools/handlers/service-token-fetch.ts, which DISCARDS the body). They
// all need the SAME response guard: cap the bytes actually streamed so a chunked / header-less
// response can't make the JSON parse buffer unboundedly (context protection). This used to be
// three byte-identical copies of `readBounded` + the cap constant; consolidating it here means
// the guard cannot silently DRIFT between connectors — it is a DoS / byte-cap primitive, where
// divergence is a security regression, not a cosmetic one.
//
// What stays PER-CONNECTOR (deliberately NOT here): host pinning + `assertEgressHost`, the
// auth/version headers, and each client's CLOSED-SET error taxonomy (`notion_api_failed`
// -32045 / `github_api_failed` -32041 / `slack_api_failed` -32049, incl. GitHub's rate-limit
// header disambiguation and Slack's 200-but-`{ok:false}` body model). `readBounded` throws only
// a generic `Error("response_too_large")`; each client's existing `catch` translates it to its
// own `MCPError`, so the per-connector taxonomy is preserved by construction.

/** Response cap (bytes) for the read clients — mirrors the v1.65 web-fetch 5 MB
 *  context-protection cap. */
export const MAX_RESPONSE_BYTES = 5 * 1024 * 1024;

/** Read a response body to a string, aborting (and throwing `Error("response_too_large")`)
 *  once it exceeds `maxBytes`. The cap is enforced on the bytes actually STREAMED, independent
 *  of any Content-Length header (so a chunked / header-less response can't bypass it).
 *
 *  A null `res.body` is a bodiless response (empty 200, 204, …) — there are no bytes to read,
 *  so the faithful bounded result is `""`. (The former `return await res.text()` fallback was
 *  UNBOUNDED — `res.text()` does NOT inherit any cap. For a genuinely empty body it returned
 *  `""` anyway, so a caller that feeds the result into `JSON.parse` sees identical behavior;
 *  `return ""` only closes the pathological non-standard-`Response` case where `.body` is null
 *  yet `.text()` would yield content.) */
export async function readBounded(res: Response, maxBytes: number): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => undefined);
        throw new Error("response_too_large");
      }
      chunks.push(value);
    }
  }
  return new TextDecoder().decode(Buffer.concat(chunks.map((c) => Buffer.from(c))));
}
