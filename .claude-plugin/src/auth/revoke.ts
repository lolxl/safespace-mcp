// OAuth refresh-token revoke against Google's RFC 7009 endpoint.
// See docs/DESIGN.md §Auth flow.
//
// Called by `safespace account-revoke <email>` (CLI in cli.ts) to invalidate
// the token server-side BEFORE we delete the local copy. Order matters: a
// delete-first failure would leave a valid refresh token in the wild with no
// way to revoke it remotely.
//
// Security pattern (mirrors refresh.ts):
//   - 10s AbortController timeout so a hanging endpoint doesn't wedge the CLI.
//   - Do NOT forward `error_description` from non-200 bodies — Google's
//     error_description may echo token fragments which would leak into a
//     thrown Error message and end up in terminal scrollback.
//   - Idempotency: 400 with `error: "invalid_token"` means already revoked
//     (or never valid). Treat as success so account-revoke can finish local
//     cleanup without forcing the user to manually delete state.

const REVOKE_URL = "https://oauth2.googleapis.com/revoke";
const REVOKE_TIMEOUT_MS = 10_000;

export interface RevokeDeps {
  fetchImpl?: typeof fetch;
}

/** Revoke a Google OAuth refresh token via RFC 7009 §2.1.
 *
 *  Returns void on success (200) or on idempotent-success (400 invalid_token).
 *  Throws on any other status, network error, or timeout — caller (the CLI)
 *  uses the throw to abort and preserve local state so the user can retry. */
export async function revokeRefreshToken(
  refreshToken: string,
  deps: RevokeDeps = {},
): Promise<void> {
  const fetchImpl = deps.fetchImpl ?? fetch;

  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), REVOKE_TIMEOUT_MS);

  let res: Response;
  try {
    res = await fetchImpl(REVOKE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ token: refreshToken }).toString(),
      signal: ac.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  if (res.ok) return;

  // Read body ONLY to extract the canonical OAuth `error` code. Discard every
  // other field — `error_description` may include token fragments.
  let errCode = "";
  try {
    const body = (await res.json()) as { error?: unknown };
    errCode = typeof body.error === "string" ? body.error : "";
  } catch {
    /* response not JSON */
  }

  if (errCode === "invalid_token") {
    // Already revoked or never valid — local cleanup should still proceed.
    return;
  }

  throw new Error(`google_revoke_endpoint_${res.status}`);
}
