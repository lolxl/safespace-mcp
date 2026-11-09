// 127.0.0.1 local OAuth callback flow.
// See docs/DESIGN.md §Next Steps Step 2 + MCP Error Code Table.
// Security-review fixes (2026-04-30): explicit PKCE wiring, signed id_token verify
// with audience, file lock for concurrent consent, scope check on tokens.scope
// (NOT granted_scopes which is implicit-flow only).
import { assertSdkLoggingDisabled } from "../google-api/sdk-logging-guard"; // MUST stay before google-auth-library (it logs token bodies when GOOGLE_SDK_NODE_LOGGING is set)
import { CodeChallengeMethod, OAuth2Client } from "google-auth-library";
import * as crypto from "node:crypto";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import {
  configDir,
  removeAccount,
  upsertAccount,
  type AccountEntry,
} from "./keychain";
// v1.70 (G3): the loopback callback server is shared with the GitHub OAuth flow.
import { startCallbackServer } from "./oauth-callback";
import { openUrl } from "./open-url";
// v1.37 BLOCKER 1: token writes go through the SecretBackend facade.
import { deleteToken, setToken } from "./token-store";
import { MCPError } from "../errors";
// v1.61: the monetary (revenue) YouTube-Analytics scope is requested ONLY when
// the opt-in flag is set (minimum privilege — see effectiveConsentScopes).
import { isYoutubeAnalyticsMonetaryEnabled } from "../policy/youtube-analytics-monetary";
import { YT_ANALYTICS_MONETARY_READONLY } from "../tools/registry/scopes";

// v2.0 unified scope set — read + label CRUD + label modify + send + drive (full).
// Replaces the v1.x two-profile read/send split (see git history before PR-2b).
// `gmail.labels` covers list/create/delete labels at the account level;
// `gmail.modify` covers per-message label add/remove (also implicitly permits
// trash/untrash/drafts — those Google API paths are NOT exposed by our tools,
// see gmail_modify_message handler).
//
// Tool exposure under v2.0 is controlled by SAFESPACE_TIER at the proxy
// tools/list filter (read|write|share), not by scope narrowing. See tier.ts.
const V1_SCOPES = [
  "openid",
  "email",
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.labels",
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/gmail.send",
  "https://www.googleapis.com/auth/drive",
  // v1.12 Phase 1a — Google Docs API (structured read + create). Grouped with
  // `drive` as the non-Gmail file/document family. See docs/v1.12-docs-api.md.
  "https://www.googleapis.com/auth/documents",
  // v1.13 Phase 1a — Google Calendar API (event read + write). Minimum-privilege
  // scope covering Phase 1 (read) + Phase 2 (write); does NOT grant access to
  // Calendar settings / ACLs / sharing. See docs/v1.13-calendar-api.md.
  "https://www.googleapis.com/auth/calendar.events",
  // v1.45 (backlog A5) — Calendar free/busy + calendar list (read-only). Two
  // NEW minimum-privilege scopes (first scope additions since v1.20).
  // `calendar.freebusy` = narrowest for freebusy.query (busy WINDOWS only, NO
  // event detail). `calendar.calendarlist.readonly` = narrowest for
  // calendarList.list (enumerate calendars). Deliberately NOT the broader
  // `calendar.readonly`. Adding these triggers a re-consent ceremony for
  // existing accounts. See docs/v1.45-calendar-freebusy-list.md §1.
  "https://www.googleapis.com/auth/calendar.freebusy",
  "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
  // v1.15 Phase 1a — Google People (Contacts) API. v1.50 (backlog B5) UPGRADES
  // this from `contacts.readonly` → full `contacts` (read + write) to authorize
  // the write tools `contacts_create` (people.createContact) + `contacts_update`
  // (people.updateContact). `contacts` is a strict superset of
  // `contacts.readonly`, so the v1.15 read tools stay satisfied via
  // SCOPE_HIERARCHY (with-context.ts) — but the upgrade triggers a one-time
  // re-consent ceremony for accounts consented before v1.50 (the granted token
  // lacks `contacts`, so findMissingScopes flags it). See
  // docs/v1.50-contacts-write.md §1.
  "https://www.googleapis.com/auth/contacts",
  // v1.16 Phase 1a — Google YouTube Data API v3 (read-only). Phase 1 ships
  // read tools only (subscriptions/uploads/video/search/comments_list).
  // Phase 2 may upgrade to youtube.force-ssl for comment writes — see
  // docs/v1.16-youtube-api.md §5 SCOPE_HIERARCHY note.
  "https://www.googleapis.com/auth/youtube.readonly",
  // v1.16 Phase 2a — YouTube comment write (force-ssl). Required for
  // youtube_video_comment_post + youtube_comment_reply (Phase 2b handlers).
  // Narrower than full `youtube` (which would allow video upload — locked
  // rejected, §14). Default-deny multi-gate enforcement: scope + tier +
  // SAFESPACE_YOUTUBE_COMMENT_TARGETS allowlist + SAFESPACE_YOUTUBE_COMMENT_BURST_LIMIT
  // counter. See docs/v1.16-youtube-api.md §3 + §4.1 + §13 Risk 3.
  "https://www.googleapis.com/auth/youtube.force-ssl",
  // v1.19 Phase 1a — Google Tasks API (read + write).
  // Bundled write scope from start (NOT split readonly+write per v1.16 pattern) —
  // Tasks is heavily write-oriented (create/complete tasks); split would force
  // a second re-consent ceremony for Phase 2 write tools without clear ROI.
  // Mirrors v1.13 calendar.events bundling precedent. Re-evaluate when a
  // future cycle introduces read-only-only use cases.
  // See docs/v1.19-tasks-api.md §3 + Q1 LOCKED.
  "https://www.googleapis.com/auth/tasks",
  // v1.20 Phase 1a — Google Sheets API (read + write).
  // Bundled write scope from start (NOT split readonly+write per v1.15 pattern) —
  // Sheets is heavily write-oriented per design §3 (personal automation:
  // build/log/track). Split would force a second re-consent ceremony for
  // Phase 2 write tools (sheets_create / sheets_append_values) without
  // clear ROI. Mirrors v1.13 calendar.events / v1.19 tasks bundling
  // precedent. Re-evaluate when a future cycle introduces read-only-only
  // use cases (the SCOPE_HIERARCHY two-key entry pre-loads
  // spreadsheets.readonly so a future narrower-scope tool ships without a
  // hierarchy edit).
  // See docs/v1.20-sheets-api.md §3 + Q1 LOCKED.
  "https://www.googleapis.com/auth/spreadsheets",
  // v1.51 Phase 1a (backlog B3) — Gmail settings (basic) for the message-filter
  // tools (gmail_list_filters / gmail_create_filter / gmail_delete_filter). The
  // narrowest scope covering users.settings.filters.*; deliberately NOT the
  // broader `gmail.settings.sharing` (forwarding-address / delegate management
  // is intentionally NOT exposed). Adding this triggers a re-consent ceremony
  // for accounts consented before v1.51. See docs/v1.51-gmail-filters.md §1.
  "https://www.googleapis.com/auth/gmail.settings.basic",
  // v1.59 — YouTube Analytics API v2 (read-only channel metrics, NON-monetary).
  // A SEPARATE scope family from the youtube.* Data scopes above; needed by
  // youtube_analytics_query (reports.query). NON-monetary only (no revenue); the
  // monetary variant is deferred (design §2 / Q1). Adding this triggers a
  // re-consent ceremony for accounts consented before v1.59. FLAT — no
  // SCOPE_HIERARCHY entry. See docs/v1.59-youtube-analytics.md §2.
  "https://www.googleapis.com/auth/yt-analytics.readonly",
  // v1.60 — Google Slides API (full read+write, bundled per the Docs/Sheets
  // precedent). Needed by slides_get/create/modify. Adding this triggers a
  // re-consent ceremony for accounts consented before v1.60. SCOPE_HIERARCHY has
  // the two-key `presentations.readonly ⊂ presentations`. See docs/v1.60-slides.md §3.
  "https://www.googleapis.com/auth/presentations",
  // v1.62 — Google Forms API. v1.63 (write slice) UPGRADES the v1.62 narrow
  // `forms.body.readonly` → full `forms.body` (read+write FORM STRUCTURE) to
  // authorize forms_create (forms.create) + forms_modify (forms.batchUpdate).
  // `forms.body` is a strict superset of `forms.body.readonly`, so the v1.62 read
  // tools (requiredScopes: [forms.body.readonly]) stay satisfied via the
  // SCOPE_HIERARCHY two-key `forms.body.readonly ⊂ forms.body` (pre-loaded in
  // v1.62) — but the upgrade triggers a one-time re-consent ceremony for accounts
  // consented before v1.63 (the granted token lacks `forms.body`, so
  // findMissingScopes flags it). This is the v1.50 contacts.readonly → contacts
  // upgrade pattern. `forms.responses.readonly` is UNCHANGED — responses stay
  // read-only (the API cannot write responses). See docs/v1.63-forms-write.md §2.
  "https://www.googleapis.com/auth/forms.body",
  "https://www.googleapis.com/auth/forms.responses.readonly",
];

// Scopes we require on the granted set (openid+email arrive via id_token, not in tokens.scope).
// V1_SCOPES / V1_REQUIRED_SCOPES are the UNCONDITIONAL BASE set (every
// deployment). The opt-in monetary scope is layered on top by the env-aware
// functions below — the base exports stay static so the per-scope sentinels in
// consent.test.ts keep pinning exactly the base set.
export const V1_REQUIRED_SCOPES = V1_SCOPES.filter((s) => s.startsWith("https://"));

// v1.61 — the EFFECTIVE consent scope set: the static base, plus the monetary
// YouTube-Analytics read scope ONLY when SAFESPACE_YOUTUBE_ANALYTICS_MONETARY is
// opted in (strict-truthy). Read at call-time (a CLI consent run), never at
// module load, so flipping the env var per-process / per-test is honored. When
// the flag is unset (the default), this is byte-identical to V1_SCOPES → the
// monetary scope is never requested (minimum privilege; see
// docs/v1.61-youtube-analytics-monetary.md §2).
// OFF → the base const itself (no copy: the existing call-sites only READ it,
// exactly as the pre-v1.61 `scope: V1_SCOPES` / `findMissingScopes(…, V1_REQUIRED_SCOPES)`
// did). ON → a fresh array with the monetary scope appended (never mutates the base).
export function effectiveConsentScopes(): string[] {
  return isYoutubeAnalyticsMonetaryEnabled()
    ? [...V1_SCOPES, YT_ANALYTICS_MONETARY_READONLY]
    : V1_SCOPES;
}

/** The https-projection of effectiveConsentScopes — what we verify Google
 *  actually granted (findMissingScopes). When the monetary flag is on, the
 *  monetary scope is in the required set, so a consent that did NOT grant it
 *  fails loudly with scope_mismatch rather than silently under-granting.
 *  Derived from V1_REQUIRED_SCOPES directly (the monetary URL is https-prefixed)
 *  so the structure mirrors effectiveConsentScopes and avoids re-filtering the
 *  full scope list on every consent call. */
export function effectiveRequiredScopes(): string[] {
  return isYoutubeAnalyticsMonetaryEnabled()
    ? [...V1_REQUIRED_SCOPES, YT_ANALYTICS_MONETARY_READONLY]
    : V1_REQUIRED_SCOPES;
}

export interface ConsentOptions {
  reAuth?: boolean;
  /** Test seam — open the authorize URL in the browser. Defaults to the cross-platform
   *  `openUrl` helper; tests inject an impl that drives the loopback callback. */
  openImpl?: (url: string) => void;
}

/* ───────── pure helpers (unit-testable) ───────── */

export function findMissingScopes(grantedString: string | undefined, required: string[]): string[] {
  const granted = new Set((grantedString ?? "").split(/\s+/).filter(Boolean));
  return required.filter((s) => !granted.has(s));
}

function lockPathFor(email: string): string {
  // Encode to keep filename safe even if the email regex layer is bypassed.
  const safe = Buffer.from(email).toString("base64url");
  return path.join(configDir(), `.consent.${safe}.lock`);
}

/** Stale-lock TTL. A lock older than this AND whose recorded PID is no longer
 * running is considered abandoned (process was SIGKILL'd, machine crashed, etc).
 * 10 minutes comfortably exceeds a normal consent flow (browser + user click). */
const STALE_LOCK_AGE_MS = 10 * 60 * 1000;

/** A lock is recoverable only when BOTH conditions hold:
 *   (1) mtime is older than STALE_LOCK_AGE_MS, AND
 *   (2) the recorded PID is no longer alive (or the file is corrupt).
 *
 * PID-only checks are unsafe (PID reuse). Age-only checks are unsafe
 * (a slow consent appears abandoned). The conjunction bounds both risks:
 * a false-positive (recovering a live lock) requires PID reuse landing on
 * an unrelated long-running process WITHIN the 10-min window — negligible
 * on a developer Mac with low PID churn. */
async function isStaleLock(p: string): Promise<boolean> {
  try {
    const stat = await fs.stat(p);
    if (Date.now() - stat.mtimeMs < STALE_LOCK_AGE_MS) return false;
    const content = await fs.readFile(p, "utf8").catch(() => "");
    const pid = parseInt(content.trim(), 10);
    if (!Number.isFinite(pid) || pid <= 0) return true; // corrupt → no live owner to verify
    try {
      process.kill(pid, 0); // signal 0 = liveness probe, never delivers a signal
      return false;
    } catch (err) {
      // M1 (sec-rev): distinguish errno. EPERM = process exists but we can't
      // signal it (different UID, e.g. Docker/multi-seat) → treat as ALIVE,
      // not recoverable. ESRCH (and anything else unexpected) → gone.
      if ((err as NodeJS.ErrnoException).code === "EPERM") return false;
      return true;
    }
  } catch {
    return false; // stat raced (file vanished); let the caller's natural retry handle it
  }
}

export async function acquireConsentLock(email: string): Promise<{ release: () => Promise<void> }> {
  await fs.mkdir(configDir(), { recursive: true, mode: 0o700 });
  const p = lockPathFor(email);
  const liveLockMsg = `consent already in progress for ${email}; if no other process is running, delete ${p}`;
  let fh: fs.FileHandle;
  try {
    fh = await fs.open(p, "wx", 0o600); // O_EXCL — fails if exists
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    // Stale-lock recovery: unlink + retry exactly once.
    if (!(await isStaleLock(p))) throw new Error(liveLockMsg);
    await fs.unlink(p).catch(() => undefined);
    try {
      fh = await fs.open(p, "wx", 0o600);
    } catch (e2) {
      // Race: another process claimed the freshly-unlinked lock between our
      // unlink and re-open. Surface a distinct message so the user knows
      // manual `rm` won't help — a peer process cleanly acquired it.
      if ((e2 as NodeJS.ErrnoException).code === "EEXIST") {
        throw new Error(`consent just started in another process for ${email}; retry shortly`);
      }
      throw e2;
    }
  }
  // Wrap write so a disk-full / I/O error doesn't leave a stale lock file
  // blocking all future consent runs for this email (code-review HIGH).
  try {
    await fh.write(`${process.pid}\n`);
  } catch (e) {
    try { await fh.close(); } catch { /* ignore */ }
    await fs.unlink(p).catch(() => undefined);
    throw e;
  }
  return {
    release: async () => {
      try { await fh.close(); } catch { /* already closed */ }
      await fs.unlink(p).catch(() => undefined);
    },
  };
}

/* ───────── orchestrator ───────── */

export async function consent(email: string, opts: ConsentOptions = {}): Promise<void> {
  assertSdkLoggingDisabled(); // fail closed before any token-bearing call (see sdk-logging-guard.ts)
  const clientId = process.env.GOOGLE_CLIENT_ID;
  const clientSecret = process.env.GOOGLE_CLIENT_SECRET;
  if (!clientId || !clientSecret) {
    throw new Error("GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET environment variables are required");
  }

  const lock = await acquireConsentLock(email);
  // Tracks whether THIS consent run has written a new token to the Keychain.
  // Cleanup on failure is only safe AFTER setToken — before that, the only
  // Keychain/accounts.json state for `email` is from a PRIOR successful
  // consent run (e.g. v1.x → v1.12 --re-auth) which a mid-flow browser/
  // network failure must NOT destroy. See PR #105 sec-rev finding D2.
  let setTokenCalled = false;
  try {
    const state = crypto.randomBytes(32).toString("base64url");
    const cb = await startCallbackServer(state);

    try {
      const oauth = new OAuth2Client({ clientId, clientSecret, redirectUri: cb.url });
      const { codeVerifier, codeChallenge } = await oauth.generateCodeVerifierAsync();

      const authUrl = oauth.generateAuthUrl({
        scope: effectiveConsentScopes(),
        state,
        code_challenge: codeChallenge,
        code_challenge_method: CodeChallengeMethod.S256,
        access_type: "offline",
        prompt: opts.reAuth ? "consent" : undefined,
      });

      console.error(`[safespace] opening browser for ${email} consent...`);
      (opts.openImpl ?? openUrl)(authUrl);

      const { code } = await cb.await;
      const { tokens } = await oauth.getToken({ code, codeVerifier, redirect_uri: cb.url });

      // verifyIdToken does signature + audience + expiry — never trust raw id_token decode (security #2).
      if (!tokens.id_token) throw new Error("no id_token returned");
      const ticket = await oauth.verifyIdToken({ idToken: tokens.id_token, audience: clientId });
      const payload = ticket.getPayload();
      if (!payload || payload.email !== email) {
        throw new Error(`email_mismatch: consented as ${payload?.email ?? "<unknown>"}, expected ${email}`);
      }

      const missing = findMissingScopes(tokens.scope, effectiveRequiredScopes());
      if (missing.length > 0) {
        throw new MCPError("scope_mismatch", { email, missing });
      }

      if (!tokens.refresh_token) {
        throw new Error("no refresh_token returned (re-run with --re-auth?)");
      }
      if (!tokens.access_token || !tokens.expiry_date) {
        throw new Error("incomplete token response from Google");
      }

      const grantedScopes = (tokens.scope ?? "").split(/\s+/).filter(Boolean);
      const tokenSet = {
        refresh_token: tokens.refresh_token,
        access_token: tokens.access_token,
        expires_at: tokens.expiry_date,
        scopes: grantedScopes,
        obtained_at: Date.now(),
      };
      await setToken(email, JSON.stringify(tokenSet));
      setTokenCalled = true;
      const entry: AccountEntry = {
        email,
        scopes: grantedScopes,
        added_at: new Date().toISOString(),
        last_used_at: null,
      };
      await upsertAccount(entry);
      console.error(`[safespace] consent saved for ${email}`);
    } finally {
      cb.stop();
    }
  } catch (err) {
    // Defensive cleanup: only safe AFTER setToken succeeded. If we failed
    // BEFORE setToken (e.g. browser closed, state_mismatch, scope_mismatch,
    // network drop during getToken), NO Keychain write happened on this
    // run — any existing Keychain/accounts.json entry for `email` belongs
    // to a PRIOR successful consent (notably a v1.x account being
    // --re-auth'd to v1.12 for new scopes) and must NOT be wiped (PR #105
    // sec-rev D2).
    //
    // If we failed AFTER setToken (i.e. during upsertAccount), the new
    // token IS persisted and accounts.json may be missing/stale. Drop
    // both surfaces so the next consent run starts from a clean state —
    // any prior token for this email was already overwritten by setToken,
    // so this cleanup destroys no recoverable state.
    if (setTokenCalled) {
      await deleteToken(email).catch(() => undefined);
      await removeAccount(email).catch(() => undefined);
    }
    throw err;
  } finally {
    await lock.release();
  }
}
