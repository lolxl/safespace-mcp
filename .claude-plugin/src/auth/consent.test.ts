import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import {
  acquireConsentLock,
  consent,
  effectiveConsentScopes,
  effectiveRequiredScopes,
  findMissingScopes,
  V1_REQUIRED_SCOPES,
} from "./consent";
import type { AccountEntry, AccountsIndex } from "./keychain";

const YT_ANALYTICS_MONETARY = "https://www.googleapis.com/auth/yt-analytics-monetary.readonly";
const ENV_MONETARY = "SAFESPACE_YOUTUBE_ANALYTICS_MONETARY";

let tmpDir: string;
let prevEnv: string | undefined;

beforeEach(async () => {
  prevEnv = process.env.SAFESPACE_CONFIG_DIR;
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-test-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
});

afterEach(async () => {
  if (prevEnv === undefined) delete process.env.SAFESPACE_CONFIG_DIR;
  else process.env.SAFESPACE_CONFIG_DIR = prevEnv;
  await fs.rm(tmpDir, { recursive: true, force: true });
});

describe("findMissingScopes", () => {
  test("returns empty when all required scopes are granted", () => {
    const granted = V1_REQUIRED_SCOPES.join(" ");
    expect(findMissingScopes(granted, V1_REQUIRED_SCOPES)).toEqual([]);
  });

  test("detects scope downgrade (missing scope)", () => {
    const granted = "https://www.googleapis.com/auth/gmail.readonly";
    const missing = findMissingScopes(granted, [
      "https://www.googleapis.com/auth/gmail.readonly",
      "https://www.googleapis.com/auth/gmail.send",
    ]);
    expect(missing).toEqual(["https://www.googleapis.com/auth/gmail.send"]);
  });

  test("returns full required list when granted is undefined", () => {
    expect(findMissingScopes(undefined, V1_REQUIRED_SCOPES)).toEqual(V1_REQUIRED_SCOPES);
  });

  test("returns full required list when granted is empty string", () => {
    expect(findMissingScopes("", V1_REQUIRED_SCOPES)).toEqual(V1_REQUIRED_SCOPES);
  });

  test("ignores extra granted scopes (not a downgrade)", () => {
    const granted = `${V1_REQUIRED_SCOPES.join(" ")} https://www.googleapis.com/auth/extra.scope`;
    expect(findMissingScopes(granted, V1_REQUIRED_SCOPES)).toEqual([]);
  });

  test("does not match by substring (security: avoid false positives)", () => {
    const granted = "https://www.googleapis.com/auth/gmail.readonly.suffix-not-real";
    const missing = findMissingScopes(granted, ["https://www.googleapis.com/auth/gmail.readonly"]);
    expect(missing).toEqual(["https://www.googleapis.com/auth/gmail.readonly"]);
  });
});

// V1_REQUIRED_READONLY_SCOPES describe block removed in v2.0 PR-2b (profile
// collapse). Read-only scope variant no longer exists — tier-based tool
// exposure (SAFESPACE_TIER) replaces scope narrowing as the read/write
// boundary. See tier.ts + proxy.ts tools/list filter.

/**
 * v1.12 Phase 1a sentinel — V1_SCOPES MUST include the `documents` scope.
 *
 * This is a single-assert canary: if a future refactor accidentally drops
 * the `documents` scope from the array, this test fails immediately,
 * surfacing it BEFORE users discover broken Docs tools at runtime.
 * V1_REQUIRED_SCOPES is the filtered-https projection of V1_SCOPES, so
 * asserting on it covers V1_SCOPES without forcing a new export.
 *
 * See docs/v1.12-docs-api.md §1 (scope choice) + §10 (re-consent ceremony).
 */
describe("V1_SCOPES — v1.12 Phase 1a documents scope sentinel", () => {
  test("V1_REQUIRED_SCOPES contains the documents scope", () => {
    expect(V1_REQUIRED_SCOPES).toContain("https://www.googleapis.com/auth/documents");
  });
});

/**
 * v1.13 Phase 1a sentinel — V1_SCOPES MUST include the `calendar.events` scope.
 *
 * Same canary pattern as the v1.12 `documents` sentinel above. If a future
 * refactor accidentally drops `calendar.events` from V1_SCOPES, this test
 * fails immediately — surfaced BEFORE users discover broken Calendar tools
 * (Phase 1b) at runtime, where the scope-mismatch pre-check in
 * with-context.ts would otherwise turn every `calendar_*` tool call into
 * scope_mismatch errors.
 *
 * See docs/v1.13-calendar-api.md §1 (scope choice rationale) + §10
 * (re-consent acceptance gate).
 */
describe("V1_SCOPES — v1.13 Phase 1a calendar.events scope sentinel", () => {
  test("V1_REQUIRED_SCOPES contains the calendar.events scope", () => {
    expect(V1_REQUIRED_SCOPES).toContain("https://www.googleapis.com/auth/calendar.events");
  });
});

/*
 * v1.45 (backlog A5) sentinels — V1_SCOPES MUST include the two NEW
 * minimum-privilege Calendar READ scopes. Same canary pattern as the v1.12 /
 * v1.13 / v1.15 sentinels: if a future refactor drops either scope, the
 * `calendar_query_freebusy` / `calendar_list_calendars` tools would turn every
 * call into scope_mismatch at runtime. See docs/v1.45-calendar-freebusy-list.md §1.
 */
describe("V1_SCOPES — v1.45 calendar.freebusy scope sentinel", () => {
  test("V1_REQUIRED_SCOPES contains the calendar.freebusy scope", () => {
    expect(V1_REQUIRED_SCOPES).toContain("https://www.googleapis.com/auth/calendar.freebusy");
  });
});

describe("V1_SCOPES — v1.45 calendar.calendarlist.readonly scope sentinel", () => {
  test("V1_REQUIRED_SCOPES contains the calendar.calendarlist.readonly scope", () => {
    expect(V1_REQUIRED_SCOPES).toContain(
      "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
    );
  });
});

/**
 * v1.50 (backlog B5) sentinel — V1_SCOPES MUST include the full `contacts`
 * scope. v1.50 UPGRADED `contacts.readonly` → `contacts` (read + write) to
 * authorize contacts_create / contacts_update. The v1.15 sentinel (which
 * asserted `contacts.readonly`) is REPLACED by this one: `contacts.readonly`
 * is intentionally no longer in V1_SCOPES (the full scope is a strict superset,
 * and the read tools stay satisfied via SCOPE_HIERARCHY).
 *
 * Same canary pattern as the v1.12 / v1.13 / v1.45 sentinels above. If a future
 * refactor drops `contacts` from V1_SCOPES, this fails immediately — surfaced
 * BEFORE users discover broken Contacts tools at runtime.
 *
 * See docs/v1.50-contacts-write.md §1 (scope upgrade + re-consent gate).
 */
describe("V1_SCOPES — v1.50 contacts (full read+write) scope sentinel", () => {
  test("V1_REQUIRED_SCOPES contains the full contacts scope", () => {
    expect(V1_REQUIRED_SCOPES).toContain("https://www.googleapis.com/auth/contacts");
  });
  test("V1_REQUIRED_SCOPES no longer contains the narrower contacts.readonly scope (upgraded to full)", () => {
    expect(V1_REQUIRED_SCOPES).not.toContain("https://www.googleapis.com/auth/contacts.readonly");
  });
});

/**
 * v1.51 (backlog B3) sentinel — V1_SCOPES MUST include the `gmail.settings.basic`
 * scope (for gmail_list_filters / gmail_create_filter / gmail_delete_filter).
 * Same canary pattern as the v1.12 / v1.13 / v1.45 / v1.50 sentinels. We also
 * assert that the broader `gmail.settings.sharing` is NOT requested — SafeSpace
 * deliberately does NOT expose forwarding-address / delegate management.
 *
 * See docs/v1.51-gmail-filters.md §1 (scope choice + re-consent gate).
 */
describe("V1_SCOPES — v1.51 gmail.settings.basic scope sentinel", () => {
  test("V1_REQUIRED_SCOPES contains the gmail.settings.basic scope", () => {
    expect(V1_REQUIRED_SCOPES).toContain("https://www.googleapis.com/auth/gmail.settings.basic");
  });
  test("V1_REQUIRED_SCOPES does NOT contain the broader gmail.settings.sharing scope", () => {
    expect(V1_REQUIRED_SCOPES).not.toContain(
      "https://www.googleapis.com/auth/gmail.settings.sharing",
    );
  });
});

/**
 * v1.16 Phase 1a sentinel — V1_SCOPES MUST include the `youtube.readonly` scope.
 *
 * Same canary pattern as the v1.12 `documents` / v1.13 `calendar.events` /
 * v1.15 `contacts.readonly` sentinels above. If a future refactor accidentally
 * drops `youtube.readonly` from V1_SCOPES, this test fails immediately —
 * surfaced BEFORE users discover broken YouTube tools (Phase 1b) at runtime,
 * where the scope-mismatch pre-check in with-context.ts would otherwise turn
 * every `youtube_*` tool call into scope_mismatch errors.
 *
 * See docs/v1.16-youtube-api.md §3 (scope choice rationale) + §5
 * (SCOPE_HIERARCHY pre-load for Phase 2 force-ssl).
 */
describe("V1_SCOPES — v1.16 Phase 1a youtube.readonly scope sentinel", () => {
  test("V1_REQUIRED_SCOPES contains the youtube.readonly scope", () => {
    expect(V1_REQUIRED_SCOPES).toContain("https://www.googleapis.com/auth/youtube.readonly");
  });
});

/**
 * v1.16 Phase 2a sentinel — V1_SCOPES MUST include the `youtube.force-ssl` scope.
 *
 * Same canary pattern as the v1.12 `documents` / v1.13 `calendar.events` /
 * v1.15 `contacts.readonly` / v1.16 Phase 1a `youtube.readonly` sentinels
 * above. Phase 2a adds the write scope so Phase 2b comment-write tools
 * (`youtube_video_comment_post` / `youtube_comment_reply`) have an OAuth
 * grant to consent against. Without this scope in V1_SCOPES, the Phase 2b
 * scope-mismatch pre-check in with-context.ts would reject every
 * comment-write call even with a non-empty SAFESPACE_YOUTUBE_COMMENT_TARGETS
 * allowlist + SAFESPACE_TIER=write — defeating the entire Phase 2 surface.
 *
 * Re-consent ceremony: this is the 3rd of the current cycle (v1.15
 * contacts.readonly was the 1st; v1.16 Phase 1a youtube.readonly was the
 * 2nd). PR #106 destructive-cleanup fix protects mid-flow failures.
 *
 * See docs/v1.16-youtube-api.md §3 (Phase 2 scope choice rationale) + §5
 * (SCOPE_HIERARCHY 2nd KEY entry shipped alongside this scope) + §13 Risk 1
 * (re-consent UX cost).
 */
describe("V1_SCOPES — v1.16 Phase 2a youtube.force-ssl scope sentinel", () => {
  test("V1_REQUIRED_SCOPES contains the youtube.force-ssl scope", () => {
    expect(V1_REQUIRED_SCOPES).toContain("https://www.googleapis.com/auth/youtube.force-ssl");
  });
});

/**
 * v1.19 Phase 1a sentinel — V1_SCOPES MUST include the `tasks` scope.
 *
 * Same canary pattern as the v1.12 `documents` / v1.13 `calendar.events` /
 * v1.15 `contacts.readonly` / v1.16 `youtube.readonly` + `youtube.force-ssl`
 * sentinels above. If a future refactor accidentally drops `tasks` from
 * V1_SCOPES, this test fails immediately — surfaced BEFORE users discover
 * broken Tasks tools (Phase 1b) at runtime, where the scope-mismatch
 * pre-check in with-context.ts would otherwise turn every `tasks_*` tool
 * call into scope_mismatch errors.
 *
 * v1.19 ships ONLY the bundled `tasks` scope (full read + write), NOT the
 * narrower `tasks.readonly` — Tasks is heavily write-oriented per locked Q1
 * and a split would force a second re-consent ceremony for Phase 2 write
 * tools without clear ROI (mirrors v1.13 `calendar.events` bundling).
 *
 * See docs/v1.19-tasks-api.md §3 (scope choice rationale + Q1 LOCKED) + §4
 * (SCOPE_HIERARCHY two-key pattern).
 */
describe("V1_SCOPES — v1.19 Phase 1a tasks scope sentinel", () => {
  test("V1_REQUIRED_SCOPES contains the tasks scope", () => {
    expect(V1_REQUIRED_SCOPES).toContain("https://www.googleapis.com/auth/tasks");
  });
});

/**
 * v1.20 Phase 1a sentinel — V1_SCOPES MUST include the `spreadsheets` scope.
 *
 * Same canary pattern as the v1.12 `documents` / v1.13 `calendar.events` /
 * v1.15 `contacts.readonly` / v1.16 `youtube.readonly` + `youtube.force-ssl` /
 * v1.19 `tasks` sentinels above. If a future refactor accidentally drops
 * `spreadsheets` from V1_SCOPES, this test fails immediately — surfaced
 * BEFORE users discover broken Sheets tools (Phase 1b) at runtime, where the
 * scope-mismatch pre-check in with-context.ts would otherwise turn every
 * `sheets_*` tool call into scope_mismatch errors.
 *
 * v1.20 ships ONLY the bundled `spreadsheets` scope (full read + write), NOT
 * the narrower `spreadsheets.readonly` — Sheets is heavily write-oriented per
 * locked Q1 (personal automation: build/log/track) and a split would force a
 * second re-consent ceremony for Phase 2 write tools (sheets_create /
 * sheets_append_values) without clear ROI (mirrors v1.13 `calendar.events` /
 * v1.19 `tasks` bundling precedent).
 *
 * See docs/v1.20-sheets-api.md §3 (scope choice rationale + Q1 LOCKED) + §4
 * (SCOPE_HIERARCHY two-key pattern).
 */
describe("V1_SCOPES — v1.20 Phase 1a spreadsheets scope sentinel", () => {
  test("V1_REQUIRED_SCOPES contains the spreadsheets scope", () => {
    expect(V1_REQUIRED_SCOPES).toContain("https://www.googleapis.com/auth/spreadsheets");
  });
});

/*
 * v1.63 — the Forms WRITE slice UPGRADES `forms.body.readonly` → full
 * `forms.body` in V1_SCOPES (the v1.50 contacts.readonly → contacts pattern).
 * V1_REQUIRED_SCOPES MUST now contain the full write scope and MUST NO LONGER
 * contain the narrow read scope (upgraded — the v1.62 read tools stay satisfied
 * via the pre-loaded SCOPE_HIERARCHY `forms.body.readonly ⊂ forms.body`).
 * `forms.responses.readonly` stays (responses remain read-only). See
 * docs/v1.63-forms-write.md §2.
 */
describe("V1_SCOPES — v1.63 Forms write scope upgrade (forms.body.readonly → forms.body)", () => {
  test("V1_REQUIRED_SCOPES contains the full forms.body (write) scope", () => {
    expect(V1_REQUIRED_SCOPES).toContain("https://www.googleapis.com/auth/forms.body");
  });
  test("V1_REQUIRED_SCOPES no longer contains the narrow forms.body.readonly (upgraded to full)", () => {
    expect(V1_REQUIRED_SCOPES).not.toContain("https://www.googleapis.com/auth/forms.body.readonly");
  });
  test("V1_REQUIRED_SCOPES still contains forms.responses.readonly (responses stay read-only)", () => {
    expect(V1_REQUIRED_SCOPES).toContain("https://www.googleapis.com/auth/forms.responses.readonly");
  });
});

/*
 * v1.61 — the monetary YouTube-Analytics scope is OPT-IN: requested at consent
 * ONLY when SAFESPACE_YOUTUBE_ANALYTICS_MONETARY=true. The BASE exports
 * (V1_SCOPES / V1_REQUIRED_SCOPES) must NEVER contain it (minimum privilege);
 * the env-aware functions add it only under the flag. See
 * docs/v1.61-youtube-analytics-monetary.md §2.
 */
describe("v1.61 — monetary YouTube-Analytics scope is opt-in", () => {
  let prev: string | undefined;
  beforeEach(() => {
    prev = process.env[ENV_MONETARY];
    delete process.env[ENV_MONETARY];
  });
  afterEach(() => {
    if (prev === undefined) delete process.env[ENV_MONETARY];
    else process.env[ENV_MONETARY] = prev;
  });

  test("BASE exports never contain the monetary scope (minimum privilege)", () => {
    expect(V1_REQUIRED_SCOPES).not.toContain(YT_ANALYTICS_MONETARY);
  });

  test("flag UNSET → effectiveConsentScopes === base (no monetary), and base yt-analytics.readonly still present", () => {
    const eff = effectiveConsentScopes();
    expect(eff).not.toContain(YT_ANALYTICS_MONETARY);
    expect(eff).toContain("https://www.googleapis.com/auth/yt-analytics.readonly");
    expect(effectiveRequiredScopes()).not.toContain(YT_ANALYTICS_MONETARY);
  });

  test("flag 'true' → effective scopes ADD the monetary scope (consent + required)", () => {
    process.env[ENV_MONETARY] = "true";
    expect(effectiveConsentScopes()).toContain(YT_ANALYTICS_MONETARY);
    expect(effectiveRequiredScopes()).toContain(YT_ANALYTICS_MONETARY);
    // base scope stays too — the monetary scope is appended, not a replacement
    expect(effectiveConsentScopes()).toContain("https://www.googleapis.com/auth/yt-analytics.readonly");
  });

  test("STRICT-TRUTHY: 'True' / '1' / 'yes' → monetary NOT added (treated as off)", () => {
    for (const v of ["True", "TRUE", "1", "yes", "on", ""]) {
      process.env[ENV_MONETARY] = v;
      expect(effectiveConsentScopes()).not.toContain(YT_ANALYTICS_MONETARY);
    }
  });
});

describe("acquireConsentLock", () => {
  test("acquires and releases successfully", async () => {
    const lock = await acquireConsentLock("a@example.com");
    await lock.release();
    const lock2 = await acquireConsentLock("a@example.com");
    await lock2.release();
  });

  test("fails when same email is already locked", async () => {
    const lock = await acquireConsentLock("a@example.com");
    await expect(acquireConsentLock("a@example.com")).rejects.toThrow(/already in progress/);
    await lock.release();
  });

  test("different emails do not conflict", async () => {
    const lockA = await acquireConsentLock("a@example.com");
    const lockB = await acquireConsentLock("b@example.com");
    await lockA.release();
    await lockB.release();
  });

  test("release is idempotent (calling twice does not throw)", async () => {
    const lock = await acquireConsentLock("a@example.com");
    await lock.release();
    await lock.release();
  });
});

describe("acquireConsentLock — stale-lock TTL (5.5)", () => {
  const STALE_AGE_MS = 11 * 60 * 1000; // > 10 min TTL

  async function plantLock(email: string, pidContent: string, ageMs: number): Promise<string> {
    const safe = Buffer.from(email).toString("base64url");
    const p = path.join(tmpDir, `.consent.${safe}.lock`);
    // tmpDir is created by `mkdtemp` in beforeEach; no mkdir needed here.
    await fs.writeFile(p, pidContent, { mode: 0o600 });
    const old = (Date.now() - ageMs) / 1000;
    await fs.utimes(p, old, old);
    return p;
  }

  async function deadPid(): Promise<number> {
    const proc = Bun.spawn(["sh", "-c", "exit 0"]);
    await proc.exited;
    // L3 (sec-rev): guard against PID reuse before isStaleLock observes it.
    // If the OS recycled the PID for an unrelated process in this gap, skip
    // by throwing — better a deterministic test failure than a silent one.
    let alive = false;
    try { process.kill(proc.pid, 0); alive = true; } catch { /* ESRCH expected */ }
    if (alive) throw new Error(`deadPid: PID ${proc.pid} was reused; rerun the test`);
    return proc.pid;
  }

  test("stale lock (old mtime + dead PID) is recovered on next acquire", async () => {
    const pid = await deadPid();
    await plantLock("a@example.com", `${pid}\n`, STALE_AGE_MS);
    const lock = await acquireConsentLock("a@example.com");
    await lock.release();
  });

  test("old mtime + LIVE PID (this process) still rejects", async () => {
    await plantLock("a@example.com", `${process.pid}\n`, STALE_AGE_MS);
    await expect(acquireConsentLock("a@example.com")).rejects.toThrow(/already in progress/);
  });

  test("recent lock (young mtime) is NEVER stale, even with dead PID", async () => {
    const pid = await deadPid();
    await plantLock("a@example.com", `${pid}\n`, 60_000); // 1 min, < 10 min TTL
    await expect(acquireConsentLock("a@example.com")).rejects.toThrow(/already in progress/);
  });

  test("corrupt content + old mtime → treated as stale, recovered", async () => {
    await plantLock("a@example.com", "not-a-pid\n", STALE_AGE_MS);
    const lock = await acquireConsentLock("a@example.com");
    await lock.release();
  });

  test("empty content + old mtime → treated as stale, recovered", async () => {
    await plantLock("a@example.com", "", STALE_AGE_MS);
    const lock = await acquireConsentLock("a@example.com");
    await lock.release();
  });

  test("recovered lock records the new owner's PID, not the stale one", async () => {
    const oldPid = await deadPid();
    const p = await plantLock("a@example.com", `${oldPid}\n`, STALE_AGE_MS);
    const lock = await acquireConsentLock("a@example.com");
    const written = await fs.readFile(p, "utf8");
    expect(written.trim()).toBe(String(process.pid));
    expect(written.trim()).not.toBe(String(oldPid));
    await lock.release();
  });
});

/**
 * v1.12 Phase 0a regression-lock — PR #105 sec-rev finding D2.
 *
 * Before this fix, the outer `catch (err) { deleteToken + removeAccount }`
 * in consent() fired for ANY error in the inner try block, including
 * failures BEFORE setToken (browser closed, state_mismatch, network drop
 * during oauth.getToken, scope_mismatch, etc.). For a user running
 * `safespace consent <email> --re-auth` to add new scopes (v1.12 docs API
 * Phase 0 requires this for ~4 accounts sequentially), any mid-flow
 * failure wiped the pre-existing v1.x consent — forcing a full
 * re-consent from scratch.
 *
 * The fix tracks `setTokenCalled`. Cleanup only runs if a NEW token was
 * actually written. This test drives consent() through a real failure
 * path: the spawn-stub captures the Google auth URL, extracts the
 * `redirect_uri` query (which points at the callback server's random
 * 127.0.0.1 port), and fires `GET <redirect_uri>?error=...` — exactly the
 * shape the user's browser sends when they deny consent or close the tab
 * mid-flow. `cb.await` rejects with `oauth_denied:...`, the inner try
 * surfaces it, and the outer try decides whether to wipe the pre-existing
 * accounts.json row. Pre-fix: row wiped. Post-fix: row preserved.
 *
 * Why file-only (accounts.json), not the Keychain side: tests must not
 * touch the real macOS Keychain. The user-visible D2 symptom is
 * `safespace account-list` showing the account is gone — driven entirely
 * by accounts.json. Asserting that file survives is the regression lock
 * the user cares about; the Keychain side is covered by the
 * setTokenCalled-flag invariant in consent.ts.
 */
describe("consent — D2 destructive-cleanup fix (v1.12 Phase 0a)", () => {
  const EMAIL = "preexisting@example.com";

  let prevClientId: string | undefined;
  let prevClientSecret: string | undefined;

  // Injected into consent() as `openImpl`: parse the authorize URL's redirect_uri (the
  // loopback callback) and fire a synthetic ?error=... callback so cb.await rejects — the
  // canonical "user closed the browser before consenting" shape. (Replaces the old global
  // Bun.spawn stub, which no longer intercepts the node:child_process-based openUrl.)
  const driveErrorCallback = (authUrl: string): void => {
    queueMicrotask(async () => {
      try {
        const redirectUri = new URL(authUrl).searchParams.get("redirect_uri");
        if (!redirectUri) return;
        await fetch(`${redirectUri}?error=test_simulated_user_closed_browser`).catch(() => undefined);
      } catch { /* ignore */ }
    });
  };

  beforeEach(() => {
    prevClientId = process.env.GOOGLE_CLIENT_ID;
    prevClientSecret = process.env.GOOGLE_CLIENT_SECRET;
    process.env.GOOGLE_CLIENT_ID = "fake-client-id.apps.googleusercontent.com";
    process.env.GOOGLE_CLIENT_SECRET = "GOCSPX-fake-secret";
  });

  afterEach(() => {
    if (prevClientId === undefined) delete process.env.GOOGLE_CLIENT_ID;
    else process.env.GOOGLE_CLIENT_ID = prevClientId;
    if (prevClientSecret === undefined) delete process.env.GOOGLE_CLIENT_SECRET;
    else process.env.GOOGLE_CLIENT_SECRET = prevClientSecret;
  });

  test("D2: mid-flow failure (?error= BEFORE setToken) leaves pre-existing accounts.json row intact", async () => {
    // Pre-seed an accounts.json row, simulating a user who already
    // consented under v1.x and is now running `safespace consent <email>
    // --re-auth` to add v1.12 scopes. Write the file directly via fs so
    // we exercise the production loadIndex path without coupling to
    // upsertAccount's internal state-sharing quirks (which would matter
    // only if a future test in this file also asserted-on-empty-index).
    const preExistingEntry: AccountEntry = {
      email: EMAIL,
      scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
      added_at: "2024-01-01T00:00:00.000Z",
      last_used_at: null,
    };
    const preExistingIndex: AccountsIndex = { version: 2, accounts: [preExistingEntry] };
    await fs.mkdir(tmpDir, { recursive: true, mode: 0o700 });
    const accountsPath = path.join(tmpDir, "accounts.json");
    await fs.writeFile(accountsPath, JSON.stringify(preExistingIndex), { mode: 0o600 });

    // Sanity: row is present on disk before consent runs.
    const beforeRaw = await fs.readFile(accountsPath, "utf8");
    expect(JSON.parse(beforeRaw)).toEqual(preExistingIndex);

    // Run consent() in --re-auth mode. The injected openImpl fires a ?error=...
    // callback as soon as consent() opens the authorize URL, causing cb.await to reject.
    await expect(consent(EMAIL, { reAuth: true, openImpl: driveErrorCallback })).rejects.toThrow(/oauth_denied/);

    // The critical D2 assertion: the pre-existing row SURVIVES the
    // mid-flow failure. Pre-fix: this row would have been wiped by
    // removeAccount() in the outer catch, leaving accounts.json with
    // `accounts: []` (or missing the EMAIL row).
    const afterRaw = await fs.readFile(accountsPath, "utf8");
    const afterIndex = JSON.parse(afterRaw) as AccountsIndex;
    expect(afterIndex.accounts.find((a) => a.email === EMAIL)).toEqual(preExistingEntry);
  });
});
