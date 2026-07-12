// `safespace doctor` — diagnostic checks (split out of status.ts, v1.112.5 —
// behavior-preserving verbatim move). See status.ts for the module SECURITY ASSUMPTIONS.
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { readActive } from "../auth/active";
import { configDir } from "../auth/keychain";
import { getToken } from "../auth/token-store";
import { isContactLookupEnabled } from "../policy/contact-lookup";
import { isYoutubeAnalyticsMonetaryEnabled } from "../policy/youtube-analytics-monetary";
import { WHITELIST_FILENAME, loadWhitelist } from "../policy/drive-whitelist";
import { getAllowlistState, summarizeAllowlist } from "../policy/recipient-allowlist";
import { getCommentBurstLimit } from "../policy/youtube-comment-burst";
import {
  getCommentTargetAllowlistState,
  parseCommentTargets,
  summarizeCommentTargetAllowlist,
} from "../policy/youtube-comment-targets";
import { getYoutubeSearchBurstLimit } from "../policy/youtube-search-burst";
import { readStartupMarker } from "../startup-marker";
import {
  ENV_TIER,
  ENV_YOUTUBE_COMMENT_TARGETS,
  ENV_YOUTUBE_COMMENT_TARGETS_EXTRA,
  ENV_YOUTUBE_COMMENT_BURST_LIMIT,
  ENV_YOUTUBE_SEARCH_BURST_LIMIT,
} from "../config";
import {
  type CheckResult,
  type DoctorReport,
  type DoctorOptions,
  type CliIO,
  ACCOUNTS_FILE,
  ENV_FILE,
  AUDIT_FILE,
  SALT_FILE,
  SALT_SIZE_BYTES,
  safeStat,
  modeVerdict,
  readAccountsSummary,
  summarize,
  defaultVersionProbe,
  tierIsValidInEnv,
} from "./shared";

export async function runDoctor(opts: DoctorOptions, io: CliIO): Promise<DoctorReport> {
  const probe = opts.versionProbe ?? defaultVersionProbe;
  const platform = opts.platform ?? process.platform;
  const checks: CheckResult[] = [];

  // Dep versions
  for (const cmd of ["bun", "claude", "jq"] as const) {
    const v = await probe(cmd);
    checks.push({
      name: cmd,
      status: v === null ? "fail" : "pass",
      value: v ?? "missing",
    });
  }

  // Tier validity (M-3: never echo env value)
  const tierValid = tierIsValidInEnv();
  checks.push({
    name: "tier",
    status: tierValid ? "pass" : "fail",
    value: tierValid
      ? (process.env[ENV_TIER] ?? "unset (defaults to read)")
      : "invalid value (expected: read|write|share|unset)",
  });

  // Config dir mode. TOCTOU note (L-1 sec-rev, #61 review): the mode check
  // here is read-only — `doctor` reports findings and never auto-fixes. If a
  // future maintainer adds auto-repair (chmod 0o700 on detected drift), the
  // stat→chmod gap becomes a real race and the check must be revisited.
  const cfg = configDir();
  const cfgStat = await safeStat(cfg);
  const cfgMode = modeVerdict(cfgStat.mode, 0o700, platform);
  checks.push({
    name: "config_dir",
    status: cfgStat.exists && cfgMode.ok ? "pass" : "fail",
    value: !cfgStat.exists ? "missing" : cfgMode.value,
  });

  // .env mode (NEVER reads content)
  const envStat = await safeStat(path.join(cfg, ENV_FILE));
  const envMode = modeVerdict(envStat.mode, 0o600, platform);
  checks.push({
    name: "env_file",
    status: !envStat.exists ? "fail" : envMode.ok ? "pass" : "fail",
    value: !envStat.exists ? "missing" : envMode.value,
  });

  // accounts.json: mode + schema
  const accountsPath = path.join(cfg, ACCOUNTS_FILE);
  const accountsStat = await safeStat(accountsPath);
  const accountsMode = modeVerdict(accountsStat.mode, 0o600, platform);
  const accountsSummary = await readAccountsSummary();
  if (!accountsStat.exists) {
    checks.push({ name: "accounts_json", status: "fail", value: "missing" });
  } else if (!accountsMode.ok) {
    checks.push({ name: "accounts_json", status: "fail", value: accountsMode.value });
  } else if (!accountsSummary.ok) {
    checks.push({ name: "accounts_json", status: "fail", value: "corrupt or invalid schema" });
  } else {
    checks.push({
      name: "accounts_json",
      status: "pass",
      value: `v${accountsSummary.version}, ${accountsSummary.count} account(s)`,
    });
  }

  // audit.jsonl mode (if exists; missing is OK — first run has no audit yet)
  const auditStat = await safeStat(path.join(cfg, AUDIT_FILE));
  if (auditStat.exists) {
    const auditMode = modeVerdict(auditStat.mode, 0o600, platform);
    checks.push({
      name: "audit_jsonl",
      status: auditMode.ok ? "pass" : "fail",
      value: auditMode.value,
    });
  }

  // audit-salt: mode + size 32 bytes (if exists; missing is OK — created lazily)
  const saltStat = await safeStat(path.join(cfg, SALT_FILE));
  if (saltStat.exists) {
    const saltMode = modeVerdict(saltStat.mode, 0o600, platform);
    if (!saltMode.ok) {
      checks.push({ name: "audit_salt", status: "fail", value: saltMode.value });
    } else if (saltStat.size !== SALT_SIZE_BYTES) {
      checks.push({
        name: "audit_salt",
        status: "fail",
        value: `wrong size (expected ${SALT_SIZE_BYTES} bytes)`,
      });
    } else {
      checks.push({ name: "audit_salt", status: "pass", value: `${saltMode.value}, 32 bytes` });
    }
  }

  // v2.1: drive-whitelist.json state. Three doctor outcomes:
  //   - absent → INFO ("policy off; tier=share fully open")
  //   - loaded with N>=0 entries → PASS (with entry count + mode check)
  //   - malformed → FAIL (fail-safe to default-deny per spec)
  // Mode is checked first; if wrong, that's the FAIL (matches .env / audit
  // patterns). loadWhitelist never echoes content into errors, so reporting
  // its error string is safe (see drive-whitelist.ts validateWhitelistFile
  // sec-rev invariant).
  const whitelistPath = path.join(cfg, WHITELIST_FILENAME);
  const whitelistStat = await safeStat(whitelistPath);
  const whitelistMode = modeVerdict(whitelistStat.mode, 0o600, platform);
  if (!whitelistStat.exists) {
    checks.push({
      name: "drive_whitelist",
      status: "pass",
      value: "absent (policy off; tier=share fully open per v2.0 behavior)",
    });
  } else if (!whitelistMode.ok) {
    checks.push({
      name: "drive_whitelist",
      status: "fail",
      value: whitelistMode.value,
    });
  } else {
    const state = await loadWhitelist(cfg);
    if (state.kind === "malformed") {
      checks.push({
        name: "drive_whitelist",
        status: "fail",
        value: `malformed: ${state.error}`,
      });
    } else if (state.kind === "loaded") {
      const folderCount = state.file.entries.filter((e) => e.type === "folder").length;
      const fileCount = state.file.entries.filter((e) => e.type === "file").length;
      const total = state.file.entries.length;
      checks.push({
        name: "drive_whitelist",
        status: "pass",
        value:
          total === 0
            ? "0 entries (default-deny — all share calls will be refused)"
            : `${total} entries (${folderCount} folder, ${fileCount} file)`,
      });
    }
  }

  // v2.2: Recipient allowlist 3-line report. Counts only, NEVER entries —
  // mirrors v2.1's "no policy state leakage" pattern. summarizeAllowlist()
  // is the only API path used here (it returns counts); we never call
  // parseAllowlistTokens directly, so ParseResult.rejected values cannot
  // leak through this check (sec-rev PR-A MEDIUM #1 mitigation).
  const allowlistState = await getAllowlistState();
  const allowlistSummary = summarizeAllowlist(allowlistState);
  if (allowlistSummary.kind === "off") {
    checks.push({
      name: "recipient_allow",
      status: "pass",
      value: "unset (policy off; gmail_send + drive_share_file user fully open per v2.1 behavior)",
    });
  } else {
    checks.push({
      name: "recipient_allow",
      status: "pass",
      value:
        allowlistSummary.allow_count === 0
          ? "0 entries (default-deny base — only self-send + EXTRA allowed)"
          : `${allowlistSummary.allow_count} entries (${allowlistSummary.allow_domain_count} domain, ${allowlistSummary.allow_email_count} email)`,
    });
  }
  checks.push({
    name: "recipient_allow_extra",
    status: "pass",
    value:
      allowlistSummary.extra_count === 0
        ? "(none)"
        : `${allowlistSummary.extra_count} entries — session-only (${allowlistSummary.extra_domain_count} domain, ${allowlistSummary.extra_email_count} email)`,
  });
  checks.push({
    name: "self_send_implicit",
    status: "pass",
    value: `${allowlistSummary.self_implicit_count} emails from accounts.json`,
  });

  // v1.18 Phase 1 — surface 4 v1.15-Phase-3 + v1.16 env vars that gate the
  // most dangerous write surfaces (YouTube comment writes + name→email
  // contact lookup). Mirrors the recipient_allow* + drive_whitelist
  // 3-line pattern: counts ONLY, never raw env-var content (sec-rev
  // hook #7 — env vars may be attacker-controlled via parent process per
  // status.ts M-3 carry-forward).
  //
  // youtube_comment_targets: cached state via getCommentTargetAllowlistState()
  // gives us parsed count + active/off discrimination. Re-parse env directly
  // to get rejected count (cached state drops it after the load-once warn).
  const commentTargetState = getCommentTargetAllowlistState();
  const commentTargetSummary = summarizeCommentTargetAllowlist(commentTargetState);
  if (commentTargetSummary.kind === "off") {
    checks.push({
      name: "youtube_comment_targets",
      status: "pass",
      value: "off (default-empty hard-deny; all comment writes refused)",
    });
  } else {
    // Re-parse to compute rejected count. NEVER echo the rejected token
    // strings — counts only. parseCommentTargets is pure + cheap.
    const baseParsed = parseCommentTargets(process.env[ENV_YOUTUBE_COMMENT_TARGETS]);
    const extraParsed = parseCommentTargets(process.env[ENV_YOUTUBE_COMMENT_TARGETS_EXTRA]);
    const rejectedCount = baseParsed.rejected.length + extraParsed.rejected.length;
    checks.push({
      name: "youtube_comment_targets",
      status: "pass",
      value: `${commentTargetSummary.count} entries (${commentTargetSummary.count} parsed, ${rejectedCount} rejected)`,
    });
  }

  // youtube_comment_burst_limit + youtube_search_burst_limit: display the
  // CLAMPED post-parse value (parser bounds-checks 1-100). Out-of-range raw
  // values cannot reach this surface — parser fell back to default.
  const commentBurst = getCommentBurstLimit();
  checks.push({
    name: "youtube_comment_burst_limit",
    status: "pass",
    value:
      process.env[ENV_YOUTUBE_COMMENT_BURST_LIMIT] === undefined
        ? `${commentBurst} (default)`
        : `${commentBurst} (env override)`,
  });
  const searchBurst = getYoutubeSearchBurstLimit();
  checks.push({
    name: "youtube_search_burst_limit",
    status: "pass",
    value:
      process.env[ENV_YOUTUBE_SEARCH_BURST_LIMIT] === undefined
        ? `${searchBurst} (default)`
        : `${searchBurst} (env override)`,
  });

  // recipient_allow_contacts: strict-truthy ("true" literal only — see
  // contact-lookup.ts). Display "on" / "off" sentinels — NEVER the raw
  // env value (could be set to "true\nALLOW_ARBITRARY_CMD=…" via parent).
  checks.push({
    name: "recipient_allow_contacts",
    status: "pass",
    value: isContactLookupEnabled() ? "on (name→email lookup enabled)" : "off",
  });

  // v1.61 youtube_analytics_monetary: strict-truthy ("true" literal only — see
  // youtube-analytics-monetary.ts). Display "on" / "off" sentinels — NEVER the
  // raw env value. "on" means the consent ceremony requests the revenue scope
  // AND youtube_analytics_query unlocks the revenue metrics; "off" (default) is
  // byte-identical to v1.59 (no revenue access).
  checks.push({
    name: "youtube_analytics_monetary",
    status: "pass",
    value: isYoutubeAnalyticsMonetaryEnabled() ? "on (revenue metrics enabled)" : "off",
  });

  // v1.8.2 #7: pending_restart — proxy reads .env + drive-whitelist.json
  // at startup (env via `bun --env-file=`, whitelist via load-once cache).
  // Changes after proxy start don't take effect until Claude Code restarts.
  // We detect this by comparing the proxy startup marker to file mtimes.
  // The startup marker filename is hidden in startup-marker.ts; no policy
  // file content is read here (only stat()), preserving the "doctor never
  // echoes policy values" invariant.
  const startupMarker = await readStartupMarker(cfg);
  if (startupMarker === null) {
    // Marker absent on fresh install (proxy hasn't run yet) or post-upgrade
    // (pre-v1.8.2 proxy never wrote one). Both are benign — informational
    // pass rather than warn so doctor doesn't shout on every fresh install.
    // The actually-bad state (marker exists + files newer) is the warn below.
    checks.push({
      name: "pending_restart",
      status: "pass",
      value: "no proxy startup marker yet (first run, or upgrade from pre-v1.8.2)",
    });
  } else {
    const filesToCheck: Array<{ name: string; path: string }> = [
      { name: "drive-whitelist.json", path: whitelistPath },
      { name: ".env", path: path.join(cfg, ENV_FILE) },
    ];
    const pending: string[] = [];
    for (const f of filesToCheck) {
      try {
        const s = await fs.stat(f.path);
        if (s.mtime.getTime() > startupMarker.getTime()) {
          pending.push(f.name);
        }
      } catch {
        /* file absent — not pending */
      }
    }
    const markerTs = startupMarker.toISOString().slice(0, 19);
    if (pending.length === 0) {
      checks.push({
        name: "pending_restart",
        status: "pass",
        value: `none (proxy started ${markerTs})`,
      });
    } else {
      checks.push({
        name: "pending_restart",
        status: "warn",
        value: `${pending.join(", ")} modified after proxy started (${markerTs}) — restart Claude Code to pick up changes`,
      });
    }
  }

  // active-account: if present, must reference an email in accounts.json (H-3)
  const active = await readActive(); // EMAIL_RE-validated; corrupt → null
  if (active !== null) {
    const inIndex = accountsSummary.ok && (accountsSummary.emails ?? []).includes(active);
    checks.push({
      name: "active_account",
      status: inIndex ? "pass" : "fail",
      value: inIndex
        ? `valid (${active})`
        : "points to an email not in accounts.json", // do NOT echo the wrong email value
    });
  }

  // --deep: per-account Keychain ping (H-1, M-1)
  if (opts.deep && accountsSummary.ok && accountsSummary.emails) {
    for (const email of accountsSummary.emails) {
      let found = false;
      try {
        // M-1: getToken returns the full token JSON briefly. We immediately
        // coerce to a boolean — never name the intermediate `token` and
        // never let it flow into output. The string is GC-eligible after
        // this line. Heap-resident for milliseconds.
        found = (await getToken(email)) !== null;
      } catch {
        // getToken throws MCPError("keychain_locked") with NO native message.
        // Render as "missing" to keep the check value a fixed string.
        found = false;
      }
      checks.push({
        name: `keychain:${email}`,
        status: found ? "pass" : "fail",
        value: found ? "found" : "missing",
      });
    }
  }

  const report: DoctorReport = { status: summarize(checks), checks };

  if (opts.json) {
    // L-4: single top-level JSON.stringify; never string-concat output.
    // H-2: NO paths leak in JSON (doctor JSON has no path fields by design).
    io.out(JSON.stringify(report));
  } else {
    for (const c of checks) {
      const tag = c.status === "pass" ? "[PASS]" : c.status === "warn" ? "[WARN]" : "[FAIL]";
      const valueSuffix = c.value !== undefined ? `: ${c.value}` : "";
      io.out(`${tag} ${c.name}${valueSuffix}`);
    }
    io.out("");
    io.out(`summary: ${report.status.toUpperCase()}`);
  }

  return report;
}
