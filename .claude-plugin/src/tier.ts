// v2.0 tier system — single env var `SAFESPACE_TIER` replaces v1.x's three
// independent kill switches (SAFESPACE_ENABLE_{SEND,MODIFY,DRIVE_SHARE}).
//
// 3-level monotonic: `share` ⊇ `write` ⊇ `read`. Higher tier exposes more
// tools via the tools/list filter in proxy.ts. Default `read` = safest.
//
// Threat model after v2.0: tier-based tool exposure is the structural defense
// (Claude can't call what it can't see). Claude Code's per-tool approve UI
// is the operational defense. See docs/DESIGN.md v2.0 Addendum for the
// full threat model shift documentation.
//
// v1.1.0 (polish PR): legacy-flag migration shim REMOVED. Per architect
// review, single-user threat model collapses the "phased deprecation" case
// — Option B (hard-fail) chosen over silent default-to-read because silent
// capability loss is the only outcome with an actually dangerous failure
// mode. See docs/DESIGN.md v2.0 Addendum.

import {
  ENV_TIER,
  ENV_ENABLE_SEND,
  ENV_ENABLE_MODIFY,
  ENV_ENABLE_DRIVE_SHARE,
} from "./config";

export type Tier = "read" | "write" | "share";

const TIER_ORDER: Record<Tier, number> = {
  read: 0,
  write: 1,
  share: 2,
};

const ALL_TIERS: ReadonlySet<string> = new Set(["read", "write", "share"]);

const LEGACY_FLAG_ERROR =
  "[safespace] SAFESPACE_ENABLE_{SEND,MODIFY,DRIVE_SHARE} are removed in v1.1. " +
  "Set SAFESPACE_TIER=read|write|share in your .env (or run `safespace migrate-v2` " +
  "if upgrading from v1.x). See docs/DESIGN.md v2.0 Addendum.";

/** Resolve the current tier from env. Priority:
 *  1. Explicit SAFESPACE_TIER if set to a valid value → that tier
 *  2. Invalid SAFESPACE_TIER → "read" with stderr warning (fail-safe: typo
 *     "writes" or "shr" never accidentally opens writes)
 *  3. Legacy SAFESPACE_ENABLE_{SEND,MODIFY,DRIVE_SHARE} set without
 *     SAFESPACE_TIER → throw (v1.1: bridge removed per architect review;
 *     silent default-to-read would mask capability loss for upgraders)
 *  4. Nothing set → "read" (the safe default) */
export function currentTier(): Tier {
  const raw = process.env[ENV_TIER];
  if (raw !== undefined && raw !== "") {
    if (ALL_TIERS.has(raw)) return raw as Tier;
    console.error(
      `[safespace] SAFESPACE_TIER="${raw}" is invalid (expected read|write|share). Falling back to "read".`,
    );
    return "read";
  }

  // v1.1: legacy-flag hard-fail. Without SAFESPACE_TIER set, the presence of
  // any v1.x kill switch is an ambiguous request — refuse rather than guess.
  // The error message is the migration doc.
  const hasLegacyFlag =
    process.env[ENV_ENABLE_SEND] === "1" ||
    process.env[ENV_ENABLE_MODIFY] === "1" ||
    process.env[ENV_ENABLE_DRIVE_SHARE] === "1";
  if (hasLegacyFlag) {
    throw new Error(LEGACY_FLAG_ERROR);
  }

  return "read";
}

/** True if `current` tier is high enough to satisfy a tool's `min_tier`. */
export function tierSatisfies(current: Tier, required: Tier): boolean {
  return TIER_ORDER[current] >= TIER_ORDER[required];
}

// ----- v1.x .env → v2.0 SAFESPACE_TIER derivation (used by migrate-v2) -----
//
// The proxy itself hard-fails on legacy-flag-only state (see currentTier
// above). These pure helpers exist so the migration tool can rewrite the
// .env file in-place at install time, sparing the user a manual edit.
// Keeping them here (not in migrate.ts) lets the wizard's future "F" path
// share the same logic.

export interface TierDerivation {
  derivedTier: Tier;
  /** Names of the legacy flags found (file order). For user-facing reporting. */
  legacyFlagsFound: string[];
}

// Match `KEY=1` where KEY is at line start (allowing leading whitespace) and
// the value is exactly the literal `1` (followed by whitespace, comment, or
// end-of-line). Preserves v1.x semantics: only "1" enables a flag.
const FLAG_LINE = /^[ \t]*SAFESPACE_ENABLE_(DRIVE_SHARE|SEND|MODIFY)[ \t]*=[ \t]*1[ \t]*(#.*)?$/;

// Match an uncommented `SAFESPACE_TIER=...` line (any value — the proxy
// validates content). If present, the user already declared a tier and
// derivation must not override.
const EXPLICIT_TIER_LINE = /^[ \t]*SAFESPACE_TIER[ \t]*=/m;

/**
 * Inspect .env content. If it contains uncommented `SAFESPACE_ENABLE_*=1`
 * legacy flags AND no `SAFESPACE_TIER=` line, return the tier those flags
 * would derive to (precedence: DRIVE_SHARE > SEND/MODIFY > nothing).
 * Otherwise return `null` — caller leaves the content untouched.
 *
 * Pure function: no I/O, no env reads. Safe to call on plaintext that
 * contains secrets — content is never logged or echoed.
 */
export function deriveTierFromLegacyEnv(content: string): TierDerivation | null {
  if (EXPLICIT_TIER_LINE.test(content)) return null;

  const flagsFound: string[] = [];
  for (const line of content.split("\n")) {
    const m = FLAG_LINE.exec(line);
    if (m) flagsFound.push(`SAFESPACE_ENABLE_${m[1]}`);
  }
  if (flagsFound.length === 0) return null;

  let derivedTier: Tier = "read";
  if (flagsFound.includes("SAFESPACE_ENABLE_DRIVE_SHARE")) {
    derivedTier = "share";
  } else if (
    flagsFound.includes("SAFESPACE_ENABLE_SEND") ||
    flagsFound.includes("SAFESPACE_ENABLE_MODIFY")
  ) {
    derivedTier = "write";
  }
  return { derivedTier, legacyFlagsFound: flagsFound };
}

/**
 * Rewrite .env content: comment out every `SAFESPACE_ENABLE_*=1` line and
 * append `SAFESPACE_TIER=<derived>` at the end. Preserves all other lines
 * verbatim (GOOGLE_CLIENT_*, comments, blank lines).
 *
 * Output always ends with a newline. Total function — does not check
 * whether derivation actually applies; caller decides.
 */
export function rewriteEnvWithDerivedTier(content: string, derivedTier: Tier): string {
  const lines = content.split("\n");
  const out: string[] = [];
  let wroteMigrationHeader = false;
  for (const line of lines) {
    if (FLAG_LINE.test(line)) {
      if (!wroteMigrationHeader) {
        out.push("# v1.1: removed — auto-migrated to SAFESPACE_TIER below");
        wroteMigrationHeader = true;
      }
      out.push(`# ${line}`);
    } else {
      out.push(line);
    }
  }
  let result = out.join("\n");
  if (!result.endsWith("\n")) result += "\n";
  result += `SAFESPACE_TIER=${derivedTier}\n`;
  return result;
}
