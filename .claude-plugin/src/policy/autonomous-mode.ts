// v1.53 F2 — autonomous / strict mode flag (Autonomy Hardening track).
//
// docs/v1.52-autonomy-hardening.md §4.2. ONE deployment-mode switch
// (`SAFESPACE_AUTONOMOUS`) that flips the three `OFF=allow` allowlists
// (recipient / drive-share / tasks-delete) to DENY-BY-DEFAULT for unattended
// agents — "before you hand the box to an autonomous agent, set
// SAFESPACE_AUTONOMOUS=true; now nothing leaves unless you listed it." The
// flag is the umbrella that F4 (v1.54) permanent-delete deny will also key off.
//
// Single var, NOT a two-layer env (locked Q8): it is a deployment-mode switch,
// not an allowlist that benefits from a shell-only overlay.
//
// STRICT-TRUTHY parsing (mirrors `isContactLookupEnabled`): returns `true` ONLY
// for the literal lowercase `"true"`. Every other value — `"True"`, `"TRUE"`,
// `"1"`, `"yes"`, `"on"`, `"false"`, `""`, undefined, any whitespace-padded
// variant — returns `false`.
//
// FAILURE DIRECTION (deliberate, locked R3): a mis-parse / typo evaluates to
// `false` → the deployment stays in today's permissive OFF=allow behavior,
// BYTE-IDENTICAL to pre-v1.53. We do NOT fail toward strict-deny on a typo:
// a misconfigured flag silently bricking every write/share/delete would be a
// worse foot-gun than running in the (well-understood) interactive default.
// Autonomous mode is an explicit opt-in; the operator who means it types it
// exactly. (Contrast the gate-side empty-allowlist warnings, which DO surface
// when an allowlist is active-but-empty — those still fire under this flag.)
//
// v1.54 F4 (docs/v1.52-autonomy-hardening.md §4.3) extends this module with the
// permanent-delete HARD-DENY that keys off the same flag — see
// `enforceAutonomousDeleteDeny` below.

import { MCPError } from "../errors";
import { PERMANENT_DELETE_TOOLS } from "./write-burst";
import { ENV_AUTONOMOUS, readStrictTruthy } from "../config";

export { ENV_AUTONOMOUS };

/** True iff `SAFESPACE_AUTONOMOUS` is the literal lowercase string "true".
 *
 *  Returns false for every other value (see the file comment for why this is
 *  strict-truthy and why a typo fails toward today's permissive behavior). */
export function isAutonomousMode(): boolean {
  return readStrictTruthy(ENV_AUTONOMOUS);
}

// ── v1.54 F4 — autonomous-mode permanent-delete hard-deny ──────────────────
//
// docs/v1.52-autonomy-hardening.md §4.3. Permanent-delete tools rely on a SOFT
// control — the tool description tells the model "confirm with the user first."
// Under autonomy there is no user, so that control simply evaporates. F4
// replaces it with a STRUCTURAL deny: when SAFESPACE_AUTONOMOUS=true, every tool
// in F1's PERMANENT_DELETE_TOOLS set is denied at the choke point, BEFORE the
// SDK call (and before F1's burst counter, so a denied delete does not consume
// burst budget). RECOVERABLE mutations — gmail trash/archive, tasks_clear,
// youtube_playlist_item_remove, gmail_delete_filter, drive_unshare_file — are in
// the write bucket, NOT this set, and are unaffected.
//
// Classifier reuse (locked Q5 = option (a)): F4 does NOT introduce its own
// permanent-delete notion — it reuses F1's `PERMANENT_DELETE_TOOLS` const Set
// verbatim, so the set is audited once and the two features cannot drift.
// (`cli/audit/deletes.ts` `classifyDestructive` is POST-HOC — it reads
// already-written audit rows — so it cannot be a runtime gate; this const Set is
// the runtime answer to "is this tool a permanent delete.")

/** Hard-deny a permanent-delete tool when autonomous mode is on. No-op for any
 *  non-permanent-delete tool, and a no-op entirely when not autonomous (the
 *  default param resolves to `isAutonomousMode()` — today's behavior is
 *  byte-identical to pre-v1.54). Throws -32033 with NO target echo (the tool
 *  name is already on the audit row). `autonomous` is injectable for tests. */
export function enforceAutonomousDeleteDeny(
  toolName: string,
  autonomous: boolean = isAutonomousMode(),
): void {
  if (!autonomous) return;
  if (PERMANENT_DELETE_TOOLS.has(toolName)) {
    throw new MCPError("destructive_denied_in_autonomous_mode");
  }
}
