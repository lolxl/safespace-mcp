// v1.86 — enforced mode: the company-deployment hardening assertion.
//
// docs/SOLE-EGRESS.md. F6 (v1.55) already did a "refuse-to-start" for ONE
// precondition (token-at-rest). Enforced mode GENERALIZES that to the SafeSpace-
// side hardening knobs a company deployment must set, and refuses to start the
// bootstrap (BEFORE the MCP handshake) when any of them is wrong — so a
// misconfigured chokepoint never serves a single tool.
//
// HONEST BOUNDARY (do not oversell — mirrors F6's note + SOLE-EGRESS's
// "necessary but not sufficient"): enforced mode can only check things in
// SafeSpace's OWN process/config. The network egress lockdown (Layer 2, the
// load-bearing one), the agent runtime sandbox (Layer 3), and provider IP-pinning
// (Layer 4) are DEPLOYMENT-EXTERNAL — SafeSpace cannot verify them. They stay the
// operator's responsibility; `safespace doctor --posture` reminds them so a green
// posture is never mistaken for "sole egress."
//
// FAILURE DIRECTION (mirrors F2 R3 / F6): the SAFESPACE_ENFORCED flag itself is
// strict-truthy — a typo ("True"/"1"/"") evaluates false → today's non-enforced
// posture (byte-identical, the safe direction; a mis-parsed flag must not brick a
// deployment). Once the flag is DELIBERATELY set to "true", the preconditions then
// fail toward REFUSE.
//
// STRICTER THAN F6: in enforced mode the SAFESPACE_ALLOW_KEYFILE_AT_REST escape
// hatch is NOT honored — a company deployment does not get to opt back into
// key-beside-ciphertext storage. Enforced is a deliberate step up from F6.
//
// ONE DELIBERATE HATCH (v1.94 A2): the all-interfaces bind gate IS relaxable via
// SAFESPACE_TLS_TERMINATED. The asymmetry with the keyfile hatch is principled —
// SafeSpace CAN fix key-at-rest in-process (a passphrase), so it refuses the weaker
// option; it CANNOT terminate TLS in-process for a plaintext node:http listener
// without becoming a cert-managing reverse proxy, so the upstream-TLS attestation is
// the honest deployment-external boundary (the listener stays plaintext; see
// httpBindGate). The hatch relaxes ONLY the bind gate; it never weakens auth.

import { isAutonomousMode } from "./autonomous-mode";
import { selectBackendKind } from "../auth/select-backend";
import { isPassphraseMode } from "../auth/file-backend";
import { transportMode, DEFAULT_BIND } from "../transport/http";
import { webhookBind, webhookEnabled } from "../transport/webhook";
import { ENV_ENFORCED, ENV_HTTP_BIND, ENV_TLS_TERMINATED, readStrictTruthy } from "../config";

export { ENV_ENFORCED };

/** True iff SAFESPACE_ENFORCED is the literal lowercase "true" (strict-truthy;
 *  every other value → false → non-enforced, today's posture). */
export function isEnforcedMode(): boolean {
  return readStrictTruthy(ENV_ENFORCED);
}

/** A single hardening precondition. `n/a` = inapplicable to the current
 *  deployment (e.g. the bind gate under stdio — there is no listener). */
export type GateStatus = "pass" | "fail" | "n/a";

export interface EnforcedGate {
  readonly name: "autonomous_mode" | "token_at_rest" | "http_bind" | "webhook_bind";
  readonly status: GateStatus;
  /** A fixed, remedy-bearing sentence. NEVER echoes a secret / PII / denied
   *  value (only the operator's own static config — bind address, backend kind). */
  readonly detail: string;
}

/** Enforced mode is built on autonomous mode: without it the OFF=allow egress
 *  allowlists never flip to deny-by-default and F4 permanent-delete deny is off,
 *  so an "enforced" deployment that isn't autonomous is incoherent. */
function autonomousGate(): EnforcedGate {
  return isAutonomousMode()
    ? {
        name: "autonomous_mode",
        status: "pass",
        detail: "autonomous mode on (deny-by-default egress + F4 permanent-delete deny)",
      }
    : {
        name: "autonomous_mode",
        status: "fail",
        detail:
          'SAFESPACE_AUTONOMOUS is not "true" — enforced mode requires it ' +
          "(deny-by-default egress allowlists + F4 permanent-delete deny). " +
          "Set SAFESPACE_AUTONOMOUS=true.",
      };
}

/** The OAuth token store must not be offline-capturable. Keychain (OS-guarded) or
 *  FileBackend in passphrase mode (no key at rest) pass; FileBackend KEY-FILE mode
 *  fails — and unlike F6, the SAFESPACE_ALLOW_KEYFILE_AT_REST hatch does NOT
 *  rescue it here (enforced > F6). */
function tokenAtRestGate(): EnforcedGate {
  if (selectBackendKind() === "keychain") {
    return {
      name: "token_at_rest",
      status: "pass",
      detail: "OAuth tokens in the OS keychain (key OS-guarded, not in an offline backup)",
    };
  }
  if (isPassphraseMode()) {
    return {
      name: "token_at_rest",
      status: "pass",
      detail: "OAuth tokens in encrypted FileBackend, passphrase mode (no key at rest)",
    };
  }
  return {
    name: "token_at_rest",
    status: "fail",
    detail:
      "OAuth token store is FileBackend KEY-FILE mode — the AES key sits beside " +
      "the ciphertext (offline-capturable). Enforced mode does NOT honor " +
      "SAFESPACE_ALLOW_KEYFILE_AT_REST: set SAFESPACE_SECRET_PASSPHRASE " +
      "(recommended) or use the OS Keychain.",
  };
}

/** The HTTP listener (Model B) must not bind all interfaces. Under stdio there is
 *  no listener → n/a. An unset/empty bind falls back to loopback (safe); only an
 *  explicit all-interfaces bind fails — UNLESS the operator attests an external
 *  TLS-terminating proxy fronts it (v1.94 A2: SAFESPACE_TLS_TERMINATED=true), which
 *  RELAXES the gate to pass with the attestation made explicit in the detail.
 *
 *  Why a relaxation (and why ONLY here): the listener is `node:http`/plaintext, so
 *  an all-interfaces bind on a public interface would expose a plaintext credential.
 *  A1's no-tailnet token deployment (and any container bridge-network topology) does
 *  bind all-interfaces inside its netns behind a reverse proxy — a legitimate, common
 *  shape SafeSpace cannot distinguish from a naked public bind. SafeSpace does NOT
 *  ship in-process TLS (that duplicates what every reverse proxy / cloud LB does
 *  better, with cert-rotation burden); instead it makes the operator's TLS+network
 *  responsibility EXPLICIT via the attestation, the same honest deployment-external
 *  boundary as the egress lockdown (docs/SOLE-EGRESS.md). Unlike the keyfile-at-rest
 *  hatch (which enforced mode deliberately does NOT honor, because SafeSpace CAN fix
 *  key-at-rest in-process via a passphrase), there is no in-process alternative to an
 *  upstream TLS terminator — so this hatch is honored. */
function httpBindGate(): EnforcedGate {
  if (transportMode() !== "http") {
    return {
      name: "http_bind",
      status: "n/a",
      detail: "stdio transport — no network listener (bind N/A)",
    };
  }
  // Mirror the production resolution (transport/http resolveHttpConfigFromEnv):
  // empty → loopback default; NEVER 0.0.0.0. Read via the catalog const, not a
  // SAFESPACE_ literal (the config drift sentinel forbids the literal form).
  const bind = process.env[ENV_HTTP_BIND] || DEFAULT_BIND;
  if (bind === "0.0.0.0" || bind === "::") {
    if (readStrictTruthy(ENV_TLS_TERMINATED)) {
      return {
        name: "http_bind",
        status: "pass",
        detail:
          `HTTP listener binds all interfaces (${bind}); permitted by ` +
          "SAFESPACE_TLS_TERMINATED — the operator attests an external TLS-terminating " +
          "proxy fronts the plaintext listener and restricts who can reach it. SafeSpace " +
          "cannot verify this (deployment-external, like the egress lockdown).",
      };
    }
    return {
      name: "http_bind",
      status: "fail",
      detail:
        `SAFESPACE_HTTP_BIND binds all interfaces (${bind}) — exposes the ` +
        "plaintext listener beyond the host. Bind loopback (127.0.0.1) or the tailscale " +
        "interface (100.x.y.z) explicitly; or, if an external TLS-terminating proxy " +
        "fronts it, set SAFESPACE_TLS_TERMINATED=true to attest that.",
    };
  }
  return {
    name: "http_bind",
    status: "pass",
    detail: `HTTP listener bound to ${bind} (not all-interfaces)`,
  };
}

/** v1.102 (W0) — the inbound webhook listener (a SEPARATE public surface from the MCP
 *  transport) must not bind all interfaces either. n/a when the listener is not enabled
 *  (SAFESPACE_WEBHOOK_PORT unset). Same SAFESPACE_TLS_TERMINATED relaxation + same
 *  reasoning as httpBindGate — without this, enforced mode would harden the MCP bind
 *  while leaving the new public webhook bind unchecked (security HIGH-2b). */
function webhookBindGate(): EnforcedGate {
  if (!webhookEnabled()) {
    return {
      name: "webhook_bind",
      status: "n/a",
      detail: "inbound webhook listener not enabled (SAFESPACE_WEBHOOK_PORT unset)",
    };
  }
  const bind = webhookBind();
  if (bind === "0.0.0.0" || bind === "::") {
    if (readStrictTruthy(ENV_TLS_TERMINATED)) {
      return {
        name: "webhook_bind",
        status: "pass",
        detail:
          `inbound webhook listener binds all interfaces (${bind}); permitted by ` +
          "SAFESPACE_TLS_TERMINATED — the operator attests an external TLS-terminating " +
          "proxy fronts the plaintext listener and restricts who can reach it. SafeSpace " +
          "cannot verify this (deployment-external, like the MCP http_bind gate).",
      };
    }
    return {
      name: "webhook_bind",
      status: "fail",
      detail:
        `SAFESPACE_WEBHOOK_BIND binds all interfaces (${bind}) — exposes the plaintext ` +
        "inbound webhook listener beyond the host. Bind a private/proxied interface " +
        "explicitly; or, if an external TLS-terminating proxy fronts it, set " +
        "SAFESPACE_TLS_TERMINATED=true to attest that.",
    };
  }
  return {
    name: "webhook_bind",
    status: "pass",
    detail: `inbound webhook listener bound to ${bind} (not all-interfaces)`,
  };
}

/** Evaluate every hardening gate. Pure (env + platform only) and INDEPENDENT of
 *  whether enforced mode is on — so `doctor --posture` can preview "what WOULD
 *  fail if you turned SAFESPACE_ENFORCED on." The refusal logic below wraps this
 *  with the enforced-flag gate. */
export function evaluateEnforcedGates(): EnforcedGate[] {
  return [autonomousGate(), tokenAtRestGate(), httpBindGate(), webhookBindGate()];
}

/** The refusal MESSAGE when enforced mode is on AND ≥1 gate fails; null when not
 *  enforced or all gates pass. Names EVERY failing precondition at once (no
 *  restart-then-fail-on-the-next whack-a-mole) + the honest external-layers
 *  footer. The message echoes no secret / PII (only the operator's own config). */
export function enforcedModeRefusal(): string | null {
  if (!isEnforcedMode()) return null;
  const failed = evaluateEnforcedGates().filter((g) => g.status === "fail");
  if (failed.length === 0) return null;
  const bullets = failed.map((g) => `  - ${g.detail}`).join("\n");
  return (
    "SAFESPACE_ENFORCED=true but the deployment is not hardened — refusing to " +
    "start. Fix the following, or unset SAFESPACE_ENFORCED to run in the " +
    "(non-enforced) default posture:\n" +
    bullets +
    "\nEnforced mode asserts SafeSpace's OWN hardening knobs only; the network " +
    "egress lockdown, agent sandbox, and provider IP-pinning remain the " +
    "deployment's responsibility — see docs/SOLE-EGRESS.md."
  );
}

/** Startup enforcement (mirrors F6's enforceAutonomousTokenStorage). Throws when
 *  `enforcedModeRefusal()` returns a message; the proxy bootstrap catches the
 *  throw, prints it to stderr, and exits non-zero BEFORE serving any tool. No-op
 *  when not enforced or all gates pass. */
export function enforceEnforcedMode(): void {
  const reason = enforcedModeRefusal();
  if (reason !== null) throw new Error(reason);
}
