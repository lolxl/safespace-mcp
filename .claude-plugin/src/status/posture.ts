// `safespace doctor --posture` — the hardening posture (split out of status.ts,
// v1.112.5): the SafeSpace-side hardening settings, the connector axis, and the
// egress allowlists / destinations. Read-only; reports, never refuses.
import { isAutonomousMode } from "../policy/autonomous-mode";
import { isSendApprovalMode } from "../policy/send-approval";
import { selectBackendKind } from "../auth/select-backend";
import { isPassphraseMode } from "../auth/file-backend";
import { listPending, pendingSendsPath } from "../auth/send-approval-store";
import { evaluateEgressPosture } from "../policy/egress-posture";
import { connectorPostureValue, resolveEnabledConnectors } from "../policy/connector-toggle";
import { EGRESS_DESTINATIONS } from "../policy/egress-destinations";
import { effectiveRequiredScopes } from "../auth/consent";
import {
  type CheckResult,
  type DoctorReport,
  type PostureOptions,
  type CliIO,
  summarize,
} from "./shared";

// ----- runPosture -----

// The honest "what SafeSpace can't check" reminder (docs/SOLE-EGRESS.md). Always
// surfaced so a green posture is never read as "sole egress" — these layers are
// DEPLOYMENT-EXTERNAL. Emitted as a NOTE (not a CheckResult) so it never pollutes
// the pass/warn/fail roll-up with a perpetual warn.
const EXTERNAL_LAYERS_NOTE =
  "SafeSpace verifies its OWN hardening knobs only. The network egress lockdown " +
  "(the load-bearing one), the agent runtime sandbox, and provider IP-pinning are " +
  "DEPLOYMENT-EXTERNAL — SafeSpace cannot check them. Verify them per docs/SOLE-EGRESS.md.";

/** `safespace doctor --posture` — report the hardening posture: autonomous mode, the
 *  token store at rest, supervised send-approval, the connector axis, and the egress
 *  allowlists / destinations. Plus the honest external-layers reminder. Read-only. */
export async function runPosture(opts: PostureOptions, io: CliIO): Promise<DoctorReport> {
  const checks: CheckResult[] = [];

  // The three SafeSpace-side hardening settings. Each one off is a FAIL, so the exit
  // code stays the hardening check scripts gate on (`doctor --posture && deploy`).
  // Nothing here refuses anything — the server starts either way.
  checks.push(
    isAutonomousMode()
      ? {
          name: "autonomous_mode",
          status: "pass",
          value: "on (deny-by-default egress allowlists + F4 permanent-delete deny)",
        }
      : {
          name: "autonomous_mode",
          status: "fail",
          value: "off — set SAFESPACE_AUTONOMOUS=true (deny-by-default egress + F4 permanent-delete deny)",
        },
  );

  if (selectBackendKind() === "keychain") {
    checks.push({ name: "token_at_rest", status: "pass", value: "OS keychain (key OS-guarded)" });
  } else if (isPassphraseMode()) {
    checks.push({
      name: "token_at_rest",
      status: "pass",
      value: "encrypted FileBackend, passphrase mode (no key at rest)",
    });
  } else {
    checks.push({
      name: "token_at_rest",
      status: "fail",
      value:
        "encrypted FileBackend, KEY-FILE mode — the key sits beside the ciphertext " +
        "(offline-capturable); set SAFESPACE_SECRET_PASSPHRASE or use the OS keychain",
    });
  }

  // Pending COUNT only; NEVER a pending body/recipient (no-PII-echo).
  if (isSendApprovalMode()) {
    let pending: string;
    try {
      pending = `${(await listPending(pendingSendsPath(), Date.now())).length} pending`;
    } catch {
      pending = "pending count unavailable (store unreadable)";
    }
    checks.push({
      name: "send_approval",
      status: "pass",
      value: `on — outbound publishes require owner approval (${pending})`,
    });
  } else {
    checks.push({
      name: "send_approval",
      status: "fail",
      value: "off — set SAFESPACE_REQUIRE_SEND_APPROVAL=true to hold outbound publishes for owner approval",
    });
  }

  // v1.127 — the connector exposure axis (SAFESPACE_CONNECTORS). Emitted as a PLAIN
  // row here, deliberately NOT registered with `evaluateEgressPosture()` below: that
  // module's `classifyEgress` is the single source of the restricted/deny-all/OPEN
  // rule for EGRESS allowlists, and this axis is not one. Routed through it, an
  // unset variable would render as `OPEN … warn` — a false security warning telling
  // the operator to shrink their tool list for safety — and under autonomous mode as
  // `deny-all`, which is flatly untrue (every tool is still exposed). Always `pass`:
  // both states are legitimate, so this row informs and never votes.
  checks.push({ name: "connectors", status: "pass", value: connectorPostureValue() });

  // v1.128 — requested Google consent vs the agent surface. Counts only; the
  // word is `requested` (effectiveRequiredScopes / V1 https list), NEVER a
  // stored grant / token. Unset CONNECTORS → pass (not a warning). A set
  // CONNECTORS value does not shrink the request list — that mismatch is a
  // warn so the operator sees it. This row does not read the token store.
  {
    const n = effectiveRequiredScopes().length;
    const restricted = resolveEnabledConnectors() !== null;
    checks.push({
      name: "google_consent_requested",
      status: restricted ? "warn" : "pass",
      value: restricted
        ? `requested ${n} https scopes; CONNECTORS does not shrink this`
        : `requested ${n} https scopes (CONNECTORS unset — request list is the full V1 set)`,
    });
  }

  // Per-connector egress/access allowlist enumeration (v1.87) — what can actually
  // reach/leave through this deployment. Rows carry COUNTS only, never contents.
  // An OPEN (off→allow + unset + interactive) connector is the one warn here.
  for (const e of await evaluateEgressPosture()) {
    checks.push({ name: `egress:${e.connector}`, status: e.status, value: e.detail });
  }

  // Egress-DESTINATION registry (v1.88) — the complementary "SafeSpace → provider"
  // direction: every external host SafeSpace's OWN process connects to. Informational
  // (always pass); `enforced` = runtime-gated at the fetch chokepoint, `declared` =
  // listed-but-ungatable (the googleapis SDK / the dynamic web-fetch url-gate own it).
  for (const d of EGRESS_DESTINATIONS) {
    checks.push({
      name: `egress-dest:${d.connector}`,
      status: "pass",
      value: `${d.hosts.join(", ")} (${d.enforcement}${d.note ? ` — ${d.note}` : ""})`,
    });
  }

  const report: DoctorReport = { status: summarize(checks), checks };

  if (opts.json) {
    io.out(JSON.stringify({ ...report, external_layers: EXTERNAL_LAYERS_NOTE }));
  } else {
    for (const c of checks) {
      const tag = c.status === "pass" ? "[PASS]" : c.status === "warn" ? "[WARN]" : "[FAIL]";
      const valueSuffix = c.value !== undefined ? `: ${c.value}` : "";
      io.out(`${tag} ${c.name}${valueSuffix}`);
    }
    io.out("");
    io.out(`note: ${EXTERNAL_LAYERS_NOTE}`);
    io.out("");
    io.out(`summary: ${report.status.toUpperCase()}`);
  }

  return report;
}
