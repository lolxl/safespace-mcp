// `safespace doctor --posture` — enforced-mode hardening posture (split out of
// status.ts, v1.112.5 — behavior-preserving verbatim move).
import { isEnforcedMode, evaluateEnforcedGates } from "../policy/enforced-mode";
import { isSendApprovalMode } from "../policy/send-approval";
import { listPending, pendingSendsPath } from "../auth/send-approval-store";
import { enabledWebhookProviders, webhookEnabled } from "../transport/webhook";
import { hasWebhookSigningSecret } from "../auth/webhook-secret-store";
import { inboxCounts, inboxPath } from "../webhook/inbox-store";
import { evaluateEgressPosture } from "../policy/egress-posture";
import { EGRESS_DESTINATIONS } from "../policy/egress-destinations";
import {
  type CheckResult,
  type DoctorReport,
  type PostureOptions,
  type CliIO,
  summarize,
} from "./shared";

// ----- runPosture (v1.86 — enforced-mode hardening posture) -----

// The honest "what SafeSpace can't check" reminder (docs/SOLE-EGRESS.md). Always
// surfaced so a green posture is never read as "sole egress" — these layers are
// DEPLOYMENT-EXTERNAL. Emitted as a NOTE (not a CheckResult) so it never pollutes
// the pass/warn/fail roll-up with a perpetual warn.
const EXTERNAL_LAYERS_NOTE =
  "SafeSpace verifies its OWN hardening knobs only. The network egress lockdown " +
  "(the load-bearing one), the agent runtime sandbox, and provider IP-pinning are " +
  "DEPLOYMENT-EXTERNAL — SafeSpace cannot check them. Verify them per docs/SOLE-EGRESS.md.";

/** `safespace doctor --posture` — report the enforced-mode hardening posture: the
 *  SAFESPACE_ENFORCED flag state + the three refuse-to-start gates (the SAME gate
 *  evaluation the startup guard uses), plus the honest external-layers reminder.
 *  Read-only; runs identically under stdio (Model A) and http (Model B). */
export async function runPosture(opts: PostureOptions, io: CliIO): Promise<DoctorReport> {
  const checks: CheckResult[] = [];

  const enforced = isEnforcedMode();
  checks.push({
    name: "enforced_mode",
    status: enforced ? "pass" : "warn",
    value: enforced ? "on (refuse-to-start active)" : "off (gates reported, not enforced)",
  });

  for (const g of evaluateEnforcedGates()) {
    checks.push({
      name: g.name,
      // CheckResult has no "n/a"; an inapplicable gate (http_bind under stdio) is
      // not a problem → render as pass, with the value making "n/a" explicit so it
      // never reads as a verified green.
      status: g.status === "n/a" ? "pass" : g.status,
      value: g.detail,
    });
  }

  // v1.100 — supervised send-approval posture (the v1.99 opt-in gate). On = outbound
  // message sends are held for owner approval; off = the default (NOT a deficiency —
  // most deployments run unsupervised / autonomous). Shows the pending COUNT only;
  // NEVER a pending body/recipient (no-PII-echo, like the egress rows).
  const supervised = isSendApprovalMode();
  let supervisedValue: string;
  if (!supervised) {
    supervisedValue = "off (sends are not gated by per-send approval — the default)";
  } else {
    let pending: string;
    try {
      pending = `${(await listPending(pendingSendsPath(), Date.now())).length} pending`;
    } catch {
      pending = "pending count unavailable (store unreadable)";
    }
    supervisedValue = `on — outbound message sends require owner approval (${pending})`;
  }
  checks.push({ name: "send_approval", status: "pass", value: supervisedValue });

  // v1.102 (W0) — inbound webhook listener posture. Disabled under Model A
  // (SAFESPACE_WEBHOOK_PORT unset) → no inbound surface, never implies one exists. When
  // enabled: which providers are wired, whether each signing secret is present, and the
  // inbox COUNT per provider (counts only — NEVER a body/sender, like the egress rows).
  // A corrupt store → "unavailable", never fails the posture (v1.87/v1.101 precedent).
  if (!webhookEnabled()) {
    checks.push({
      name: "webhook",
      status: "pass",
      value: "disabled (SAFESPACE_WEBHOOK_PORT unset — no inbound webhook surface)",
    });
  } else {
    const providers = enabledWebhookProviders();
    const secretParts: string[] = [];
    for (const p of providers) {
      let present = false;
      try {
        present = await hasWebhookSigningSecret(p);
      } catch {
        present = false;
      }
      secretParts.push(`${p} secret ${present ? "present" : "MISSING"}`);
    }
    let counts: string;
    try {
      const c = await inboxCounts(inboxPath(), Date.now());
      counts = providers.map((p) => `${p}:${c[p]}`).join(", ");
    } catch {
      counts = "count unavailable (store unreadable)";
    }
    const anyMissing = secretParts.some((s) => s.includes("MISSING"));
    checks.push({
      name: "webhook",
      status: anyMissing ? "warn" : "pass",
      value: `on — providers: ${providers.join(", ")}; ${secretParts.join("; ")}; inbox ${counts}`,
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
