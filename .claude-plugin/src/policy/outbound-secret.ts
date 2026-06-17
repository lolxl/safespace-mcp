// v1.57 F3a — outbound secret-shape scanner (Autonomy Hardening track).
//
// docs/v1.57-f3a-outbound-secret-and-f3b-gate.md §4.2. Closes P8 (C8 exfil / C9
// 2FA-relay): a read-then-send can put a secret in a gmail body and exfiltrate
// it. F3a scans the outbound body for a MECHANICALLY-RECOGNIZABLE secret SHAPE —
// a private-key block or a named provider API-key. Under autonomous mode the
// handler REJECTS (-32035); interactive mode records an audit flag (NO block).
//
// STRICTLY SHAPE-BASED — this is the narrow, defensible fragment of "outbound
// DLP", NOT a content judgement. A literal `-----BEGIN ... PRIVATE KEY-----` or
// an `AKIA…` token IS a secret by its shape; we never ask "does this look
// confidential". The FP-prone rules (high-entropy base64 + verification-code
// shape) are DEFAULT OFF (locked Q6) behind an explicit opt-in env, because a
// legitimate body can contain a long token or a 6-digit number.
//
// The matched bytes are NEVER returned — only the closed-set shape CLASS, which
// the handler echoes as errorData.reason (a bounded value, mirroring formula-
// reject's UPPERCASED function name; no secret-byte leak).

import { ENV_OUTBOUND_SECRET_EXTRA, readStrictTruthy } from "../config";

export type OutboundSecretShape =
  | "private_key"
  | "aws_key"
  | "google_api_key"
  | "github_token"
  | "slack_token"
  | "stripe_key"
  | "openai_key"
  | "high_entropy_base64"
  | "verification_code";

// DEFAULT list — unambiguous secret shapes, always checked under the F3a path.
// All anchored / bounded character classes (no nested quantifiers → ReDoS-safe).
const DEFAULT_SECRET_RULES: ReadonlyArray<{ shape: OutboundSecretShape; re: RegExp }> = [
  { shape: "private_key", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/ },
  { shape: "aws_key", re: /\bAKIA[0-9A-Z]{16}\b/ },
  { shape: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  { shape: "github_token", re: /\bgh[posru]_[0-9A-Za-z]{36}\b|\bgithub_pat_[0-9A-Za-z_]{22,}\b/ },
  { shape: "slack_token", re: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { shape: "stripe_key", re: /\bsk_live_[0-9A-Za-z]{24,}\b/ },
  { shape: "openai_key", re: /\bsk-[A-Za-z0-9]{32,}\b/ },
];

// EXTRA list — FP-prone shapes, applied ONLY when the opt-in env is set (Q6).
// high_entropy_base64: a long standalone base64 run (matches legit tokens too).
// verification_code: a 6-8 digit number co-occurring with a code keyword.
const EXTRA_SECRET_RULES: ReadonlyArray<{ shape: OutboundSecretShape; re: RegExp }> = [
  { shape: "high_entropy_base64", re: /\b[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])/ },
  {
    shape: "verification_code",
    re: /\b(?:code|otp|verification|passcode|one[-\s]?time|驗證碼)\b[^\n]{0,24}\b\d{6,8}\b|\b\d{6,8}\b[^\n]{0,24}\b(?:code|otp|passcode)\b/i,
  },
];

/** Opt-in env (locked Q6, strict-truthy literal lowercase "true", mirrors
 *  SAFESPACE_AUTONOMOUS): when set, the FP-prone EXTRA rules are ALSO checked. */
export { ENV_OUTBOUND_SECRET_EXTRA };

function extraRulesEnabled(): boolean {
  return readStrictTruthy(ENV_OUTBOUND_SECRET_EXTRA);
}

/** Scan an outbound body for a recognizable secret SHAPE. Returns the shape class
 *  on the first match (DEFAULT rules always; EXTRA rules only when the opt-in env
 *  is set), else null. Pure (env + input only); the matched bytes are never
 *  returned. Safe on large bodies (the handler caps at 1 MB first; bounded
 *  regexes, single pass each). */
export function scanOutboundSecret(body: string): OutboundSecretShape | null {
  if (typeof body !== "string" || body.length === 0) return null;
  for (const r of DEFAULT_SECRET_RULES) {
    if (r.re.test(body)) return r.shape;
  }
  if (extraRulesEnabled()) {
    for (const r of EXTRA_SECRET_RULES) {
      if (r.re.test(body)) return r.shape;
    }
  }
  return null;
}

/** @internal */
export const __internal = { DEFAULT_SECRET_RULES, EXTRA_SECRET_RULES };
