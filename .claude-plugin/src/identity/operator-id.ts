// v1.36 BLOCKER 2 (audit actor) -- operator identity resolution (Model A).
//
// Model A deployment (docs/v1.36-identity-tenancy-layer.md section 4.3): each
// human operator runs their own local SafeSpace process and shares POLICY +
// AUDIT (not tokens). The operator's identity for the audit log comes from the
// $SAFESPACE_OPERATOR_ID env var (Q2 LOCKED). This is intentionally distinct
// from a Google account email: one operator may drive several Google accounts,
// and one Google account may be co-managed by several operators.
//
// operatorId is recorded PLAINTEXT on the audit row (Q3 LOCKED), mirroring the
// existing plaintext `account` email (audit.ts header / sec-rev 5.8 LOW). It is
// NOT a secret -- it is a self-chosen handle, the human counterpart to
// `account`. NEVER put a token / password here.
//
// Unset OR malformed => null (Q4 zero-impact single-user default). Malformed is
// fail-safe: a typo'd / injection-y id is dropped to null with a stderr warning
// rather than trusted, mirroring tier.ts currentTier()'s invalid-tier handling.
// Dropping (not throwing) keeps a bad env var from crashing every tool call --
// audit identity is observability, not correctness.

/** Allowed operator-id shape: 1-64 chars of [A-Za-z0-9_.-]. Deliberately a
 *  strict subset of printable ASCII -- no spaces, control chars, quotes, angle
 *  brackets, slashes, `@`, or non-ASCII. Anchored ^...$ so a partial match
 *  cannot smuggle a control char onto the audit row (cf. the gmail label-name
 *  CR/LF/NUL gate). */
import { ENV_OPERATOR_ID } from "../config";

const OPERATOR_ID_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;

/** Pure validator -- true iff `id` matches OPERATOR_ID_PATTERN. No I/O, no env
 *  read; safe to unit-test directly and to call on untrusted input. */
export function isValidOperatorId(id: string): boolean {
  return OPERATOR_ID_PATTERN.test(id);
}

/** Resolve the operator id from $SAFESPACE_OPERATOR_ID for the current process
 *  (Model A). Returns the validated id, or `null` when the env var is unset /
 *  empty / malformed. Never throws.
 *
 *  null is the single-user default: the audit row's `operator` field becomes
 *  `null` and every other field is byte-identical (Q4). A malformed value is
 *  logged to stderr -- WITHOUT echoing the raw value (it could carry control /
 *  injection bytes the operator field exists to keep off the row) -- and
 *  treated as unset. */
export function resolveOperatorId(): string | null {
  const raw = process.env[ENV_OPERATOR_ID];
  if (raw === undefined || raw === "") return null;
  if (!isValidOperatorId(raw)) {
    console.error(
      "[safespace] SAFESPACE_OPERATOR_ID is invalid (expected ^[A-Za-z0-9_.-]{1,64}$). Audit operator will be null.",
    );
    return null;
  }
  return raw;
}
