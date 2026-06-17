// v1.107.1 — pinned keyed-MAC / signature algorithm invariant (the #2 "Kong-borrow"
// alg-confusion lockdown, made EXPLICIT).
//
// SafeSpace's authentication + integrity surface uses keyed HMACs in exactly three
// places: the inbound bearer-token hash, the inbound webhook signature verification,
// and the audit tamper-evident MAC chain. Each pins its algorithm HERE, at compile
// time — the algorithm is NEVER read from a request header, a token field, a config
// value, or any other caller-controlled input.
//
// WHY THIS IS SAFE TODAY (and why this module exists anyway): unlike a JWT verifier,
// SafeSpace has NO `alg`-header path — there is no JOSE/JWT decode that could be tricked
// into HS-vs-RS algorithm confusion or a `none` downgrade. So the live attack surface is
// already zero. This module does NOT patch a hole; it CODIFIES the absence of one, so
// that a future regression (someone adds a JWT path, makes an algorithm configurable, or
// inlines a weaker literal) trips the `crypto-algorithms.test.ts` sentinel instead of
// silently weakening a MAC. Crypto-agility done deliberately, not by accident.
//
// Each constant is an INDEPENDENT wire / at-rest contract (a webhook signature is a wire
// format other parties compute; the audit MAC is an at-rest chain a verifier recomputes;
// the bearer hash is the at-rest lookup key). They happen to share SHA-256 today, but are
// pinned separately so that changing one is a conscious, single-contract decision.
//
// SCOPE: this covers the KEYED-MAC / signature surface only. Non-keyed content digests
// used for dedup / args-stamping / passphrase fingerprints (`createHash` in audit
// args-hashing, the FileBackend, send-approval, contacts) are NOT authentication and are
// out of scope by design — they carry no algorithm-confusion threat.

/** Bearer agent-token hashing — `auth/agent-token-store.ts`.
 *  HMAC-SHA256(per-install salt, token) → the at-rest store key + lookup. */
export const AGENT_TOKEN_HMAC_ALG = "sha256";

/** Inbound webhook signature verification — Slack (`v0=<hex>`) + LINE (base64).
 *  HMAC-SHA256(signing/channel secret, raw body). A WIRE format the provider computes;
 *  changing it breaks signature compatibility. */
export const WEBHOOK_SIGNATURE_HMAC_ALG = "sha256";

/** Audit tamper-evident MAC chain + target-email hashing — `audit.ts`.
 *  HMAC-SHA256(per-install audit salt, …). An at-rest contract `safespace audit verify`
 *  recomputes; changing it invalidates pre-existing chains. */
export const AUDIT_HMAC_ALG = "sha256";
