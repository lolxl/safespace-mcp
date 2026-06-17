// v1.103 (W1) — shared webhook-verify helpers. The constant-time signature compare is
// SECURITY-load-bearing, so it lives in ONE place (the v1.97.1 read-client DRY rationale:
// a security primitive must not silently drift between connectors — e.g. one provider's
// verify "fixed" to a non-constant compare). Slack + LINE both import these.

import * as crypto from "node:crypto";
import type { IncomingHttpHeaders } from "node:http";

/** First value of a header, or null when absent/empty. */
export function headerOf(headers: IncomingHttpHeaders, name: string): string | null {
  const v = headers[name];
  const s = Array.isArray(v) ? v[0] : v;
  return typeof s === "string" && s.length > 0 ? s : null;
}

/** A plain (non-array) object. */
export function isObject(v: unknown): v is Record<string, unknown> {
  return v != null && typeof v === "object" && !Array.isArray(v);
}

/** Timing-safe equality of two ASCII strings (the hex/base64 signatures). A length
 *  mismatch short-circuits to false BEFORE crypto.timingSafeEqual (which throws on
 *  unequal lengths) — the digest length is fixed + public, so no secret leaks. */
export function timingSafeEqualStr(a: string, b: string): boolean {
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}
