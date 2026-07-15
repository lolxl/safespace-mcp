// B6.1-B (v1.125.1) — THE CONNECTOR ERROR-MAPPING CONTRACT. Type-only module:
// ZERO runtime exports, erased at build time. This file is the citable home of a
// contract that until now lived implicitly across five client implementations.
//
// THE CONTRACT — "the client IS the mapper":
//
//   Every REST connector maps upstream failures AT ITS CLIENT LAYER — the single
//   module that owns the socket — into `MCPError("<connector>_api_failed", {reason})`
//   with a CLOSED-SET reason, before anything reaches a handler. A handler never
//   catch-maps a REST connector error; it lets the client's typed MCPError bubble.
//
//   The five client chokepoints (each file's head comment points back here):
//     - tools/handlers/service-token-fetch.ts  `postServiceTokenJson` — the 5 class-B
//       connectors (line / telegram / discord / slack / mattermost), one shared impl
//     - auth/github/client.ts                  github_api_failed
//     - auth/notion/client.ts                  notion_api_failed
//     - auth/x/client.ts                       x_api_failed
//     - auth/http/bounded-read.ts              the shared 5 MB read cap the three
//       OAuth clients above call (a cap breach surfaces as the CALLER's brand)
//
//   Mapping discipline (uniform across all five, pinned by each client's tests):
//     - network failure / timeout (AbortError)            → reason "api_error"
//     - non-ok HTTP status                                → mapStatusToReason(status),
//       a closed set; status code ONLY — response free text NEVER picks the reason
//     - oversized / unreadable / unparseable response     → reason "api_error"
//     - NEVER echo the token, the URL (it can carry a token), the request body,
//       the raw error, or the response body into the MCPError
//
//   The brand set is FROZEN (8 members, errors.ts `ErrorName` + the errors.test.ts
//   sentinel): a future connector reuses a shared generic code through the owner
//   gate instead of minting a 9th `*_api_failed` name. The type below derives the
//   set from ErrorName by suffix, so type and freeze can never drift.
//
// THE THREE DELIBERATE EXCEPTIONS — handler-level mappers that STAY:
//
//   - google-api/errors.ts `toGoogleError` / `mapGoogleError` — the googleapis SDK
//     owns the socket (no SafeSpace client layer to map in), and the 401 contract
//     (`UpstreamError{httpStatus:401}` must escape the handler so the choke point's
//     force-refresh retry sees it) is load-bearing (with-context.ts).
//   - policy/url-gate.ts `mapWebFetchError` — web_fetch's gate/fetch/map are one
//     inseparable SSRF pipeline over DYNAMIC hosts; there is no per-connector client.
//   - policy/fs-gate.ts `mapFsReadError` — no network at all; maps fs errors.
//
//   These three have live, tested call sites. The F2 decision (v1.116.1) stands: a
//   choke-point catch-all CANNOT replace them behavior-neutrally — handlers throw
//   deliberate plain-Error validation messages (user-actionable) that a catch-all
//   would re-wrap. Any future seam proposal must re-clear that bar first.

export type { ConnectorApiFailedName } from "../../errors";

import type { ConnectorApiFailedName } from "../../errors";
import type { ServiceTokenErrorName } from "../../tools/handlers/service-token-fetch";

// ── Compile-time anchors (erased; fail typecheck if the contract drifts) ────────
// The service-token cluster is a subset of the frozen brand set, and the three
// OAuth client brands are members. A rename / removal on either side breaks here.
type _Assert<T extends true> = T;
type _ServiceTokenClusterIsSubset = _Assert<
  ServiceTokenErrorName extends ConnectorApiFailedName ? true : false
>;
type _GithubBrand = _Assert<"github_api_failed" extends ConnectorApiFailedName ? true : false>;
type _NotionBrand = _Assert<"notion_api_failed" extends ConnectorApiFailedName ? true : false>;
type _XBrand = _Assert<"x_api_failed" extends ConnectorApiFailedName ? true : false>;
// Suppress unused-type warnings while keeping the anchors named + greppable.
export type _ContractAnchors = [
  _ServiceTokenClusterIsSubset,
  _GithubBrand,
  _NotionBrand,
  _XBrand,
];
