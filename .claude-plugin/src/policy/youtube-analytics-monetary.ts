// v1.61 — YouTube Analytics monetary (revenue) opt-in gate.
//
// docs/v1.61-youtube-analytics-monetary.md §1.1. v1.59 shipped the NON-monetary
// `youtube_analytics_query` and deliberately deferred revenue (estimatedRevenue,
// ad revenue, CPM, monetized playbacks) to "a later opt-in" (v1.59 §Q1 / R4).
// This is that opt-in: ONE deployment-mode switch that, when (and only when) set,
//   (1) makes the consent ceremony additionally request the narrow
//       `yt-analytics-monetary.readonly` scope (see auth/consent.ts
//       effectiveConsentScopes), and
//   (2) unlocks the revenue metric allowlist in the existing
//       youtube_analytics_query handler (see tools/handlers/youtube.ts
//       ANALYTICS_MONETARY_METRICS).
// It adds NO new MCP tool — it is a scope-gated capability unlock on the
// existing tool.
//
// STRICT-TRUTHY parsing (mirrors isAutonomousMode / isContactLookupEnabled):
// returns `true` ONLY for the literal lowercase `"true"`. Every other value —
// `"True"`, `"TRUE"`, `"1"`, `"yes"`, `"on"`, `"false"`, `""`, undefined, any
// whitespace-padded variant — returns `false`.
//
// FAILURE DIRECTION (deliberate, locked Q5/R5): a mis-parse / typo evaluates to
// `false` → the deployment stays in v1.59's non-monetary behavior, BYTE-IDENTICAL
// to pre-v1.61 (the monetary scope is not requested, revenue metrics are not in
// the allowlist, a revenue metric is rejected). We fail toward LESS access — a
// misconfigured flag must never silently expose revenue. Revenue access is an
// explicit opt-in; the operator who means it types the flag exactly.

import { ENV_YOUTUBE_ANALYTICS_MONETARY as ENV_YT_ANALYTICS_MONETARY, readStrictTruthy } from "../config";

export { ENV_YT_ANALYTICS_MONETARY };

/** True iff `SAFESPACE_YOUTUBE_ANALYTICS_MONETARY` is the literal lowercase
 *  string "true". Returns false for every other value (see the file comment for
 *  why this is strict-truthy and why a typo fails toward v1.59 non-monetary
 *  behavior). */
export function isYoutubeAnalyticsMonetaryEnabled(): boolean {
  return readStrictTruthy(ENV_YT_ANALYTICS_MONETARY);
}
