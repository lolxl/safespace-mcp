// v1.22 Phase 2 — single source of truth for Sheets cap constants.
//
// Extraction rationale (v1.22 design §2.3 I-1): the 3 cell content cap
// constants `SHEETS_CELL_MAX_BYTES` / `SHEETS_BATCH_MAX_BYTES` /
// `SHEETS_MAX_CELLS_PER_CALL` were defined TWICE in handlers.ts — once
// in v1.20 PR #157 (sheets_append_values + sheets_create section, unprefixed)
// and again in v1.21 PR #160 (sheets_update_values + sheets_batch_update
// section, with `_PHASE2C_` prefix). The v1.21 redeclaration was a locality
// preference (the Phase 2c handlers live 500+ lines below the v1.20 handlers
// in the same file), NOT a semantic difference — values are identical. This
// module collapses both into a single canonical location so a future cap
// bump (e.g., per-cell 50KB → 60KB) cannot drift between sites.
//
// `SHEETS_BATCH_UPDATE_MAX_REQUESTS` (v1.21) moves alongside as the 4th
// Sheets cap — it belongs in the same module by topic.
//
// Per design §8.3 cheapest-first ordering, enforcement layers fire in
// order Layer 4 (request count) → Layer 1 (per-cell) → Layer 3 (per-batch
// cumulative) → Layer 2 (per-call cumulative).
//
// Google API natural ceilings (defense-in-depth — handler caps surface
// clean MCPErrors instead of opaque upstream 400s; mirror v1.17
// docs_modify_structured insertText.text 100KB cap convention):
//   - Per-cell content: 50000 chars (Sheets v4 natural cell content limit)
//   - Per-batch request payload: no documented hard cap; 100000 bytes
//     chosen as defense-in-depth
//   - Per-call cell count: no documented hard cap; 10000 chosen as DoS guard
//   - Per-batch_update request count: no documented hard cap; 50 chosen
//     as DoS guard (mirror v1.17 docs_modify_structured 50-request cap)
//
// Pattern reference: v1.18 Phase 1 PR #143 extracted
// SAFESPACE_YOUTUBE_SEARCH_BURST_LIMIT env parser from handlers.ts into
// src/policy/youtube-search-burst.ts (closest in-handlers constant
// extraction precedent).
//
// Behavior is UNCHANGED from the v1.20 + v1.21 inline implementations —
// this is a NAME-only refactor. All handler call sites that previously
// referenced `SHEETS_CELL_MAX_BYTES` (v1.20) or `SHEETS_PHASE2C_CELL_MAX_BYTES`
// (v1.21) now import from this module.

/** Per-cell content cap. Google's natural cell content ceiling is 50000
 *  characters; we cap UTF-8 BYTES at the same number (sec-rev hook #16
 *  defense-in-depth). Mirrors v1.17 docs_modify_structured insertText.text
 *  100KB cap rationale (positive cap at the handler boundary even when
 *  the API would also reject — gives the caller a clean MCPError instead
 *  of an opaque upstream 400). */
export const SHEETS_CELL_MAX_BYTES = 50000;

/** Per-batch total-bytes cap. v1.21 semantics: CUMULATIVE across all
 *  cells in all requests (Q7 LOCKED). Mirrors v1.17
 *  docs_modify_structured insertText cap convention. Anti-DoS /
 *  payload-bloat guard. */
export const SHEETS_BATCH_MAX_BYTES = 100000;

/** Max cells per call. v1.21 semantics: CUMULATIVE across batch_update
 *  requests (Q7 LOCKED). 10,000 matches Google's natural append ceiling
 *  for small-row writes; defends against runaway loops. */
export const SHEETS_MAX_CELLS_PER_CALL = 10000;

/** Max number of requests in a single `sheets_batch_update` call (v1.21
 *  design §8.2 + Risk 5). Layer 4 cap — checked FIRST per §8.3
 *  cheapest-first ordering. Matches v1.17
 *  `docs_modify_structured.requests.length ≤ 50` cap. */
export const SHEETS_BATCH_UPDATE_MAX_REQUESTS = 50;

/** v1.33 sec-L1 — defensive cap on the FORENSIC
 *  `rejected_formula_homoglyph_source` field captured by
 *  `applyHomoglyphPipeline` (src/sheets/homoglyph-normalize.ts). A
 *  homoglyph-flood cell (≤ SHEETS_CELL_MAX_BYTES = 50KB) could otherwise emit
 *  a ~25000-char field on ONE REJECT audit row + the matching MCPError.data.
 *  256 codepoints is ample to identify the attack family — the rejected
 *  function name is preserved separately + in full via
 *  `rejected_formula_function`. Caps the forensic BUFFER ONLY; the
 *  `normalized` security output (the REJECT-verdict input) is NEVER capped.
 *  Deliberate, documented relaxation of v1.32 Q2 LOCK ("capture ALL
 *  transformed bytes") for the pathological flood case only — see
 *  docs/v1.33-audit-cli-forensics.md §4.1. */
export const SHEETS_HOMOGLYPH_SOURCE_MAX_CHARS = 256;
