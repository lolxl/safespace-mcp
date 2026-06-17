/**
 * v1.26 Phase 1 Item 2 (NEW-5) — test-only export barrel.
 *
 * Consolidates `_*_FOR_TEST` exports for centralized test-surface audit.
 * Pattern established v1.17; v1.25 Phase 3 added GridRange/GridCoordinate
 * key Sets pushing the count to 3+; barrel centralizes the surface.
 *
 * Q3 LOCKED Option A: definitions STAY in `handlers.ts` (preserves
 * coherence of `validateGridRange` / `validateGridCoordinate` colocated
 * with the const Sets they iterate). Barrel only re-exports.
 *
 * To ADD a new `_*_FOR_TEST` export: define const in `handlers.ts` with
 * the `_*_FOR_TEST` prefix; add a re-export line below.
 */
export {
  _SHEETS_BATCH_UPDATE_ALLOWED_TYPES_FOR_TEST,
  _SHEETS_GRID_RANGE_KEYS_FOR_TEST,
  _SHEETS_GRID_COORDINATE_KEYS_FOR_TEST,
  // Add future _*_FOR_TEST re-exports here
} from "./handlers";
