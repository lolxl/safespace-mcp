// v1.89 — `safespace audit verify [--json]`: re-walk the tamper-evident hash-chain
// and report the FIRST broken link. The chain (audit.ts) stamps every row with
// `row_mac` = HMAC-SHA256(audit-salt, prev_mac ‖ canonicalJson(row)); this recomputes
// each MAC from the previous row's stored MAC and flags the first mismatch.
//
// WHOLE-FILE by design (no window flag): a hash-chain only verifies from its genesis
// — a partial window would have no valid `prev_mac` for its first row.
//
// exitCode: 0 = chain intact (mirrors `audit deletes` / `suspicious`), 1 = BROKEN
// (or a chained row followed by an unhashed one — an inserted/legacy row mid-chain).
//
// The tip MAC is printed so an operator can record it OUT-OF-BAND: the chain detects
// edit/delete/insert of PAST rows, but NOT tail truncation (deleting the last N rows
// leaves the rest internally consistent) — comparing the printed tip against a
// previously-recorded one closes that gap.

import { CliError, type CliIO } from "../../cli";
import { chainGenesis, computeRowMac, getOrCreateAuditSalt } from "../../audit";
import { streamAuditRows, auditFilePath, type AuditRow } from "./reader";

const USAGE = "usage: safespace audit verify [--json]";

interface VerifyResult {
  ok: boolean;
  chainedRows: number;
  legacyRows: number;
  /** The chain tip: on an intact chain the last row's MAC; on a BROKEN chain the
   *  last VERIFIED row's MAC (the known-good prefix tip, not the file's raw last row). */
  tipMac: string | null;
  brokenAt: number | null; // 1-based audit-row index of the first break
  reason: "mac_mismatch" | "unhashed_after_chain" | null;
}

function rowWithoutMac(row: AuditRow): Record<string, unknown> {
  const { row_mac: _omit, ...rest } = row;
  return rest;
}

/** Walk the chain. Legacy rows (no `row_mac`) BEFORE the chain starts are a
 *  pre-upgrade prefix (skipped); a row with no `row_mac` AFTER the chain has
 *  started is a break (an inserted/legacy row mid-chain). */
export async function verifyChain(filePath: string, salt: Buffer): Promise<VerifyResult> {
  let prevMac: string | null = null; // null = chain not yet started
  let chainedRows = 0;
  let legacyRows = 0;
  let index = 0;
  for await (const row of streamAuditRows(filePath)) {
    index++;
    const mac = row.row_mac;
    if (typeof mac !== "string") {
      if (prevMac === null) {
        legacyRows++; // pre-upgrade unhashed prefix
        continue;
      }
      return { ok: false, chainedRows, legacyRows, tipMac: prevMac, brokenAt: index, reason: "unhashed_after_chain" };
    }
    const expected = computeRowMac(salt, prevMac ?? chainGenesis(), rowWithoutMac(row));
    // Plain string `!==` (not timingSafeEqual): this is OFFLINE forensic verification,
    // not an online auth oracle — there is no attacker timing the comparison.
    if (expected !== mac) {
      return { ok: false, chainedRows, legacyRows, tipMac: prevMac, brokenAt: index, reason: "mac_mismatch" };
    }
    prevMac = mac;
    chainedRows++;
  }
  return { ok: true, chainedRows, legacyRows, tipMac: prevMac, brokenAt: null, reason: null };
}

export async function runAuditVerify(args: string[], io: CliIO): Promise<void> {
  let json = false;
  for (const f of args) {
    if (f === "--json") json = true;
    else throw new CliError(`unknown flag: ${f}\n       ${USAGE}`);
  }

  const filePath = auditFilePath();
  const salt = await getOrCreateAuditSalt();
  const r = await verifyChain(filePath, salt);

  if (json) {
    io.out(JSON.stringify(r));
  } else if (r.ok) {
    const legacy = r.legacyRows > 0 ? ` (${r.legacyRows} legacy unhashed prefix row${r.legacyRows === 1 ? "" : "s"} skipped)` : "";
    if (r.chainedRows === 0) {
      io.out(`audit chain: no chained rows yet${legacy} — nothing to verify`);
    } else {
      io.out(`audit chain INTACT — ${r.chainedRows} chained row${r.chainedRows === 1 ? "" : "s"} verified${legacy}`);
      io.out(`tip MAC: ${r.tipMac}`);
      io.out(`(record the tip MAC out-of-band — the chain does not detect TAIL truncation on its own)`);
    }
  } else {
    const why =
      r.reason === "unhashed_after_chain"
        ? "an unhashed row appears after the chain started (a row was inserted, or a chained row replaced)"
        : "row_mac does not match (this row was edited, or a prior row was deleted/inserted/reordered)";
    io.err(`audit chain BROKEN at row #${r.brokenAt}: ${why}`);
    io.err(
      r.brokenAt === 1
        ? `no rows verified intact before the break (${r.chainedRows} chained).`
        : `rows #1–#${(r.brokenAt ?? 1) - 1} verified intact (${r.chainedRows} chained).`,
    );
  }

  // Non-zero exit on a broken chain so cron/CI can gate on `safespace audit verify`.
  process.exitCode = r.ok ? 0 : 1;
}
