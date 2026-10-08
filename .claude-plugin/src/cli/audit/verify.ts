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
import {
  chainGenesis,
  computeRowMac,
  getOrCreateAuditSalt,
  readStrictCommitment,
  strictCommitmentLanded,
  STRICT_MARKER_EVENT,
  strictChainGenesis,
  type StrictCommitment,
} from "../../audit";
import { auditCliPath, cliChainGenesis, walkStrictChain, type StrictWalkResult } from "../../audit/cli-chain";
import { streamAuditRows, auditFilePath, type AuditRow } from "./reader";

const USAGE = "usage: safespace audit verify [--json]";

interface VerifyResult {
  ok: boolean;
  chainedRows: number;
  legacyRows: number;
  /** Rows with no `row_mac` but carrying an `event` field, seen AFTER a v1 chain
   *  started and before its strict marker — older CLI approve/deny rows or pre-chain
   *  bare-appender rows in existing logs. Tolerated + counted, NOT a break (in a strict
   *  chain they are a break). */
  unchainedEventRows: number;
  /** The chain tip: on an intact chain the last row's MAC; on a BROKEN chain the
   *  last VERIFIED row's MAC (the known-good prefix tip, not the file's raw last row). */
  tipMac: string | null;
  brokenAt: number | null; // 1-based audit-row index of the first break
  reason: "mac_mismatch" | "unhashed_after_chain" | "unhashed_in_strict_chain" | "strict_commitment_broken" | null;
}

function rowWithoutMac(row: AuditRow): Record<string, unknown> {
  const { row_mac: _omit, ...rest } = row;
  return rest;
}

/** Walk the chain. Two kinds of chain (docs/AUDIT-CHAIN.md):
 *  - STRICT (its first row chains from the v2 genesis — every audit.jsonl started since
 *    strict chains): every row must be chained; any row without `row_mac`, before or after
 *    the chain starts, is a break (`unhashed_in_strict_chain`).
 *  - v1 (begun earlier): legacy rows (no `row_mac`) BEFORE the chain starts are a
 *    pre-upgrade prefix (skipped). AFTER it has started, a row with no `row_mac` is
 *    tolerated IFF it carries an `event` field (older CLI approve/deny rows were written
 *    unchained); a no-mac row with NO `event` field mid-chain is a break. From the chain's
 *    first verified `STRICT_MARKER_EVENT` row on, the chain is strict.
 *  Malformed (non-JSON) lines are skipped by the reader, as before. */
export async function verifyChain(
  filePath: string,
  salt: Buffer,
  /** Called with `cli_tip_mac` of every CHAINED, verified `cli_chain_anchor` row (an
   *  unchained one — e.g. inserted by hand — is not an anchor). */
  onAnchor?: (cliTipMac: string | null) => void,
  /** The strict commitment kept beside the salt (`readStrictCommitment`): the log must
   *  hold the committed marker row (a v2 chain: every line chained; a v1 chain: every line
   *  chained from the marker on). Undefined/null: in-log rules only. */
  commitment?: StrictCommitment | null | "invalid",
): Promise<VerifyResult> {
  // The record must be self-consistent: its row, chained from its predecessor, has its MAC.
  if (
    commitment === "invalid" ||
    (commitment && commitment.marker_row !== undefined && commitment.prev_mac !== undefined &&
      macOrNull(salt, commitment.prev_mac, commitment.marker_row) !== commitment.marker_mac)
  ) {
    return { ok: false, chainedRows: 0, legacyRows: 0, unchainedEventRows: 0, tipMac: null, brokenAt: 1, reason: "strict_commitment_broken" };
  }
  let prevMac: string | null = null; // null = chain not yet started
  let version: 1 | 2 | null = null;
  let committedMarkerSeen = false;
  let strict = false;
  let chainedRows = 0;
  let legacyRows = 0;
  let firstLegacyIndex: number | null = null;
  let unchainedEventRows = 0;
  let index = 0;
  const broken = (reason: VerifyResult["reason"], at: number): VerifyResult => ({
    ok: false, chainedRows, legacyRows, unchainedEventRows, tipMac: prevMac, brokenAt: at, reason,
  });
  for await (const row of streamAuditRows(filePath)) {
    index++;
    const mac = row.row_mac;
    if (typeof mac !== "string") {
      if (prevMac === null) {
        if (commitment?.strict === "v2") return broken("strict_commitment_broken", index);
        legacyRows++; // a pre-upgrade unhashed prefix — unless the chain turns out strict
        firstLegacyIndex ??= index;
        continue;
      }
      if (strict) return broken("unhashed_in_strict_chain", index);
      // Unchained row in a v1 chain before its marker. An `event:` row is legitimately
      // unchained (older CLI approve/deny rows, pre-upgrade bare-appender rows). Tolerate
      // it (skip WITHOUT advancing prevMac, so the chained subsequence still verifies
      // end-to-end). A no-mac row with NO `event` field stays a break: it is a chained row
      // stripped of its MAC or a non-event insert.
      if (typeof (row as Record<string, unknown>).event === "string") {
        unchainedEventRows++;
        continue;
      }
      return broken("unhashed_after_chain", index);
    }
    const rest = rowWithoutMac(row);
    // Plain string `!==` (not timingSafeEqual): this is OFFLINE forensic verification,
    // not an online auth oracle — there is no attacker timing the comparison.
    if (prevMac === null) {
      if (macOrNull(salt, strictChainGenesis(), rest) === mac) {
        strict = true;
        version = 2;
        if (firstLegacyIndex !== null) return broken("unhashed_in_strict_chain", firstLegacyIndex);
      } else if (macOrNull(salt, chainGenesis(), rest) === mac) {
        version = 1; // under a v2 commitment, reported once the walk ends
      } else {
        return broken("mac_mismatch", index);
      }
    } else if (macOrNull(salt, prevMac, rest) !== mac) {
      return broken("mac_mismatch", index);
    }
    if (commitment && mac === commitment.marker_mac) {
      const prev = prevMac ?? (version === 2 ? strictChainGenesis() : chainGenesis());
      if (commitment.prev_mac !== undefined && commitment.prev_mac !== prev) return broken("strict_commitment_broken", index);
    }
    prevMac = mac;
    chainedRows++;
    const r = row as Record<string, unknown>;
    if (r.event === STRICT_MARKER_EVENT) strict = true;
    if (commitment && mac === commitment.marker_mac) committedMarkerSeen = true;
    if (r.event === "cli_chain_anchor") onAnchor?.(typeof r.cli_tip_mac === "string" ? r.cli_tip_mac : null);
  }
  // The committed marker must still be in the chain (a stripped, emptied or replaced log,
  // or one cut back past the marker, no longer holds it); a v2 commitment also needs a v2
  // chain.
  if ((commitment && !committedMarkerSeen) || (commitment?.strict === "v2" && version !== 2)) {
    return broken("strict_commitment_broken", index + 1);
  }
  return { ok: true, chainedRows, legacyRows, unchainedEventRows, tipMac: prevMac, brokenAt: null, reason: null };
}

/** computeRowMac, or null when the row cannot be canonicalized (e.g. nested too deeply):
 *  such a row is not a valid row. */
function macOrNull(salt: Buffer, prev: string, row: Record<string, unknown>): string | null {
  try {
    return computeRowMac(salt, prev, row);
  } catch {
    return null;
  }
}

export async function runAuditVerify(args: string[], io: CliIO): Promise<void> {
  let json = false;
  for (const f of args) {
    if (f === "--json") json = true;
    else throw new CliError(`unknown flag: ${f}\n       ${USAGE}`);
  }

  const filePath = auditFilePath();
  const salt = await getOrCreateAuditSalt();
  const anchors: Array<string | null> = [];
  const commitment = await readStrictCommitment();
  const r = await verifyChain(filePath, salt, (tip) => anchors.push(tip), commitment);
  // Present only when a commitment exists: false while its first row is not yet recorded
  // as landed (the window in docs/AUDIT-CHAIN.md), so scripts can see it too.
  const landed = commitment !== null && commitment !== "invalid" ? await strictCommitmentLanded() : undefined;
  const out = landed === undefined ? r : { ...r, strictLanded: landed };
  if (landed === false) {
    io.err(
      "warning: the strict commitment's first row is not yet recorded as landed (audit-chain.json.landed); " +
        "until it is, a log cut back to the committed row's predecessor can be refilled from the commitment. The server records it on its next write.",
    );
  }
  const cli = await verifyCliChain(salt, anchors);

  if (cli === null) {
    // No CLI chain and no anchors: exactly today's report.
    if (json) io.out(JSON.stringify(out));
    else renderServerChain(r, io);
    process.exitCode = r.ok ? 0 : 1;
    return;
  }

  const ok = r.ok && cli.ok;
  if (json) {
    io.out(JSON.stringify({ ...out, ok, cli }));
  } else {
    if (ok) renderServerChain(r, io);
    else if (r.ok) io.out(`server chain verified — ${r.chainedRows} chained row${r.chainedRows === 1 ? "" : "s"}, tip MAC: ${r.tipMac}`);
    else renderServerChain(r, io);
    renderCliChain(cli, io);
  }
  process.exitCode = ok ? 0 : 1;
}

interface CliVerifyResult {
  ok: boolean;
  exists: boolean;
  chainedRows: number;
  tipMac: string | null;
  brokenAt: number | null;
  reason: StrictWalkResult["reason"] | "cli_anchor_missing" | null;
  /** Anchors in the verified server chain, and how many name a MAC that is not in the
   *  verified CLI chain (a null-tip anchor always counts as missing). */
  anchors: number;
  anchorsMissing: number;
}

/** Strict walk of audit-cli.jsonl plus the anchor check. null when there is no CLI file
 *  and no anchor (nothing to report). An anchor is satisfied by the PRESENCE of its MAC
 *  in the verified CLI chain, so repeated anchors of one tip are fine. */
async function verifyCliChain(salt: Buffer, anchors: Array<string | null>): Promise<CliVerifyResult | null> {
  const pending = new Set(anchors.filter((a): a is string => a !== null));
  const walk = await walkStrictChain(auditCliPath(), salt, cliChainGenesis(), (mac) => pending.delete(mac));
  if (!walk.exists && anchors.length === 0) return null;
  // Count every unsatisfied anchor (two anchors of one deleted tip are two missing).
  const anchorsMissing = anchors.filter((a) => a === null || pending.has(a)).length;
  const walkOk = walk.exists ? walk.ok : true;
  return {
    ok: walkOk && anchorsMissing === 0,
    exists: walk.exists,
    chainedRows: walk.chainedRows,
    tipMac: walk.tipMac,
    brokenAt: walk.brokenAt,
    reason: !walkOk ? walk.reason : anchorsMissing > 0 ? "cli_anchor_missing" : null,
    anchors: anchors.length,
    anchorsMissing,
  };
}

const CLI_WHY: Record<string, string> = {
  malformed_line: "a line is not a JSON object (inserted or damaged)",
  unhashed_row: "a row has no row_mac (inserted, or a chained row replaced)",
  mac_mismatch: "row_mac does not match (this row was edited, or a prior row was deleted/inserted/reordered)",
  incomplete_tail: "the last line has no newline (a write in progress, or a cut/edited final row)",
  read_error: "the file could not be read",
  cli_anchor_missing:
    "the server chain sealed CLI rows that are no longer in audit-cli.jsonl (the file was deleted, emptied or cut)",
};

function renderCliChain(c: CliVerifyResult, io: CliIO): void {
  if (c.ok) {
    io.out(`CLI chain (audit-cli.jsonl) INTACT — ${c.chainedRows} chained row${c.chainedRows === 1 ? "" : "s"} verified, ${c.anchors} anchor${c.anchors === 1 ? "" : "s"} checked`);
    io.out(`CLI tip MAC: ${c.tipMac}`);
    io.out(`(record both tip MACs out-of-band)`);
    return;
  }
  const at = c.brokenAt !== null ? ` at line #${c.brokenAt}` : "";
  io.err(`CLI chain (audit-cli.jsonl) BROKEN${at}: ${CLI_WHY[c.reason ?? ""] ?? String(c.reason)}`);
  if (c.reason === "cli_anchor_missing") io.err(`${c.anchorsMissing} of ${c.anchors} anchor${c.anchors === 1 ? "" : "s"} not found.`);
  else io.err(`${c.chainedRows} CLI row${c.chainedRows === 1 ? "" : "s"} verified before the break.`);
}

/** Today's server-chain report (unchanged). */
function renderServerChain(r: VerifyResult, io: CliIO): void {
  if (r.ok) {
    const skips: string[] = [];
    if (r.legacyRows > 0)
      skips.push(`${r.legacyRows} legacy unhashed prefix row${r.legacyRows === 1 ? "" : "s"}`);
    if (r.unchainedEventRows > 0)
      skips.push(`${r.unchainedEventRows} unchained event row${r.unchainedEventRows === 1 ? "" : "s"}`);
    const legacy = skips.length > 0 ? ` (${skips.join(", ")} skipped)` : "";
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
        : r.reason === "unhashed_in_strict_chain"
          ? "an unhashed row in a strict chain (a row was inserted, or a chained row replaced)"
          : r.reason === "strict_commitment_broken"
            ? "the log no longer matches its strict-chain commitment (audit-chain.json): rows were stripped, the log was cut back or replaced, or the commitment file was altered"
          : "row_mac does not match (this row was edited, or a prior row was deleted/inserted/reordered)";
    io.err(`audit chain BROKEN at row #${r.brokenAt}: ${why}`);
    io.err(
      r.brokenAt === 1
        ? `no rows verified intact before the break (${r.chainedRows} chained).`
        : `rows #1–#${(r.brokenAt ?? 1) - 1} verified intact (${r.chainedRows} chained).`,
    );
  }
}
