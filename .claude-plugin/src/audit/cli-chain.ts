// The CLI audit chain (audit-cli.jsonl) — rows written by `safespace` CLI processes
// (`exec`, `send approve/deny`). audit.jsonl stays the SERVER's chain; a CLI process
// never appends to it (one writer per chain file). docs/AUDIT-CHAIN.md.
//
// This file has a STRICT walk shared by two callers: `audit verify` and the server's
// anchor of the CLI tip. Unlike the server walk, it tolerates nothing. The CLI file is new, so it has no legacy prefix and no
// rows that are legitimately unchained. Any malformed line, any row without a valid
// `row_mac`, a MAC mismatch, a final line with no "\n", or a read error ends the
// VERIFIED prefix. It also has `resumeTip`, the forward walk both writers resume from.
//
// RUNTIME-SAFE CYCLE: imports computeRowMac from ../audit, which imports this module.
// Both sides only call each other inside function bodies (hoisted declarations), the
// same pattern as audit/events.ts.

import { createReadStream } from "node:fs";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import { configDir } from "../auth/keychain";
import { computeRowMac } from "../audit";

const AUDIT_CLI_FILE = "audit-cli.jsonl";

/** The prev-mac seed of the CLI chain's first row. Distinct from the server genesis,
 *  so a CLI file copied over audit.jsonl (or the two swapped) breaks at row 1. */
const CLI_CHAIN_GENESIS = "safespace-audit-chain/cli/genesis/v1";

export function auditCliPath(): string {
  return path.join(configDir(), AUDIT_CLI_FILE);
}

export function cliChainGenesis(): string {
  return CLI_CHAIN_GENESIS;
}

export type StrictWalkReason =
  | "malformed_line"
  | "unhashed_row"
  | "mac_mismatch"
  | "incomplete_tail"
  | "read_error";

export interface StrictWalkResult {
  /** False when the file was not found (nothing to walk). */
  exists: boolean;
  /** Complete ("\n"-terminated, non-empty) lines seen before the walk stopped. */
  completeRows: number;
  /** Rows in the verified prefix. */
  chainedRows: number;
  /** MAC of the last verified row; null when nothing verified. */
  tipMac: string | null;
  /** True when the walk reached the end with every line verified. */
  ok: boolean;
  /** 1-based line of the first failure, or null. */
  brokenAt: number | null;
  reason: StrictWalkReason | null;
}

/** Read size in bytes (the stream default, made explicit so tests can aim at its edges). */
export const READ_CHUNK = 65536;

export interface RawLine {
  text: string;
  /** False only for a final line with no line ending. */
  complete: boolean;
}

/** Yield the file's lines, streamed. A line ends at "\r\n", "\n" or a lone "\r" — never
 *  at U+2028 / U+2029, which JSON.stringify leaves raw inside strings — and any length is
 *  parsed. Both writers and every audit reader (`streamAuditRows`, so `audit verify` too)
 *  use this one splitter, so they always see the same rows whatever the runtime. */
export async function* rawLines(filePath: string): AsyncGenerator<RawLine> {
  const stream = createReadStream(filePath, { encoding: "utf8", highWaterMark: READ_CHUNK });
  // Only each new chunk is searched, and the pieces of an unfinished line are joined once
  // when it ends, so a very long line costs linear time.
  let parts: string[] = [];
  // The previous chunk ended with "\r": a line end, which a leading "\n" here completes.
  let pendingCr = false;
  const line = (): RawLine => {
    const text = parts.join("");
    parts = [];
    return { text, complete: true };
  };
  for await (const c of stream) {
    const chunk = c as string;
    let start = 0;
    if (pendingCr) {
      pendingCr = false;
      yield line();
      if (chunk.startsWith("\n")) start = 1;
    }
    const re = /\r\n|\n|\r/g;
    re.lastIndex = start;
    for (let m = re.exec(chunk); m !== null; m = re.exec(chunk)) {
      parts.push(chunk.slice(start, m.index));
      start = m.index + m[0].length;
      if (m[0] === "\r" && start === chunk.length) {
        pendingCr = true;
        break;
      }
      yield line();
    }
    if (start < chunk.length) parts.push(chunk.slice(start));
  }
  if (pendingCr) yield line();
  const tail = parts.join("");
  if (tail.length > 0) yield { text: tail, complete: false };
}

/** The rows of an audit file as every audit reader sees them: the non-empty lines `rawLines`
 *  yields (a line ends at "\r\n", "\n" or a lone "\r"). Counted while streaming, without
 *  assembling any line, so memory stays fixed however long a line is. 0 for a missing file;
 *  other read errors throw. `status` and `migrate-v2` count with this, so their numbers
 *  match what the readers and `verify` walk. */
export async function countRows(filePath: string): Promise<number> {
  // Every "\r" or "\n" ends the current line; only lines with content count, so "\r\n"
  // (whose second half ends an empty line) needs no special case.
  let n = 0;
  let nonEmpty = false; // the current line has content
  try {
    for await (const c of createReadStream(filePath, { encoding: "utf8", highWaterMark: READ_CHUNK })) {
      const chunk = c as string;
      for (let i = 0; i < chunk.length; i++) {
        const code = chunk.charCodeAt(i);
        if (code === 13 || code === 10) {
          if (nonEmpty) n++;
          nonEmpty = false;
        } else nonEmpty = true;
      }
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return 0;
    throw e;
  }
  return nonEmpty ? n + 1 : n;
}

/** computeRowMac, or null when the row cannot be canonicalized (e.g. nested too deeply). */
function macOrNull(salt: Buffer, prevMac: string, row: Record<string, unknown>): string | null {
  try {
    return computeRowMac(salt, prevMac, row);
  } catch {
    return null;
  }
}

/** Strict walk of a chain file from `genesis`. `onVerified` is called with each
 *  verified row's MAC (verify uses it to tick off anchors). Never throws. */
export async function walkStrictChain(
  filePath: string,
  salt: Buffer,
  genesis: string,
  onVerified?: (mac: string) => void,
): Promise<StrictWalkResult> {
  let prevMac = genesis;
  let completeRows = 0;
  let chainedRows = 0;
  let tipMac: string | null = null;
  let line = 0;
  const stop = (reason: StrictWalkReason): StrictWalkResult => ({
    exists: true, completeRows, chainedRows, tipMac, ok: false, brokenAt: line, reason,
  });
  try {
    for await (const { text, complete } of rawLines(filePath)) {
      line++;
      if (!complete) return stop("incomplete_tail");
      completeRows++;
      let row: unknown;
      try {
        row = JSON.parse(text);
      } catch {
        return stop("malformed_line");
      }
      if (typeof row !== "object" || row === null || Array.isArray(row)) return stop("malformed_line");
      const { row_mac: mac, ...rest } = row as Record<string, unknown>;
      if (typeof mac !== "string") return stop("unhashed_row");
      if (macOrNull(salt, prevMac, rest) !== mac) return stop("mac_mismatch");
      prevMac = mac;
      tipMac = mac;
      chainedRows++;
      onVerified?.(mac);
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") {
      return { exists: false, completeRows: 0, chainedRows: 0, tipMac: null, ok: true, brokenAt: null, reason: null };
    }
    return stop("read_error");
  }
  return { exists: true, completeRows, chainedRows, tipMac, ok: true, brokenAt: null, reason: null };
}

/** Read the last `bytes` of a file (or all of it). null when it does not exist. */
async function readTail(filePath: string, bytes: number): Promise<Buffer | null> {
  let fh: fs.FileHandle | null = null;
  try {
    fh = await fs.open(filePath, "r");
    const { size } = await fh.stat();
    const start = Math.max(0, size - bytes);
    const buf = Buffer.alloc(size - start);
    await fh.read(buf, 0, buf.length, start);
    return buf;
  } catch {
    return null;
  } finally {
    await fh?.close();
  }
}

/** The MAC to resume a chain from — a CLI process for this file: a streamed FORWARD walk
 *  of the whole file from `genesis` that adopts a line only when its `row_mac`
 *  authenticates against the tip so far (a final line without "\n" included, so a valid
 *  row missing only its newline is resumed from). Every other line — junk, a crashed
 *  partial write, an unchained row, a forged `{"row_mac": <older MAC>}`, a replayed older
 *  row, the losing row of a fork — is skipped without moving the tip, so the writer only
 *  ever extends the chain it can trace back to genesis, and removing the one bad line
 *  repairs the chain.
 *
 *  A missing file → `genesis`. Any other read error THROWS, so the caller writes nothing
 *  rather than linking a row to a tip short of the file's real end. */
export async function resumeTip(filePath: string, salt: Buffer, genesis: string): Promise<string> {
  let tip = genesis;
  try {
    for await (const row of hashedRows(filePath)) {
      if (macOrNull(salt, tip, row.rest) === row.mac) tip = row.mac;
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === "ENOENT") return genesis;
    throw e;
  }
  return tip;
}

/** The JSON object rows of a file that carry a string `row_mac`, streamed. */
async function* hashedRows(filePath: string): AsyncGenerator<{ mac: string; rest: Record<string, unknown> }> {
  for await (const { text } of rawLines(filePath)) {
    if (text.length === 0) continue; // as the audit reader does; cheap on a flood of blank lines
    let row: unknown;
    try {
      row = JSON.parse(text);
    } catch {
      continue;
    }
    if (typeof row !== "object" || row === null || Array.isArray(row)) continue;
    const { row_mac: mac, ...rest } = row as Record<string, unknown>;
    if (typeof mac === "string") yield { mac, rest };
  }
}

/** Where the server resumes audit.jsonl. The same forward walk as `resumeTip`, except that
 *  the chain may start from either genesis: `v2` (strict) or `v1` (a chain begun before
 *  strict chains). Returns the tip (`v2` when no row chains yet and the file holds no JSON
 *  object row at all — empty, missing, or only junk / a crashed partial line; `v1` when it
 *  holds only unchained JSON rows, a pre-chain prefix), the chain's genesis version (null:
 *  no chained row) and the MAC of its first verified `marker` row, if any. Read errors as
 *  for `resumeTip`. */
export async function resumeServerChain(
  filePath: string,
  salt: Buffer,
  v1: string,
  v2: string,
  marker: string,
  /** A MAC to look for (the committed row's); `committedSeen` reports whether a verified
   *  row of the chain carries it. */
  committedMac?: string,
): Promise<{ tip: string; version: 1 | 2 | null; markerMac: string | null; committedSeen: boolean; rowsAfterTip: number }> {
  let tip: string | null = null;
  let version: 1 | 2 | null = null;
  let markerMac: string | null = null;
  let committedSeen = false;
  let sawRow = false;
  let rowsAfterTip = 0; // JSON object rows after the last adopted row
  try {
    for await (const { text } of rawLines(filePath)) {
      if (text.length === 0) continue;
      let row: unknown;
      try {
        row = JSON.parse(text);
      } catch {
        continue;
      }
      if (typeof row !== "object" || row === null || Array.isArray(row)) continue;
      sawRow = true;
      rowsAfterTip++;
      const { row_mac: mac, ...rest } = row as Record<string, unknown>;
      if (typeof mac !== "string") continue;
      if (tip === null) {
        if (macOrNull(salt, v2, rest) === mac) version = 2;
        else if (macOrNull(salt, v1, rest) === mac) version = 1;
        else continue;
      } else if (macOrNull(salt, tip, rest) !== mac) continue;
      tip = mac;
      rowsAfterTip = 0;
      if (rest.event === marker && markerMac === null) markerMac = mac;
      if (mac === committedMac) committedSeen = true;
    }
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
  }
  return { tip: tip ?? (sawRow ? v1 : v2), version, markerMac, committedSeen, rowsAfterTip };
}

/** True when the file is non-empty and does not end with "\n" (a crashed or stripped
 *  write). The writer then starts its row on a new line, so it never glues onto the
 *  partial one. */
export async function endsMidLine(filePath: string): Promise<boolean> {
  const buf = await readTail(filePath, 1);
  return buf !== null && buf.length === 1 && buf[0] !== 0x0a;
}
