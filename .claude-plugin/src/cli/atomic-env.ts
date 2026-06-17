// v2.3 — Atomic editor for the safespace `.env` file.
//
// Used by `safespace recipient {add,remove,list}` to mutate
// SAFESPACE_RECIPIENT_ALLOW in `${configDir()}/.env` without disturbing
// other keys / comments / blank lines.
//
// Invariants:
//   - Mode 0o600 preserved across rewrites (atomic mktemp → rename(2)).
//   - Other keys + comments + blank lines kept verbatim.
//   - "Last occurrence wins" matches Bun's `--env-file=` dotenv semantics:
//       * 0 occurrences → append at end of file.
//       * 1 occurrence  → replace inline (preserves position).
//       * 2+ occurrences → refuse with `duplicate_key` so we don't silently
//         drop one of the user's manually-edited lines.
//   - readEnvKey returns the EFFECTIVE value (last occurrence) so callers
//     observe the same value Bun's loader does.
//   - Values are written raw (no quoting). Callers must pre-validate the
//     value contains no `\n`, `#`, or quote chars (recipient-allowlist
//     tokens are pure ASCII, validated by parseAllowlistTokens).

import { promises as fs } from "node:fs";
import * as path from "node:path";

export class EnvFileError extends Error {
  constructor(
    message: string,
    public readonly code:
      | "duplicate_key"
      | "invalid_value"
      | "io_failed",
  ) {
    super(message);
    this.name = "EnvFileError";
  }
}

/** Returns the effective (last-occurrence) value for `key`, or undefined
 *  if the key is absent. Treats ENOENT as "no occurrences" — undefined.
 *  Does NOT strip surrounding quotes (we never write quoted values; if a
 *  user manually quoted theirs, the literal quote chars surface). */
export async function readEnvKey(
  filePath: string,
  key: string,
): Promise<string | undefined> {
  assertValidKey(key);
  let content: string;
  try {
    content = await fs.readFile(filePath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new EnvFileError(
      `read failed: ${(err as Error).message}`,
      "io_failed",
    );
  }
  const re = lineRegexFor(key);
  let lastValue: string | undefined;
  for (const line of content.split("\n")) {
    const m = re.exec(line);
    if (m !== null) lastValue = m[1];
  }
  return lastValue;
}

/** Set `KEY=value`. See module header for occurrence-count semantics.
 *  Empty `value` (`""`) writes `KEY=` — the v2.2 default-deny baseline. */
export async function writeEnvKey(
  filePath: string,
  key: string,
  value: string,
): Promise<void> {
  assertValidKey(key);
  assertValidValue(value);
  await mutateEnvFile(filePath, key, { kind: "set", value });
}

/** Remove all occurrences of `KEY=...` lines. No-op if absent (idempotent). */
export async function removeEnvKey(filePath: string, key: string): Promise<void> {
  assertValidKey(key);
  await mutateEnvFile(filePath, key, { kind: "remove" });
}

type Mutation = { kind: "set"; value: string } | { kind: "remove" };

async function mutateEnvFile(
  filePath: string,
  key: string,
  mut: Mutation,
): Promise<void> {
  let existing: string;
  let fileExisted = true;
  try {
    existing = await fs.readFile(filePath, "utf8");
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      existing = "";
      fileExisted = false;
    } else {
      throw new EnvFileError(
        `read failed: ${(err as Error).message}`,
        "io_failed",
      );
    }
  }

  const re = lineRegexFor(key);
  const lines = existing === "" ? [] : existing.split("\n");

  // Preserve trailing-newline-ness: most .env files end with "\n" → split
  // produces a trailing "" we re-add at write time. Track separately.
  let trailingNewline = false;
  if (lines.length > 0 && lines[lines.length - 1] === "") {
    trailingNewline = true;
    lines.pop();
  }

  const matchIdx: number[] = [];
  for (let i = 0; i < lines.length; i++) {
    if (re.test(lines[i]!)) matchIdx.push(i);
  }

  let output: string[];
  if (mut.kind === "remove") {
    if (matchIdx.length === 0) {
      // No-op for idempotency. Avoid touching the file (no rewrite = no
      // mode-flip risk, no atime change).
      return;
    }
    const drop = new Set(matchIdx);
    output = lines.filter((_, i) => !drop.has(i));
  } else {
    // set
    if (matchIdx.length >= 2) {
      throw new EnvFileError(
        `${key} appears ${matchIdx.length} times in ${path.basename(filePath)}; ` +
          `please deduplicate manually before re-running.`,
        "duplicate_key",
      );
    }
    const newLine = `${key}=${mut.value}`;
    if (matchIdx.length === 1) {
      output = lines.slice();
      output[matchIdx[0]!] = newLine;
    } else {
      output = lines.slice();
      output.push(newLine);
    }
  }

  // Re-attach trailing newline. For a brand-new file, default to ending
  // with "\n" so future appends behave predictably.
  let content = output.join("\n");
  if (trailingNewline || !fileExisted || output.length > 0) {
    content += "\n";
  }

  await atomicWrite(filePath, content);
}

/** mktemp sibling → 'wx'+0o600 → chmod (defensive against umask drop) →
 *  rename(2). */
async function atomicWrite(filePath: string, content: string): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  const tmp = `${filePath}.write.${randomSuffix()}`;
  const fh = await fs.open(tmp, "wx", 0o600);
  try {
    await fh.writeFile(content, { encoding: "utf8" });
  } finally {
    await fh.close();
  }
  try {
    await fs.chmod(tmp, 0o600);
    await fs.rename(tmp, filePath);
  } catch (err) {
    await fs.unlink(tmp).catch(() => {});
    throw new EnvFileError(
      `write failed: ${(err as Error).message}`,
      "io_failed",
    );
  }
}

function randomSuffix(): string {
  return Math.floor(Math.random() * 0xffffffff)
    .toString(16)
    .padStart(8, "0");
}

const KEY_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;

function assertValidKey(key: string): void {
  if (!KEY_RE.test(key)) {
    throw new EnvFileError(
      `invalid key (must match POSIX env-name shape)`,
      "invalid_value",
    );
  }
}

function assertValidValue(value: string): void {
  // Reject characters that would break dotenv parsing OR allow injection
  // of a second key. We never write quoted values, so a literal '\n' would
  // be split into two lines by readers — disallow up front.
  if (/[\r\n]/.test(value)) {
    throw new EnvFileError(
      `value contains CR/LF (not allowed in unquoted .env values)`,
      "invalid_value",
    );
  }
  if (value.includes("\0")) {
    throw new EnvFileError(`value contains NUL byte`, "invalid_value");
  }
}

/** Build a regex that matches a single .env line carrying `key`.
 *  Allows optional leading whitespace and optional `export ` prefix.
 *  Capture group 1 = the raw value (rest of the line after `=`). */
function lineRegexFor(key: string): RegExp {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return new RegExp(`^\\s*(?:export\\s+)?${escaped}=(.*)$`);
}

/** Test-only. */
/** @internal */
export const __internal = {
  lineRegexFor,
  KEY_RE,
};
