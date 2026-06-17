import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import {
  STARTUP_MARKER_FILE,
  readStartupMarker,
  writeStartupMarker,
} from "./startup-marker";

let tmp: string;

beforeEach(async () => {
  tmp = await fs.mkdtemp(path.join(tmpdir(), "startup-marker-test-"));
});

afterEach(async () => {
  await fs.rm(tmp, { recursive: true, force: true });
});

describe("writeStartupMarker", () => {
  test("creates marker file at mode 0o600 with ISO 8601 + trailing newline", async () => {
    await writeStartupMarker(tmp);

    const markerPath = path.join(tmp, STARTUP_MARKER_FILE);
    const stat = await fs.stat(markerPath);
    expect(stat.mode & 0o777).toBe(0o600);

    const content = await fs.readFile(markerPath, "utf8");
    expect(content).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z\n$/);
  });

  test("creates configDir if absent (mode 0o700)", async () => {
    const newDir = path.join(tmp, "nested", "dir");
    await writeStartupMarker(newDir);

    const dirStat = await fs.stat(newDir);
    expect(dirStat.isDirectory()).toBe(true);
    expect(dirStat.mode & 0o777).toBe(0o700);
  });

  test("subsequent writes overwrite (last-writer-wins)", async () => {
    await writeStartupMarker(tmp);
    const first = await fs.readFile(path.join(tmp, STARTUP_MARKER_FILE), "utf8");

    // Sleep to ensure distinct timestamps (ms-precision).
    await new Promise((r) => setTimeout(r, 5));
    await writeStartupMarker(tmp);
    const second = await fs.readFile(path.join(tmp, STARTUP_MARKER_FILE), "utf8");

    expect(second).not.toBe(first);
    // Both parse to valid Dates with second > first.
    expect(new Date(second.trim()).getTime()).toBeGreaterThan(
      new Date(first.trim()).getTime(),
    );
  });

  test("write failure is logged + swallowed (no throw)", async () => {
    // Pass a path that can't be a dir — proxy startup must never fail on
    // marker write. Direct file as parent → mkdir fails → writeFile fails.
    const badParent = path.join(tmp, "i-am-a-file");
    await fs.writeFile(badParent, "this is a file, not a dir");
    const badDir = path.join(badParent, "child");

    // Should not throw. Stderr will have a warning line (captured by harness).
    await expect(writeStartupMarker(badDir)).resolves.toBeUndefined();
  });

  test("mode preserved across overwrite (defense against umask drift)", async () => {
    await writeStartupMarker(tmp);
    const beforeStat = await fs.stat(path.join(tmp, STARTUP_MARKER_FILE));
    expect(beforeStat.mode & 0o777).toBe(0o600);

    await writeStartupMarker(tmp);
    const afterStat = await fs.stat(path.join(tmp, STARTUP_MARKER_FILE));
    expect(afterStat.mode & 0o777).toBe(0o600);
  });
});

describe("readStartupMarker", () => {
  test("returns null when marker file missing", async () => {
    const result = await readStartupMarker(tmp);
    expect(result).toBeNull();
  });

  test("returns parsed Date when marker is valid ISO 8601", async () => {
    await writeStartupMarker(tmp);
    const result = await readStartupMarker(tmp);
    expect(result).not.toBeNull();
    expect(result instanceof Date).toBe(true);
    // The marker should be within ~1s of now.
    const drift = Math.abs(Date.now() - result!.getTime());
    expect(drift).toBeLessThan(1000);
  });

  test("returns null when marker is empty file", async () => {
    await fs.writeFile(path.join(tmp, STARTUP_MARKER_FILE), "");
    const result = await readStartupMarker(tmp);
    expect(result).toBeNull();
  });

  test("returns null when marker content is garbage", async () => {
    await fs.writeFile(path.join(tmp, STARTUP_MARKER_FILE), "not a timestamp");
    const result = await readStartupMarker(tmp);
    expect(result).toBeNull();
  });

  test("returns null when marker has trailing garbage that makes parsing fail", async () => {
    await fs.writeFile(
      path.join(tmp, STARTUP_MARKER_FILE),
      "2026-05-18T01:23:45.678Z garbage suffix",
    );
    const result = await readStartupMarker(tmp);
    expect(result).toBeNull();
  });

  test("ignores trailing whitespace in valid marker (read is lenient)", async () => {
    await fs.writeFile(
      path.join(tmp, STARTUP_MARKER_FILE),
      "2026-05-18T01:23:45.678Z\n\n  \n",
    );
    const result = await readStartupMarker(tmp);
    expect(result).not.toBeNull();
    expect(result!.toISOString()).toBe("2026-05-18T01:23:45.678Z");
  });

  test("write + read round-trip preserves ms precision", async () => {
    const before = Date.now();
    await writeStartupMarker(tmp);
    const after = Date.now();

    const result = await readStartupMarker(tmp);
    expect(result).not.toBeNull();
    const ts = result!.getTime();
    expect(ts).toBeGreaterThanOrEqual(before);
    expect(ts).toBeLessThanOrEqual(after);
  });
});
