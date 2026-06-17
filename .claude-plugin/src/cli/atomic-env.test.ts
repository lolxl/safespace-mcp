import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { promises as fs } from "node:fs";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { EnvFileError, __internal, readEnvKey, removeEnvKey, writeEnvKey } from "./atomic-env";

let tmp: string;
let envPath: string;

beforeEach(async () => {
  tmp = await fs.mkdtemp(path.join(tmpdir(), "atomic-env-test-"));
  envPath = path.join(tmp, ".env");
});

afterEach(async () => {
  await fs.rm(tmp, { recursive: true, force: true });
});

describe("readEnvKey", () => {
  test("returns undefined when file missing", async () => {
    expect(await readEnvKey(envPath, "FOO")).toBeUndefined();
  });

  test("returns undefined when key absent", async () => {
    await fs.writeFile(envPath, "BAR=baz\n");
    expect(await readEnvKey(envPath, "FOO")).toBeUndefined();
  });

  test("returns value for single occurrence", async () => {
    await fs.writeFile(envPath, "FOO=hello\n");
    expect(await readEnvKey(envPath, "FOO")).toBe("hello");
  });

  test("returns LAST occurrence (dotenv last-wins)", async () => {
    await fs.writeFile(envPath, "FOO=first\nBAR=baz\nFOO=second\n");
    expect(await readEnvKey(envPath, "FOO")).toBe("second");
  });

  test("ignores leading whitespace + export prefix", async () => {
    await fs.writeFile(envPath, "  export FOO=hello\n");
    expect(await readEnvKey(envPath, "FOO")).toBe("hello");
  });

  test("does not match key as substring", async () => {
    await fs.writeFile(envPath, "MYFOO=trap\nFOO=real\n");
    expect(await readEnvKey(envPath, "FOO")).toBe("real");
  });

  test("returns empty string for explicit empty value", async () => {
    await fs.writeFile(envPath, "FOO=\n");
    expect(await readEnvKey(envPath, "FOO")).toBe("");
  });
});

describe("writeEnvKey", () => {
  test("creates new .env file with trailing newline", async () => {
    await writeEnvKey(envPath, "FOO", "hello");
    const content = await fs.readFile(envPath, "utf8");
    expect(content).toBe("FOO=hello\n");
  });

  test("created file has mode 0o600", async () => {
    await writeEnvKey(envPath, "FOO", "hello");
    const stat = await fs.stat(envPath);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  test("appends when key absent in existing file", async () => {
    await fs.writeFile(envPath, "BAR=baz\n");
    await writeEnvKey(envPath, "FOO", "hello");
    const content = await fs.readFile(envPath, "utf8");
    expect(content).toBe("BAR=baz\nFOO=hello\n");
  });

  test("replaces inline when key exists once", async () => {
    await fs.writeFile(envPath, "BAR=baz\nFOO=old\nQUUX=quux\n");
    await writeEnvKey(envPath, "FOO", "new");
    const content = await fs.readFile(envPath, "utf8");
    expect(content).toBe("BAR=baz\nFOO=new\nQUUX=quux\n");
  });

  test("preserves comments + blank lines", async () => {
    const original = "# header comment\n\nBAR=baz\n# section\nFOO=old\n";
    await fs.writeFile(envPath, original);
    await writeEnvKey(envPath, "FOO", "new");
    const content = await fs.readFile(envPath, "utf8");
    expect(content).toBe("# header comment\n\nBAR=baz\n# section\nFOO=new\n");
  });

  test("preserves mode 0o600 after replace", async () => {
    await fs.writeFile(envPath, "FOO=old\n", { mode: 0o600 });
    await writeEnvKey(envPath, "FOO", "new");
    const stat = await fs.stat(envPath);
    expect(stat.mode & 0o777).toBe(0o600);
  });

  test("throws duplicate_key when key appears twice", async () => {
    await fs.writeFile(envPath, "FOO=a\nFOO=b\n");
    try {
      await writeEnvKey(envPath, "FOO", "new");
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(EnvFileError);
      expect((e as EnvFileError).code).toBe("duplicate_key");
    }
    const content = await fs.readFile(envPath, "utf8");
    expect(content).toBe("FOO=a\nFOO=b\n");
  });

  test("writes empty value (default-deny baseline)", async () => {
    await writeEnvKey(envPath, "FOO", "");
    const content = await fs.readFile(envPath, "utf8");
    expect(content).toBe("FOO=\n");
  });

  test("rejects CR/LF in value", async () => {
    try {
      await writeEnvKey(envPath, "FOO", "evil\nOTHER=x");
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(EnvFileError);
      expect((e as EnvFileError).code).toBe("invalid_value");
    }
  });

  test("rejects NUL in value", async () => {
    try {
      await writeEnvKey(envPath, "FOO", "a\0b");
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(EnvFileError);
      expect((e as EnvFileError).code).toBe("invalid_value");
    }
  });

  test("rejects invalid POSIX env key shape", async () => {
    try {
      await writeEnvKey(envPath, "1FOO", "x");
      throw new Error("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(EnvFileError);
      expect((e as EnvFileError).code).toBe("invalid_value");
    }
  });

  test("appends to file with no trailing newline", async () => {
    await fs.writeFile(envPath, "BAR=baz");
    await writeEnvKey(envPath, "FOO", "hello");
    const content = await fs.readFile(envPath, "utf8");
    expect(content).toBe("BAR=baz\nFOO=hello\n");
  });

  test("temp file cleaned up after rename", async () => {
    await writeEnvKey(envPath, "FOO", "hello");
    const dir = await fs.readdir(tmp);
    expect(dir).toEqual([".env"]);
  });
});

describe("removeEnvKey", () => {
  test("no-op when file missing", async () => {
    await removeEnvKey(envPath, "FOO");
    try {
      await fs.stat(envPath);
      throw new Error("file unexpectedly created");
    } catch (e) {
      expect((e as NodeJS.ErrnoException).code).toBe("ENOENT");
    }
  });

  test("no-op when key absent", async () => {
    await fs.writeFile(envPath, "BAR=baz\n");
    await removeEnvKey(envPath, "FOO");
    const content = await fs.readFile(envPath, "utf8");
    expect(content).toBe("BAR=baz\n");
  });

  test("removes single occurrence", async () => {
    await fs.writeFile(envPath, "BAR=baz\nFOO=hello\nQUUX=q\n");
    await removeEnvKey(envPath, "FOO");
    const content = await fs.readFile(envPath, "utf8");
    expect(content).toBe("BAR=baz\nQUUX=q\n");
  });

  test("removes all duplicate occurrences", async () => {
    await fs.writeFile(envPath, "FOO=a\nBAR=baz\nFOO=b\n");
    await removeEnvKey(envPath, "FOO");
    const content = await fs.readFile(envPath, "utf8");
    expect(content).toBe("BAR=baz\n");
  });
});

describe("__internal.lineRegexFor", () => {
  test("escapes regex metacharacters in key", () => {
    const re = __internal.lineRegexFor("FO.O");
    expect(re.test("FOXO=x")).toBe(false);
    expect(re.test("FO.O=x")).toBe(true);
  });
});
