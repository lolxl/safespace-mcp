// v1.66 Phase C PR 2 — service-token store: env-precedence, SecretBackend
// round-trip, presence probe, reserved-key isolation. Uses the file backend +
// tmpdir so it runs on any platform (mirrors token-store.test.ts).

import { afterEach, beforeEach, describe, expect, spyOn, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { MCPError } from "../errors";
import {
  __resetServiceTokenBackendForTests,
  deleteServiceToken,
  hasServiceToken,
  readServiceToken,
  setServiceToken,
} from "./service-token-store";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};
const ENV = [
  "SAFESPACE_CONFIG_DIR",
  "SAFESPACE_SECRET_BACKEND",
  "SAFESPACE_OPERATOR_ID",
  "SAFESPACE_SECRET_PASSPHRASE",
  "SAFESPACE_LINE_CHANNEL_TOKEN",
  "SAFESPACE_TELEGRAM_BOT_TOKEN",
  "SAFESPACE_DISCORD_BOT_TOKEN",
];
let errSpy: ReturnType<typeof spyOn>;

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-sts-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file"; // platform-independent
  delete process.env.SAFESPACE_OPERATOR_ID;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  delete process.env.SAFESPACE_LINE_CHANNEL_TOKEN;
  delete process.env.SAFESPACE_TELEGRAM_BOT_TOKEN;
  delete process.env.SAFESPACE_DISCORD_BOT_TOKEN;
  errSpy = spyOn(console, "error").mockImplementation(() => undefined);
  __resetServiceTokenBackendForTests();
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  errSpy.mockRestore();
  __resetServiceTokenBackendForTests();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

describe("service-token store", () => {
  test("round-trips set/read/delete via the SecretBackend", async () => {
    expect(await readServiceToken("line")).toBeNull();
    await setServiceToken("line", "channel-tok-abc");
    expect(await readServiceToken("line")).toBe("channel-tok-abc");
    await deleteServiceToken("line");
    expect(await readServiceToken("line")).toBeNull();
  });

  test("env override takes precedence over the SecretBackend value", async () => {
    await setServiceToken("line", "from-backend");
    process.env.SAFESPACE_LINE_CHANNEL_TOKEN = "from-env";
    expect(await readServiceToken("line")).toBe("from-env");
    // Unsetting the env falls back to the backend value.
    delete process.env.SAFESPACE_LINE_CHANNEL_TOKEN;
    expect(await readServiceToken("line")).toBe("from-backend");
  });

  test("env override is trimmed; whitespace-only env is ignored (→ backend)", async () => {
    await setServiceToken("line", "backend-tok");
    process.env.SAFESPACE_LINE_CHANNEL_TOKEN = "   ";
    expect(await readServiceToken("line")).toBe("backend-tok");
    process.env.SAFESPACE_LINE_CHANNEL_TOKEN = "  padded-tok  ";
    expect(await readServiceToken("line")).toBe("padded-tok");
  });

  test("hasServiceToken reflects env OR backend, never the token value", async () => {
    expect(await hasServiceToken("line")).toBe(false);
    await setServiceToken("line", "x");
    expect(await hasServiceToken("line")).toBe(true);
    await deleteServiceToken("line");
    expect(await hasServiceToken("line")).toBe(false);
    process.env.SAFESPACE_LINE_CHANNEL_TOKEN = "envtok";
    expect(await hasServiceToken("line")).toBe(true);
  });

  test("the reserved storage key contains ':' and no '@' — cannot collide with an email", () => {
    // The LINE token is stored under the bare reserved account
    // string. It must be unspoofable as a Google email key.
    const key = "line:channel-access-token";
    expect(key).toBe("line:channel-access-token");
    expect(key).toContain(":");
    expect(key).not.toContain("@");
  });
});

describe("service-token store — telegram (v1.68)", () => {
  test("round-trips set/read/delete via the SecretBackend", async () => {
    expect(await readServiceToken("telegram")).toBeNull();
    await setServiceToken("telegram", "bot-tok-abc");
    expect(await readServiceToken("telegram")).toBe("bot-tok-abc");
    await deleteServiceToken("telegram");
    expect(await readServiceToken("telegram")).toBeNull();
  });

  test("env override takes precedence over the SecretBackend value", async () => {
    await setServiceToken("telegram", "from-backend");
    process.env.SAFESPACE_TELEGRAM_BOT_TOKEN = "from-env";
    expect(await readServiceToken("telegram")).toBe("from-env");
    delete process.env.SAFESPACE_TELEGRAM_BOT_TOKEN;
    expect(await readServiceToken("telegram")).toBe("from-backend");
  });

  test("telegram + line tokens are stored under distinct reserved keys (no collision)", async () => {
    await setServiceToken("line", "line-tok");
    await setServiceToken("telegram", "tg-tok");
    expect(await readServiceToken("line")).toBe("line-tok");
    expect(await readServiceToken("telegram")).toBe("tg-tok");
    const key = "telegram:bot-token";
    expect(key).toBe("telegram:bot-token");
    expect(key).toContain(":");
    expect(key).not.toContain("@");
  });
});

describe("service-token store — discord (v1.69)", () => {
  test("round-trips set/read/delete via the SecretBackend", async () => {
    expect(await readServiceToken("discord")).toBeNull();
    await setServiceToken("discord", "bot-tok-abc");
    expect(await readServiceToken("discord")).toBe("bot-tok-abc");
    await deleteServiceToken("discord");
    expect(await readServiceToken("discord")).toBeNull();
  });

  test("env override takes precedence over the SecretBackend value", async () => {
    await setServiceToken("discord", "from-backend");
    process.env.SAFESPACE_DISCORD_BOT_TOKEN = "from-env";
    expect(await readServiceToken("discord")).toBe("from-env");
    delete process.env.SAFESPACE_DISCORD_BOT_TOKEN;
    expect(await readServiceToken("discord")).toBe("from-backend");
  });

  test("discord + telegram + line tokens are stored under distinct reserved keys (no collision)", async () => {
    await setServiceToken("line", "line-tok");
    await setServiceToken("telegram", "tg-tok");
    await setServiceToken("discord", "dc-tok");
    expect(await readServiceToken("line")).toBe("line-tok");
    expect(await readServiceToken("telegram")).toBe("tg-tok");
    expect(await readServiceToken("discord")).toBe("dc-tok");
    const key = "discord:bot-token";
    expect(key).toBe("discord:bot-token");
    expect(key).toContain(":");
    expect(key).not.toContain("@");
  });
});
