// v1.102 (W0) — webhook signing-secret store: env precedence, SecretBackend round-trip,
// presence probe, reserved-key isolation from the bot token. Uses the file backend +
// tmpdir so it runs on any platform (mirrors service-token-store.test.ts).

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { storageKey } from "./secret-backend";
import {
  __resetWebhookSecretBackendForTests,
  deleteWebhookSigningSecret,
  hasWebhookSigningSecret,
  readWebhookSigningSecret,
  setWebhookSigningSecret,
  webhookSecretEnvVar,
} from "./webhook-secret-store";

let tmpDir: string;
const saved: Record<string, string | undefined> = {};
const ENV = ["SAFESPACE_CONFIG_DIR", "SAFESPACE_SECRET_BACKEND", "SAFESPACE_OPERATOR_ID", "SAFESPACE_SECRET_PASSPHRASE", "SAFESPACE_SLACK_WEBHOOK_SECRET"];

beforeEach(async () => {
  for (const k of ENV) saved[k] = process.env[k];
  tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "safespace-whsec-"));
  process.env.SAFESPACE_CONFIG_DIR = tmpDir;
  process.env.SAFESPACE_SECRET_BACKEND = "file";
  delete process.env.SAFESPACE_OPERATOR_ID;
  delete process.env.SAFESPACE_SECRET_PASSPHRASE;
  delete process.env.SAFESPACE_SLACK_WEBHOOK_SECRET;
  __resetWebhookSecretBackendForTests();
});

afterEach(async () => {
  for (const k of ENV) {
    if (saved[k] === undefined) delete process.env[k];
    else process.env[k] = saved[k]!;
  }
  __resetWebhookSecretBackendForTests();
  await fs.rm(tmpDir, { recursive: true, force: true }).catch(() => undefined);
});

describe("webhook signing-secret store", () => {
  test("round-trips set/read/has/delete via the SecretBackend", async () => {
    expect(await readWebhookSigningSecret("slack")).toBeNull();
    expect(await hasWebhookSigningSecret("slack")).toBe(false);
    await setWebhookSigningSecret("slack", "sign-sec-abc");
    expect(await readWebhookSigningSecret("slack")).toBe("sign-sec-abc");
    expect(await hasWebhookSigningSecret("slack")).toBe(true);
    await deleteWebhookSigningSecret("slack");
    expect(await readWebhookSigningSecret("slack")).toBeNull();
  });

  test("the shell-only env override takes precedence over the backend", async () => {
    await setWebhookSigningSecret("slack", "persisted");
    process.env.SAFESPACE_SLACK_WEBHOOK_SECRET = "  env-wins  "; // trimmed
    expect(await readWebhookSigningSecret("slack")).toBe("env-wins");
    delete process.env.SAFESPACE_SLACK_WEBHOOK_SECRET;
    expect(await readWebhookSigningSecret("slack")).toBe("persisted");
  });

  test("an empty env override does NOT activate (falls through to backend)", async () => {
    await setWebhookSigningSecret("slack", "persisted");
    process.env.SAFESPACE_SLACK_WEBHOOK_SECRET = "   ";
    expect(await readWebhookSigningSecret("slack")).toBe("persisted");
  });

  test("the reserved key is webhook-namespaced (cannot collide with the bot token)", () => {
    const key = storageKey(null, "webhook:slack-signing-secret");
    expect(key).toContain("webhook:slack-signing-secret");
    expect(key).not.toContain("@");
  });

  test("webhookSecretEnvVar reports the slack + line override vars; telegram has none (W2)", () => {
    expect(webhookSecretEnvVar("slack")).toBe("SAFESPACE_SLACK_WEBHOOK_SECRET");
    expect(webhookSecretEnvVar("line")).toBe("SAFESPACE_LINE_WEBHOOK_SECRET");
    expect(webhookSecretEnvVar("telegram")).toBeUndefined();
  });
});
