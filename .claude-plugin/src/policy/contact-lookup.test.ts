// v1.15 Phase 3 — `isContactLookupEnabled` strict-truthy parsing tests.
//
// Locks the env-var contract per docs/v1.15-contacts-api.md §11 hook #3:
// MUST require literal string "true" lowercase. Every other value → false.
// See contact-lookup.ts file comment for the full rationale on why this is
// stricter than SAFESPACE_TIER / SAFESPACE_RECIPIENT_ALLOW.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import {
  ENV_RECIPIENT_ALLOW_CONTACTS,
  isContactLookupEnabled,
} from "./contact-lookup";

describe("isContactLookupEnabled — strict-truthy env-var parsing (v1.15 Phase 3)", () => {
  let originalEnv: string | undefined;

  beforeEach(() => {
    originalEnv = process.env[ENV_RECIPIENT_ALLOW_CONTACTS];
    delete process.env[ENV_RECIPIENT_ALLOW_CONTACTS];
  });

  afterEach(() => {
    if (originalEnv === undefined) {
      delete process.env[ENV_RECIPIENT_ALLOW_CONTACTS];
    } else {
      process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = originalEnv;
    }
  });

  test("ENV_RECIPIENT_ALLOW_CONTACTS constant matches design contract", () => {
    // Locked constant name — referenced in user-facing docs (PR description,
    // CLAUDE.md) and shell setup. Renaming breaks `safespace doctor` lookup
    // and any user .env file already using it. Sentinel against accidental
    // rename in a refactor.
    expect(ENV_RECIPIENT_ALLOW_CONTACTS).toBe("SAFESPACE_RECIPIENT_ALLOW_CONTACTS");
  });

  test("literal 'true' (lowercase) → true (the ONLY accepted shape)", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "true";
    expect(isContactLookupEnabled()).toBe(true);
  });

  test("'True' (TitleCase) → false (defends against shell autocompletion / dotenv case-folding)", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "True";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("'TRUE' (uppercase) → false (defends against Windows locale upper-casing)", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "TRUE";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("'1' → false (NOT a truthy shorthand; this env var requires the literal word)", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "1";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("'yes' → false (NOT accepted as truthy)", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "yes";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("'on' → false (NOT accepted as truthy)", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "on";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("'false' → false (literal opposite, explicitly disabled)", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "false";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("'0' → false", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "0";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("empty string '' → false (set-but-empty does NOT enable)", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("undefined / unset → false (default-disabled preserves v1.14 behaviour)", () => {
    delete process.env[ENV_RECIPIENT_ALLOW_CONTACTS];
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("' true ' (whitespace-padded) → false (no .trim() — exact match only)", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = " true ";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("'true ' (trailing whitespace) → false", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "true ";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("' true' (leading whitespace) → false", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = " true";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("'true\\n' (with trailing newline) → false (dotenv often slips a trailing \\n)", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "true\n";
    expect(isContactLookupEnabled()).toBe(false);
  });

  test("arbitrary garbage value → false", () => {
    process.env[ENV_RECIPIENT_ALLOW_CONTACTS] = "enable_contacts_please";
    expect(isContactLookupEnabled()).toBe(false);
  });
});
