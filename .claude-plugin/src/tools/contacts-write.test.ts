// v1.50 (backlog B5) — contacts_create / contacts_update WRITE tier.
// SDK-level mock via setGaxiosHandler (same surface as drive-file-write.test.ts).
// Security-relevant assertions: ALLOWLIST construction (forbidden top-level +
// nested fields rejected), free-text byte caps, urls[*].value scheme allowlist,
// etag-required optimistic-concurrency contract on update, updatePersonFields
// mask derivation, and tier defense-in-depth (read tier → scope_mismatch).

import { beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import { contactsCreate, contactsUpdate } from "./handlers";
import { MCPError } from "../errors";
import type { ToolContext } from "./types";

const FAKE_CTX: ToolContext = {
  credential: oauthCred("alice@example.com", () => "fake-token"),
  audit: NOOP_AUDIT,
  tier: "write",
};
const READ_CTX: ToolContext = {
  credential: oauthCred("alice@example.com", () => "fake-token"),
  audit: NOOP_AUDIT,
  tier: "read",
};

const RESOURCE = "people/c1234567890123456789";

// v1.15 §9 NEGATIVE sentinel — ≥10 forbidden Person fields. Each MUST be
// rejected by the allowlist-construction handler.
const FORBIDDEN_FIELDS = [
  "photos",
  "coverPhotos",
  "externalIds",
  "metadata",
  "resourceName",
  "etag", // etag is a control key for update, but NOT a Person field group for create
  "ageRange",
  "genders",
  "imClients",
  "interests",
  "locales",
  "nicknames",
  "occupations",
  "relations",
  "residences",
  "sipAddresses",
  "skills",
  "taglines",
  "events",
  "clientData",
];

beforeEach(async () => {
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});

describe("contacts_create", () => {
  test("happy path — names + email; constructs Person body, returns created resource", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: Record<string, unknown> = {};
    let method = "";
    setGaxiosHandler(async (opts) => {
      method = (opts.method ?? "").toUpperCase();
      body = (opts.data ?? {}) as Record<string, unknown>;
      return { data: { resourceName: RESOURCE, etag: "newetag" }, status: 200 };
    });
    const res = (await contactsCreate(FAKE_CTX, {
      names: [{ givenName: "Alice", familyName: "Smith" }],
      emailAddresses: [{ value: "alice@example.com", type: "work" }],
    })) as { resourceName: string };
    expect(res.resourceName).toBe(RESOURCE);
    expect(method).toBe("POST");
    expect(body.names).toEqual([{ givenName: "Alice", familyName: "Smith" }]);
    expect(body.emailAddresses).toEqual([{ value: "alice@example.com", type: "work" }]);
  });

  test("accepts the full allowlisted field set (bio/url/userDefined/birthday/address/org/phone)", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: Record<string, unknown> = {};
    setGaxiosHandler(async (opts) => {
      body = (opts.data ?? {}) as Record<string, unknown>;
      return { data: { resourceName: RESOURCE }, status: 200 };
    });
    await contactsCreate(FAKE_CTX, {
      names: [{ displayName: "Bob" }],
      phoneNumbers: [{ value: "+1-555-1234", type: "mobile" }],
      organizations: [{ name: "Acme", title: "Eng" }],
      addresses: [{ formattedValue: "1 Main St", city: "Townsville" }],
      biographies: [{ value: "hello", contentType: "TEXT_PLAIN" }],
      urls: [{ value: "https://example.com", type: "home" }],
      userDefined: [{ key: "nickname", value: "Bobby" }],
      birthdays: [{ date: { year: 1990, month: 5, day: 14 } }],
    });
    expect(body.urls).toEqual([{ value: "https://example.com", type: "home" }]);
    expect(body.birthdays).toEqual([{ date: { year: 1990, month: 5, day: 14 } }]);
  });

  test("NEGATIVE sentinel — every forbidden top-level field is rejected", async () => {
    for (const f of FORBIDDEN_FIELDS) {
      await expect(
        contactsCreate(FAKE_CTX, { names: [{ givenName: "A" }], [f]: [{ x: 1 }] }),
      ).rejects.toThrow(/is not allowed/);
    }
  });

  test("rejects a smuggled nested leaf property (names[*].metadata)", async () => {
    await expect(
      contactsCreate(FAKE_CTX, { names: [{ givenName: "A", metadata: { primary: true } }] }),
    ).rejects.toThrow(/is not an allowed property/);
  });

  test("rejects an empty write (no field group)", async () => {
    await expect(contactsCreate(FAKE_CTX, {})).rejects.toThrow(/requires at least one non-empty contact field/);
    await expect(contactsCreate(FAKE_CTX, { names: [] })).rejects.toThrow(
      /requires at least one non-empty contact field/,
    );
  });

  test("byte caps — biographies.value ≤2048, urls.value ≤512, userDefined.value ≤512, generic ≤1024", async () => {
    await expect(
      contactsCreate(FAKE_CTX, { biographies: [{ value: "x".repeat(2049) }] }),
    ).rejects.toThrow(/exceeds 2048 bytes/);
    await expect(
      contactsCreate(FAKE_CTX, { urls: [{ value: `https://e.com/${"x".repeat(513)}` }] }),
    ).rejects.toThrow(/exceeds 512 bytes/);
    await expect(
      contactsCreate(FAKE_CTX, { userDefined: [{ key: "k", value: "x".repeat(513) }] }),
    ).rejects.toThrow(/exceeds 512 bytes/);
    await expect(
      contactsCreate(FAKE_CTX, { names: [{ givenName: "x".repeat(1025) }] }),
    ).rejects.toThrow(/exceeds 1024 bytes/);
  });

  test("urls[*].value scheme allowlist — javascript:/data:/file: rejected, http/https/mailto ok", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    setGaxiosHandler(async () => ({ data: { resourceName: RESOURCE }, status: 200 }));
    await expect(
      contactsCreate(FAKE_CTX, { urls: [{ value: "javascript:alert(1)" }] }),
    ).rejects.toThrow(/URL scheme .* not allowed/);
    await expect(
      contactsCreate(FAKE_CTX, { urls: [{ value: "data:text/html,x" }] }),
    ).rejects.toThrow(/URL scheme .* not allowed/);
    await expect(
      contactsCreate(FAKE_CTX, { urls: [{ value: "not a url at all" }] }),
    ).rejects.toThrow(/not a valid URL/);
    // mailto + https accepted
    await expect(
      contactsCreate(FAKE_CTX, { urls: [{ value: "mailto:a@b.com" }] }),
    ).resolves.toBeDefined();
  });

  test("userDefined requires a non-empty key", async () => {
    await expect(
      contactsCreate(FAKE_CTX, { userDefined: [{ value: "no-key" }] }),
    ).rejects.toThrow(/requires a non-empty 'key'/);
  });

  test("birthday date validation — month range + integer", async () => {
    await expect(
      contactsCreate(FAKE_CTX, { birthdays: [{ date: { month: 13 } }] }),
    ).rejects.toThrow(/month must be 1-12/);
    await expect(
      contactsCreate(FAKE_CTX, { birthdays: [{ date: { day: 1.5 } }] }),
    ).rejects.toThrow(/must be an integer/);
    await expect(
      contactsCreate(FAKE_CTX, { birthdays: [{ date: { era: "AD" } }] }),
    ).rejects.toThrow(/year\/month\/day only/);
  });

  test("tier=read → scope_mismatch (defense-in-depth), no SDK call", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(
      contactsCreate(READ_CTX, { names: [{ givenName: "A" }] }),
    ).rejects.toBeInstanceOf(MCPError);
    expect(called).toBe(false);
  });
});

describe("contacts_update", () => {
  test("happy path — derives updatePersonFields from supplied groups; puts etag in body", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let body: Record<string, unknown> = {};
    let params: Record<string, unknown> = {};
    let method = "";
    setGaxiosHandler(async (opts) => {
      method = (opts.method ?? "").toUpperCase();
      body = (opts.data ?? {}) as Record<string, unknown>;
      params = (opts.params ?? {}) as Record<string, unknown>;
      return { data: { resourceName: RESOURCE, etag: "etag2" }, status: 200 };
    });
    await contactsUpdate(FAKE_CTX, {
      resource_name: RESOURCE,
      etag: "etag1",
      names: [{ givenName: "Alice" }],
      emailAddresses: [{ value: "a@b.com" }],
    });
    expect(method).toBe("PATCH");
    // etag flows into the body for optimistic concurrency.
    expect(body.etag).toBe("etag1");
    // updatePersonFields mask = the supplied field groups, comma-joined.
    expect(params.updatePersonFields).toBe("names,emailAddresses");
    // resource_name is NOT echoed into the Person body (server-assigned field).
    expect(body).not.toHaveProperty("resourceName");
  });

  test("rejects a missing / empty etag (optimistic-concurrency contract)", async () => {
    await expect(
      contactsUpdate(FAKE_CTX, { resource_name: RESOURCE, names: [{ givenName: "A" }] }),
    ).rejects.toThrow(/requires the contact's current 'etag'/);
    await expect(
      contactsUpdate(FAKE_CTX, { resource_name: RESOURCE, etag: "  ", names: [{ givenName: "A" }] }),
    ).rejects.toThrow(/requires the contact's current 'etag'/);
  });

  test("rejects a malformed resource_name (echoes the rule, not the value)", async () => {
    await expect(
      contactsUpdate(FAKE_CTX, { resource_name: "people/../etc", etag: "e", names: [{ givenName: "A" }] }),
    ).rejects.toThrow(/must match/);
    await expect(
      contactsUpdate(FAKE_CTX, { resource_name: "c123", etag: "e", names: [{ givenName: "A" }] }),
    ).rejects.toThrow(/must match/);
  });

  test("rejects an empty update (etag present but no field group)", async () => {
    await expect(
      contactsUpdate(FAKE_CTX, { resource_name: RESOURCE, etag: "e" }),
    ).rejects.toThrow(/requires at least one non-empty contact field/);
  });

  test("shares the create allowlist — forbidden field rejected", async () => {
    await expect(
      contactsUpdate(FAKE_CTX, {
        resource_name: RESOURCE,
        etag: "e",
        relations: [{ person: "spouse" }],
      }),
    ).rejects.toThrow(/is not allowed/);
  });

  test("tier=read → scope_mismatch (defense-in-depth), no SDK call", async () => {
    const { setGaxiosHandler } = await import("../google-api/test-utils");
    let called = false;
    setGaxiosHandler(async () => {
      called = true;
      return { data: {}, status: 200 };
    });
    await expect(
      contactsUpdate(READ_CTX, { resource_name: RESOURCE, etag: "e", names: [{ givenName: "A" }] }),
    ).rejects.toBeInstanceOf(MCPError);
    expect(called).toBe(false);
  });
});
