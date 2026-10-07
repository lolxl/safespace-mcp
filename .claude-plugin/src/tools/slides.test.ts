// v1.60 — Slides handler tests (slides_get / slides_create / slides_modify),
// through the SDK-level setGaxiosHandler seam. Pins the slides_modify POSITIVE
// request-type allowlist (the load-bearing gate) + the SSRF exclusion
// (createImage/createSheetsChart/createVideo rejected) + the negative-sentinel.

import { afterEach, beforeEach, describe, expect, test } from "bun:test";
import { oauthCred, NOOP_AUDIT } from "./test-audit";
import { currentTier } from "../tier";
import { slidesCreate, slidesGet, slidesModify } from "./handlers";
import {
  SLIDES_MODIFY_ALLOWED_REQUEST_TYPES,
  _SLIDES_MODIFY_FORBIDDEN_REQUEST_TYPES_FOR_TEST,
} from "./handlers/slides";
import type { ToolContext } from "./types";

const FAKE_TOKEN = "ya29.fake-token-for-tests";
const CTX: ToolContext = {
  credential: oauthCred("alice@example.com", () => FAKE_TOKEN),
  audit: NOOP_AUDIT,
  get tier() {
    return currentTier();
  },
};

interface CapturedOpts {
  url?: string;
  method?: string;
  data?: unknown;
}
let captured: CapturedOpts | undefined;

beforeEach(async () => {
  const { resetGaxiosHandler, setGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
  captured = undefined;
  setGaxiosHandler(async (o) => {
    captured = o as CapturedOpts;
    return { data: { presentationId: "pNEW", replies: [{}] }, status: 200 };
  });
});
afterEach(async () => {
  const { resetGaxiosHandler } = await import("../google-api/test-utils");
  resetGaxiosHandler();
});

const PID = "1AbcDEF_-ghiJKLmnop";
const REQ = (over: object) => ({ presentation_id: PID, requests: [over] });

describe("slides_get", () => {
  test("valid id → presentations.get; bad id → reject (rule not value)", async () => {
    await slidesGet(CTX, { presentation_id: PID });
    expect(captured?.url).toContain(`/presentations/${PID}`);
    await expect(slidesGet(CTX, { presentation_id: "bad/id space" })).rejects.toThrow(/must match/);
    await expect(slidesGet(CTX, {})).rejects.toThrow(/must be a string/);
  });
});

describe("slides_create", () => {
  test("valid title → presentations.create with {title}; gates reject", async () => {
    const res = (await slidesCreate(CTX, { title: "  Q3 Deck  " })) as { presentationId: string };
    expect(res.presentationId).toBe("pNEW");
    expect((captured?.data as { title?: string })?.title).toBe("Q3 Deck"); // trimmed
    await expect(slidesCreate(CTX, { title: "   " })).rejects.toThrow(/non-empty/);
    await expect(slidesCreate(CTX, { title: "bad\r\ntitle" })).rejects.toThrow(/CR\/LF/);
    await expect(slidesCreate(CTX, { title: "x".repeat(1001) })).rejects.toThrow(/exceeds 1000 bytes/);
    await expect(slidesCreate(CTX, {})).rejects.toThrow(/must be a string/);
  });
});

describe("slides_modify — allowlist gate + SSRF exclusion", () => {
  test("happy path — an allowlisted insertText → batchUpdate with the requests", async () => {
    await slidesModify(CTX, REQ({ insertText: { objectId: "o1", text: "hello" } }));
    expect(captured?.url).toContain(`/presentations/${PID}:batchUpdate`);
    const sent = (captured?.data as { requests?: unknown[] })?.requests;
    expect(sent).toHaveLength(1);
  });

  test("every ALLOWED type is accepted (passes the gate)", async () => {
    for (const t of SLIDES_MODIFY_ALLOWED_REQUEST_TYPES) {
      // minimal body per type; structural correctness is Google's job.
      const body = t === "insertText" ? { text: "x" } : t === "replaceAllText" ? { replaceText: "y" } : {};
      await expect(slidesModify(CTX, REQ({ [t]: body }))).resolves.toBeDefined();
    }
  });

  test("SECURITY: every external-URL-fetching request type → rejected (image/sheet/video SSRF)", async () => {
    // The full SSRF set — create* AND replaceAllShapesWith* (both fetch an
    // external URL with the user's identity, the Sheets IMAGE/IMPORTRANGE class).
    for (const t of [
      "createImage",
      "createSheetsChart",
      "createVideo",
      "replaceAllShapesWithImage",
      "replaceAllShapesWithSheetsChart",
    ]) {
      await expect(slidesModify(CTX, REQ({ [t]: { url: "https://evil.example/x.png" } }))).rejects.toThrow(
        /not in allowlist/,
      );
    }
  });

  test("negative sentinel: EVERY known-forbidden request type is rejected", async () => {
    for (const t of _SLIDES_MODIFY_FORBIDDEN_REQUEST_TYPES_FOR_TEST) {
      expect(SLIDES_MODIFY_ALLOWED_REQUEST_TYPES.has(t)).toBe(false);
      await expect(slidesModify(CTX, REQ({ [t]: {} }))).rejects.toThrow(/not in allowlist/);
    }
  });

  test("request shape gates: 0-key, 2-key, non-object, empty array, over-cap", async () => {
    await expect(slidesModify(CTX, REQ({}))).rejects.toThrow(/exactly ONE key/);
    await expect(slidesModify(CTX, REQ({ insertText: { text: "a" }, deleteText: {} }))).rejects.toThrow(/exactly ONE key/);
    await expect(slidesModify(CTX, { presentation_id: PID, requests: ["notanobject"] })).rejects.toThrow(/must be an object/);
    await expect(slidesModify(CTX, { presentation_id: PID, requests: [] })).rejects.toThrow(/non-empty/);
    const tooMany = Array.from({ length: 51 }, () => ({ insertText: { text: "a" } }));
    await expect(slidesModify(CTX, { presentation_id: PID, requests: tooMany })).rejects.toThrow(/at most 50/);
  });

  test("content byte caps: insertText.text 100KB, replaceAllText.replaceText 1KB", async () => {
    await expect(
      slidesModify(CTX, REQ({ insertText: { text: "x".repeat(100 * 1024 + 1) } })),
    ).rejects.toThrow(/insertText.text exceeds/);
    await expect(
      slidesModify(CTX, REQ({ replaceAllText: { replaceText: "x".repeat(1025) } })),
    ).rejects.toThrow(/replaceText exceeds/);
  });

  test("bad presentation_id → reject", async () => {
    await expect(slidesModify(CTX, { presentation_id: "bad id", requests: [{ insertText: { text: "a" } }] })).rejects.toThrow(/must match/);
  });
});
