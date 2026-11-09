// Subprocess fixture for real-transport.test.ts — NOT a test file.
//
// Runs real handlers through the REAL googleapis -> googleapis-common -> gaxios
// stack (no `mock.module("gaxios")`; the bun test preload mocks it in-process,
// which is why this must be its own process) with only the network replaced:
// `globalThis.fetch` is swapped for an in-memory server that reads the request
// body to EOF, exactly like a socket would. A request body that never
// terminates (the Bun 1.3.x `Readable.toWeb(<push(null)-ended PassThrough>)`
// hang) makes the read time out and the fixture exits non-zero.
//
// Usage: bun run real-transport-fixture.ts <scenario>
// Prints one JSON line (see `emit`).

import { MCPError } from "../errors";
import {
  driveCreateFile,
  driveGetFileContent,
  formsPublish,
  gmailModifyMessagesBatch,
} from "../tools/handlers";
import { NOOP_AUDIT, oauthCred } from "../tools/test-audit";
import type { ToolContext } from "../tools/types";

const READ_TIMEOUT_MS = 3000;

interface Seen {
  url: string;
  method: string;
  contentType: string | null;
  bodyText: string | null;
}
const seen: Seen = { url: "", method: "", contentType: null, bodyText: null };

async function readBodyToEof(body: unknown): Promise<string> {
  if (body == null) return "";
  if (typeof body === "string") return body;
  const reader = (body as ReadableStream<Uint8Array>).getReader();
  const chunks: Uint8Array[] = [];
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_, rej) => {
    timer = setTimeout(() => rej(new Error("request body never reached EOF")), READ_TIMEOUT_MS);
  });
  try {
    for (;;) {
      const r = await Promise.race([reader.read(), timeout]);
      if (r.done) break;
      chunks.push(r.value);
    }
  } finally {
    clearTimeout(timer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const FILE_ID = "1FileAAAAAAAAAAAAAAAAAA";
const MSG_ID = "19de5a8c628b9010";
const BATCH_BOUNDARY = "response_batch_zzz";

function batchOk(): Response {
  const part =
    `--${BATCH_BOUNDARY}\r\nContent-Type: application/http\r\nContent-ID: <response-${MSG_ID}>\r\n\r\n` +
    `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n` +
    JSON.stringify({ id: MSG_ID, threadId: MSG_ID, labelIds: ["INBOX", "STARRED"] }) +
    `\r\n--${BATCH_BOUNDARY}--\r\n`;
  return new Response(part, {
    status: 200,
    headers: { "content-type": `multipart/mixed; boundary=${BATCH_BOUNDARY}` },
  });
}

const forbidden = (): Response =>
  json(403, {
    error: {
      code: 403,
      message: "Request had insufficient authentication scopes.",
      status: "PERMISSION_DENIED",
      errors: [{ reason: "insufficientPermissions" }],
    },
  });

// scenario -> { server, run }
const CONTENTS: Record<string, string> = {
  drive_create_file: "héllo wörld ✓",
  drive_create_file_empty: "",
  drive_create_file_large: "x".repeat(4 * 1024 * 1024),
};

const scenario = process.argv[2] ?? "";

globalThis.fetch = (async (input: unknown, init?: RequestInit) => {
  seen.url = String(input);
  seen.method = (init?.method ?? "GET").toUpperCase();
  const h = new Headers(init?.headers);
  seen.contentType = h.get("content-type");
  seen.bodyText = await readBodyToEof(init?.body);
  const url = seen.url;
  if (scenario in CONTENTS) {
    return json(200, { id: "1NewFileAAAAAAAAAAAAAAA", name: "notes.txt", mimeType: "text/plain" });
  }
  if (scenario.startsWith("drive_get_content")) {
    if (url.includes("alt=media")) {
      return scenario === "drive_get_content_403"
        ? forbidden()
        : new Response("hello from drive", { status: 200, headers: { "content-type": "text/plain" } });
    }
    return json(200, { id: FILE_ID, name: "a.txt", mimeType: "text/plain", size: "16" });
  }
  if (scenario === "forms_publish") {
    return json(200, {
      formId: "1FormAAAAAAAAAAAAAAAAAA",
      publishSettings: { publishState: { isPublished: true, isAcceptingResponses: true } },
    });
  }
  if (scenario === "gmail_batch_ok") return batchOk();
  if (scenario === "gmail_batch_403") return forbidden();
  return json(500, { error: { message: `fixture: no route for ${scenario}` } });
}) as typeof fetch;

const ctx: ToolContext = {
  credential: oauthCred("alice@example.com", () => "fake-token"),
  audit: NOOP_AUDIT,
  tier: "write",
};

function emit(extra: Record<string, unknown>): void {
  const body = seen.bodyText ?? "";
  const big = body.length > 65_536;
  console.log(
    JSON.stringify({
      ...extra,
      ...seen,
      bodyText: big ? null : body,
      bodyLength: body.length,
      bodyHasPayload: scenario in CONTENTS ? body.includes(CONTENTS[scenario] ?? "") : undefined,
    }),
  );
}

try {
  let res: unknown;
  if (scenario in CONTENTS) {
    res = await driveCreateFile(ctx, { name: "notes.txt", content: CONTENTS[scenario] ?? "" });
  } else if (scenario.startsWith("drive_get_content")) {
    res = await driveGetFileContent(ctx, { id: FILE_ID });
  } else if (scenario === "forms_publish") {
    res = await formsPublish({ ...ctx, tier: "share" }, { form_id: "1FormAAAAAAAAAAAAAAAAAA" });
  } else if (scenario.startsWith("gmail_batch")) {
    res = await gmailModifyMessagesBatch(ctx, { ids: [MSG_ID], addLabelIds: ["STARRED"] });
  } else {
    throw new Error(`unknown scenario ${scenario}`);
  }
  emit({ ok: true, res });
  process.exitCode = 0;
} catch (err) {
  emit({
    ok: false,
    error: String((err as Error)?.message ?? err),
    errorName: err instanceof MCPError ? err.errorName : undefined,
    httpStatus: (err as { httpStatus?: number })?.httpStatus,
  });
  process.exitCode = 1;
}
