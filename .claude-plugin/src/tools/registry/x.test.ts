// v1.114 / v1.115 — X tool registry shape pins (tier / direction / source / schema).

import { describe, expect, test } from "bun:test";
import { IMPLEMENTED_TOOLS, TOOL_REGISTRY } from "./index";

const X_READ_TOOLS = ["x_get_me", "x_search_recent"] as const;

describe("v1.114 — X read tools (the first tools of the 4th OAuth source)", () => {
  test("both X read tools are registered + implemented", () => {
    for (const t of X_READ_TOOLS) {
      expect(TOOL_REGISTRY[t]).toBeDefined();
      expect(IMPLEMENTED_TOOLS.has(t)).toBe(true);
    }
  });

  test("each is source:x, min_tier:read, inbound-read, requiredScopes empty, additionalProperties:false", () => {
    for (const t of X_READ_TOOLS) {
      const def = TOOL_REGISTRY[t]!;
      expect(def.source).toBe("x");
      expect(def.min_tier).toBe("read");
      expect(def.direction).toBe("inbound-read");
      expect(def.requiredScopes).toEqual([]);
      expect(def.cross_account).toBeUndefined();
      expect(def.inputSchema.additionalProperties).toBe(false);
    }
  });

  test("x_get_me has no required args; x_search_recent requires query", () => {
    expect(TOOL_REGISTRY.x_get_me!.inputSchema.required).toBeUndefined();
    expect(TOOL_REGISTRY.x_search_recent!.inputSchema.required).toEqual(["query"]);
  });
});

describe("v1.115 — x_post_create (PUBLIC-surface write)", () => {
  test("registered + implemented", () => {
    expect(TOOL_REGISTRY.x_post_create).toBeDefined();
    expect(IMPLEMENTED_TOOLS.has("x_post_create")).toBe(true);
  });

  test("source:x, min_tier:write, outbound-write, requiredScopes empty, text required", () => {
    const def = TOOL_REGISTRY.x_post_create!;
    expect(def.source).toBe("x");
    expect(def.min_tier).toBe("write");
    expect(def.direction).toBe("outbound-write");
    expect(def.requiredScopes).toEqual([]);
    expect(def.inputSchema.required).toEqual(["text"]);
    expect(def.inputSchema.additionalProperties).toBe(false);
  });
});
