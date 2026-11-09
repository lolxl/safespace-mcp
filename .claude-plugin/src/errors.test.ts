import { describe, expect, test } from "bun:test";
import { ERROR_CODES, MCPError } from "./errors";
import type { ConnectorApiFailedName } from "./auth/http/connector-error-contract";

describe("ERROR_CODES table", () => {
  test("contains 55 names (v1.128 added telegram_ack_denied_in_autonomous_mode; inbox_read_failed retired with the webhook listener)", () => {
    expect(Object.keys(ERROR_CODES).sort()).toEqual([
      "account_not_found",
      "batch_too_large",
      "comment_burst_limit_exceeded",
      "comment_target_denied_by_policy",
      "destructive_denied_in_autonomous_mode",
      "discord_api_failed",
      "download_stalled",
      "drive_delete_denied_by_policy",
      "egress_destination_blocked",
      "file_too_large",
      "file_unsupported_binary",
      "formula_rejected",
      "fs_read_failed",
      "github_api_failed",
      "github_approve_denied_by_policy",
      "github_merge_denied_by_policy",
      "github_write_denied_by_policy",
      "internal_routing_error",
      "keychain_locked",
      "label_limit_exceeded",
      "line_api_failed",
      "mattermost_api_failed",
      "notion_api_failed",
      "outbound_sanitize_rejected",
      "outbound_secret_rejected",
      "path_blocked_by_policy",
      "rate_limited",
      "recipient_denied_by_policy",
      "recipient_lookup_failed",
      "refresh_token_invalid",
      "sanitize_failed",
      "scope_mismatch",
      "search_burst_limit_exceeded",
      "secret_store_corrupt",
      "send_approval_required",
      "share_denied_by_policy",
      "share_expiration_forbidden",
      "share_expiration_required",
      "share_role_forbidden",
      "share_target_forbidden",
      "slack_api_failed",
      "system_label_forbidden",
      "tainted_recipient_denied",
      "tasks_delete_denied_by_policy",
      "telegram_ack_denied_in_autonomous_mode",
      "telegram_api_failed",
      "tool_not_found",
      "url_blocked_by_policy",
      "value_render_option_rejected",
      "video_target_denied_by_policy",
      "web_fetch_failed",
      "write_burst_limit_exceeded",
      "x_api_failed",
      "x_post_denied_by_policy",
      "youtube_quota_exceeded",
    ]);
  });

  test("codes -32000..-32029 with gaps (v2.0 removed -32009/-32010/-32013; v1.21 Phase 1b adds -32029 formula_rejected)", () => {
    // v2.0 removed send_disabled (-32009), modify_disabled (-32010),
    // share_disabled (-32013). v2.1 added share_denied_by_policy (-32018).
    // v2.2 added recipient_denied_by_policy (-32019).
    // v2.3 PR-C added batch_too_large (-32020).
    // v1.11 Phase 2 PR-5 added download_stalled (-32021).
    // v1.15 Phase 3 added recipient_lookup_failed (-32022).
    // v1.16 Phase 1b added youtube_quota_exceeded (-32024) and
    // search_burst_limit_exceeded (-32026).
    // v1.16 Phase 2a wired the previously-reserved Phase 2 codes:
    //   -32023 comment_target_denied_by_policy
    //   -32025 comment_burst_limit_exceeded
    // v1.16 Phase 2b added -32027 outbound_sanitize_rejected — the FIRST
    // outbound (compose-time) sanitize-reject code, distinct from the
    // inbound sanitize_failed (-32000). Used by youtube_video_comment_post /
    // youtube_comment_reply handlers when args.text fails the 6-step
    // outbound pipeline (zero-width / length / wrapper-close / truncate
    // marker / warning preamble).
    // v1.20 Phase 1b-1 added -32028 value_render_option_rejected — the
    // first error code of the v1.20 cycle. Used by sheets_get_values when
    // value_render_option=FORMULA is supplied (design §11 Q4 LOCKED — formula
    // text leaks user secrets). errorData carries closed-enum reason
    // discriminator "formula_rendering_rejected" (mirrors -32027 pattern).
    // v1.21 Phase 1b added -32029 formula_rejected — applied to
    // USER_ENTERED cell strings starting with `=`/`+` whose outer function
    // name matches the 11-function REJECT set. errorData carries closed-enum
    // `reason: "formula_rejected"` + separate `rejected_formula_function`
    // string field (UPPERCASED function name from the closed 11-item set).
    // Numbers stay sparse — never renumber, downstream log readers may
    // pattern-match on codes.
    // v1.37 BLOCKER 1 added -32031 secret_store_corrupt (encrypted FileBackend
    // non-retryable failure class). v1.39 BLOCKER 4 SPENT the previously-reserved
    // -32030 on tasks_delete_denied_by_policy (the tasks-delete target allowlist;
    // roadmap Q9). -32031 and -32030 are now both present, contiguous above -32029.
    // v1.52 F1 (Autonomy Hardening) added -32032 write_burst_limit_exceeded.
    // v1.54 F4 (Autonomy Hardening) added -32033
    // destructive_denied_in_autonomous_mode — new most-negative (permanent-delete
    // hard-deny under SAFESPACE_AUTONOMOUS; reuses F1's PERMANENT_DELETE_TOOLS).
    // v1.57 (Autonomy Hardening) added -32034 tainted_recipient_denied (F3b-gate)
    // + -32035 outbound_secret_rejected (F3a).
    // v1.65 Phase C (web-fetch keyless connector) added -32036 url_blocked_by_policy
    // (SSRF gate rejection) + -32037 web_fetch_failed (operational fetch failure).
    // v1.66 Phase C PR 2 (LINE OA service-token connector) added -32038
    // line_api_failed.
    // v1.68 (Telegram Bot service-token connector) added -32039 telegram_api_failed.
    // v1.69 (Discord) added -32040 discord_api_failed; v1.70 G2 added -32041
    // github_api_failed; v1.71 (GitHub WRITE) added -32042
    // github_write_denied_by_policy — new most-negative.
    // v1.75 (fs_read keyless connector) added -32043 path_blocked_by_policy (the
    // filesystem path gate) + -32044 fs_read_failed (operational).
    // v1.77 (Notion service-token connector) added -32045 notion_api_failed.
    // v1.82 (GitHub PR merge) added -32046 github_merge_denied_by_policy.
    // v1.88 (centralized egress-destination registry) added -32047
    // egress_destination_blocked (a SafeSpace-owned outbound fetch targeted an
    // unregistered host; backstop, host echoed, no URL/token).
    // v1.90 (github_create_pull_request_review) added -32048
    // github_approve_denied_by_policy — new most-negative (the APPROVE-event review
    // gate; its OWN default-deny allowlist, separate from -32042's write list).
    // v1.95 (Slack service-token connector) added -32049 slack_api_failed — new
    // most-negative (the chat.postMessage 200-but-ok:false body model maps here).
    // v1.99 (enforced send-approval gate) added -32050 send_approval_required
    // (supervised mode blocks an unapproved outbound message send).
    // v1.102 added -32051 inbox_read_failed; retired with the webhook listener (gap).
    // v1.106 (youtube_video_update) added -32052 video_target_denied_by_policy — new
    // most-negative (the deny-default video-metadata-write target allowlist).
    // v1.107 (Mattermost self-hosted class-B connector) added -32053 mattermost_api_failed.
    // v1.112.8 added -32055 internal_routing_error (fail-closed sourceFor + provider-guard
    // throws; -32054 was skipped, reserved for the X connector).
    // v1.113 (X/Twitter OAuth provider, class A — ZERO tools yet) added -32054 x_api_failed.
    // v1.115 (x_post_create) added -32056 x_post_denied_by_policy.
    // v1.128 Q5-B added -32057 telegram_ack_denied_in_autonomous_mode.
    // Drive trash/delete allowlist added -32060 drive_delete_denied_by_policy (-32058/-32059 reserved).
    const codes = Object.values(ERROR_CODES).map((s) => s.code).sort((a, b) => a - b);
    expect(codes).toEqual([
      -32060,
      -32057,
      -32056,
      -32055,
      -32054,
      -32053,
      -32052,
      -32050,
      -32049,
      -32048,
      -32047,
      -32046, -32045, -32044, -32043, -32042,
      -32041, -32040, -32039, -32038, -32037, -32036, -32035, -32034, -32033, -32032, -32031, -32030,
      -32029, -32028, -32027, -32026, -32025, -32024, -32023, -32022, -32021, -32020,
      -32019, -32018, -32017, -32016, -32015, -32014,
      -32012, -32011,
      -32008, -32007, -32006, -32005, -32004, -32003, -32002, -32001, -32000,
    ]);
  });

  test("every recovery hint is non-empty", () => {
    for (const [name, spec] of Object.entries(ERROR_CODES)) {
      expect(spec.recovery.length, `recovery for ${name}`).toBeGreaterThan(0);
    }
  });
});

describe("MCPError.toJsonRpc()", () => {
  test("returns JSON-RPC shape with code/message/recovery", () => {
    const err = new MCPError("keychain_locked");
    const j = err.toJsonRpc();
    expect(j.code).toBe(-32002);
    expect(j.message).toBe("keychain_locked");
    expect(j.data.recovery).toContain("Keychain");
  });

  test("merges custom data fields after recovery", () => {
    const err = new MCPError("account_not_found", { email: "alice@example.com" });
    const j = err.toJsonRpc();
    expect(j.data.email).toBe("alice@example.com");
    expect(j.data.recovery).toContain("safespace consent");
  });

  test("is throwable as an Error subclass", () => {
    expect(() => {
      throw new MCPError("tool_not_found");
    }).toThrow(MCPError);
  });
});

describe("formula_rejected — v1.21 Phase 1b new error code", () => {
  test("code is -32029 and recovery is non-empty (closed-enum reason discriminator)", () => {
    const spec = ERROR_CODES.formula_rejected;
    expect(spec.code).toBe(-32029);
    expect(spec.recovery.length).toBeGreaterThan(0);
    // Recovery is generic — does NOT echo cell content per cross-API NO-PII
    // invariant (design §10 hook #13).
    expect(spec.recovery).toContain("Formula");
    expect(spec.recovery).toContain("RAW");
  });

  test("errorData carries reason discriminator + rejected_formula_function field", () => {
    const err = new MCPError("formula_rejected", {
      reason: "formula_rejected",
      rejected_formula_function: "IMPORTRANGE",
    });
    const j = err.toJsonRpc();
    expect(j.code).toBe(-32029);
    expect(j.message).toBe("formula_rejected");
    expect(j.data.reason).toBe("formula_rejected");
    expect(j.data.rejected_formula_function).toBe("IMPORTRANGE");
  });
});

describe("secret_store_corrupt — v1.37 BLOCKER 1 new error code", () => {
  test("code is -32031 (−32030 reserved for BLOCKER 4) and recovery is non-empty", () => {
    const spec = ERROR_CODES.secret_store_corrupt;
    expect(spec.code).toBe(-32031);
    expect(spec.recovery.length).toBeGreaterThan(0);
    // Generic recovery: re-consent guidance, no key material / path echo.
    expect(spec.recovery).toContain("safespace consent");
  });

  test("recovery carries NO key material, path, or wrong-passphrase-vs-tamper oracle", () => {
    const spec = ERROR_CODES.secret_store_corrupt;
    // Must not distinguish wrong-passphrase from tamper (would be an oracle),
    // and must not leak a filesystem path or hex key fragment.
    expect(spec.recovery).not.toMatch(/\/(Users|home|root|tmp|var)\//);
    expect(spec.recovery.toLowerCase()).not.toContain("secret.key");
    expect(spec.recovery.toLowerCase()).not.toContain("secret.enc");
  });

  test("default toJsonRpc carries only recovery (no leaked data fields)", () => {
    const j = new MCPError("secret_store_corrupt").toJsonRpc();
    expect(j.code).toBe(-32031);
    expect(j.message).toBe("secret_store_corrupt");
    expect(Object.keys(j.data)).toEqual(["recovery"]);
  });
});

describe("keychain_locked recovery — v1.37 BLOCKER 1 generalized (B9)", () => {
  test("still contains 'Keychain' (back-compat) AND now mentions the passphrase path", () => {
    const spec = ERROR_CODES.keychain_locked;
    expect(spec.recovery).toContain("Keychain");
    expect(spec.recovery).toContain("SAFESPACE_SECRET_PASSPHRASE");
  });
});

describe("internal_routing_error — v1.112.8 fail-closed source routing", () => {
  test("code is -32055 (skipping reserved -32054) and recovery is generic / non-user-actionable", () => {
    const spec = ERROR_CODES.internal_routing_error;
    expect(spec.code).toBe(-32055);
    expect(spec.recovery).toMatch(/internal source-routing misconfiguration/i);
    expect(spec.recovery).toMatch(/bug/i);
    // Closed reasons documented; no provider/credential detail in the recovery text.
    expect(spec.recovery).toContain("unknown_source");
    expect(spec.recovery).toContain("credential_mismatch");
    // v1.115.3 — residual envelope tripwires (choke-point authModel / cross_account /
    // resolveCredential accountId backstops).
    expect(spec.recovery).toContain("invariant_violation");
    // v1.116 — the choke-point egress tripwire (outbound-write handler returned
    // without invoking its centralized egress gate).
    expect(spec.recovery).toContain("egress_gate_not_fired");
  });

  test("toJsonRpc merges closed-set reason without leaking identifiers", () => {
    const j = new MCPError("internal_routing_error", { reason: "unknown_source" }).toJsonRpc();
    expect(j.code).toBe(-32055);
    expect(j.message).toBe("internal_routing_error");
    expect(j.data.reason).toBe("unknown_source");
    expect(j.data.recovery).toMatch(/misconfiguration/i);
  });
});

describe("*_api_failed brand set — FROZEN as of v1.118 (pack step 3, arch-review F8)", () => {
  // Every connector so far minted its OWN `<brand>_api_failed` code, growing the
  // global (closed) error taxonomy linearly with connectors. As of v1.118 the set
  // is FROZEN: a NEW connector reuses a shared generic path (designed through the
  // owner gate) rather than minting a new brand code. This sentinel enumerates the
  // `*_api_failed` names straight from the ERROR_CODES spec table (same way the
  // "ERROR_CODES table" block above iterates Object.keys) and pins the set exactly.
  //
  // SOURCE-OF-TRUTH note: the pack-step-3 work order named a 7-member set
  // {line,telegram,discord,slack,mattermost,github,x} and OMITTED notion_api_failed
  // (-32045, the class-A Notion OAuth connector — see errors.ts). The real
  // ERROR_CODES table carries 8 such names; SOURCE wins, so the frozen set is these 8.
  // B6.1-B — the list is now TYPE-TIED to the contract's derived brand type
  // (`ConnectorApiFailedName`, src/auth/http/connector-error-contract.ts) in BOTH
  // directions: `satisfies` rejects a list entry outside the type; the `_Missing`
  // anchor below rejects a type member absent from the list. The runtime filter
  // test then ties both to the ERROR_CODES table.
  const FROZEN_API_FAILED_BRANDS = [
    "discord_api_failed",
    "github_api_failed",
    "line_api_failed",
    "mattermost_api_failed",
    "notion_api_failed",
    "slack_api_failed",
    "telegram_api_failed",
    "x_api_failed",
  ] as const satisfies readonly ConnectorApiFailedName[];
  type _Missing = Exclude<ConnectorApiFailedName, (typeof FROZEN_API_FAILED_BRANDS)[number]>;
  const _noneMissing: [_Missing] extends [never] ? true : never = true;
  void _noneMissing;

  test("the set of ErrorNames matching /_api_failed$/ is exactly the frozen 8", () => {
    const actual = Object.keys(ERROR_CODES)
      .filter((name) => /_api_failed$/.test(name))
      .sort();
    expect(
      actual,
      "The *_api_failed brand set is frozen — see the freeze note in errors.ts. " +
        "A new connector reuses the shared generic path (owner gate); it does NOT " +
        "mint another *_api_failed brand. Do not extend this list to make a new " +
        "connector pass — take the freeze to the owner gate first.",
    ).toEqual([...FROZEN_API_FAILED_BRANDS]);
  });
});
