// Audit META-CHANNEL registry — the per-channel forensic metadata interfaces +
// the `AUDIT_META_CHANNELS` serialize table (the registry-driven `serialize`
// dispatch auditEnd loops over). Extracted VERBATIM from audit.ts (the v1.89
// chain WRITER) so the two read-side CLI consumers
// (cli/audit/{suspicious,policy-decisions}.ts) can import the registry WITHOUT
// pulling the chain writer + its per-process mutex/salt state onto the read
// path (the reader -> writer import edge). PURE leaf: zero dependency on the
// chain core (salt / MAC / mutex / fs) — every serialize fn is a pure
// `meta -> Record` transform. Re-exported by ../audit (the barrel), so existing
// `from "../audit"` imports keep working unchanged.

/** v1.16 Phase 2b — Comment-post audit metadata channel for the
 *  youtube_video_comment_post / youtube_comment_reply handlers.
 *
 *  Captured via `ctx.audit.record("commentPostMeta", …)` (with-context.ts; see
 *  ToolContext in types.ts). Threaded into the standard `auditEnd()` JSONL
 *  row — these fields appear on the SAME line as the per-call row, NOT as
 *  a separate event. Mirrors v1.15 Phase 3 `resolved_recipient_hash` shape
 *  (output channel + conditional field emission).
 *
 *  Field semantics (per docs/v1.16-youtube-api.md §7 Phase 2 audit):
 *
 *    target_video_hash — plain SHA-256 (NOT HMAC) hex of args.video_id.
 *      Forensic pivot: "which videos did Claude attempt to post on".
 *      Plain SHA-256 matches the `args_hash` algorithm convention; HMAC is
 *      reserved for the `target_email_hash` family (share_forensic /
 *      recipient_denied_by_policy) where dictionary-attack defense
 *      matters more than algorithm uniformity. Video IDs are 11-char
 *      opaque base64-ish handles — keyspace is large enough that an
 *      unsalted hash is not meaningfully dictionary-attackable.
 *
 *    parent_comment_id_hash — plain SHA-256 hex of args.parent_comment_id
 *      (youtube_comment_reply ONLY). Per-thread forensic pivot — pairs
 *      with `target_video_hash` to correlate replies. ABSENT on
 *      `youtube_video_comment_post` rows (top-level comments have no
 *      parent comment ID).
 *
 *    comment_length — integer length of args.text (NOT bytes; raw
 *      character count). Quota + anti-spam forensic trail. Plaintext
 *      comment text NEVER appears in audit. Forensic question "what did
 *      Claude actually post?" requires inspecting the live YouTube
 *      comment (visible to anyone with the comment URL).
 *
 *    policy_decision — locked enum:
 *      "allowed"                              — all 4 gates passed; SDK call
 *                                               succeeded; counter incremented
 *      "denied_no_allowlist"                  — env var unset/empty (state.kind="off")
 *      "denied_not_in_allowlist"              — target resolved but not in allowlist
 *      "denied_tier"                          — proxy tier gate (defense-in-depth;
 *                                               normally caught by tools/list filter)
 *      "denied_burst_limit"                   — per-session counter exceeded
 *      "denied_outbound_sanitize_rejected"    — outbound sanitize raised
 *
 *  ABSENT (field-not-emitted) when the call is NOT a comment-post tool —
 *  pre-Phase-2b tools never set these and auditEnd skips them. */
export interface CommentPostAuditMeta {
  target_video_hash: string;
  parent_comment_id_hash?: string;
  comment_length: number;
  policy_decision:
    | "allowed"
    | "denied_no_allowlist"
    | "denied_not_in_allowlist"
    | "denied_tier"
    | "denied_burst_limit"
    | "denied_outbound_sanitize_rejected";
}

/** v1.17 Phase 1 — Calendar-mutation audit metadata channel for the
 *  calendar_update_event / calendar_delete_event / calendar_respond handlers.
 *
 *  Captured via `ctx.audit.record("calendarMutationMeta", …)` (with-context.ts; see
 *  ToolContext in types.ts). Threaded into the standard `auditEnd()` JSONL
 *  row — these fields appear on the SAME line as the per-call row, NOT as
 *  a separate event. Mirrors v1.16 Phase 2b `commentPostMeta` shape (output
 *  channel + conditional field emission). Field PRESENCE itself signals
 *  "this is a calendar-mutation call" (mirror v1.15 / v1.16 PRESENCE-as-signal
 *  pattern; see docs/v1.17-deferred-completion.md §5 + §8 hook #7).
 *
 *  Field semantics (per docs/v1.17-deferred-completion.md §5):
 *
 *    target_event_hash — plain SHA-256 (NOT HMAC) hex of args.event_id.
 *      Forensic correlation key across update/delete/respond sessions —
 *      "which event was touched". Plain SHA-256 matches the `args_hash`
 *      algorithm convention; HMAC is reserved for the `target_email_hash`
 *      family where the keyspace is small enough that dictionary attacks
 *      matter. Calendar event IDs are large opaque server-generated
 *      handles — unsalted hash is not meaningfully attackable.
 *
 *    policy_decision — small enum for v1.17 Phase 1 (no allowlist / burst
 *      gates on Calendar mutation):
 *        "allowed"                            — tier+scope passed; SDK call
 *                                               initiated (forensically
 *                                               recorded BEFORE the SDK
 *                                               call per hook #7 — survives
 *                                               SDK 5xx failure)
 *        "denied_tier"                        — proxy tier gate caught a
 *                                               write tool at tier=read
 *                                               (defense-in-depth)
 *        "denied_outbound_sanitize_rejected"  — reserved for future Phase
 *                                               1c+; not emitted in Phase 1
 *
 *    rsvp_response — closed-enum RSVP value passed to calendar_respond.
 *      EMITTED ONLY by calendar_respond (never by calendar_update_event /
 *      calendar_delete_event — those leave it undefined). Closes the
 *      forensic gap identified in PR #138 pre-merge review sec-M1: prior
 *      impl recorded `target_event_hash + policy_decision` but log readers
 *      could NOT tell which RSVP value Claude attempted. Per design §5
 *      this field is part of the calendar_respond audit row. Closed-enum
 *      value (no PII) — same {accepted|declined|tentative|needsAction} set
 *      validated by the handler at the API boundary. ABSENT on update/
 *      delete rows; PRESENCE itself disambiguates "this is a respond row".
 *
 *  ABSENT (field-not-emitted) when the call is NOT a calendar-mutation
 *  tool — pre-v1.17 tools never set this and auditEnd skips it. */
export interface CalendarMutationAuditMeta {
  target_event_hash: string;
  policy_decision:
    | "allowed"
    | "denied_tier"
    | "denied_outbound_sanitize_rejected";
  /** PR #138 sec-M1 — RSVP value for calendar_respond ONLY. Other 2 calendar
   *  mutation tools (update / delete) MUST NOT set this. Closed-enum,
   *  no PII. */
  rsvp_response?: "accepted" | "declined" | "tentative" | "needsAction";
}

/** v1.17 Phase 2 — Docs-modify audit metadata channel for the
 *  docs_modify_structured handler. Captured via `ctx.audit.record("docsModifyMeta", …)`
 *  (with-context.ts; see ToolContext in types.ts). Threaded into the
 *  standard `auditEnd()` JSONL row — these fields appear on the SAME line
 *  as the per-call row, NOT as a separate event. Mirrors v1.16 / v1.17
 *  Phase 1 PRESENCE-as-signal pattern (field presence on the row signals
 *  "this is a docs-modify call"; mutually exclusive with `commentPostMeta`
 *  and `calendarMutationMeta` per call).
 *
 *  Field semantics (per docs/v1.17-deferred-completion.md §5):
 *
 *    target_document_id_hash — plain SHA-256 (NOT HMAC) hex of args.document_id.
 *      Forensic correlation key — "which doc was edited". Plain SHA-256
 *      matches the args_hash algorithm convention; HMAC is reserved for the
 *      target_email_hash family (share_forensic / recipient_denied_by_policy)
 *      where the keyspace is small enough that dictionary attacks matter.
 *      Doc IDs are large opaque server-generated handles — unsalted hash is
 *      not meaningfully attackable.
 *
 *    modification_count — integer (requests.length). Forensic question
 *      "how many requests did Claude batch in this call?".
 *
 *    request_types_csv — comma-joined request type names IN CALLER-SUPPLIED
 *      ORDER (NOT sorted). Order is forensically relevant per design §5 +
 *      F15: "did replaceAllText run before or after deleteContentRange?"
 *      changes what was actually mutated. Sorting would destroy this. Caller
 *      may legitimately have N occurrences of same type — duplicates
 *      preserved.
 *
 *    total_text_replacements — integer (sum of occurrencesChanged across
 *      all replaceAllText requests in the batch, captured from Google's
 *      replies[i].replaceAllText.occurrencesChanged). Forensic question
 *      "did Claude rewrite the whole doc?" answerable from audit alone (no
 *      hard cap; audit visibility IS the defense per design §2.4 + §8 hook
 *      #12). ABSENT when no replaceAllText was in the batch OR when the SDK
 *      call failed before a reply was available (denied_tier rows, SDK 5xx
 *      with no reply body).
 *
 *    policy_decision — small enum for v1.17 Phase 2:
 *      "allowed"                            — tier+per-request gates passed;
 *                                             SDK call initiated (forensically
 *                                             recorded BEFORE the SDK call per
 *                                             hook #7 — survives SDK 5xx)
 *      "denied_tier"                        — proxy tier gate caught a write
 *                                             tool at tier=read (defense-in-depth)
 *      "denied_outbound_sanitize_rejected"  — reserved forward-compat; not
 *                                             emitted in Phase 2 (no outbound
 *                                             sanitize on docs surface today)
 *
 *  ABSENT (field-not-emitted) when the call is NOT docs_modify_structured —
 *  pre-v1.17-Phase-2 tools never set this and auditEnd skips it. */
export interface DocsModifyAuditMeta {
  target_document_id_hash: string;
  modification_count: number;
  request_types_csv: string;
  total_text_replacements?: number;
  policy_decision:
    | "allowed"
    | "denied_tier"
    | "denied_outbound_sanitize_rejected";
}

/** v1.17 Phase 3 — Comment-delete audit metadata channel for the
 *  youtube_comment_delete handler. Captured via `ctx.audit.record("commentDeleteMeta", …)`
 *  (with-context.ts; see ToolContext in types.ts). Threaded into the standard
 *  `auditEnd()` JSONL row — these fields appear on the SAME line as the
 *  per-call row, NOT as a separate event. Mirrors v1.16 / v1.17 Phase 1+2
 *  PRESENCE-as-signal pattern (field presence on the row signals "this is a
 *  comment-DELETE call"; mutually exclusive with `commentPostMeta` /
 *  `calendarMutationMeta` / `docsModifyMeta` per call).
 *
 *  Why a NEW field vs union into `commentPostMeta.policy_decision` (per
 *  design §5 + §8 hook #13): conflating two semantically distinct operations
 *  (post vs delete) into the same `commentPostMeta.policy_decision` enum
 *  would break audit forensic queries (`grep commentPostMeta` for posts vs
 *  `grep commentDeleteMeta` for deletes). PRESENCE-as-signal pattern:
 *  `commentDeleteMeta` PRESENT on a row signals "this is a comment-delete
 *  row", `commentPostMeta` PRESENT signals "this is a comment-post row".
 *  Mutually exclusive per call (enforced via with-context.ts runtime
 *  assertion — see hook B from Phase 3 prompt).
 *
 *  Field semantics (per docs/v1.17-deferred-completion.md §2.5 + §5):
 *
 *    target_comment_id_hash — plain SHA-256 (NOT HMAC) hex of args.comment_id.
 *      Forensic correlation key — "which comment was deleted". Matches v1.16
 *      `target_video_hash` convention (plain SHA-256 on opaque server-generated
 *      IDs; HMAC reserved for the small-keyspace email family).
 *
 *    policy_decision — small enum for v1.17 Phase 3:
 *        "deleted"      — tier+scope passed; SDK call initiated (forensically
 *                         recorded BEFORE the SDK call per hook #7 — survives
 *                         SDK 5xx failure). "deleted" semantically distinguishes
 *                         from `commentPostMeta`'s "allowed" — same channel
 *                         conceptually (gates passed) but different operation.
 *        "denied_tier"  — proxy tier gate caught the write tool at tier=read
 *                         (defense-in-depth; recovery-bypass per §2.5 +
 *                         §8 hook #4 does NOT cover tier — tier is the floor).
 *
 *  ABSENT (field-not-emitted) when the call is NOT youtube_comment_delete —
 *  pre-v1.17-Phase-3 tools never set this and auditEnd skips emission. */
export interface CommentDeleteAuditMeta {
  target_comment_id_hash: string;
  policy_decision: "deleted" | "denied_tier";
}

/** v1.19 Phase 2b — `TasksMutationAuditMeta` for tasks_create / tasks_update /
 *  tasks_delete. Captured via `ctx.audit.record("tasksMutationMeta", …)` (with-context.ts;
 *  see ToolContext in types.ts). Threaded into the standard `auditEnd()` JSONL
 *  row — these fields appear on the SAME line as the per-call row, NOT as a
 *  separate event. Mirrors v1.17 Phase 1+2+3 PRESENCE-as-signal pattern
 *  (field presence on the row signals "this is a tasks mutation call";
 *  mutually exclusive with the other 4 metas per call).
 *
 *  Field semantics (per docs/v1.19-tasks-api.md §6):
 *
 *    target_tasklist_hash — plain SHA-256 (NOT HMAC) hex of args.tasklist_id.
 *      Forensic correlation key — "which task list was touched". Plain SHA-256
 *      matches the args_hash algorithm convention; HMAC is reserved for the
 *      target_email_hash family.
 *
 *      Minor leak ack (sec-L1 from design): tasklist IDs include the sentinel
 *      value "@default" (well-known constant). An audit-log reader can
 *      recognize SHA256("@default") rows, which leaks "user used default
 *      tasklist" — minor signal; acceptable trade-off vs HMAC complexity.
 *      Mirrors v1.16 target_video_hash plain-SHA-256 rationale.
 *
 *    target_task_hash — plain SHA-256 hex of args.task_id. ABSENT on `create`
 *      (no task ID yet) — the field PRESENCE itself signals
 *      "this is an update or delete row, not a create row" at the audit-log
 *      reader layer (in addition to `operation` enum).
 *
 *    operation — closed enum, discriminates the tasks mutation rows:
 *      "create" | "update" | "delete" | "move" | "clear". The first three
 *      are v1.19 Phase 2b; "move"/"clear" are the v1.47 surface-completion
 *      tools (tasks.tasks.move / tasks.tasks.clear), both ABOVE-board
 *      non-permanent ops riding this SAME channel (NOT a new audit channel —
 *      a value-union extension, like the v1.32 forensic field). Only
 *      "delete" drives the v1.18 deletes density alert (`safespace audit
 *      deletes`) — see classifyDestructive 3rd branch; move/clear are NOT
 *      destructive-delete and correctly do not inflate it.
 *
 *    policy_decision — small enum, binary shape matching
 *      calendarMutationMeta / docsModifyMeta:
 *        "allowed"      — tier+scope passed; SDK call initiated (forensically
 *                          recorded BEFORE the SDK call per design §8 hook #7
 *                          — survives SDK 5xx failure)
 *        "denied_tier"  — proxy tier gate caught a write tool at tier=read
 *                          (defense-in-depth)
 *
 *      NOTE (sec-M3 clarification from design §6): `tasks_delete` rows use
 *      `operation === "delete"` (NOT `policy_decision === "deleted"`) to
 *      discriminate delete operations. Intentionally diverges from v1.17
 *      `commentDeleteMeta` (which used policy_decision="deleted" because it
 *      had no dedicated `operation` field). Future channels should follow
 *      the v1.19 pattern (binary policy_decision + separate operation enum).
 *
 *  ABSENT (field-not-emitted) when the call is NOT a tasks mutation tool —
 *  pre-v1.19-Phase-2b tools never set this and auditEnd skips emission. */
export interface TasksMutationAuditMeta {
  target_tasklist_hash: string;
  target_task_hash?: string;
  operation: "create" | "update" | "delete" | "move" | "clear";
  policy_decision: "allowed" | "denied_tier" | "denied_target_not_in_allowlist";
}

/** v1.20 Phase 1b-2 — `SheetsMutationAuditMeta` for sheets_create /
 *  sheets_append_values. Captured via `ctx.audit.record("sheetsMutationMeta", …)`
 *  (with-context.ts; see ToolContext in types.ts). Threaded into the standard
 *  `auditEnd()` JSONL row — these fields appear on the SAME line as the
 *  per-call row, NOT as a separate event. Mirrors v1.17 Phase 1+2+3 / v1.19
 *  Phase 2b PRESENCE-as-signal pattern (field presence on the row signals
 *  "this is a sheets mutation call"; mutually exclusive with the other 5
 *  metas per call).
 *
 *  Field semantics (per docs/v1.20-sheets-api.md §5):
 *
 *    target_spreadsheet_id_hash — plain SHA-256 (NOT HMAC) hex of
 *      args.spreadsheet_id (`sheets_append_values`) OR of the spreadsheet_id
 *      assigned by Google (`sheets_create`, patched in post-SDK).
 *
 *      For `sheets_create` the audit-before-SDK pattern emits a sentinel
 *      `"<pending-create>"` value first (forensic survives 5xx); on SDK
 *      success the recorder is called again with the real ID hash
 *      (last-write-wins via with-context.ts).
 *
 *      Minor leak ack (sec-L1 from design): spreadsheet IDs are ~40-100-char
 *      Drive file IDs; opaque enough that hash-recognition attacks are not
 *      practical. Plain SHA-256 matches the `args_hash` algorithm convention;
 *      HMAC is reserved for `target_email_hash` family. Mirrors v1.16
 *      target_video_hash / v1.19 target_tasklist_hash plain-SHA-256 rationale.
 *
 *    target_range_hash — plain SHA-256 hex of the normalized A1-notation
 *      `range` string. ABSENT on `create` (no range yet). PRESENT on
 *      `append_values` (and Phase 2c update_values / batch_update). Hashing
 *      is over the POST-strict-parse canonical form.
 *
 *    operation — closed enum (Phase 1b-2 ships 2; remaining values reserved
 *      for Phase 2c+):
 *        "create"           — sheets_create
 *        "append_values"    — sheets_append_values
 *        "update_values"    — Phase 2c
 *        "batch_update"     — Phase 2c
 *
 *      Drives nothing today (no sheets delete tool); included for parity
 *      with v1.19 tasksMutationMeta + future audit deletes discriminator.
 *
 *    policy_decision — small enum, binary shape matching
 *      calendarMutationMeta / docsModifyMeta / tasksMutationMeta:
 *        "allowed"      — tier+scope passed; SDK call initiated (forensically
 *                          recorded BEFORE the SDK call per design §5 +
 *                          v1.17 §8 hook #7 / v1.19 §10 hook #11 —
 *                          survives SDK 5xx failure).
 *        "denied_tier"  — proxy tier gate caught a write tool at tier=read
 *                          (defense-in-depth; normally caught by tools/list
 *                          filter).
 *
 *      FORMULA-rejection rows are recorded via -32028 MCPError + thrown
 *      pre-meta; they do NOT set sheetsMutationMeta at all (the read-tier
 *      `value_render_option=FORMULA` rejection happens in sheets_get_values,
 *      which is read tier and never records sheets-mutation meta anyway).
 *
 *  ABSENT (field-not-emitted) when the call is NOT a sheets mutation tool —
 *  pre-v1.20-Phase-1b-2 tools never set this and auditEnd skips emission. */
export interface SheetsMutationAuditMeta {
  target_spreadsheet_id_hash: string;
  target_range_hash?: string;
  operation: "create" | "append_values" | "update_values" | "batch_update";
  /** v1.21 Phase 1b extension — adds `denied_formula_rejected` enum value.
   *  Emitted when `sheets_update_values` or `sheets_batch_update` rejects a
   *  USER_ENTERED cell whose outer function is in the 11-function REJECT
   *  list (`src/sheets/formula-reject.ts`). Forensic correlation key with
   *  the new -32029 MCPError row. */
  policy_decision: "allowed" | "denied_tier" | "denied_formula_rejected";
  /** v1.21 Phase 1b — ONLY for batch_update; CSV of allowed request types
   *  in caller-supplied ORDER (mirror v1.17 docsModifyMeta convention).
   *  Forensically relevant per design §2.2 Order preservation — "did
   *  deleteSheet run before addSheet?" affects which sheetIds were valid
   *  mid-batch. Duplicate types preserved. */
  request_types_csv?: string;
  /** v1.21 Phase 1b — ONLY for batch_update; cumulative cell-write count
   *  across all updateCells + repeatCell requests in the batch. Mirror v1.17
   *  `total_text_replacements` blast-radius pattern. Forensically answerable
   *  "did Claude rewrite the whole sheet?" from audit alone. */
  total_cell_writes?: number;
  /** v1.21 Phase 1b — ONLY when policy_decision === "denied_formula_rejected".
   *  UPPERCASED function name from the closed 11-item REJECT set (e.g.,
   *  "IMPORTRANGE"). Bounded value space — no PII echo concern. Operator-
   *  facing forensic — answers "which function did the offending call try
   *  to invoke". Mirror v1.21 -32029 errorData.rejected_formula_function. */
  rejected_formula_function?: string;
  /** v1.32 Phase 2 — OPTIONAL forensic field. PRESENT only when
   *  policy_decision === "denied_formula_rejected" AND the rejected cell
   *  used non-ASCII source bytes (Default_Ignorable / Bidi / Cyrillic /
   *  Greek) that `applyHomoglyphPipeline` transformed. ABSENT on pure-ASCII
   *  REJECTs — preserves audit row bytes IDENTICAL to v1.31 for the ASCII
   *  attack family (Q3 LOCK fully preserved; PRESENCE-as-signal mirror
   *  v1.24 `error_code?` + v1.20 `target_range_hash?`).
   *
   *  Carries the LITERAL pre-normalize UTF-8 bytes (in input order) that
   *  the homoglyph pipeline rewrote — the dedicated forensic axis that lets
   *  an operator distinguish a user-typo / autocomplete ASCII REJECT (LOW
   *  signal) from a prompt-injection-driven homoglyph smuggle (HIGH signal),
   *  WITHOUT conflating attack-source with the canonical ASCII
   *  `rejected_formula_function` (Q4 LOCK preserves single-token grouping
   *  for `safespace audit suspicious`). Closes v1.30 INFO-2 carry-forward.
   *
   *  Audit log viewers MUST handle Unicode (jq / vim / less are all native
   *  UTF-8). The captured bytes are ONLY the chars `applyHomoglyphPipeline`
   *  transformed — a narrow predefined codepoint set (~44 Cyrillic/Greek
   *  confusers in HOMOGLYPH_MAP + ~79 invisible chars in DEFAULT_IGNORABLE_RE /
   *  BIDI_OVERRIDE_RE) — captured anywhere in the cell (INCLUDING inside a
   *  REJECTED function's quoted arguments, e.g. `=IMPORTRANGE("і","і")` →
   *  "іі"). Arbitrary cell content (ASCII text / numbers / URLs / name+phone
   *  PII) CANNOT reach this field: ASCII hits the pipeline fast-path and
   *  non-homoglyph non-ASCII is passed through untransformed, so neither is
   *  accumulated. Size is bounded by the per-cell 50KB cap. See design §3.6 +
   *  §3.7 (NOTE: §3.7's "identifier chars only" framing is imprecise — the
   *  real bound is the homoglyph-class codepoint set, not the FORMULA_PREFIX_RE
   *  function-name match scope; corrected here per v1.32 Phase 2 sec review M1). */
  rejected_formula_homoglyph_source?: string;
  /** v1.41 — OPTIONAL forensic discriminator. PRESENT (`true`) only when
   *  policy_decision === "denied_formula_rejected" AND the REJECT fired on
   *  the STEP 5 nested/sibling scanner (a wrapper smuggle like
   *  `=SUM(IMPORTRANGE(...))` / `=A1+IMPORTRANGE(...)`) rather than the STEP 4
   *  direct outer-name match. ABSENT on direct attacks — preserves audit row
   *  bytes IDENTICAL to v1.40 for the dominant direct-attack family
   *  (PRESENCE-as-signal, mirror `rejected_formula_homoglyph_source?`).
   *  Literal `true`; its presence is the signal — a bare flag with no payload
   *  and no PII. Serialized AFTER rejected_formula_function and BEFORE
   *  rejected_formula_homoglyph_source (Q3 LOCK forensic order). */
  rejected_formula_nested?: true;
}

/** v1.48 B4 — `PlaylistMutationAuditMeta` for the 3 non-destructive YouTube
 *  playlist WRITE tools (`youtube_playlist_create` / `youtube_playlist_update`
 *  / `youtube_playlist_item_insert`). Captured via
 *  `ctx.audit.record("playlistMutationMeta", …)` (with-context.ts; see ToolContext in
 *  types.ts). Threaded into the standard `auditEnd()` JSONL row — these fields
 *  appear on the SAME line as the per-call row, NOT as a separate event.
 *  Mirrors the v1.19 tasksMutation / v1.20 sheetsMutation PRESENCE-as-signal
 *  pattern (field presence on the row signals "this is a playlist mutation
 *  call"; mutually exclusive with the other 6 metas per call).
 *
 *  Why a NEW channel (not a value-union into an existing one, unlike v1.46/
 *  v1.47): there is no pre-existing YouTube-playlist channel. `commentPostMeta`
 *  is comment-shaped (`target_video_hash` + `comment_length`); reusing it for
 *  playlists would be a semantic mismatch. The 7th channel is the honest shape.
 *
 *  Field semantics (per docs/v1.48-youtube-playlists.md §3):
 *
 *    target_playlist_hash — plain SHA-256 (NOT HMAC) hex. Present on EVERY row:
 *      update / item_insert hash `args.playlist_id`; create uses the
 *      `sheets_create` 2-step (sha256("<pending-create>") BEFORE the SDK call,
 *      then the real `res.data.id` hash AFTER success — Map last-write-wins).
 *      Always-present ⇒ it is the channel `flatHash` for the
 *      `cli/audit/policy-decisions.ts` auto-discovery.
 *
 *    target_video_hash — plain SHA-256 hex of args.video_id. PRESENT ONLY on
 *      `playlist_item_insert`; its PRESENCE discriminates item-insert rows from
 *      create/update rows (in addition to the `operation` enum).
 *
 *    operation — closed enum discriminating the playlist mutation rows:
 *      v1.48 non-destructive: "playlist_create" | "playlist_update" |
 *      "playlist_item_insert". v1.49 destructive slice extends this union with
 *      "playlist_item_remove" (RECOVERABLE — re-insert) + "playlist_delete"
 *      (PERMANENT — no YouTube playlist trash). This is a value-union extension
 *      of the SAME channel (v1.47 tasks move/clear precedent), NOT a new
 *      channel: the serializer emits `operation` generically so it is UNCHANGED
 *      and `AUDIT_META_CHANNELS` stays 7. Only `cli/audit/deletes.ts`
 *      `classifyDestructive` gains a branch — for "playlist_delete" ONLY
 *      (matched via `operation`, NOT `policy_decision`, mirror tasks_delete
 *      sec-M3); "playlist_item_remove" is recoverable so it is deliberately NOT
 *      counted, exactly like tasks_clear / tasks_move.
 *
 *    policy_decision — binary, matching tasksMutation / calendarMutation:
 *        "allowed"     — tier+scope passed; SDK call initiated (recorded BEFORE
 *                         the SDK call so it survives an SDK 5xx).
 *        "denied_tier" — proxy tier gate caught a write tool at tier=read
 *                         (defense-in-depth). */
export interface PlaylistMutationAuditMeta {
  target_playlist_hash: string;
  target_video_hash?: string;
  operation:
    | "playlist_create"
    | "playlist_update"
    | "playlist_item_insert"
    | "playlist_item_remove"
    | "playlist_delete";
  policy_decision: "allowed" | "denied_tier";
}

/** v1.106 — `VideoMutationAuditMeta` for the `youtube_video_update` tool
 *  (videos.update snippet metadata: title / description / tags). Captured via
 *  `ctx.audit.record("videoMutationMeta", …)` (with-context.ts; see ToolContext
 *  in types.ts). Threaded into the standard `auditEnd()` JSONL row — same line
 *  as the per-call row, NOT a separate event. Mirrors the PRESENCE-as-signal
 *  pattern (field presence on the row signals "this is a video-metadata mutation
 *  call"; mutually exclusive with the other 7 metas per call).
 *
 *  Why a NEW (8th) channel, not a value-union into an existing one: there is no
 *  pre-existing video-METADATA-write channel. `commentPostMeta` is comment-shaped
 *  (`target_video_hash` + `comment_length`) and PRESENT signals "comment-post
 *  row"; `playlistMutationMeta` is playlist-shaped (`target_playlist_hash`
 *  always-present). A video-metadata write is video-shaped but neither — the 8th
 *  channel is the honest shape (same reasoning v1.48 added the 7th for playlists).
 *
 *  Field semantics:
 *    target_video_hash — plain SHA-256 (NOT HMAC) hex of args.video_id. Present on
 *      EVERY row ⇒ it is the channel `flatHash` for cli/audit/policy-decisions.ts.
 *    operation — single-value enum "video_update" (the channel's one operation;
 *      a closed enum for forensic-grep symmetry with the playlist/tasks channels).
 *    title_length / description_length / tag_count — non-identifying integers
 *      (NEVER the plaintext title/description/tags); title_length always present,
 *      description_length present only when a description was supplied, tag_count
 *      present only when tags were supplied (PRESENCE mirrors the optional fields).
 *      These are the PRE-sanitize INPUT lengths (the raw-length convention shared by
 *      commentPost/playlist); outboundSanitize REJECTS rather than shortening, so on
 *      the allowed path they match what is sent modulo a rare NFC char-count shift.
 *    policy_decision — "allowed" (tier+scope+target+sanitize passed; recorded
 *      BEFORE the SDK call so it survives an SDK 5xx) | "denied_tier" (proxy tier
 *      gate caught a write tool at tier=read, defense-in-depth) |
 *      "denied_outbound_sanitize_rejected" (a field failed the 6-step REJECT).
 *      The target-allowlist + F3a denials throw an MCPError (-32052 / -32035) and
 *      are captured via the row's errorCode (github-write model), NOT here. */
export interface VideoMutationAuditMeta {
  target_video_hash: string;
  operation: "video_update";
  title_length: number;
  description_length?: number;
  tag_count?: number;
  policy_decision:
    | "allowed"
    | "denied_tier"
    | "denied_outbound_sanitize_rejected";
}

/** v1.18 Phase 1 — centralized registry for the audit-meta channels.
 *
 *  Maps the `AuditEndContext` field name (the "ctx-side key") to its
 *  per-channel metadata: the short channel label used in mutual-exclusion
 *  warnings + the flattened-row hash field name used by `cli/audit/
 *  policy-decisions.ts` to discriminate flattened audit rows.
 *
 *  v1.19 Phase 2b refactor (sec-L4 drift class closure): registry value
 *  expanded from bare `string` to `{label, flatHash}` so the flattened-row
 *  detector in `policy-decisions.ts` becomes fully registry-driven. Adding
 *  a 6th channel auto-extends both branches without hand-edit drift.
 *
 *  Sentinel test (`audit.test.ts`) pins length === 6 (was 5 pre-v1.20, was
 *  4 pre-v1.19). Adding a 7th channel forces re-acknowledgment at FOUR call
 *  sites — ALL FOUR now TypeScript-enforced as of v1.25 Phase 2:
 *    1. add the entry here (TypeScript-enforced via `satisfies Record<…>`),
 *    2. add the corresponding key to the `localMetas` object in
 *       `with-context.ts`'s finally block (TypeScript enforces this via
 *       `Record<keyof typeof AUDIT_META_CHANNELS, unknown>`),
 *    3. add the optional field to `AuditEndContext` + the recorder helper
 *       on `ToolContext`,
 *    4. v1.25 Phase 2 Item 2 — site 4 is now TypeScript-enforced: declare
 *       a `serialize: (meta) => Record<string, unknown>` on the registry
 *       entry; the satisfies clause requires it. `auditEnd()` iterates
 *       AUDIT_META_CHANNELS and dispatches automatically. Closes v1.19
 *       NEW-3 PERMANENTLY at compile time. Belt-and-braces regression net
 *       (v1.22 audit roundtrip tests; Q3 LOCKED v1.25 §2.2) stays UNTOUCHED.
 *  See docs/v1.18-operational-quality.md §2.3 + sec-rev hook #8 +
 *  docs/v1.19-tasks-api.md §6 + docs/v1.25-multi-item-batch.md §2.2. */
/** v1.24 Phase 1 — per-channel suspicious-decision classification (Item 1).
 *  Locked Q2 Option A — nested-object per-channel value shape.
 *
 *  Each channel declares which of its `policy_decision` enum values map to
 *  the suspicious-track confidence buckets in `cli/audit/suspicious.ts`:
 *
 *    - high              — HIGH-confidence direct REJECT signals; on by default
 *    - medium_allowlist  — MEDIUM allowlist denials; opt-in
 *    - medium_burst      — MEDIUM burst-limit denials; opt-in
 *    - low_tier          — LOW tier denials; opt-in
 *
 *  Adding a new audit-meta channel OR a new `policy_decision` value to an
 *  existing channel is the SAME edit site — extend the channel's
 *  `suspiciousDecisions` here, and `cli/audit/suspicious.ts` classifier
 *  picks it up automatically (closes the 4th hardcoded-enum drift site
 *  flagged at v1.23 Q5 LOCKED). Error-code class signals (scope_mismatch
 *  / recipient_lookup_failed / *_burst_limit_exceeded) STAY hardcoded in
 *  suspicious.ts — they are top-level MCPError codes, NOT per-channel
 *  `policy_decision` values. */
export type SuspiciousClassification = {
  high?: ReadonlyArray<string>;
  medium_allowlist?: ReadonlyArray<string>;
  medium_burst?: ReadonlyArray<string>;
  low_tier?: ReadonlyArray<string>;
};

/** v1.27 Phase 1 Item 3 (NEW-11) — phantom-typed registry-key ↔ meta-type
 *  pairing. Single source of truth: each KEY MUST match a channel name in
 *  `AUDIT_META_CHANNELS`, each VALUE is that channel's concrete meta
 *  interface. Order matches `AUDIT_META_CHANNELS` declaration order for
 *  symmetry.
 *
 *  Strengthens v1.25 Phase 2's `SerializeFn = (meta: unknown) → …` typing
 *  (which left the registry-key ↔ meta-type pairing as a code-review
 *  convention) into a compile-time invariant via the mapped-type
 *  satisfies clause on `AUDIT_META_CHANNELS` (see below).
 *
 *  Closes v1.25 Phase 2 dual-review security DEFER-1 observation: prior
 *  shape required hand-cast `meta as ConcreteAuditMeta` in each
 *  serialize fn body — a copy-paste cross-key error (e.g., a serialize
 *  body for `commentPostMeta` accidentally written against
 *  `CalendarMutationAuditMeta`) compiled silently and produced malformed
 *  audit rows at runtime, surfaced only via field probe (or never if the
 *  channel path was untested).
 *
 *  Adding a 7th channel:
 *    1. add the entry to `AUDIT_META_CHANNELS`
 *    2. add the corresponding `MetaMap` entry (TypeScript-enforced —
 *       missing → "Property 'xMeta' is missing in type 'MetaMap'")
 *    3. typing the serialize fn parameter with a different channel's
 *       meta interface fails compile ("Type '(meta: WrongMeta) → …' is
 *       not assignable to type 'SerializeFn<MetaMap["xMeta"]>'") */
export interface MetaMap {
  commentPostMeta: CommentPostAuditMeta;
  calendarMutationMeta: CalendarMutationAuditMeta;
  docsModifyMeta: DocsModifyAuditMeta;
  commentDeleteMeta: CommentDeleteAuditMeta;
  tasksMutationMeta: TasksMutationAuditMeta;
  sheetsMutationMeta: SheetsMutationAuditMeta;
  playlistMutationMeta: PlaylistMutationAuditMeta;
  videoMutationMeta: VideoMutationAuditMeta;
}

/** v1.25 Phase 2 Item 2 — per-channel `serialize` function type. Pure
 *  mapping from meta-input to JSONL-output field record (Q2 LOCKED:
 *  pure-return vs mutation). Each channel implements its own
 *  serialize fn; `auditEnd` iterates the registry and `Object.assign`s
 *  the result into the row payload. Closes v1.19 NEW-3 "manual 4th
 *  site" drift class PERMANENTLY at the TypeScript-enforced level —
 *  the satisfies clause requires every channel to declare `serialize`,
 *  so adding a 7th channel without a serialize fn fails compile.
 *
 *  Belt-and-braces layer: v1.22 audit roundtrip tests stay UNCHANGED
 *  as a regression net (Q3 LOCKED). Layer 1 (this satisfies clause)
 *  enforces site 4 EXISTS; Layer 2 (roundtrip tests) enforces site 4
 *  EMITS THE RIGHT FIELDS for every channel's MAX + MIN field-set.
 *
 *  v1.27 Phase 1 Item 3 (NEW-11) — parameterized over the meta type `M`
 *  (was `SerializeFn = (meta: unknown) => …` in v1.25 Phase 2). Combined
 *  with the `{[K in keyof MetaMap]: {…serialize: SerializeFn<MetaMap[K]>}}`
 *  mapped-type satisfies clause on AUDIT_META_CHANNELS, this strengthens
 *  registry-key ↔ meta-type pairing from a code-review convention to a
 *  COMPILE-TIME invariant. Each per-channel impl is INTENTIONALLY left
 *  with parameter type `unknown` (+ inline `const m = meta as
 *  ConcreteAuditMeta` cast) to preserve Q3 LOCK regression-net
 *  compatibility: `(meta: unknown) => R` is contravariantly assignable to
 *  the narrow expected `(meta: MetaMap[K]) => R`, but a WRONG-narrow
 *  copy-paste like `(meta: CalendarMutationAuditMeta) => R` under the
 *  `commentPostMeta` key fails the satisfies clause. The compile-time
 *  contract works without changing function bodies or the auditEnd
 *  dispatch loop. */
// v1.28 Phase 1 Item 4 (NEW-6) — SerializeFn<M> parameterization convention:
// Parameterized on the META type directly via `<M>` (NOT on the registry
// KEY `<K extends keyof MetaMap>`). The v1.27 design doc §2.3 lines 387-389
// specified `SerializeFn<K extends keyof MetaMap> = (meta: MetaMap[K]) => R`
// (KEY-parameterized form). Shipped form `SerializeFn<M> = (meta: M) => R`
// (META-parameterized form) is PHANTOM-TYPE EQUIVALENT to design at the
// satisfies clause expansion below — both expand to
// `(meta: MetaMap[K]) => Record<string, unknown>` for each channel entry
// via mapped-type substitution:
//   - design <K>:    SerializeFn<K>             with K = "commentPostMeta"
//                    → (meta: MetaMap["commentPostMeta"]) => R
//                    = (meta: CommentPostAuditMeta) => R
//   - shipped <M>:   SerializeFn<MetaMap["commentPostMeta"]>
//                    → (meta: CommentPostAuditMeta) => R
//
// META-parameterized form chosen because:
//   - The function signature itself doesn't reference MetaMap — the
//     meta-type is the natural function parameter.
//   - `<K>` would require every per-channel impl reference to use
//     `SerializeFn<"commentPostMeta">` (key-based), coupling function-type
//     references to registry string literals.
//   - Mapped-type expansion on the satisfies clause does all the heavy
//     lifting regardless of the parameterization choice.
//
// Anchor for future extensions (e.g., async variant): an async SerializeFn
// would mirror the <M> shape as
//   `type AsyncSerializeFn<M> = (meta: M) => Promise<Record<string, unknown>>`
// — same satisfies-clause expansion holds. Future v1.29+ extension MUST
// preserve META-form so the composable async variant stays clean (a
// KEY-parameterized async variant would conflate type parameters).
//
// `audit.metamap-sentinel.test.ts` carries the runtime sentinel + the
// `SerializeFn<MetaMap["commentPostMeta"]>` probe assignment that pins
// the type-alias surface so a future PR cannot silently flatten
// `SerializeFn` back to non-generic.
export type SerializeFn<M> = (meta: M) => Record<string, unknown>;

export const AUDIT_META_CHANNELS = {
  commentPostMeta: {
    label: "commentPost",
    flatHash: "target_video_hash",
    // v1.24 Phase 1 Item 1 — commentPost canary classifications.
    suspiciousDecisions: {
      high: ["denied_outbound_sanitize_rejected"],
      medium_allowlist: ["denied_no_allowlist", "denied_not_in_allowlist"],
      medium_burst: ["denied_burst_limit"],
      low_tier: ["denied_tier"],
    },
    // v1.25 Phase 2 Item 2 — serialize maps CommentPostAuditMeta → JSONL
    // row fields. Field ORDER mirrors the v1.24 manual write block (lines
    // 880-888) for byte-stability across the refactor. parent_comment_id_hash
    // is conditional (ABSENT on top-level post; PRESENT on reply).
    //
    // v1.27 Phase 1 Item 3 — `meta: unknown` parameter signature INTENTIONALLY
    // RETAINED for Q3 LOCK regression-net compatibility (per-channel narrow
    // params would collapse to an intersection under `Object.entries` iteration
    // and break `audit.serialize-refactor.test.ts`'s `entry.serialize(unknown)`
    // call pattern). The channel-key ↔ meta-type pairing IS enforced at the
    // SATISFIES CLAUSE LEVEL via `SerializeFn<MetaMap["commentPostMeta"]>` —
    // TypeScript contravariance accepts the WIDE `(meta: unknown) => R` impl
    // as assignable to the NARROW expected `(meta: CommentPostAuditMeta) => R`,
    // BUT a WRONG-NARROW impl (e.g., copy-pasted `(meta: CalendarMutationAuditMeta)`
    // under this `commentPostMeta` key) FAILS the satisfies clause cleanly.
    // Drift surface closed at the registry declaration without churning the
    // function body.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as CommentPostAuditMeta;
      const out: Record<string, unknown> = {
        target_video_hash: m.target_video_hash,
        comment_length: m.comment_length,
        policy_decision: m.policy_decision,
      };
      if (m.parent_comment_id_hash !== undefined) {
        out.parent_comment_id_hash = m.parent_comment_id_hash;
      }
      return out;
    },
  },
  calendarMutationMeta: {
    label: "calendarMutation",
    flatHash: "target_event_hash",
    suspiciousDecisions: { low_tier: ["denied_tier"] },
    // v1.25 Phase 2 Item 2 — serialize maps CalendarMutationAuditMeta. Field
    // ORDER mirrors v1.24 manual write block (lines 896-906). rsvp_response
    // is ONLY set by calendar_respond (ABSENT on update/delete rows).
    // v1.27 Phase 1 Item 3 — `meta: unknown` retained per Q3 LOCK rationale
    // documented on `commentPostMeta.serialize`; satisfies clause enforces
    // channel-key ↔ meta-type pairing at the registry declaration level.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as CalendarMutationAuditMeta;
      const out: Record<string, unknown> = {
        target_event_hash: m.target_event_hash,
        policy_decision: m.policy_decision,
      };
      if (m.rsvp_response !== undefined) {
        out.rsvp_response = m.rsvp_response;
      }
      return out;
    },
  },
  docsModifyMeta: {
    label: "docsModify",
    flatHash: "target_document_id_hash",
    suspiciousDecisions: { low_tier: ["denied_tier"] },
    // v1.25 Phase 2 Item 2 — serialize maps DocsModifyAuditMeta. Field ORDER
    // mirrors v1.24 manual write block (lines 917-931). total_text_replacements
    // is ABSENT when no replaceAllText was in the batch OR when SDK failed
    // before a reply was available.
    // v1.27 Phase 1 Item 3 — `meta: unknown` retained per Q3 LOCK rationale
    // documented on `commentPostMeta.serialize`.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as DocsModifyAuditMeta;
      const out: Record<string, unknown> = {
        target_document_id_hash: m.target_document_id_hash,
        modification_count: m.modification_count,
        request_types_csv: m.request_types_csv,
        policy_decision: m.policy_decision,
      };
      if (m.total_text_replacements !== undefined) {
        out.total_text_replacements = m.total_text_replacements;
      }
      return out;
    },
  },
  commentDeleteMeta: {
    label: "commentDelete",
    flatHash: "target_comment_id_hash",
    suspiciousDecisions: { low_tier: ["denied_tier"] },
    // v1.25 Phase 2 Item 2 — serialize maps CommentDeleteAuditMeta. Field
    // ORDER mirrors v1.24 manual write block (lines 940-944).
    // v1.27 Phase 1 Item 3 — `meta: unknown` retained per Q3 LOCK rationale
    // documented on `commentPostMeta.serialize`.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as CommentDeleteAuditMeta;
      return {
        target_comment_id_hash: m.target_comment_id_hash,
        policy_decision: m.policy_decision,
      };
    },
  },
  // v1.19 Phase 2b — 5th channel. flatHash = "target_tasklist_hash" (present
  // on ALL 3 tasks mutation rows — create / update / delete; target_task_hash
  // is ABSENT on create rows so it would not be a reliable discriminator).
  tasksMutationMeta: {
    label: "tasksMutation",
    flatHash: "target_tasklist_hash",
    suspiciousDecisions: { low_tier: ["denied_tier"] },
    // v1.25 Phase 2 Item 2 — serialize maps TasksMutationAuditMeta. Field
    // ORDER mirrors v1.24 manual write block (lines 961-972). target_task_hash
    // is ABSENT on `create` rows (no task ID yet at create time).
    // v1.27 Phase 1 Item 3 — `meta: unknown` retained per Q3 LOCK rationale
    // documented on `commentPostMeta.serialize`.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as TasksMutationAuditMeta;
      const out: Record<string, unknown> = {
        target_tasklist_hash: m.target_tasklist_hash,
        operation: m.operation,
        policy_decision: m.policy_decision,
      };
      if (m.target_task_hash !== undefined) {
        out.target_task_hash = m.target_task_hash;
      }
      return out;
    },
  },
  // v1.20 Phase 1b-2 — 6th channel. flatHash = "target_spreadsheet_id_hash"
  // (present on ALL sheets mutation rows — create / append_values; the future
  // Phase 2c update_values / batch_update will also carry it).
  // target_range_hash is ABSENT on create rows so it would NOT be a reliable
  // discriminator. FIRST production test of v1.19 path-(b) registry refactor
  // — `cli/audit/policy-decisions.ts` auto-discovers this channel via
  // `entry.flatHash` with ZERO code edit at the policy-decisions site.
  sheetsMutationMeta: {
    label: "sheetsMutation",
    flatHash: "target_spreadsheet_id_hash",
    // v1.24 Phase 1 Item 1 — sheets denied_formula_rejected is the FIRST
    // HIGH-confidence canary outside commentPost (v1.21 introduced; v1.23
    // suspicious.ts hardcoded it; v1.24 moves it to the registry).
    suspiciousDecisions: {
      high: ["denied_formula_rejected"],
      low_tier: ["denied_tier"],
    },
    // v1.25 Phase 2 Item 2 — serialize maps SheetsMutationAuditMeta. Field
    // ORDER mirrors v1.24 manual write block. All 5 optional fields are
    // ABSENT on the relevant non-applicable rows per the v1.21 + v1.20 +
    // v1.32 conditional emission contract:
    //   target_range_hash                — ABSENT on `create` rows.
    //   request_types_csv                — ONLY on `batch_update` rows.
    //   total_cell_writes                — ONLY on `batch_update` rows that
    //                                      touched cells via updateCells /
    //                                      repeatCell.
    //   rejected_formula_function        — ONLY when policy_decision ===
    //                                      "denied_formula_rejected".
    //   rejected_formula_homoglyph_source — v1.32 Phase 2; ONLY when a
    //                                      denied_formula_rejected row's cell
    //                                      used non-ASCII (homoglyph / bidi /
    //                                      Default_Ignorable) source bytes.
    //                                      PRESENCE-as-signal — ABSENT on
    //                                      ASCII REJECTs (Q3 LOCK byte-stable).
    // v1.27 Phase 1 Item 3 — `meta: unknown` retained per Q3 LOCK rationale
    // documented on `commentPostMeta.serialize`.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as SheetsMutationAuditMeta;
      const out: Record<string, unknown> = {
        target_spreadsheet_id_hash: m.target_spreadsheet_id_hash,
        operation: m.operation,
        policy_decision: m.policy_decision,
      };
      if (m.target_range_hash !== undefined) {
        out.target_range_hash = m.target_range_hash;
      }
      if (m.request_types_csv !== undefined) {
        out.request_types_csv = m.request_types_csv;
      }
      if (m.total_cell_writes !== undefined) {
        out.total_cell_writes = m.total_cell_writes;
      }
      if (m.rejected_formula_function !== undefined) {
        out.rejected_formula_function = m.rejected_formula_function;
      }
      // v1.41 — emit the nested-smuggle discriminator AFTER
      // rejected_formula_function and BEFORE rejected_formula_homoglyph_source
      // (Q3 LOCK forensic order: function → nested → homoglyph). PRESENCE-as-
      // signal: ABSENT on direct STEP 4 attacks → audit row bytes stay
      // IDENTICAL to v1.40 for the direct-attack family. ORDER pinned by the
      // Category I serialize sentinel (formula-reject.integration).
      if (m.rejected_formula_nested !== undefined) {
        out.rejected_formula_nested = m.rejected_formula_nested;
      }
      // v1.32 Phase 2 — emit the forensic homoglyph-source bytes AFTER
      // rejected_formula_function for forensic visual locality (auditor reads
      // the canonical function name THEN the original transformed bytes).
      // PRESENCE-as-signal: ABSENT on pure-ASCII REJECTs → audit row bytes
      // stay IDENTICAL to v1.31 for the ASCII attack family (Q3 LOCK). ORDER
      // pinned by the Category I serialize sentinel (formula-reject.integration).
      if (m.rejected_formula_homoglyph_source !== undefined) {
        out.rejected_formula_homoglyph_source =
          m.rejected_formula_homoglyph_source;
      }
      return out;
    },
  },
  // v1.48 B4 — 7th channel. flatHash = "target_playlist_hash" (present on ALL
  // playlist mutation rows — create uses the sheets_create 2-step sentinel→real
  // so the field is reliable on create too; target_video_hash is ABSENT on
  // create/update so it would NOT be a reliable discriminator). The
  // policy-decisions + suspicious CLIs auto-discover this channel via
  // entry.flatHash / entry.suspiciousDecisions — ZERO CLI code edit.
  playlistMutationMeta: {
    label: "playlistMutation",
    flatHash: "target_playlist_hash",
    suspiciousDecisions: { low_tier: ["denied_tier"] },
    // v1.48 — serialize maps PlaylistMutationAuditMeta. Field ORDER:
    // target_playlist_hash → operation → policy_decision → target_video_hash
    // (optional, ONLY on playlist_item_insert). `meta: unknown` retained per
    // the Q3 LOCK rationale documented on `commentPostMeta.serialize`.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as PlaylistMutationAuditMeta;
      const out: Record<string, unknown> = {
        target_playlist_hash: m.target_playlist_hash,
        operation: m.operation,
        policy_decision: m.policy_decision,
      };
      if (m.target_video_hash !== undefined) {
        out.target_video_hash = m.target_video_hash;
      }
      return out;
    },
  },
  videoMutationMeta: {
    label: "videoMutation",
    flatHash: "target_video_hash",
    // canary: only `low_tier` is declared here. `denied_outbound_sanitize_rejected`
    // is a HIGH canary, but it is matched channel-AGNOSTICALLY by suspicious.ts's
    // flattened `pdTop === "denied_outbound_sanitize_rejected"` branch (so a
    // video_update reject is still counted) — re-declaring it in `high` would
    // DOUBLE-COUNT, because collectByBucket("high") (unlike low_tier) is not
    // Set-deduped. `denied_tier` IS deduped, so declaring it is safe + correct
    // (mirrors the playlistMutation channel, which also declares only low_tier).
    suspiciousDecisions: {
      low_tier: ["denied_tier"],
    },
    // v1.106 — serialize maps VideoMutationAuditMeta. Field ORDER:
    // target_video_hash → operation → title_length → policy_decision, then the
    // two optional length fields (description_length / tag_count) when present.
    // `meta: unknown` retained per the Q3 LOCK rationale on commentPostMeta.serialize.
    serialize: (meta: unknown): Record<string, unknown> => {
      const m = meta as VideoMutationAuditMeta;
      const out: Record<string, unknown> = {
        target_video_hash: m.target_video_hash,
        operation: m.operation,
        title_length: m.title_length,
        policy_decision: m.policy_decision,
      };
      if (m.description_length !== undefined) {
        out.description_length = m.description_length;
      }
      if (m.tag_count !== undefined) {
        out.tag_count = m.tag_count;
      }
      return out;
    },
  },
  // v1.27 Phase 1 Item 3 (NEW-11) — `satisfies` clause switched from
  // `Record<string, {…serialize: SerializeFn}>` to a MAPPED TYPE
  // `{[K in keyof MetaMap]: {…serialize: SerializeFn<MetaMap[K]>}}`. This
  // projects EACH registry key K to a unique entry shape where the
  // serialize function's parameter type is `MetaMap[K]`. Net effect:
  // registry-key ↔ meta-type pairing is now a compile-time invariant.
  //
  // Failure modes the mapped-type catches at compile:
  //   - adding a 7th channel `xMeta` to AUDIT_META_CHANNELS without
  //     extending MetaMap → "Property 'xMeta' is missing in type
  //     'MetaMap'" (because the satisfies expected type has an exact
  //     `[K in keyof MetaMap]` index set)
  //   - typing serialize with the wrong channel's meta interface (e.g.
  //     copy-pasted `(meta: CalendarMutationAuditMeta) => …` under the
  //     `commentPostMeta` key) → "Type '(meta: CalendarMutationAuditMeta)
  //     => …' is not assignable to type
  //     'SerializeFn<MetaMap[\"commentPostMeta\"]>'" (narrow params
  //     incompatible under contravariance check)
  //
  // Closes v1.25 Phase 2 dual-review DEFER-1 security observation +
  // LOW-2 code review observation. Q3 LOCK regression net preserved:
  // per-channel impls retain `(meta: unknown)` + inline `as` cast (their
  // wider param signature is contravariantly assignable to the narrow
  // expected `SerializeFn<MetaMap[K]>`), so function BODIES stay
  // byte-identical and the v1.22/v1.24/v1.25 regression tests pass
  // UNCHANGED.
} as const satisfies {
  [K in keyof MetaMap]: {
    label: string;
    flatHash: string;
    suspiciousDecisions?: SuspiciousClassification;
    // v1.25 Phase 2 Item 2 — REQUIRED on every channel. The satisfies clause
    // enforces presence at compile time: omitting `serialize` from a new
    // channel fails TypeScript. Closes v1.19 NEW-3 manual 4th site PERMANENTLY.
    //
    // v1.27 Phase 1 Item 3 (NEW-11) — parameterized over `MetaMap[K]` via
    // arrow-property syntax. TypeScript contravariance accepts a WIDE
    // `(meta: unknown) => R` impl as assignable to NARROW
    // `SerializeFn<MetaMap[K]> = (meta: MetaMap[K]) => R` — which is why
    // the per-channel impl signatures stay `(meta: unknown)` for Q3 LOCK
    // regression-net compatibility (the v1.25 Phase 2
    // `audit.serialize-refactor.test.ts` iterates the registry and calls
    // `entry.serialize(unknown)`; narrow impl params would collapse to an
    // INTERSECTION under iteration and break the test).
    //
    // The contract is still tightened from convention to compile-time
    // invariant: a future PR that types a serialize fn with the WRONG
    // narrow meta interface (e.g., copy-pasted
    // `(meta: CalendarMutationAuditMeta) => R` under the `commentPostMeta`
    // key) FAILS the satisfies clause — `(meta: CalendarMutationAuditMeta)
    // => R` is NOT assignable to `SerializeFn<MetaMap["commentPostMeta"]>
    // = (meta: CommentPostAuditMeta) => R` (incompatible parameter types).
    // Wrong-cross-key drift surface closed at the registry declaration.
    serialize: SerializeFn<MetaMap[K]>;
  };
};
