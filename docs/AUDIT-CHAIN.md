# Tamper-evident audit hash-chain (v1.89)

SafeSpace's `audit.jsonl` is the forensic record of everything that went *through*
the gate (`run_id` session grouping, per-call metadata, policy decisions). A flat
append-only log answers "what did SafeSpace do" — but a log an attacker can quietly
edit is only as trustworthy as the box it sits on. The hash-chain makes **tampering
with past rows detectable**.

## How it works

Every audit row carries one extra field, `row_mac`:

```
row_mac = HMAC-SHA256(audit-salt, prev_mac ‖ "\n" ‖ canonicalJson(row-without-row_mac))
```

- **`canonicalJson`** sorts object keys recursively, so the MAC reproduces at verify
  time regardless of JSON key order.
- **`prev_mac`** is the previous row's `row_mac` (the first chained row uses a fixed
  genesis seed). Because each MAC folds in the previous one, editing, deleting,
  inserting, or reordering *any* past row changes every MAC after it — a break the
  verifier pins to the first offending row.
- **`audit-salt`** is the per-install 32-byte secret (`~/.config/safespace/audit-salt`,
  mode `0600`) — the same key already used to HMAC email hashes. It lives **outside**
  `audit.jsonl`.

Writes are serialized through a per-process mutex (the chain needs each row to fold in
the previous row's MAC), and the running tip is continued across restarts by reading
the file's last `row_mac`.

## Verifying

```
safespace audit verify           # walks the whole chain, prints INTACT + the tip MAC
safespace audit verify --json    # {ok, chainedRows, legacyRows, unchainedEventRows, tipMac, brokenAt, reason[, strictLanded][, cli]}
```

Exit code is `0` when intact, `1` when broken (so cron/CI can gate on it). A broken
chain reports the **first** offending row index and whether it was an edit/delete
(`mac_mismatch`) or an unhashed row inserted (`unhashed_in_strict_chain`, or
`unhashed_after_chain` in the tolerant part of an older chain).

**Strict and older chains.** A fresh `audit.jsonl` chains from the strict genesis
(`safespace-audit-chain/genesis/v2`): every line must be a chained row. A chain begun
before strict chains (genesis `…/v1`) keeps its old rules — rows written *before* the
chain have no `row_mac` and are a tolerated prefix, and unchained rows with an `event`
field (older CLI approve/deny rows) are tolerated — until its first chained
`audit_chain_strict` row. The server writes that marker once, before its first row, into
any v1 chain that lacks one; from it on the chain is strict. Only a chained, verified
marker counts, and it is never the last row (a row always follows it), so deleting it
breaks the chain.

**The commitment beside the salt.** The log alone cannot prove it was ever strict:
stripped of every `row_mac`, emptied, or cut back, it would read as a pre-chain prefix or a
fresh log. So every strict chain has one committed row, recorded in `audit-chain.json` next
to `audit-salt` BEFORE that row is appended: the first row of a fresh log (chained from the
v2 genesis), or the marker row of an upgraded one. The file holds the chain kind (`v2` or
`v1`), that row's MAC, the row itself and its predecessor. It is written whole to a synced
temp file and published with a link that never replaces an existing file, so it is created
once and never overwritten; the server never commits or writes a second marker while it
exists. `verify` requires the committed row in the log (and, for `v2`, a v2 chain with
every line chained); otherwise the result is `strict_commitment_broken` — rows stripped,
the log emptied, cut back past that row or replaced, or the commitment unreadable or
altered (its recorded row and predecessor must reproduce its MAC, and the row must follow
that predecessor in the log). If the committed row's append failed, the next write (or
start) re-appends that exact row (same MAC), but only while the log still ends exactly
where the row was to go (the same rows after that point as when it was committed) and only
until
`audit-chain.json.landed` records that the row reached the log — so once it is recorded, a
log emptied, cut back or rewritten later cannot get it back. That record is written only after the log
is synced; a start that finds the committed row without it writes it; a failure to write
it is logged and retried by every later write, and never stops audit rows. Files are
published whole (synced temp file, then a non-replacing link, or on a filesystem without
hard links a rename after checking the target is absent) and the directory synced. After any failed append the next write
re-walks the log, so it continues from the file's real tip. The salt's location is trusted, and both
files live there. To rotate `audit.jsonl`, move `audit-chain.json` and
`audit-chain.json.landed` with it; a fresh log then starts a new commitment.

**Two chains, one writer each.** `audit.jsonl` is the **server's** chain: every
`auditEnd` row and every forensic / policy row the stdio server writes (share /
share-denied, recipient-denied, the cross-account aggregate, supervised-send `pending` /
`consumed`). `audit-cli.jsonl` is the chain of rows written by **`safespace` CLI
processes**: every row of a `safespace exec` call and the owner's `send approve` / `deny`.
A process writes only its own file, so a server and an `exec` running at the same time no
longer fork a chain. The CLI chain starts from its own genesis label, so a CLI file copied
over `audit.jsonl` (or the two swapped) breaks at row 1.

**Anchors.** On its first chained write, each server process seals the CLI chain's
verified tip into `audit.jsonl` as a chained `cli_chain_anchor` row. `verify` checks that
every anchor's MAC is still present in the verified CLI chain, so deleting, emptying or
cutting `audit-cli.jsonl` after a server start is reported (`cli_anchor_missing`). Do not
delete or rotate `audit-cli.jsonl`: it fails that check. While the CLI file's last line is
unfinished (or the file cannot be read) the server seals the verified prefix at once and
retries — a bounded number of times — to seal the completed row (a file that cannot be
read at all stays due until it can); a CLI file in which
nothing verifies is not anchored (the strict walk already fails verify while that content
is there).

Both writers resume from the tip of their chain traced forward from the genesis. Walking
the whole file (streamed), a writer adopts a row only when its `row_mac` authenticates
against the tip so far. A CLI process does this for `audit-cli.jsonl` at its first write,
and the server does it for `audit.jsonl` when it restarts. Every other line is skipped: a
forged `{"row_mac": …}`, a replayed older row, junk, a crashed partial write, an unchained
legacy row, the losing row of a fork. A valid row missing only its newline is resumed
from, and a writer starts its row on a new line if the file ends mid-line. So nothing in
the file can pick the resume point, and removing the one bad line repairs the chain. An
unchained row is skipped like any other: in a strict chain `verify` reports it (so a tail
row stripped of its MAC and edited still breaks verify), and an older log ending in an
unchained approve/deny row resumes cleanly. The writers and every audit reader (`verify` included) split lines with one shared
splitter: a line ends at "\r\n", "\n" or a lone "\r" (never at U+2028 / U+2029, which some
runtimes' `readline` treats as line ends but JSON leaves raw in strings), and is parsed at
any length, so they always see the same rows on any runtime. A writer, like `verify`,
holds one line in memory at a time, so a huge planted line costs that much memory
(time stays linear: about 0.1 s per 128 MiB line measured). If a file cannot be read to its end (any error but a missing file), the writer
drops that row with an error on stderr and retries the walk on its next write, rather
than linking a row to a tip short of the real end.
Cost: each server start reads `audit.jsonl` and `audit-cli.jsonl` once, and each CLI
process reads `audit-cli.jsonl` once (about 0.2 s per 100 MB measured), so that work grows
with the files.
Anchor rows count as rows in `audit stats` / `sessions` / `status` line counts.

`verify` walks `audit.jsonl` by the rules above (strict, or an older chain's tolerance up
to its marker) and walks
`audit-cli.jsonl` STRICTLY — every line must be a JSON object with a valid `row_mac`, and
a final line without a newline fails (`incomplete_tail`). The top-level result, the INTACT
banner and the exit code cover both chains and the anchors. With no `audit-cli.jsonl` and
no anchor, the output is exactly what it was. Text mode prints both tips.

## Threat model — what it does and does NOT defend (be honest)

**Detects** (because the MAC is keyed by the salt): edit / delete / insert / reorder
of past rows by anyone who can read or modify `audit.jsonl` but **cannot read the
salt** — a backup leak, a log-shipping pipeline, a lower-privileged user, an offline
disk image. This is the same limited-access / offline-capture threat model as F6
token-at-rest hardening.

**Does NOT defend against:**

- **A same-host attacker who can read the salt.** With the key they can recompute the
  whole chain forward from a tampered point. The chain raises the bar against
  *offline / limited-access* tampering, not a fully-compromised box. (Mitigate by
  keeping the salt off the box where the log is shipped/stored — the salt and the log
  should not leak together.)
- **Tail truncation.** Deleting the last *N* rows leaves the remaining chain
  internally consistent — there is no in-file signal that rows were dropped from the
  end. `safespace audit verify` **prints the tip MAC** for exactly this reason: record
  it out-of-band (a monitoring system, a separate host) and compare — a tip that moved
  backward (or a shorter chain) reveals truncation.
- **Rows after the last anchor, or a CLI file never anchored.** A server seals the CLI
  tip only at its first chained write; CLI rows written later, or a CLI file that no server
  has started after, are protected by the CLI chain alone — deleting them is a tail
  truncation. Rolling **both** files back to an older consistent pair, or truncating the
  server tail (which drops the newest anchors), is likewise not detected. A last CLI row
  missing only its newline is not sealed until the next CLI write terminates it, so
  deleting it before then is also a tail truncation. Record both printed tips out of band.
- **A server row followed by an offline `exec`.** Before the split, an `exec` row chained
  onto the server's last row, so deleting that server row was detected; now that row is
  the server chain's tail (tail truncation).
- **Two CLI processes at once** (e.g. overlapping cron `exec` runs) fork the CLI chain;
  `verify` then reports a break that cannot be repaired without rewriting history.
- **Deleting `audit-chain.json`** together with stripping the log needs write access to
  the salt's location (like reading the salt); then only the in-log rules apply.
- **Before `.landed` is recorded.** While `audit-chain.json.landed` is missing (its write
  keeps failing, or a crash came between the committed row and it), cutting the log back to
  the committed row's recorded predecessor with the same rows after it (for a fresh log:
  emptying it; kept bytes turned into non-JSON lines count as cut; a record without
  `rows_after_prev`, written only by unreleased builds, skips that row-count condition) lets
  the next start
  refill the committed row, and the history after it is lost unnoticed. The server retries
  the record on every write; `audit verify` warns while it is missing, and `--json` reports
  `strictLanded: false`.
- **A commitment that cannot be published** (a write error in the salt's location) means
  the row that would have been committed is not written either (logged on stderr): the
  commitment always precedes its row. The next write tries again.
- **The tolerant part of an older chain.** Before its strict marker, an inserted
  no-`row_mac` row with an `event` field still passes, and so does a chained row from
  before the upgrade relabelled as such a row before the first post-upgrade server write
  (it then lands before the marker). In any chain a malformed (non-JSON) line is skipped
  by the reader, so a last row corrupted into non-JSON passes (the same as truncating
  it). A log already forked by `exec` before the CLI chain split stays BROKEN.
- `safespace exec` is reachable from an agent's shell and bypasses tier; its rows are as
  protected as the CLI chain plus anchors.

## Assumptions

- **One writer per chain file**: the stdio server for `audit.jsonl`, one `safespace` CLI
  process at a time for `audit-cli.jsonl`. Two servers on one config dir, or overlapping
  CLI processes, fork that file's chain — which `verify` reports (correctly: it is an
  anomaly).
- The `row_mac` field is additive; every existing audit reader (`safespace audit
  recent / stats / deletes / suspicious / sessions`, `doctor`) ignores it. Those readers
  read both files; `recent` and the CEF export mark rows from `audit-cli.jsonl`.

## See also

- [`SECURITY.md`](../SECURITY.md) — the trust boundary and threat model.
- [`SOLE-EGRESS.md`](SOLE-EGRESS.md) — the Layer-5 detection context (audit + an
  egress monitor = everything that left + an alarm if something left another way).
