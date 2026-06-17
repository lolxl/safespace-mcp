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
safespace audit verify --json    # {ok, chainedRows, legacyRows, tipMac, brokenAt, reason}
```

Exit code is `0` when intact, `1` when broken (so cron/CI can gate on it). A broken
chain reports the **first** offending row index and whether it was an edit/delete
(`mac_mismatch`) or an unhashed row inserted mid-chain (`unhashed_after_chain`).

Rows written *before* the upgrade have no `row_mac`; they are a tolerated legacy
prefix, and the chain verifies from the first hashed row onward.

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

## Assumptions

- **Single writer.** The chain assumes one process appends to a given `audit.jsonl`
  (both supported topologies are single-writer: Model A = one stdio process; Model B =
  one in-process container). Two processes appending to the same file would fork the
  chain — which `verify` surfaces as a break (correctly: it *is* an anomaly).
- The `row_mac` field is additive; every existing audit reader (`safespace audit
  recent / stats / deletes / suspicious / sessions`, `doctor`) ignores it.

## See also

- [`SECURITY.md`](../SECURITY.md) — the trust boundary and threat model.
- [`SOLE-EGRESS.md`](SOLE-EGRESS.md) — the Layer-5 detection context (audit + an
  egress monitor = everything that left + an alarm if something left another way).
