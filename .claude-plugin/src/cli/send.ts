// v1.99 — `safespace send <list|approve|deny>`: the owner's out-of-band approval interface for
// supervised mode (SAFESPACE_REQUIRE_SEND_APPROVAL). When the gate blocks an agent send it lands
// in pending-sends.json (configDir); `list` shows the pending/approved sends, `approve <id>` lets
// the agent's IDENTICAL retry through exactly ONCE, `deny <id>` drops it. The message body lives
// only in this local store and is shown here for the owner to review before approving.

import { CliError, type CliIO } from "../cli";
import { auditSendApprovalEvent } from "../audit";
import {
  approvePending,
  findAndRemovePending,
  formatApprovalTarget,
  listPending,
  pendingSendsPath,
  type PendingSend,
} from "../auth/send-approval-store";

const USAGE =
  "usage: safespace send <list|approve|deny> [pending_id]\n" +
  "       safespace send list\n" +
  "       safespace send approve <pending_id>\n" +
  "       safespace send deny <pending_id>";

export async function runSendCmd(rest: string[], io: CliIO): Promise<void> {
  const [sub, ...args] = rest;
  if (!sub) throw new CliError(USAGE);
  if (sub === "list") return list(args, io);
  if (sub === "approve") return approve(args, io);
  if (sub === "deny") return deny(args, io);
  throw new CliError(`unknown send subcommand: ${sub}\n       ${USAGE}`);
}

function requireId(args: string[], verb: string): string {
  const [id, ...extra] = args;
  if (id === undefined || id.startsWith("--") || extra.length > 0) {
    throw new CliError(`${verb} requires exactly <pending_id>\n       ${USAGE}`);
  }
  return id;
}

/** One-line, whitespace-collapsed, length-capped body preview for the list view. */
function preview(body: string): string {
  const oneLine = body.replace(/\s+/g, " ").trim();
  return oneLine.length > 80 ? `${oneLine.slice(0, 79)}…` : oneLine;
}

async function list(args: string[], io: CliIO): Promise<void> {
  if (args.length > 0) throw new CliError(`list takes no arguments\n       ${USAGE}`);
  let rows: PendingSend[];
  try {
    rows = await listPending(pendingSendsPath(), Date.now());
  } catch (e) {
    throw new CliError(e instanceof Error ? e.message : String(e));
  }
  if (rows.length === 0) {
    io.out("(no pending sends)");
    return;
  }
  for (const r of rows) {
    io.out(`${r.pending_id}  ${r.status.padEnd(8)} ${r.tool}`);
    if (r.target !== undefined) io.out(`  target: ${formatApprovalTarget(r.target)}`);
    io.out(`  to: ${r.recipients.join(", ")}`);
    io.out(`  body: ${preview(r.body)}`);
    io.out(`  expires ${r.expires_at}`);
    io.out("");
  }
}

async function approve(args: string[], io: CliIO): Promise<void> {
  const id = requireId(args, "approve");
  let rec: PendingSend | null;
  try {
    rec = await approvePending(pendingSendsPath(), id, Date.now());
  } catch (e) {
    throw new CliError(e instanceof Error ? e.message : String(e));
  }
  if (rec === null) {
    io.out(`no pending send with id ${id} (it may have expired or been consumed)`);
    return;
  }
  await auditSendApprovalEvent({
    event: "approved",
    pending_id: rec.pending_id,
    tool: rec.tool,
    fingerprint: rec.fingerprint,
    recipients: rec.recipients,
    operator: rec.operator,
    ...(rec.target !== undefined ? { target: rec.target } : {}),
  });
  // NOTE: `recipients` is the contact-RESOLVED final list; `target` is the typed public-surface
  // identity — shown in the owner's LOCAL terminal. Never sent anywhere.
  const dest = rec.target !== undefined ? formatApprovalTarget(rec.target) : rec.recipients.join(", ");
  io.out(`approved ${id} (${rec.tool} → ${dest}). The agent's identical retry will send ONCE.`);
}

async function deny(args: string[], io: CliIO): Promise<void> {
  const id = requireId(args, "deny");
  // Atomic single-load find-and-remove (NO list-then-remove TOCTOU): the returned record is
  // audited; null = nothing to deny (absent / already consumed / expired).
  let rec: PendingSend | null;
  try {
    rec = await findAndRemovePending(pendingSendsPath(), id, Date.now());
  } catch (e) {
    throw new CliError(e instanceof Error ? e.message : String(e));
  }
  if (rec === null) {
    io.out(`no pending send with id ${id}`);
    return;
  }
  await auditSendApprovalEvent({
    event: "denied",
    pending_id: rec.pending_id,
    tool: rec.tool,
    fingerprint: rec.fingerprint,
    recipients: rec.recipients,
    operator: rec.operator,
    ...(rec.target !== undefined ? { target: rec.target } : {}),
  });
  io.out(`denied ${id} — dropped from the pending store.`);
}
