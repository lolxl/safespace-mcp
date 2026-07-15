// v1.70 (G4) — the GitHub read handlers (the FIRST tools of the 2nd OAuth source).
//
// docs/v1.70-github-oauth-connector.md §7. Five READ tools over api.github.com:
//   github_list_repos · github_list_issues · github_get_issue ·
//   github_get_pull_request · github_list_issue_comments
// v1.76 deepens READ with six more (repo / PR list / PR files / commits / file content).
//
// OAUTH (provider github): each handler reads the bearer via requireGithub(ctx)
// (handlers/shared.ts) — the R8 cross-provider backstop that throws if the
// credential is not a github OAuth credential, so a Google bearer can never be sent
// to api.github.com (and vice-versa). The token is used ONLY inline (passed to
// githubApiGet) — never stored, logged, or echoed.
//
// THE ENVELOPE IS THE POINT: issue/PR/comment free text (title / body / comment body /
// repo name+description / label name / user login+name) is the #1 prompt-injection
// vector in an agent↔GitHub integration. These handlers return a CURATED shape (only
// the useful fields — never the raw GitHub object), and `withToolContext` then runs
// the source's sanitize tree-walk over it with GITHUB_SKIP_FIELDS (tools/source.ts):
// the opaque/structural string keys (html_url, the timestamps, state, status, node_id)
// are skipped; EVERY other string — all the attacker-influenced free text — is wrapped
// in `<untrusted-source>`. The handlers never wrap themselves; they shape, the envelope
// wraps.
//
// PATH SEGMENTS: owner / repo / number are anchored-regex validated BEFORE URL
// interpolation (and `..` is rejected outright) so a segment can never traverse the
// api.github.com path — the same discipline as discord.ts's channel_id. v1.76's two new
// path inputs — a file `path` and a commit `ref` — get their own validators + a
// per-segment URL encoder for the same reason.

import { githubApiGet, githubApiWrite } from "../../auth/github/client";
import { outboundSanitize } from "../../sanitize/outbound";
// B6.1 wave A — the github egress gates (enforceGithub*EgressGates) are now PIPELINE-FIRED
// by with-context.ts via each write tool's egress descriptor (tools/egress-pipeline.ts);
// the handlers no longer import/call them (anti-double-fire). Only the GithubReviewEvent
// type is still needed (the review validator's return type).
import type { GithubReviewEvent } from "../egress";
import type { ToolContext } from "../types";
import { requireGithub } from "./shared";

/** Test-injection seam — production leaves it undefined (→ the real global fetch).
 *  Mirrors DiscordSendDeps; the handler forwards it to githubApiGet. */
export interface GithubReadDeps {
  fetchImpl?: typeof fetch;
}

/** owner / repo path segment: GitHub's allowed character set, anchored + length-capped.
 *  `..` is rejected separately (the regex allows `.`, so `..` would otherwise match and
 *  could traverse the URL path). */
const OWNER_REPO_RE = /^[A-Za-z0-9_.-]{1,100}$/;
const ISSUE_STATES: ReadonlySet<string> = new Set(["open", "closed", "all"]);
const PER_PAGE_DEFAULT = 30;
const PER_PAGE_MAX = 100;

function requireOwnerRepo(args: Record<string, unknown>, key: "owner" | "repo"): string {
  const v = args[key];
  if (typeof v !== "string" || !OWNER_REPO_RE.test(v) || v.includes("..")) {
    throw new Error(
      `github: '${key}' must match ${OWNER_REPO_RE.source} and contain no '..'`,
    );
  }
  return v;
}

function requireNumber(args: Record<string, unknown>, key: string): number {
  const raw = args[key];
  const n = typeof raw === "number" ? raw : typeof raw === "string" ? Number(raw) : NaN;
  if (!Number.isInteger(n) || n < 1 || n > 1_000_000_000) {
    throw new Error(`github: '${key}' must be a positive integer ≤ 1,000,000,000`);
  }
  return n;
}

function clampPerPage(raw: unknown): number {
  const n = typeof raw === "number" && Number.isFinite(raw) && raw >= 1 ? raw : PER_PAGE_DEFAULT;
  return Math.floor(Math.min(n, PER_PAGE_MAX));
}

function clampPage(raw: unknown): number {
  const n = typeof raw === "number" && Number.isFinite(raw) && raw >= 1 ? raw : 1;
  return Math.floor(n);
}

/* ── v1.76 — file-path + git-ref validators (the two NEW path inputs) ── */

const FILE_PATH_MAX_BYTES = 1024;
/** A git ref: a commit SHA, a branch, or a tag. Anchored charset (no spaces / control
 *  chars / URL metacharacters), no "..". */
const REF_RE = /^[A-Za-z0-9_.\/-]{1,255}$/;

/** True if `s` contains an ASCII control character (U+0000–U+001F or U+007F). Uses a
 *  numeric code-unit scan rather than a regex with `\u` escapes (so no literal control
 *  byte ever appears in this source file). */
function hasControlChar(s: string): boolean {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return true;
  }
  return false;
}

/** A repo-relative file path for the Contents API. No NUL/control char, no leading "/",
 *  and every "/"-segment must be non-empty and not "." / ".." — so it can NEVER traverse
 *  the api.github.com path. Returned raw; {@link encodePathSegments} encodes it at
 *  URL-build time. Throws a plain Error echoing the RULE, never the value. */
function requireFilePath(args: Record<string, unknown>): string {
  const v = args.path;
  if (typeof v !== "string" || v.length === 0) {
    throw new Error("github: 'path' must be a non-empty string");
  }
  if (Buffer.byteLength(v, "utf8") > FILE_PATH_MAX_BYTES) {
    throw new Error(`github: 'path' must be ≤ ${FILE_PATH_MAX_BYTES} bytes`);
  }
  if (hasControlChar(v)) {
    throw new Error("github: 'path' must not contain control characters");
  }
  if (v.startsWith("/")) {
    throw new Error("github: 'path' must be repo-relative (no leading '/')");
  }
  for (const seg of v.split("/")) {
    if (seg === "" || seg === "." || seg === "..") {
      throw new Error("github: 'path' has an empty or traversal ('..') segment");
    }
  }
  return v;
}

/** A git ref (commit SHA / branch / tag). Anchored to a URL-safe charset; the regex
 *  ALLOWS "." (so `..` would pass it) — the explicit `v.includes("..")` below is the
 *  load-bearing traversal guard. Used either in the URL path (get_commit →
 *  {@link encodePathSegments}) or a query param (ref / sha → URLSearchParams-encoded).
 *  Throws echoing the RULE, never the value. */
function requireRef(
  args: Record<string, unknown>,
  key: string,
  required: boolean,
): string | undefined {
  const v = args[key];
  if (v === undefined) {
    if (required) throw new Error(`github: '${key}' is required`);
    return undefined;
  }
  if (typeof v !== "string" || !REF_RE.test(v) || v.includes("..")) {
    throw new Error(`github: '${key}' must match ${REF_RE.source} and contain no '..'`);
  }
  return v;
}

/** Encode a validated repo-relative path / ref for the api.github.com URL path: encode
 *  each "/"-segment (so a space / "#" / "?" / unicode in a filename can't break or escape
 *  the path) and rejoin with literal "/" separators. "/" stays a separator; ".." is
 *  already rejected upstream. */
function encodePathSegments(p: string): string {
  return p.split("/").map(encodeURIComponent).join("/");
}

/* ── curated response shapers (pick ONLY safe fields; never the raw object) ── */

type Obj = Record<string, unknown>;
const asObj = (v: unknown): Obj | null => (v && typeof v === "object" ? (v as Obj) : null);

/** A user/owner sub-object. `login` (the stable identity) + `type` are strings NOT
 *  in GITHUB_SKIP_FIELDS → they wrap; the numeric `id` is a number (sanitize never
 *  wraps numbers), returned for reference. The display `name` is intentionally
 *  omitted — `login` is the stable id, and `name` is higher-injection free text not
 *  needed by these read tools. */
function shapeUser(v: unknown): Obj | null {
  const o = asObj(v);
  return o ? { login: o.login, id: o.id, type: o.type } : null;
}

function shapeRepo(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    name: o.name,
    full_name: o.full_name,
    description: o.description,
    private: o.private,
    fork: o.fork,
    archived: o.archived,
    html_url: o.html_url,
    language: o.language,
    default_branch: o.default_branch,
    updated_at: o.updated_at,
    owner: shapeUser(o.owner),
    stargazers_count: o.stargazers_count,
    open_issues_count: o.open_issues_count,
  };
}

function shapeLabels(v: unknown): unknown[] {
  if (!Array.isArray(v)) return [];
  return v.map((l) => {
    const o = asObj(l);
    return o ? o.name : l; // label NAME wraps (attacker-creatable)
  });
}

function shapeIssue(v: unknown): Obj {
  const o = asObj(v) ?? {};
  const milestone = asObj(o.milestone);
  return {
    number: o.number,
    title: o.title,
    state: o.state,
    body: o.body,
    user: shapeUser(o.user),
    labels: shapeLabels(o.labels),
    milestone_title: milestone ? milestone.title : null,
    comments: o.comments,
    html_url: o.html_url,
    created_at: o.created_at,
    updated_at: o.updated_at,
    closed_at: o.closed_at,
  };
}

function shapePullRequest(v: unknown): Obj {
  const o = asObj(v) ?? {};
  const head = asObj(o.head);
  const base = asObj(o.base);
  return {
    number: o.number,
    title: o.title,
    state: o.state,
    body: o.body,
    user: shapeUser(o.user),
    draft: o.draft,
    merged: o.merged,
    // branch ref names are attacker-influenced (a PR from a fork) → WRAP (not skipped).
    head_ref: head ? head.ref : null,
    base_ref: base ? base.ref : null,
    comments: o.comments,
    commits: o.commits,
    additions: o.additions,
    deletions: o.deletions,
    changed_files: o.changed_files,
    html_url: o.html_url,
    created_at: o.created_at,
    updated_at: o.updated_at,
    closed_at: o.closed_at,
    merged_at: o.merged_at,
  };
}

/** PUT /pulls/{n}/merge response — {sha, merged, message}. All three are
 *  Google/GitHub-controlled (a commit sha, a boolean, GitHub's status string), no
 *  attacker free text → returned as-is (the choke point still sanitize-walks them). */
function shapeMergeResult(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return { merged: o.merged, sha: o.sha, message: o.message };
}

function shapeComment(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    id: o.id,
    body: o.body,
    user: shapeUser(o.user),
    html_url: o.html_url,
    created_at: o.created_at,
    updated_at: o.updated_at,
  };
}

/** POST /pulls/{n}/reviews response — a submitted review. `state` is GitHub's controlled
 *  enum (APPROVED / CHANGES_REQUESTED / COMMENTED), `commit_id` a SHA; `body` is the review
 *  text echoed back (already outbound-sanitized on send + the choke point sanitize-walks
 *  the response). */
function shapeReview(v: unknown): Obj {
  const o = asObj(v) ?? {};
  return {
    id: o.id,
    state: o.state,
    body: o.body,
    user: shapeUser(o.user),
    commit_id: o.commit_id,
    html_url: o.html_url,
    submitted_at: o.submitted_at,
  };
}

/** v1.76 — a PR-file / commit-file change. `filename` / `previous_filename` / `patch`
 *  are attacker free text (a PR from a fork controls them) → WRAP; `status` is GitHub's
 *  controlled change enum → skip (GITHUB_SKIP_FIELDS); the counts are numbers. The diff
 *  `patch` is truncated for context protection BEFORE the envelope wraps it (and GitHub
 *  itself omits `patch` for very large diffs — then it is simply absent). */
const PATCH_MAX_CHARS = 20_000;
function shapeFile(v: unknown): Obj {
  const o = asObj(v) ?? {};
  const out: Obj = {
    filename: o.filename,
    status: o.status,
    additions: o.additions,
    deletions: o.deletions,
    changes: o.changes,
  };
  if (o.previous_filename !== undefined) out.previous_filename = o.previous_filename;
  if (typeof o.patch === "string") {
    out.patch =
      o.patch.length > PATCH_MAX_CHARS
        ? `${o.patch.slice(0, PATCH_MAX_CHARS)}\n…[patch truncated]`
        : o.patch;
  }
  return out;
}

/** v1.76 — a commit. `message` + the git author identity (name / email) + the GitHub
 *  `author` login are attacker-controlled (git lets you set any author) → WRAP; sha /
 *  html_url skip; dates wrap harmlessly. `stats` (numbers) + `files` (shapeFile[]) are
 *  present only on the single-commit GET (the list endpoint omits them). */
function shapeCommit(v: unknown): Obj {
  const o = asObj(v) ?? {};
  const commit = asObj(o.commit) ?? {};
  const cAuthor = asObj(commit.author) ?? {};
  const cCommitter = asObj(commit.committer) ?? {};
  const out: Obj = {
    sha: o.sha,
    message: commit.message,
    author: shapeUser(o.author), // the GitHub account (may be null for an unlinked email)
    author_name: cAuthor.name, // the git author identity (attacker-set) → wraps
    author_email: cAuthor.email,
    author_date: cAuthor.date,
    committer_date: cCommitter.date,
    comment_count: commit.comment_count,
    html_url: o.html_url,
  };
  const stats = asObj(o.stats);
  if (stats) {
    out.stats = { additions: stats.additions, deletions: stats.deletions, total: stats.total };
  }
  if (Array.isArray(o.files)) out.files = o.files.map(shapeFile);
  return out;
}

/* ── handlers ── */

/** GET /user/repos — the authenticated user's repositories (most-recently-updated). */
export async function githubListRepos(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const data = await githubApiGet({
    token,
    path: "/user/repos",
    query: { per_page: clampPerPage(args.per_page), page: clampPage(args.page), sort: "updated" },
    fetchImpl: deps.fetchImpl,
  });
  return { repos: Array.isArray(data) ? data.map(shapeRepo) : [] };
}

/** GET /repos/{owner}/{repo}/issues — issues (NOTE: GitHub includes PRs in this list). */
export async function githubListIssues(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const state = typeof args.state === "string" && ISSUE_STATES.has(args.state) ? args.state : "open";
  const data = await githubApiGet({
    token,
    path: `/repos/${owner}/${repo}/issues`,
    query: { state, per_page: clampPerPage(args.per_page), page: clampPage(args.page) },
    fetchImpl: deps.fetchImpl,
  });
  return { issues: Array.isArray(data) ? data.map(shapeIssue) : [] };
}

/** GET /repos/{owner}/{repo}/issues/{number} — a single issue. */
export async function githubGetIssue(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const number = requireNumber(args, "number");
  const data = await githubApiGet({
    token,
    path: `/repos/${owner}/${repo}/issues/${number}`,
    fetchImpl: deps.fetchImpl,
  });
  return shapeIssue(data);
}

/** GET /repos/{owner}/{repo}/pulls/{number} — a single pull request. */
export async function githubGetPullRequest(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const number = requireNumber(args, "number");
  const data = await githubApiGet({
    token,
    path: `/repos/${owner}/${repo}/pulls/${number}`,
    fetchImpl: deps.fetchImpl,
  });
  return shapePullRequest(data);
}

/** GET /repos/{owner}/{repo}/issues/{number}/comments — an issue's comments (the
 *  highest-value injection surface; Q3). */
export async function githubListIssueComments(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const number = requireNumber(args, "number");
  const data = await githubApiGet({
    token,
    path: `/repos/${owner}/${repo}/issues/${number}/comments`,
    query: { per_page: clampPerPage(args.per_page), page: clampPage(args.page) },
    fetchImpl: deps.fetchImpl,
  });
  return { comments: Array.isArray(data) ? data.map(shapeComment) : [] };
}

/* ── v1.76 — READ-deepening handlers (repo / PR list / PR files / commits / file
 * content). Pure inbound: requireGithub (R8 backstop) → validate → githubApiGet →
 * curated shape; the choke point's sanitize wraps every attacker-influenced string. ── */

/** GET /repos/{owner}/{repo} — a single repository's metadata. */
export async function githubGetRepo(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const data = await githubApiGet({
    token,
    path: `/repos/${owner}/${repo}`,
    fetchImpl: deps.fetchImpl,
  });
  return shapeRepo(data);
}

/** GET /repos/{owner}/{repo}/pulls — list pull requests (state filter + pagination). */
export async function githubListPullRequests(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const state = typeof args.state === "string" && ISSUE_STATES.has(args.state) ? args.state : "open";
  const data = await githubApiGet({
    token,
    path: `/repos/${owner}/${repo}/pulls`,
    query: { state, per_page: clampPerPage(args.per_page), page: clampPage(args.page) },
    fetchImpl: deps.fetchImpl,
  });
  return { pull_requests: Array.isArray(data) ? data.map(shapePullRequest) : [] };
}

/** GET /repos/{owner}/{repo}/pulls/{number}/files — a PR's changed files (the diff).
 *  Each `patch` is truncated (shapeFile) + the endpoint is paginated. */
export async function githubListPullRequestFiles(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const number = requireNumber(args, "number");
  const data = await githubApiGet({
    token,
    path: `/repos/${owner}/${repo}/pulls/${number}/files`,
    query: { per_page: clampPerPage(args.per_page), page: clampPage(args.page) },
    fetchImpl: deps.fetchImpl,
  });
  return { files: Array.isArray(data) ? data.map(shapeFile) : [] };
}

/** GET /repos/{owner}/{repo}/commits — commit history (optional `sha` ref to start from
 *  + optional `path` filter; both go in the query, URLSearchParams-encoded). */
export async function githubListCommits(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const sha = requireRef(args, "sha", false);
  const path = args.path === undefined ? undefined : requireFilePath(args);
  const data = await githubApiGet({
    token,
    path: `/repos/${owner}/${repo}/commits`,
    query: { sha, path, per_page: clampPerPage(args.per_page), page: clampPage(args.page) },
    fetchImpl: deps.fetchImpl,
  });
  return { commits: Array.isArray(data) ? data.map(shapeCommit) : [] };
}

/** GET /repos/{owner}/{repo}/commits/{ref} — a single commit + stats + files. The `ref`
 *  goes in the URL path → per-segment encoded. */
export async function githubGetCommit(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const ref = requireRef(args, "ref", true)!;
  // encodePathSegments is a no-op for any REF_RE-passing ref (its charset is already
  // URL-safe) — applied anyway so EVERY user value interpolated into a path goes through
  // the one encoder (the same invariant as githubGetFileContent), defense-in-depth if
  // REF_RE is ever loosened. A slashed branch ref ("feature/x") keeps its "/" separators.
  const data = await githubApiGet({
    token,
    path: `/repos/${owner}/${repo}/commits/${encodePathSegments(ref)}`,
    fetchImpl: deps.fetchImpl,
  });
  return shapeCommit(data);
}

/** The Contents API base64 limit — GitHub serves a file ≤ 1 MB as base64; a larger file
 *  comes back as `encoding:"none"` with empty content (needs the Blob API, out of scope). */
const FILE_CONTENT_MAX_BYTES = 1_000_000;

/** GET /repos/{owner}/{repo}/contents/{path} — read a file's UTF-8 text content.
 *  base64-decode → NUL/round-trip-UTF-8 binary guard → size cap (mirrors fs_read). A
 *  directory (array response) or a >1 MB / non-base64 file → a clear plain Error (→
 *  github_api_failed{api_error} at the choke point; ZERO new error code). The decoded
 *  `content` (and name / path) are sanitize-wrapped by the choke point. */
export async function githubGetFileContent(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const path = requireFilePath(args);
  const ref = requireRef(args, "ref", false);
  const data = await githubApiGet({
    token,
    path: `/repos/${owner}/${repo}/contents/${encodePathSegments(path)}`,
    query: { ref },
    fetchImpl: deps.fetchImpl,
  });
  if (Array.isArray(data)) {
    throw new Error("github: path is a directory, not a file");
  }
  const o = asObj(data) ?? {};
  if (o.type !== "file" || o.encoding !== "base64" || typeof o.content !== "string") {
    throw new Error("github: not a readable text file (too large or unsupported type)");
  }
  const buf = Buffer.from(o.content, "base64");
  if (buf.byteLength > FILE_CONTENT_MAX_BYTES) {
    throw new Error("github: file too large");
  }
  if (buf.includes(0)) {
    throw new Error("github: file is binary (NUL byte), not text");
  }
  const content = buf.toString("utf8");
  // toString("utf8") replaces invalid sequences with U+FFFD; a round-trip mismatch ⇒
  // the bytes were not valid UTF-8 → reject rather than feed garbage to the model.
  if (Buffer.byteLength(content, "utf8") !== buf.byteLength) {
    throw new Error("github: file is not valid UTF-8 text");
  }
  return { name: o.name, path: o.path, sha: o.sha, size: buf.byteLength, content };
}

/* ── WRITE handlers (v1.71 — the PUBLIC-surface egress slice) ──────────────────
 *
 * Each write: [PIPELINE-FIRED egress — DEFAULT-DENY repo allowlist + F3a secret-shape,
 * run by with-context.ts via the tool's egress descriptor BEFORE the handler; B6.1 wave A]
 * → requireGithub (R8 backstop) → validate (the SAME exported validator the descriptor's
 * extract ran) → per-field outboundSanitize (the public-surface REJECT, byte-capped) →
 * ALLOWLIST-CONSTRUCTED request body (ONLY title/body/state — no agent-supplied assignee/
 * label/HTML field can slip through) → githubApiWrite → shape the created/updated resource
 * (its echoed text is wrapped by the choke point's sanitize like any read). Public OR private
 * repo (v1.83 `repo` scope); the default-deny allowlist — not the scope — is what bounds which
 * repos a write can touch. */

const TITLE_MAX_BYTES = 256; // GitHub issue title limit
const BODY_MAX_BYTES = 65536; // GitHub issue/comment body limit
const ISSUE_UPDATE_STATES: ReadonlySet<string> = new Set(["open", "closed"]);

/** Read an optional/required string field. Throws a plain Error (bad input) echoing
 *  the RULE, never the value. */
function requireText(
  args: Record<string, unknown>,
  key: string,
  required: boolean,
): string | undefined {
  const v = args[key];
  if (v === undefined) {
    if (required) throw new Error(`github: '${key}' is required`);
    return undefined;
  }
  if (typeof v !== "string") throw new Error(`github: '${key}' must be a string`);
  return v;
}

/* ── B6.1 wave A — exported validators (SINGLE SOURCE for the egress descriptor's
 * `extract` + the handler). Each reproduces the tool's former pre-gate validation
 * VERBATIM (same order, same plain-Error messages) and returns the validated fields;
 * the descriptor's extract maps them to the gate's `body`, the handler consumes them
 * for the allowlist-constructed request. The handler re-runs the validator (cheap,
 * pure, identical result — defense-in-depth + the handler's own unit surface); the
 * egress gate is now PIPELINE-FIRED (with-context.ts) so no handler calls it. ── */

export function validateGithubCreateIssueArgs(args: Record<string, unknown>): {
  owner: string;
  repo: string;
  title: string;
  body: string | undefined;
} {
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const title = requireText(args, "title", true)!;
  if (title.trim().length === 0) throw new Error("github: 'title' must be non-empty");
  const body = requireText(args, "body", false);
  return { owner, repo, title, body };
}

export function validateGithubCreateIssueCommentArgs(args: Record<string, unknown>): {
  owner: string;
  repo: string;
  number: number;
  body: string;
} {
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const number = requireNumber(args, "number");
  const body = requireText(args, "body", true)!;
  if (body.trim().length === 0) throw new Error("github: 'body' must be non-empty");
  return { owner, repo, number, body };
}

export function validateGithubUpdateIssueArgs(args: Record<string, unknown>): {
  owner: string;
  repo: string;
  number: number;
  title: string | undefined;
  body: string | undefined;
  state: string | undefined;
} {
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const number = requireNumber(args, "number");
  const title = requireText(args, "title", false);
  const body = requireText(args, "body", false);
  let state: string | undefined;
  if (args.state !== undefined) {
    if (typeof args.state !== "string" || !ISSUE_UPDATE_STATES.has(args.state)) {
      throw new Error("github: 'state' must be 'open' or 'closed'");
    }
    state = args.state;
  }
  if (title === undefined && body === undefined && state === undefined) {
    throw new Error("github: github_update_issue requires at least one of title / body / state");
  }
  if (title !== undefined && title.trim().length === 0) {
    throw new Error("github: 'title' must be non-empty");
  }
  return { owner, repo, number, title, body, state };
}

export function validateGithubCreatePullRequestArgs(args: Record<string, unknown>): {
  owner: string;
  repo: string;
  title: string;
  head: string;
  base: string;
  body: string | undefined;
  draft: boolean | undefined;
} {
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const title = requireText(args, "title", true)!;
  if (title.trim().length === 0) throw new Error("github: 'title' must be non-empty");
  const head = requireRef(args, "head", true)!;
  const base = requireRef(args, "base", true)!;
  const body = requireText(args, "body", false);
  let draft: boolean | undefined;
  if (args.draft !== undefined) {
    if (typeof args.draft !== "boolean") throw new Error("github: 'draft' must be a boolean");
    draft = args.draft;
  }
  return { owner, repo, title, head, base, body, draft };
}

export function validateGithubMergePullRequestArgs(args: Record<string, unknown>): {
  owner: string;
  repo: string;
  number: number;
  method: string;
  sha: string | undefined;
  commitTitle: string | undefined;
  commitMessage: string | undefined;
} {
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const number = requireNumber(args, "number");

  let method = "squash";
  if (args.merge_method !== undefined) {
    if (typeof args.merge_method !== "string" || !MERGE_METHODS.has(args.merge_method)) {
      throw new Error("github: 'merge_method' must be one of merge / squash / rebase");
    }
    method = args.merge_method;
  }
  let sha: string | undefined;
  if (args.sha !== undefined) {
    if (typeof args.sha !== "string" || !SHA_RE.test(args.sha)) {
      throw new Error("github: 'sha' must be a 7–40 char hex commit SHA");
    }
    sha = args.sha;
  }
  const commitTitle = requireText(args, "commit_title", false);
  const commitMessage = requireText(args, "commit_message", false);
  return { owner, repo, number, method, sha, commitTitle, commitMessage };
}

export function validateGithubReviewArgs(args: Record<string, unknown>): {
  owner: string;
  repo: string;
  number: number;
  event: GithubReviewEvent;
  body: string | undefined;
  commitId: string | undefined;
} {
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const number = requireNumber(args, "number");

  if (typeof args.event !== "string" || !REVIEW_EVENTS.has(args.event)) {
    throw new Error("github: 'event' must be one of APPROVE / REQUEST_CHANGES / COMMENT");
  }
  const event = args.event as GithubReviewEvent;
  const body = requireText(args, "body", false);
  if (event !== "APPROVE" && (body === undefined || body.trim().length === 0)) {
    throw new Error(`github: 'body' is required (non-empty) for a ${event} review`);
  }
  let commitId: string | undefined;
  if (args.commit_id !== undefined) {
    if (typeof args.commit_id !== "string" || !SHA_RE.test(args.commit_id)) {
      throw new Error("github: 'commit_id' must be a 7–40 char hex commit SHA");
    }
    commitId = args.commit_id;
  }
  return { owner, repo, number, event, body, commitId };
}

export function validateGithubSetIssueLabelsArgs(args: Record<string, unknown>): {
  owner: string;
  repo: string;
  number: number;
  rawLabels: string[];
} {
  const owner = requireOwnerRepo(args, "owner");
  const repo = requireOwnerRepo(args, "repo");
  const number = requireNumber(args, "number");
  if (!Array.isArray(args.labels)) {
    throw new Error("github: 'labels' must be an array of strings (use [] to clear all)");
  }
  if (args.labels.length > MAX_LABELS) {
    throw new Error(`github: at most ${MAX_LABELS} labels per call (got ${args.labels.length})`);
  }
  const rawLabels: string[] = [];
  for (let i = 0; i < args.labels.length; i++) {
    const l = args.labels[i];
    if (typeof l !== "string") throw new Error(`github: labels[${i}] must be a string`);
    if (l.trim().length === 0) throw new Error(`github: labels[${i}] must be non-empty`);
    rawLabels.push(l);
  }
  return { owner, repo, number, rawLabels };
}

/** POST /repos/{owner}/{repo}/issues — create an issue (title + optional body). */
export async function githubCreateIssue(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const { owner, repo, title, body } = validateGithubCreateIssueArgs(args);

  // Egress (DEFAULT-DENY repo allowlist + F3a secret-shape) is PIPELINE-FIRED before this
  // handler (with-context.ts via githubCreateIssueEgressDescriptor); the handler must NOT
  // call the gate (anti-double-fire — egress-callsite.test.ts enforces both directions).
  // Public-surface REJECT + byte-cap, per field. Request body is allowlist-constructed.
  const reqBody: Record<string, unknown> = {
    title: outboundSanitize(title, { tool: "github_create_issue", maxBytes: TITLE_MAX_BYTES }),
  };
  if (body !== undefined) {
    reqBody.body = outboundSanitize(body, { tool: "github_create_issue", maxBytes: BODY_MAX_BYTES });
  }
  const data = await githubApiWrite({
    token,
    method: "POST",
    path: `/repos/${owner}/${repo}/issues`,
    body: reqBody,
    fetchImpl: deps.fetchImpl,
  });
  return shapeIssue(data);
}

/** POST /repos/{owner}/{repo}/issues/{number}/comments — comment on an issue or PR. */
export async function githubCreateIssueComment(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const { owner, repo, number, body } = validateGithubCreateIssueCommentArgs(args);

  // Egress PIPELINE-FIRED before this handler (githubCreateIssueCommentEgressDescriptor).
  const reqBody = {
    body: outboundSanitize(body, { tool: "github_create_issue_comment", maxBytes: BODY_MAX_BYTES }),
  };
  const data = await githubApiWrite({
    token,
    method: "POST",
    path: `/repos/${owner}/${repo}/issues/${number}/comments`,
    body: reqBody,
    fetchImpl: deps.fetchImpl,
  });
  return shapeComment(data);
}

/** PATCH /repos/{owner}/{repo}/issues/{number} — edit an issue (title?/body?/state?).
 *  Non-destructive + recoverable (state:closed is the recoverable "delete" — GitHub has
 *  no delete-issue API). Requires ≥1 of title/body/state. */
export async function githubUpdateIssue(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const { owner, repo, number, title, body, state } = validateGithubUpdateIssueArgs(args);

  // Egress PIPELINE-FIRED before this handler (githubUpdateIssueEgressDescriptor). The
  // descriptor's extract reproduces the combined-text scan input verbatim
  // ([title, body].filter().join("\n")); the target check runs even for a state-only update.
  const reqBody: Record<string, unknown> = {};
  if (title !== undefined) {
    reqBody.title = outboundSanitize(title, { tool: "github_update_issue", maxBytes: TITLE_MAX_BYTES });
  }
  if (body !== undefined) {
    reqBody.body = outboundSanitize(body, { tool: "github_update_issue", maxBytes: BODY_MAX_BYTES });
  }
  if (state !== undefined) reqBody.state = state; // controlled enum — not free text
  const data = await githubApiWrite({
    token,
    method: "PATCH",
    path: `/repos/${owner}/${repo}/issues/${number}`,
    body: reqBody,
    fetchImpl: deps.fetchImpl,
  });
  return shapeIssue(data);
}

/** POST /repos/{owner}/{repo}/pulls — open a pull request (head → base). v1.81.
 *  Same public-surface egress slice as github_create_issue (default-DENY repo
 *  allowlist + F3a secret-shape + per-field outboundSanitize + allowlist-constructed
 *  body). `head`/`base` are branch REFS (structural identifiers) — validated by
 *  REF_RE + no "..", NOT sanitized (same posture as the issue `number`). Same-repo
 *  only: a cross-fork `head` ("owner:branch") fails REF_RE → deferred (cross-fork needs
 *  `owner:branch` parsing). Title/body are public free text → REJECT + byte-cap. */
export async function githubCreatePullRequest(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const { owner, repo, title, head, base, body, draft } = validateGithubCreatePullRequestArgs(args);

  // Egress PIPELINE-FIRED before this handler (githubCreatePullRequestEgressDescriptor).
  // head/base are refs, not secret-bearing prose → not part of the scan.
  // Public-surface REJECT + byte-cap on the free-text fields. Request body is
  // ALLOWLIST-CONSTRUCTED — only title/head/base/body/draft reach the wire.
  const reqBody: Record<string, unknown> = {
    title: outboundSanitize(title, { tool: "github_create_pull_request", maxBytes: TITLE_MAX_BYTES }),
    head, // validated ref — controlled identifier, not free text
    base, // validated ref
  };
  if (body !== undefined) {
    reqBody.body = outboundSanitize(body, { tool: "github_create_pull_request", maxBytes: BODY_MAX_BYTES });
  }
  if (draft !== undefined) reqBody.draft = draft; // controlled boolean
  const data = await githubApiWrite({
    token,
    method: "POST",
    path: `/repos/${owner}/${repo}/pulls`,
    body: reqBody,
    fetchImpl: deps.fetchImpl,
  });
  return shapePullRequest(data);
}

const MERGE_METHODS: ReadonlySet<string> = new Set(["merge", "squash", "rebase"]);
const SHA_RE = /^[0-9a-f]{7,40}$/i; // a GitHub commit SHA (abbrev 7 … full 40 hex)

/** PUT /repos/{owner}/{repo}/pulls/{number}/merge — merge a pull request. v1.82.
 *  IRREVERSIBLE, so gated by the SEPARATE default-deny SAFESPACE_GITHUB_MERGE_TARGETS
 *  allowlist (`enforceGithubMergeEgressGates`) — a repo write-allowlisted for issues/PRs
 *  is NOT thereby merge-allowlisted. `merge_method` ∈ {merge, squash, rebase} (default
 *  squash, matching the project's own squash-merge convention); optional `sha` pins the
 *  expected PR head SHA (GitHub 409s on a mismatch = anti-race). `commit_title` /
 *  `commit_message` are agent-authored merge-commit text → outboundSanitize REJECT +
 *  F3a secret-shape; body is ALLOWLIST-CONSTRUCTED. */
export async function githubMergePullRequest(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const { owner, repo, number, method, sha, commitTitle, commitMessage } =
    validateGithubMergePullRequestArgs(args);

  // Egress (SEPARATE default-deny MERGE allowlist + F3a secret-shape on the merge-commit
  // text) is PIPELINE-FIRED before this handler (githubMergePullRequestEgressDescriptor).
  // ALLOWLIST-CONSTRUCTED body — only merge_method/sha/commit_title/commit_message.
  const reqBody: Record<string, unknown> = { merge_method: method };
  if (sha !== undefined) reqBody.sha = sha;
  if (commitTitle !== undefined) {
    reqBody.commit_title = outboundSanitize(commitTitle, {
      tool: "github_merge_pull_request",
      maxBytes: TITLE_MAX_BYTES,
    });
  }
  if (commitMessage !== undefined) {
    reqBody.commit_message = outboundSanitize(commitMessage, {
      tool: "github_merge_pull_request",
      maxBytes: BODY_MAX_BYTES,
    });
  }
  const data = await githubApiWrite({
    token,
    method: "PUT",
    path: `/repos/${owner}/${repo}/pulls/${number}/merge`,
    body: reqBody,
    fetchImpl: deps.fetchImpl,
  });
  return shapeMergeResult(data);
}

const REVIEW_EVENTS: ReadonlySet<string> = new Set(["APPROVE", "REQUEST_CHANGES", "COMMENT"]);

/** POST /repos/{owner}/{repo}/pulls/{number}/reviews — submit a pull-request review. v1.90.
 *  EVENT-CONDITIONAL gating (`enforceGithubReviewEgressGates`): an APPROVE rides the
 *  SEPARATE default-deny SAFESPACE_GITHUB_APPROVE_TARGETS (it can unblock a protected-branch
 *  merge — a higher bar), while COMMENT / REQUEST_CHANGES ride the WRITE allowlist (same
 *  trust as an issue comment: they annotate / block but never advance the PR). `body` is
 *  agent-authored public text → outboundSanitize REJECT + F3a secret-shape; GitHub REQUIRES
 *  a non-empty body for COMMENT / REQUEST_CHANGES (422s without one) — validated locally —
 *  and allows an empty one only for APPROVE. Optional `commit_id` pins the reviewed head
 *  SHA (anti-race, mirrors merge's `sha`). Inline diff comments are NOT exposed in v1
 *  (deferred). Request is ALLOWLIST-CONSTRUCTED — only event/body/commit_id reach the wire. */
export async function githubCreatePullRequestReview(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const { owner, repo, number, event, body, commitId } = validateGithubReviewArgs(args);

  // Egress (EVENT-CONDITIONAL allowlist: APPROVE → approve list, else write list; + F3a
  // secret-shape) is PIPELINE-FIRED before this handler (githubCreatePullRequestReviewEgressDescriptor).
  // ALLOWLIST-CONSTRUCTED body — only event/body/commit_id reach the wire.
  const reqBody: Record<string, unknown> = { event };
  if (body !== undefined) {
    reqBody.body = outboundSanitize(body, {
      tool: "github_create_pull_request_review",
      maxBytes: BODY_MAX_BYTES,
    });
  }
  if (commitId !== undefined) reqBody.commit_id = commitId;

  const data = await githubApiWrite({
    token,
    method: "POST",
    path: `/repos/${owner}/${repo}/pulls/${number}/reviews`,
    body: reqBody,
    fetchImpl: deps.fetchImpl,
  });
  return shapeReview(data);
}

const LABEL_MAX_BYTES = 50; // GitHub label-name limit
const MAX_LABELS = 20; // blast-radius cap (one call can't create a flood of labels)

/** PUT /repos/{owner}/{repo}/issues/{number}/labels — REPLACE the full label set on an
 *  issue or PR (a PR is an issue for this endpoint). v1.84. Idempotent set-semantics: the
 *  given list becomes the labels (one primitive covers add + remove); `[]` clears all.
 *  A label name that doesn't exist is CREATED on the repo, so a name is agent-authored
 *  text on a public/private surface → per-label outboundSanitize REJECT + the same
 *  default-deny write-targets allowlist + F3a as the issue writes. Body is allowlist-
 *  constructed (ONLY `labels`). */
export async function githubSetIssueLabels(
  ctx: ToolContext,
  args: Record<string, unknown>,
  deps: GithubReadDeps = {},
): Promise<unknown> {
  const token = requireGithub(ctx).getAccessToken();
  const { owner, repo, number, rawLabels } = validateGithubSetIssueLabelsArgs(args);

  // Egress (default-deny repo allowlist + F3a secret-shape on the combined label text) is
  // PIPELINE-FIRED before this handler (githubSetIssueLabelsEgressDescriptor).
  // Per-label public-surface REJECT + byte-cap. Body is ALLOWLIST-CONSTRUCTED (only labels).
  const labels = rawLabels.map((l) =>
    outboundSanitize(l, { tool: "github_set_issue_labels", maxBytes: LABEL_MAX_BYTES }),
  );
  const data = await githubApiWrite({
    token,
    method: "PUT",
    path: `/repos/${owner}/${repo}/issues/${number}/labels`,
    body: { labels },
    fetchImpl: deps.fetchImpl,
  });
  return { number, labels: shapeLabels(data) };
}
