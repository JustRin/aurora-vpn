/**
 * Release notes from the commits since the previous release — the way
 * llama.cpp publishes them: every commit's title and body, linked to the
 * commit, plus a compare link at the end. Markdown goes to stdout; the release
 * workflow appends it under the download table.
 *
 *   node scripts/release-notes.mjs [ref]   # default: HEAD
 *
 * The previous release is the nearest `v*` tag reachable from the parent of
 * `ref`, so the list covers exactly what the tag adds. Links need the
 * repository name: `GITHUB_REPOSITORY` (owner/name) on CI, the origin remote
 * locally.
 *
 * Left out on purpose: merge commits (their content is the merged commits),
 * version-bump commits (the release is the version) and attribution trailers
 * (`Co-Authored-By`, `Signed-off-by`…), which mean nothing to someone reading
 * what changed.
 */

import { execFileSync } from "node:child_process";

const ref = process.argv[2] || "HEAD";

function git(...args) {
  return execFileSync("git", args, { encoding: "utf8" }).trim();
}

function tryGit(...args) {
  try {
    return git(...args);
  } catch {
    return "";
  }
}

function repository() {
  if (process.env.GITHUB_REPOSITORY) return process.env.GITHUB_REPOSITORY;
  const match = tryGit("remote", "get-url", "origin").match(/github\.com[:/](.+?)(?:\.git)?$/);
  return match ? match[1] : "";
}

/** Markdown that would otherwise turn a commit title into formatting. Backticks
 * stay: a code span in a title is deliberate. */
function escapeMarkdown(text) {
  return text.replace(/[\\*_[\]<>]/g, "\\$&");
}

const TRAILER = /^(co-authored-by|signed-off-by|assisted-by|reviewed-by|acked-by|tested-by):/i;

function withoutTrailers(body) {
  return body
    .split("\n")
    .filter((line) => !TRAILER.test(line.trim()))
    .join("\n")
    .trim();
}

/** «chore: bump version to 0.3.3» and nothing else. A bump that also carries
 * work («bump version to 0.3.2 and refactor…») is a real change and stays. */
const isVersionBump = (subject) =>
  /^(?:\w+(?:\([^)]*\))?!?:\s*)?bump version(?: to \S+)?$/i.test(subject.trim());

const repo = repository();
const previous = tryGit("describe", "--tags", "--abbrev=0", "--match", "v*", `${ref}^`);
const range = previous ? `${previous}..${ref}` : ref;

// One record per commit: hash, subject and body, split by control characters
// that cannot appear in a commit message.
const commits = tryGit("log", "--no-merges", "--reverse", "--format=%H%x1f%s%x1f%b%x1e", range)
  .split("\x1e")
  .map((record) => record.trim())
  .filter(Boolean)
  .map((record) => {
    const [hash, subject = "", body = ""] = record.split("\x1f");
    return { hash, subject: subject.trim(), body: withoutTrailers(body) };
  })
  .filter((commit) => !isVersionBump(commit.subject));

const lines = ["### What's changed / Что изменилось", ""];

if (commits.length === 0) {
  lines.push(previous ? `_No code changes since ${previous}._` : "_No commits._");
}
for (const commit of commits) {
  const short = commit.hash.slice(0, 7);
  const link = repo ? `[${short}](https://github.com/${repo}/commit/${commit.hash})` : `\`${short}\``;
  lines.push(`- **${escapeMarkdown(commit.subject)}** (${link})`);
  if (commit.body) {
    // Indented under the bullet, so the body's own bullets nest and its
    // paragraphs stay with their commit.
    lines.push("");
    for (const line of commit.body.split("\n")) lines.push(line ? `  ${line}` : "");
    lines.push("");
  }
}

if (previous && repo) {
  if (lines.at(-1) !== "") lines.push("");
  lines.push(`**Full changelog**: [${previous}...${ref}](https://github.com/${repo}/compare/${previous}...${ref})`);
}

process.stdout.write(`${lines.join("\n")}\n`);
