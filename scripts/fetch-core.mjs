/**
 * Download the sing-box core for the host platform and install it as a Tauri
 * sidecar (`src-tauri/binaries/sing-box-<rust-target-triple>`).
 *
 * The binary is ~45 MB and therefore not committed; run `npm run fetch-core`
 * after a fresh clone.
 *
 *   node scripts/fetch-core.mjs [version]   # default: latest release
 */

import { execFileSync } from "node:child_process";
import { createWriteStream } from "node:fs";
import { mkdir, mkdtemp, readdir, copyFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { pipeline } from "node:stream/promises";
import { Readable } from "node:stream";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = path.join(ROOT, "src-tauri", "binaries");

/** Node platform/arch → sing-box asset suffix + Rust target triple. */
const TARGETS = {
  "win32-x64": { asset: "windows-amd64", ext: "zip", triple: "x86_64-pc-windows-msvc" },
  "win32-arm64": { asset: "windows-arm64", ext: "zip", triple: "aarch64-pc-windows-msvc" },
  "linux-x64": { asset: "linux-amd64", ext: "tar.gz", triple: "x86_64-unknown-linux-gnu" },
  "linux-arm64": { asset: "linux-arm64", ext: "tar.gz", triple: "aarch64-unknown-linux-gnu" },
  "darwin-x64": { asset: "darwin-amd64", ext: "tar.gz", triple: "x86_64-apple-darwin" },
  "darwin-arm64": { asset: "darwin-arm64", ext: "tar.gz", triple: "aarch64-apple-darwin" },
};

/** Xray publishes one zip per platform, named differently from sing-box. */
const XRAY_ASSETS = {
  "win32-x64": "Xray-windows-64.zip",
  "win32-arm64": "Xray-windows-arm64-v8a.zip",
  "linux-x64": "Xray-linux-64.zip",
  "linux-arm64": "Xray-linux-arm64-v8a.zip",
  "darwin-x64": "Xray-macos-64.zip",
  "darwin-arm64": "Xray-macos-arm64-v8a.zip",
};

async function latestTag(repo) {
  // `GITHUB_TOKEN` lifts the anonymous rate limit on CI runners, whose shared
  // egress addresses exhaust it quickly; locally it is simply absent.
  const auth = process.env.GITHUB_TOKEN
    ? { Authorization: `Bearer ${process.env.GITHUB_TOKEN}` }
    : {};
  const response = await fetch(
    `https://api.github.com/repos/${repo}/releases/latest`,
    { headers: { "User-Agent": "aurora-vpn-setup", ...auth } },
  );
  if (!response.ok) throw new Error(`GitHub API ответил ${response.status}`);
  const body = await response.json();
  return String(body.tag_name);
}

async function download(url, dest) {
  const response = await fetch(url, { headers: { "User-Agent": "aurora-vpn-setup" } });
  if (!response.ok) throw new Error(`не удалось скачать ${url}: ${response.status}`);
  await pipeline(Readable.fromWeb(response.body), createWriteStream(dest));
}

async function extract(archive, into) {
  if (archive.endsWith(".zip")) {
    if (process.platform === "win32") {
      execFileSync(
        "powershell",
        ["-NoProfile", "-Command", `Expand-Archive -LiteralPath '${archive}' -DestinationPath '${into}' -Force`],
        { stdio: "inherit" },
      );
    } else {
      execFileSync("unzip", ["-o", archive, "-d", into], { stdio: "inherit" });
    }
  } else {
    execFileSync("tar", ["-xzf", archive, "-C", into], { stdio: "inherit" });
  }
}

/** sing-box archives nest the binary one directory down. */
async function findBinary(dir, name) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const found = await findBinary(full, name);
      if (found) return found;
    } else if (entry.name === name) {
      return full;
    }
  }
  return null;
}

/** Download one engine and install it under its Rust target-triple name. */
async function install({ label, url, exeStem, triple }) {
  const work = await mkdtemp(path.join(tmpdir(), "aurora-core-"));
  try {
    const ext = url.endsWith(".tar.gz") ? "tar.gz" : "zip";
    const archive = path.join(work, `core.${ext}`);
    await download(url, archive);
    await extract(archive, work);

    const exeName = process.platform === "win32" ? `${exeStem}.exe` : exeStem;
    const found = await findBinary(work, exeName);
    if (!found) throw new Error(`в архиве не найден бинарник ${exeStem}`);

    await mkdir(OUT_DIR, { recursive: true });
    const suffix = process.platform === "win32" ? ".exe" : "";
    const dest = path.join(OUT_DIR, `${exeStem}-${triple}${suffix}`);
    await copyFile(found, dest);
    if (process.platform !== "win32") {
      execFileSync("chmod", ["+x", dest]);
    }

    const { size } = await stat(dest);
    console.log(`✓ ${label}: ${path.relative(ROOT, dest)} (${(size / 1024 / 1024).toFixed(1)} МБ)`);
  } finally {
    await rm(work, { recursive: true, force: true });
  }
}

async function main() {
  // `CORE_TARGET` lets CI fetch cores for a cross-compiled architecture of the
  // same OS (e.g. darwin-x64 from an arm64 runner); locally it is absent.
  const key = process.env.CORE_TARGET || `${process.platform}-${process.arch}`;
  const target = TARGETS[key];
  if (!target) {
    throw new Error(`платформа ${key} не поддерживается этим скриптом`);
  }

  const pinned = process.argv[2]?.replace(/^v/, "");
  const singboxVersion = pinned ?? (await latestTag("SagerNet/sing-box")).replace(/^v/, "");
  console.log(`→ sing-box ${singboxVersion} для ${key}`);
  await install({
    label: "sing-box",
    url:
      `https://github.com/SagerNet/sing-box/releases/download/v${singboxVersion}` +
      `/sing-box-${singboxVersion}-${target.asset}.${target.ext}`,
    exeStem: "sing-box",
    triple: target.triple,
  });

  // Second engine: needed for VLESS Encryption and XHTTP, which sing-box does
  // not implement. Optional — the app runs without it, minus those nodes.
  const xrayAsset = XRAY_ASSETS[key];
  if (!xrayAsset) {
    console.log(`! Xray для ${key} не публикуется — пропускаю`);
    return;
  }
  const xrayTag = await latestTag("XTLS/Xray-core");
  console.log(`→ Xray ${xrayTag} для ${key}`);
  await install({
    label: "Xray",
    url: `https://github.com/XTLS/Xray-core/releases/download/${xrayTag}/${xrayAsset}`,
    exeStem: "xray",
    triple: target.triple,
  });
}

main().catch((error) => {
  console.error(`✗ ${error.message}`);
  process.exit(1);
});
