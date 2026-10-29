/**
 * Build the desktop sing-box sidecar from upstream source with Aurora's
 * patches (scripts/sing-box-patches.mjs), replacing the official binary that
 * `npm run fetch-core` installs.
 *
 * Why not the official binary: upstream sing-box always strips the
 * X25519MLKEM768 key share from REALITY handshakes, and REALITY servers since
 * Xray 26.9 reject exactly those — every VLESS-REALITY node of a panel that
 * updates its core stops connecting. The patched core sends the short hello
 * first and adds the share only when the server turns it away. Android's
 * libbox is built from source anyway and gets the same patches, so both
 * platforms run one core.
 *
 *   node scripts/build-sing-box.mjs [version]   # default: latest stable tag
 *
 * Needs git and Go (the version upstream builds that tag with, see
 * .github/workflows/build.yml there). `CORE_TARGET` picks another
 * architecture of the same OS, as in fetch-core.mjs. Linker flags come from
 * the checkout's own `release/LDFLAGS`; the build tags are only the features
 * the app's config generator uses (TAGS below), which makes the binary less
 * than half the official one.
 */

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { copyFile, mkdir, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { PATCH_LEVEL, patchSingBox } from "./sing-box-patches.mjs";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT_DIR = path.join(ROOT, "src-tauri", "binaries");
const REPO = "https://github.com/SagerNet/sing-box";

/** Node platform/arch → Go target + Rust target triple (as in fetch-core.mjs). */
const TARGETS = {
  "win32-x64": { goos: "windows", goarch: "amd64", triple: "x86_64-pc-windows-msvc" },
  "win32-arm64": { goos: "windows", goarch: "arm64", triple: "aarch64-pc-windows-msvc" },
  "linux-x64": { goos: "linux", goarch: "amd64", triple: "x86_64-unknown-linux-gnu" },
  "linux-arm64": { goos: "linux", goarch: "arm64", triple: "aarch64-unknown-linux-gnu" },
  "darwin-x64": { goos: "darwin", goarch: "amd64", triple: "x86_64-apple-darwin" },
  "darwin-arm64": { goos: "darwin", goarch: "arm64", triple: "aarch64-apple-darwin" },
};

/**
 * What src-tauri/src/core/config.rs can emit, and nothing else: the gVisor
 * TUN stack, QUIC (Hysteria2, TUIC, DoQ/DoH3), WireGuard endpoints, uTLS and
 * REALITY, and the Clash API the app drives the core through. Upstream's
 * release set adds Tailscale, cloudflared, OpenVPN, ACME and more — another
 * 40 MB of binary and memory for nothing. A feature the generator starts
 * using needs its tag here, or the core refuses the document at start-up.
 */
const TAGS = [
  "with_gvisor", "with_quic", "with_wireguard", "with_utls", "with_clash_api",
  "badlinkname", "tfogo_checklinkname0",
].join(",");

function run(cmd, args, opts = {}) {
  console.log(`→ ${cmd} ${args.join(" ")}`);
  execFileSync(cmd, args, { stdio: "inherit", ...opts });
}

/** Highest stable `vX.Y.Z` tag — no API call, so no rate limit to hit. */
function latestStableTag() {
  const out = execFileSync("git", ["ls-remote", "--tags", "--refs", REPO, "v*"]).toString();
  const versions = out
    .split("\n")
    .map((line) => line.split("refs/tags/v")[1]?.trim())
    .filter((v) => v && /^\d+\.\d+\.\d+$/.test(v))
    .map((v) => ({ v, parts: v.split(".").map(Number) }));
  versions.sort((a, b) => a.parts[0] - b.parts[0] || a.parts[1] - b.parts[1] || a.parts[2] - b.parts[2]);
  const last = versions.at(-1);
  if (!last) throw new Error("не удалось узнать последнюю версию sing-box");
  return last.v;
}

async function releaseFile(src, name) {
  const file = path.join(src, "release", name);
  return existsSync(file) ? (await readFile(file, "utf8")).trim() : null;
}

async function main() {
  const key = process.env.CORE_TARGET || `${process.platform}-${process.arch}`;
  const target = TARGETS[key];
  if (!target) throw new Error(`платформа ${key} не поддерживается этим скриптом`);

  const version = (process.argv[2] ?? process.env.SINGBOX_VERSION ?? latestStableTag()).replace(/^v/, "");
  console.log(`→ sing-box ${version} из исходников + патчи Aurora (${PATCH_LEVEL}) для ${key}`);

  // One checkout per version, kept between runs: patching restores the files
  // it touches to the tag first.
  const src = path.join(tmpdir(), `aurora-sing-box-${version}`);
  if (!existsSync(path.join(src, "go.mod"))) {
    await rm(src, { recursive: true, force: true });
    run("git", ["-c", "advice.detachedHead=false", "clone", "--depth", "1", "--branch", `v${version}`, REPO, src]);
  }
  await patchSingBox(src);

  const sharedLdflags = (await releaseFile(src, "LDFLAGS")) ?? "-checklinkname=0";
  const exe = target.goos === "windows" ? "sing-box.exe" : "sing-box";
  const built = path.join(src, "dist", `${target.goos}-${target.goarch}`, exe);

  run(
    "go",
    [
      "build", "-trimpath",
      "-o", built,
      "-tags", TAGS,
      "-ldflags",
      `-X github.com/sagernet/sing-box/constant.Version=${version}-${PATCH_LEVEL} ${sharedLdflags} -s -w -buildid=`,
      "./cmd/sing-box",
    ],
    {
      cwd: src,
      env: {
        ...process.env,
        // Pure Go everywhere, as upstream builds Windows and its purego Linux
        // assets: one runner can cross-build the other architecture.
        CGO_ENABLED: "0",
        GOOS: target.goos,
        GOARCH: target.goarch,
        GOTOOLCHAIN: "local",
      },
    },
  );

  await mkdir(OUT_DIR, { recursive: true });
  const suffix = target.goos === "windows" ? ".exe" : "";
  const dest = path.join(OUT_DIR, `sing-box-${target.triple}${suffix}`);
  await copyFile(built, dest);
  if (process.platform !== "win32") execFileSync("chmod", ["+x", dest]);

  const { size } = await stat(dest);
  console.log(`✓ sing-box ${version}-${PATCH_LEVEL}: ${path.relative(ROOT, dest)} (${(size / 1024 / 1024).toFixed(1)} МБ)`);
}

main().catch((error) => {
  console.error(`✗ ${error.message}`);
  process.exit(1);
});
