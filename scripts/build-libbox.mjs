/**
 * Build libbox — sing-box compiled as an Android library (gomobile) — and
 * install it as `src-tauri/gen/android/app/libs/libbox.aar`.
 *
 * The desktop app runs sing-box as a child process, but Android only hands the
 * TUN device to a `VpnService`, so the engine has to live inside the app
 * process. This is the same approach Hiddify and NekoBox take.
 *
 *   node scripts/build-libbox.mjs [version] [--force]
 *
 * Requirements: git, Go ≥ 1.24, JDK ≥ 17, ANDROID_HOME + ANDROID_NDK_HOME.
 * ABIS env limits architectures (e.g. ABIS="android/arm64" for quick local
 * builds); the default builds every ABI the app ships.
 */

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, rm, copyFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const OUT = path.join(ROOT, "src-tauri", "gen", "android", "app", "libs", "libbox.aar");

/** Pinned: bump deliberately, together with a smoke test on a device. */
const DEFAULT_VERSION = "1.13.19";

// Tags mirror sing-box's own cmd/internal/build_libbox (main variant, API 23).
const TAGS = [
  "with_gvisor", "with_quic", "with_wireguard", "with_utls",
  "with_naive_outbound", "with_clash_api", "badlinkname", "tfogo_checklinkname0",
  "with_tailscale", "ts_omit_logtail", "ts_omit_ssh", "ts_omit_drive",
  "ts_omit_taildrop", "ts_omit_webclient", "ts_omit_doctor", "ts_omit_capture",
  "ts_omit_kube", "ts_omit_aws", "ts_omit_synology", "ts_omit_bird",
].join(",");

function run(cmd, args, opts = {}) {
  console.log(`→ ${cmd} ${args.join(" ")}`);
  execFileSync(cmd, args, { stdio: "inherit", ...opts });
}

async function main() {
  const force = process.argv.includes("--force");
  const version = (process.argv.find((a) => /^v?\d+\.\d+/.test(a)) ?? DEFAULT_VERSION)
    .replace(/^v/, "");

  if (existsSync(OUT) && !force) {
    console.log(`✓ ${path.relative(ROOT, OUT)} уже существует — пропускаю (--force для пересборки)`);
    return;
  }
  for (const name of ["ANDROID_HOME", "ANDROID_NDK_HOME"]) {
    if (!process.env[name]) throw new Error(`не задана переменная ${name}`);
  }

  const work = path.join(tmpdir(), `aurora-libbox-${version}`);
  const src = path.join(work, "sing-box");
  if (!existsSync(path.join(src, "go.mod"))) {
    await rm(work, { recursive: true, force: true });
    await mkdir(work, { recursive: true });
    run("git", [
      "clone", "--depth", "1", "--branch", `v${version}`,
      "https://github.com/SagerNet/sing-box", src,
    ]);
  }

  // sing-box pins a gomobile fork; installing from inside the module dir
  // resolves the exact version its go.mod asks for.
  run("go", [
    "install",
    "github.com/sagernet/gomobile/cmd/gomobile",
    "github.com/sagernet/gomobile/cmd/gobind",
  ], { cwd: src });

  const gopath = execFileSync("go", ["env", "GOPATH"]).toString().trim();
  const gomobile = path.join(gopath, "bin", process.platform === "win32" ? "gomobile.exe" : "gomobile");
  const target = process.env.ABIS || "android";

  // Same flags as sing-box's build_libbox main variant, minus its jdk-17-only
  // check — any modern JDK compiles the generated bindings.
  run(gomobile, [
    "bind", "-v",
    "-o", "libbox.aar",
    "-target", target,
    "-androidapi", "23",
    "-javapkg=io.nekohasekai",
    "-libname=box",
    "-trimpath", "-buildvcs=false",
    "-ldflags", `-X github.com/sagernet/sing-box/constant.Version=v${version} -X internal/godebug.defaultGODEBUG=multipathtcp=0 -s -w -buildid= -checklinkname=0`,
    "-tags", TAGS,
    "./experimental/libbox",
  ], { cwd: src, env: { ...process.env, PATH: `${path.join(gopath, "bin")}${path.delimiter}${process.env.PATH}` } });

  await mkdir(path.dirname(OUT), { recursive: true });
  await copyFile(path.join(src, "libbox.aar"), OUT);
  console.log(`✓ libbox ${version} → ${path.relative(ROOT, OUT)}`);
}

main().catch((error) => {
  console.error(`✗ ${error.message}`);
  process.exit(1);
});
