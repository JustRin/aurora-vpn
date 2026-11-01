#!/usr/bin/env node
/**
 * Скачивает wintun.dll — драйвер виртуального адаптера от авторов WireGuard — в
 * src-tauri/binaries. Нужен встроенному движку на Windows; sing-box несёт его внутри
 * себя. Файл идёт с подписью авторов, поэтому лежит отдельно, а не внутри exe.
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFile, mkdir, mkdtemp, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const binaries = path.join(root, "src-tauri/binaries");
const target = path.join(binaries, "wintun.dll");

const WINTUN_URL = "https://www.wintun.net/builds/wintun-0.14.1.zip";
const WINTUN_SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51";
const WINTUN_ARCH = "amd64";

if (await stat(target).then(() => true, () => false)) {
  console.log("wintun.dll уже есть");
  process.exit(0);
}

console.log(`скачиваю ${WINTUN_URL}`);
const response = await fetch(WINTUN_URL);
if (!response.ok) throw new Error(`wintun: HTTP ${response.status}`);
const zip = Buffer.from(await response.arrayBuffer());
const hash = createHash("sha256").update(zip).digest("hex");
if (hash !== WINTUN_SHA256) {
  throw new Error(`wintun: контрольная сумма не сошлась: ${hash}`);
}

await mkdir(binaries, { recursive: true });
const dir = await mkdtemp(path.join(tmpdir(), "wintun-"));
try {
  const archive = path.join(dir, "wintun.zip");
  await writeFile(archive, zip);
  // tar из состава Windows 10+ понимает zip; тот, что идёт с Git, нет — и первым
  // в PATH на машине разработчика и на раннере оказывается именно он.
  const tar = path.join(process.env.SystemRoot || "C:\\Windows", "System32", "tar.exe");
  execFileSync(tar, ["-xf", archive, "-C", dir], { stdio: "inherit" });
  await copyFile(path.join(dir, "wintun", "bin", WINTUN_ARCH, "wintun.dll"), target);
} finally {
  await rm(dir, { recursive: true, force: true });
}
console.log("wintun.dll получен, архив проверен по SHA-256");
