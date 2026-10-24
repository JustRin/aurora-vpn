/**
 * Aurora's own changes to upstream sing-box, applied to a fresh checkout of a
 * release tag before it is built — for the desktop sidecar
 * (scripts/build-sing-box.mjs) and for Android's libbox
 * (scripts/build-libbox.mjs) alike, so both platforms run the same core.
 *
 * Every patch is a literal replacement that must match exactly once: a tag
 * whose code has moved fails the build loudly instead of shipping a core that
 * silently lacks the fix. A patch whose fix upstream already carries is
 * recognised and skipped.
 */

import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

/**
 * Appended to the core's version string, so the app's log and the about line
 * tell a patched core from an official one. Bump it whenever a patch changes:
 * the CI caches of the built cores are keyed on this file.
 */
export const PATCH_LEVEL = "aurora.1";

const PATCHES = [
  {
    id: "reality-keeps-x25519mlkem768",
    file: "common/tls/reality_client.go",
    /*
     * Upstream strips the X25519MLKEM768 share from every REALITY Client
     * Hello. REALITY servers since Xray 26.9 (XTLS/REALITY 8cdf7bf, "Reject
     * outdated/strange Client Hello that doesn't have X25519MLKEM768 before
     * optional X25519") refuse exactly such a hello: the client lands on the
     * camouflage site and the node never connects. Keeping the share as the
     * uTLS fingerprint carries it (chrome: X25519MLKEM768, then X25519) is
     * what Xray's own client does. Older servers keep working too — they take
     * the plain X25519 share, the one the auth key below is derived from.
     */
    find: [
      "\tfor _, extension := range uConn.Extensions {",
      "\t\tif ce, ok := extension.(*utls.SupportedCurvesExtension); ok {",
      "\t\t\tce.Curves = common.Filter(ce.Curves, func(curveID utls.CurveID) bool {",
      "\t\t\t\treturn curveID != utls.X25519MLKEM768",
      "\t\t\t})",
      "\t\t}",
      "\t\tif ks, ok := extension.(*utls.KeyShareExtension); ok {",
      "\t\t\tks.KeyShares = common.Filter(ks.KeyShares, func(share utls.KeyShare) bool {",
      "\t\t\t\treturn share.Group != utls.X25519MLKEM768",
      "\t\t\t})",
      "\t\t}",
      "\t}",
      "",
    ].join("\n"),
    replace: [
      "\t// Aurora: the hello keeps the X25519MLKEM768 share its fingerprint",
      "\t// carries; REALITY servers since Xray 26.9 reject a hello without it.",
      "",
    ].join("\n"),
    // Upstream fixed it if the file no longer filters the hybrid out.
    applied: (source) => !source.includes("!= utls.X25519MLKEM768"),
    // The filter was the file's only use of sing/common.
    after: (source) =>
      source.includes("common.")
        ? source
        : source.replace('\t"github.com/sagernet/sing/common"\n', ""),
  },
];

/** Apply every patch to the checkout at `src`; returns the ids applied. */
export async function patchSingBox(src) {
  const applied = [];
  for (const patch of PATCHES) {
    const file = path.join(src, patch.file);
    // Git on Windows may have checked the tree out with CRLF line endings.
    const original = await readFile(file, "utf8");
    const crlf = original.includes("\r\n");
    let source = crlf ? original.replaceAll("\r\n", "\n") : original;

    const count = source.split(patch.find).length - 1;
    if (count === 0 && patch.applied(source)) {
      console.log(`  · ${patch.id}: уже применён (или исправлен в апстриме), пропускаю`);
      continue;
    }
    if (count !== 1) {
      throw new Error(
        `патч ${patch.id}: ${patch.file} не совпал с ожидаемым (${count} совпадений) — ` +
          "код в этой версии sing-box сдвинулся, патч нужно обновить",
      );
    }
    source = source.replace(patch.find, patch.replace);
    if (patch.after) source = patch.after(source);
    await writeFile(file, crlf ? source.replaceAll("\n", "\r\n") : source);
    applied.push(patch.id);
    console.log(`  ✓ ${patch.id}`);
  }
  return applied;
}
