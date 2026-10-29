/**
 * Aurora's own changes to upstream sing-box, applied to a fresh checkout of a
 * release tag before it is built — for the desktop sidecar
 * (scripts/build-sing-box.mjs) and for Android's libbox
 * (scripts/build-libbox.mjs) alike, so both platforms run the same core.
 *
 * Every edit is a literal replacement that must match exactly once: a tag
 * whose code has moved fails the build loudly instead of shipping a core that
 * silently lacks the fix. The files a patch touches are restored to the tag
 * first, so a checkout kept from an earlier build — patched at an older
 * level — is patched from scratch rather than twice.
 */

import { execFileSync } from "node:child_process";
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";

/**
 * Appended to the core's version string, so the app's log and the about line
 * tell a patched core from an official one. Bump it whenever a patch changes:
 * the CI caches of the built cores are keyed on this file.
 */
export const PATCH_LEVEL = "aurora.2";

const lines = (...rows) => rows.join("\n");

const PATCHES = [
  {
    /*
     * REALITY servers since Xray 26.9 (XTLS/REALITY 8cdf7bf, "Reject
     * outdated/strange Client Hello that doesn't have X25519MLKEM768 before
     * optional X25519") refuse a hello without the X25519MLKEM768 share — the
     * one upstream strips. Keeping the share always is no answer either: the
     * hello then outgrows one TCP segment (≈1.8 KB against an MSS of ~1450),
     * and Russian TSPU boxes drop the second segment of such a hello on its
     * way to foreign hosting. The handshake never completes; the server logs
     * "failed to read client hello" after its 30 s timeout. Observed on
     * Rostelecom and Dom.ru in October 2026, on Xray 26.6 and 26.10 alike,
     * while the short hello of the same clients passed.
     *
     * So the hello starts short, as upstream sends it, and the share is added
     * only once the server has turned the short one away — it then hands the
     * connection to its camouflage target, and the client lands on a
     * certificate that is not REALITY's. That attempt fails with
     * errRealityWantsPostQuantum, the TLS dialer dials once more, and every
     * later connection of the outbound carries the share straight away.
     */
    id: "reality-post-quantum-on-demand",
    edits: [
      {
        file: "common/tls/reality_client.go",
        find: lines('\t"strings"', '\t"time"', ""),
        replace: lines('\t"strings"', '\t"sync/atomic"', '\t"time"', ""),
      },
      {
        file: "common/tls/reality_client.go",
        find: lines("\tpublicKey []byte", "\tshortID   [8]byte", "}", ""),
        replace: lines(
          "\tpublicKey []byte",
          "\tshortID   [8]byte",
          "\t// Aurora: set once the server has turned away a hello without the",
          "\t// post-quantum key share; shared by every clone of this config.",
          "\tpostQuantum *atomic.Bool",
          "}",
          "",
        ),
      },
      {
        file: "common/tls/reality_client.go",
        find: "&RealityClientConfig{ctx, uClient.(*UTLSClientConfig), publicKey, shortID}",
        replace: "&RealityClientConfig{ctx, uClient.(*UTLSClientConfig), publicKey, shortID, new(atomic.Bool)}",
      },
      {
        file: "common/tls/reality_client.go",
        find: lines("\t\te.publicKey,", "\t\te.shortID,", "\t}"),
        replace: lines("\t\te.publicKey,", "\t\te.shortID,", "\t\te.postQuantum,", "\t}"),
      },
      {
        file: "common/tls/reality_client.go",
        find: lines(
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
        ),
        replace: lines(
          "\t// Aurora: the short hello fits one TCP segment; the X25519MLKEM768",
          "\t// share stays out until the server asks for it (errRealityWantsPostQuantum).",
          "\tpostQuantum := e.postQuantum.Load()",
          "\tif !postQuantum {",
          "\t\tfor _, extension := range uConn.Extensions {",
          "\t\t\tif ce, ok := extension.(*utls.SupportedCurvesExtension); ok {",
          "\t\t\t\tce.Curves = common.Filter(ce.Curves, func(curveID utls.CurveID) bool {",
          "\t\t\t\t\treturn curveID != utls.X25519MLKEM768",
          "\t\t\t\t})",
          "\t\t\t}",
          "\t\t\tif ks, ok := extension.(*utls.KeyShareExtension); ok {",
          "\t\t\t\tks.KeyShares = common.Filter(ks.KeyShares, func(share utls.KeyShare) bool {",
          "\t\t\t\t\treturn share.Group != utls.X25519MLKEM768",
          "\t\t\t\t})",
          "\t\t\t}",
          "\t\t}",
          "\t}",
          "",
        ),
      },
      {
        file: "common/tls/reality_client.go",
        find: lines(
          "\terr = uConn.HandshakeContext(ctx)",
          "\tif err != nil {",
          "\t\treturn nil, err",
          "\t}",
        ),
        replace: lines(
          "\terr = uConn.HandshakeContext(ctx)",
          "\tif err != nil {",
          "\t\t// Aurora: landed on the target and its chain did not verify here —",
          "\t\t// a rejection of the short hello all the same.",
          "\t\tif !postQuantum && verifier.landed {",
          "\t\t\te.postQuantum.Store(true)",
          "\t\t\treturn nil, errRealityWantsPostQuantum",
          "\t\t}",
          "\t\treturn nil, err",
          "\t}",
        ),
      },
      {
        file: "common/tls/reality_client.go",
        find: lines(
          "\tif !verifier.verified {",
          "\t\tgo realityClientFallback(e.ctx, uConn, e.uClient.ServerName(), e.uClient.id)",
          '\t\treturn nil, E.New("reality verification failed")',
          "\t}",
        ),
        replace: lines(
          "\tif !verifier.verified {",
          "\t\tgo realityClientFallback(e.ctx, uConn, e.uClient.ServerName(), e.uClient.id)",
          "\t\tif !postQuantum {",
          "\t\t\te.postQuantum.Store(true)",
          "\t\t\treturn nil, errRealityWantsPostQuantum",
          "\t\t}",
          '\t\treturn nil, E.New("reality verification failed")',
          "\t}",
        ),
      },
      {
        file: "common/tls/reality_client.go",
        find: lines("\tauthKey    []byte", "\tverified   bool", "}"),
        replace: lines(
          "\tauthKey    []byte",
          "\tverified   bool",
          "\t// Aurora: the server answered with a certificate other than REALITY's,",
          "\t// i.e. it turned the hello away and handed the connection to its target.",
          "\tlanded bool",
          "}",
        ),
      },
      {
        file: "common/tls/reality_client.go",
        find: lines("\topts := x509.VerifyOptions{", "\t\tDNSName:       c.serverName,"),
        replace: lines("\tc.landed = true", "\topts := x509.VerifyOptions{", "\t\tDNSName:       c.serverName,"),
      },
      {
        file: "common/tls/client.go",
        find: "func NewDialer(dialer N.Dialer, config Config) Dialer {",
        replace: lines(
          "// Aurora: a REALITY server turned away the short hello (reality_client.go);",
          "// the config now carries the post-quantum key share, so dialling again works.",
          'var errRealityWantsPostQuantum = errors.New("reality: the server wants the post-quantum key share")',
          "",
          "func NewDialer(dialer N.Dialer, config Config) Dialer {",
        ),
      },
      {
        file: "common/tls/client.go",
        find: lines(
          "\ttlsConn, err := aTLS.ClientHandshake(ctx, conn, d.config)",
          "\tif err != nil {",
          "\t\tconn.Close()",
        ),
        replace: lines(
          "\ttlsConn, err := aTLS.ClientHandshake(ctx, conn, d.config)",
          "\tif err != nil {",
          "\t\tconn.Close()",
          "\t\tif errors.Is(err, errRealityWantsPostQuantum) {",
          "\t\t\treturn d.dialContext(ctx, destination, echRetry)",
          "\t\t}",
        ),
      },
    ],
  },
];

/** Apply every patch to the checkout at `src`; returns the ids applied. */
export async function patchSingBox(src) {
  const files = [...new Set(PATCHES.flatMap((patch) => patch.edits.map((edit) => edit.file)))];
  execFileSync("git", ["checkout", "--", ...files], { cwd: src, stdio: "inherit" });

  const applied = [];
  for (const patch of PATCHES) {
    for (const edit of patch.edits) {
      const file = path.join(src, edit.file);
      // Git on Windows may have checked the tree out with CRLF line endings.
      const original = await readFile(file, "utf8");
      const crlf = original.includes("\r\n");
      let source = crlf ? original.replaceAll("\r\n", "\n") : original;

      const count = source.split(edit.find).length - 1;
      if (count !== 1) {
        throw new Error(
          `патч ${patch.id}: ${edit.file} не совпал с ожидаемым (${count} совпадений) — ` +
            "код в этой версии sing-box сдвинулся, патч нужно обновить",
        );
      }
      source = source.replace(edit.find, () => edit.replace);
      await writeFile(file, crlf ? source.replaceAll("\n", "\r\n") : source);
    }
    applied.push(patch.id);
    console.log(`  ✓ ${patch.id}`);
  }
  return applied;
}
