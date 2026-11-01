#!/usr/bin/env node
/**
 * Стенд: движок против настоящих серверов.
 *
 * Поднимает локально Xray и sing-box как серверы всех протоколов и гоняет через
 * aura-engine настоящий трафик до локального HTTP-сервера. Сверяет содержимое
 * байт в байт: юнит-тесты не докажут совместимость с чужой реализацией, а это
 * докажет. Заодно снимает сравнение ресурсов с sing-box на той же нагрузке.
 *
 *   node engine/tests/stand.mjs            — все протоколы
 *   node engine/tests/stand.mjs bench      — плюс замер против sing-box
 *
 * Использует xray и sing-box из src-tauri/binaries; пишет только во временный каталог.
 */

import { execFileSync, spawn } from "node:child_process";
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync, existsSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(here, "../..");
const triple = "x86_64-pc-windows-msvc";
const ENGINE = process.env.STAND_ENGINE || path.join(root, "engine/target/release/aura-engine.exe");
const XRAY = path.join(root, `src-tauri/binaries/xray-${triple}.exe`);
const SINGBOX = path.join(root, `src-tauri/binaries/sing-box-${triple}.exe`);
const bench = process.argv.includes("bench");

const dir = mkdtempSync(path.join(tmpdir(), "aura-stand-"));
const children = [];
const UUID = "b831381d-6324-4d53-ad4f-8cda48b30811";
const PASSWORD = "stand-password";
const SECRET = "stand-secret";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function start(exe, args, label) {
  const child = spawn(exe, args, { cwd: dir, stdio: ["ignore", "pipe", "pipe"] });
  const lines = [];
  const eat = (b) => {
    for (const line of String(b).split(/\r?\n/)) if (line) lines.push(line);
    if (lines.length > 400) lines.splice(0, 200);
  };
  child.stdout.on("data", eat);
  child.stderr.on("data", eat);
  child.label = label;
  child.lines = lines;
  children.push(child);
  return child;
}

function cleanup() {
  for (const c of children) {
    try {
      c.kill();
    } catch {}
  }
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {}
}
process.on("exit", cleanup);

async function waitPort(port, ms = 8000) {
  const until = Date.now() + ms;
  while (Date.now() < until) {
    const ok = await new Promise((res) => {
      const s = net.connect({ host: "127.0.0.1", port }, () => {
        s.destroy();
        res(true);
      });
      s.on("error", () => res(false));
    });
    if (ok) return true;
    await sleep(100);
  }
  return false;
}

// ------------------------------------------------------------- цель трафика
const PAYLOAD = randomBytes(8 * 1024 * 1024);
const PAYLOAD_SHA = createHash("sha256").update(PAYLOAD).digest("hex");

const origin = http.createServer((req, res) => {
  if (req.url === "/big") {
    res.writeHead(200, { "content-length": PAYLOAD.length });
    res.end(PAYLOAD);
  } else if (req.url === "/echo" && req.method === "POST") {
    const parts = [];
    req.on("data", (d) => parts.push(d));
    req.on("end", () => {
      const body = Buffer.concat(parts);
      res.writeHead(200, { "content-length": body.length });
      res.end(body);
    });
  } else if (req.url === "/generate_204") {
    res.writeHead(204);
    res.end();
  } else {
    res.writeHead(200, { "content-length": 2 });
    res.end("ok");
  }
});
await new Promise((r) => origin.listen(0, "127.0.0.1", r));
const ORIGIN_PORT = origin.address().port;
const TARGET = `127.0.0.1:${ORIGIN_PORT}`;

// ------------------------------------------------------------------ сертификат
function selfSigned() {
  const out = execFileSync(SINGBOX, ["generate", "tls-keypair", "localhost", "-m", "1"], { cwd: dir }).toString();
  const key = out.match(/-----BEGIN PRIVATE KEY-----[\s\S]+?-----END PRIVATE KEY-----/)[0];
  const cert = out.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/)[0];
  writeFileSync(path.join(dir, "key.pem"), key);
  writeFileSync(path.join(dir, "cert.pem"), cert);
}

function realityKeys() {
  const out = execFileSync(XRAY, ["x25519"], { cwd: dir }).toString();
  const priv = out.match(/Private(?:\s*key|Key)?:\s*(\S+)/i)[1];
  const pub = out.match(/(?:Public(?:\s*key|Key)?|Password(?:\s*\(PublicKey\))?):\s*(\S+)/i)[1];
  return { priv, pub };
}

// ---------------------------------------------------------------------- сервер
const P = {
  vless_reality_vision: 39001,
  vless_reality: 39002,
  vless_tls_vision: 39003,
  vless_ws_tls: 39004,
  vless_plain: 39005,
  trojan_tls: 39006,
  trojan_ws: 39007,
  vmess_plain: 39008,
  vmess_ws: 39009,
  ss_chacha: 39010,
  ss_aes256: 39011,
  ss_aes128: 39012,
  vless_httpupgrade: 39013,
  hy2: 39014,
  mask: 39015,
};

function xrayConfig(keys) {
  const tls = {
    security: "tls",
    tlsSettings: { certificates: [{ certificateFile: path.join(dir, "cert.pem"), keyFile: path.join(dir, "key.pem") }], alpn: ["http/1.1"] },
  };
  const reality = {
    security: "reality",
    realitySettings: {
      show: false,
      dest: `127.0.0.1:${P.mask}`,
      serverNames: ["localhost"],
      privateKey: keys.priv,
      shortIds: ["abcd1234"],
    },
  };
  const client = (flow) => ({ id: UUID, ...(flow ? { flow } : {}) });
  const vless = (port, stream, flow, tag) => ({
    tag,
    listen: "127.0.0.1",
    port,
    protocol: "vless",
    settings: { clients: [client(flow)], decryption: "none" },
    streamSettings: stream,
  });
  return {
    log: { loglevel: "warning" },
    inbounds: [
      vless(P.vless_reality_vision, { network: "tcp", ...reality }, "xtls-rprx-vision", "a"),
      vless(P.vless_reality, { network: "tcp", ...reality }, "", "b"),
      vless(P.vless_tls_vision, { network: "tcp", ...tls }, "xtls-rprx-vision", "c"),
      vless(P.vless_ws_tls, { network: "ws", wsSettings: { path: "/ws" }, ...tls }, "", "d"),
      vless(P.vless_plain, { network: "tcp" }, "", "e"),
      vless(P.vless_httpupgrade, { network: "httpupgrade", httpupgradeSettings: { path: "/up" } }, "", "f"),
      {
        tag: "g",
        listen: "127.0.0.1",
        port: P.trojan_tls,
        protocol: "trojan",
        settings: { clients: [{ password: PASSWORD }] },
        streamSettings: { network: "tcp", ...tls },
      },
      {
        tag: "h",
        listen: "127.0.0.1",
        port: P.trojan_ws,
        protocol: "trojan",
        settings: { clients: [{ password: PASSWORD }] },
        streamSettings: { network: "ws", wsSettings: { path: "/tr" }, ...tls },
      },
      {
        tag: "i",
        listen: "127.0.0.1",
        port: P.vmess_plain,
        protocol: "vmess",
        settings: { clients: [{ id: UUID }] },
        streamSettings: { network: "tcp" },
      },
      {
        tag: "j",
        listen: "127.0.0.1",
        port: P.vmess_ws,
        protocol: "vmess",
        settings: { clients: [{ id: UUID }] },
        streamSettings: { network: "ws", wsSettings: { path: "/vm" } },
      },
      ...[
        ["k", P.ss_chacha, "chacha20-ietf-poly1305"],
        ["l", P.ss_aes256, "aes-256-gcm"],
        ["m", P.ss_aes128, "aes-128-gcm"],
      ].map(([tag, port, method]) => ({
        tag,
        listen: "127.0.0.1",
        port,
        protocol: "shadowsocks",
        settings: { method, password: PASSWORD, network: "tcp,udp" },
      })),
    ],
    outbounds: [{ protocol: "freedom", tag: "direct" }],
  };
}

function singboxServerConfig() {
  return {
    log: { level: "warn" },
    inbounds: [
      {
        type: "hysteria2",
        tag: "hy2-in",
        listen: "127.0.0.1",
        listen_port: P.hy2,
        users: [{ password: PASSWORD }],
        tls: { enabled: true, alpn: ["h3"], certificate_path: path.join(dir, "cert.pem"), key_path: path.join(dir, "key.pem") },
      },
    ],
    outbounds: [{ type: "direct" }],
  };
}

// ---------------------------------------------------------------------- клиент
function outbounds(keys) {
  const tlsOn = { enabled: true, server_name: "localhost", insecure: true };
  const utls = (fp) => ({ ...tlsOn, utls: { enabled: true, fingerprint: fp } });
  const reality = (fp) => ({
    enabled: true,
    server_name: "localhost",
    utls: { enabled: true, fingerprint: fp },
    reality: { enabled: true, public_key: keys.pub, short_id: "abcd1234" },
  });
  const base = (tag, type, port, extra) => ({ tag, type, server: "127.0.0.1", server_port: port, ...extra });
  const vless = { uuid: UUID, packet_encoding: "xudp" };
  return [
    base("vless-reality-vision-chrome", "vless", P.vless_reality_vision, { ...vless, flow: "xtls-rprx-vision", tls: reality("chrome") }),
    base("vless-reality-vision-firefox", "vless", P.vless_reality_vision, { ...vless, flow: "xtls-rprx-vision", tls: reality("firefox") }),
    base("vless-reality-vision-safari", "vless", P.vless_reality_vision, { ...vless, flow: "xtls-rprx-vision", tls: reality("safari") }),
    base("vless-reality", "vless", P.vless_reality, { ...vless, tls: reality("chrome") }),
    base("vless-tls-vision", "vless", P.vless_tls_vision, { ...vless, flow: "xtls-rprx-vision", tls: utls("chrome") }),
    base("vless-ws-tls", "vless", P.vless_ws_tls, { ...vless, tls: utls("chrome"), transport: { type: "ws", path: "/ws", headers: { Host: "localhost" } } }),
    base("vless-plain", "vless", P.vless_plain, vless),
    base("vless-httpupgrade", "vless", P.vless_httpupgrade, { ...vless, transport: { type: "httpupgrade", path: "/up" } }),
    base("trojan-tls", "trojan", P.trojan_tls, { password: PASSWORD, tls: utls("chrome") }),
    base("trojan-ws", "trojan", P.trojan_ws, { password: PASSWORD, tls: utls("android"), transport: { type: "ws", path: "/tr" } }),
    base("vmess-plain", "vmess", P.vmess_plain, { uuid: UUID, security: "auto", alter_id: 0 }),
    base("vmess-ws", "vmess", P.vmess_ws, { uuid: UUID, security: "auto", alter_id: 0, transport: { type: "ws", path: "/vm" } }),
    base("ss-chacha", "shadowsocks", P.ss_chacha, { method: "chacha20-ietf-poly1305", password: PASSWORD }),
    base("ss-aes256", "shadowsocks", P.ss_aes256, { method: "aes-256-gcm", password: PASSWORD }),
    base("ss-aes128", "shadowsocks", P.ss_aes128, { method: "aes-128-gcm", password: PASSWORD }),
    base("hysteria2", "hysteria2", P.hy2, { password: PASSWORD, tls: { enabled: true, server_name: "localhost", insecure: true, alpn: ["h3"] } }),
  ];
}

function clientConfig(nodes, mixedPort, apiPort, finalTag) {
  const tags = nodes.map((n) => n.tag);
  return {
    log: { level: "info" },
    dns: { servers: [{ type: "udp", tag: "dns-direct", server: "1.1.1.1" }], final: "dns-direct" },
    inbounds: [{ type: "mixed", tag: "mixed-in", listen: "127.0.0.1", listen_port: mixedPort }],
    outbounds: [
      ...nodes,
      { type: "urltest", tag: "auto", outbounds: tags, url: `http://${TARGET}/generate_204`, interval: "3m", tolerance: 50 },
      { type: "selector", tag: "proxy", outbounds: ["auto", ...tags], default: finalTag, interrupt_exist_connections: false },
      { type: "direct", tag: "direct" },
    ],
    route: { final: "proxy", default_domain_resolver: "dns-direct" },
    experimental: { clash_api: { external_controller: `127.0.0.1:${apiPort}`, secret: SECRET, default_mode: "Rule" } },
  };
}

// ------------------------------------------------------------- SOCKS-клиент
function socksConnect(mixedPort, host, port) {
  return new Promise((resolve, reject) => {
    const s = net.connect({ host: "127.0.0.1", port: mixedPort });
    let stage = 0;
    let buf = Buffer.alloc(0);
    s.on("error", reject);
    s.on("connect", () => s.write(Buffer.from([5, 1, 0])));
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (stage === 0 && buf.length >= 2) {
        buf = buf.subarray(2);
        stage = 1;
        const ip = host.split(".").map(Number);
        s.write(Buffer.from([5, 1, 0, 1, ...ip, port >> 8, port & 255]));
      }
      if (stage === 1 && buf.length >= 10) {
        s.removeListener("data", onData);
        resolve(s);
      }
    };
    s.on("data", onData);
  });
}

function fetchThrough(mixedPort, urlPath, method = "GET", body = null) {
  return new Promise(async (resolve, reject) => {
    let s;
    try {
      s = await socksConnect(mixedPort, "127.0.0.1", ORIGIN_PORT);
    } catch (e) {
      return reject(e);
    }
    const chunks = [];
    const timer = setTimeout(() => {
      // Кто держит соединение: состояния TCP в момент зависания.
      if (process.env.STAND_DIAG) {
        const local = s.localPort;
        const table = execFileSync("netstat", ["-ano", "-p", "TCP"]).toString().split(/\r?\n/);
        console.log("--- завис: клиентский порт", local, "получено", got, "из", wanted);
        for (const line of table) if (/:390(0|1|5)\d\s/.test(line) && !/LISTENING|TIME_WAIT/.test(line)) console.log(line.trim());
      }
      s.destroy();
      reject(new Error("таймаут"));
    }, Number(process.env.STAND_TIMEOUT || 30000));
    let got = 0;
    let wanted = -1;
    s.on("data", (d) => {
      chunks.push(d);
      got += d.length;
      if (wanted < 0) {
        const all = Buffer.concat(chunks);
        const split = all.indexOf("\r\n\r\n");
        if (split >= 0) {
          const m = all.subarray(0, split).toString().match(/content-length: (\d+)/i);
          wanted = split + 4 + (m ? Number(m[1]) : 0);
        }
      }
      // Конец ответа по длине: иначе меряется таймер закрытия у сервера, а не скорость.
      if (wanted >= 0 && got >= wanted && !process.env.STAND_CLOSE) s.destroy();
    });
    s.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    s.on("close", () => {
      clearTimeout(timer);
      const all = Buffer.concat(chunks);
      const split = all.indexOf("\r\n\r\n");
      if (split < 0) return reject(new Error(`нет ответа (${all.length} Б)`));
      resolve({ head: all.subarray(0, split).toString(), body: all.subarray(split + 4) });
    });
    const head = `${method} ${urlPath} HTTP/1.1\r\nHost: origin\r\nConnection: close\r\n${
      body ? `Content-Length: ${body.length}\r\n` : ""
    }\r\n`;
    s.write(head);
    if (body) s.write(body);
  });
}

async function api(port, method, url, body) {
  const res = await fetch(`http://127.0.0.1:${port}${url}`, {
    method,
    headers: { authorization: `Bearer ${SECRET}`, ...(body ? { "content-type": "application/json" } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  return { status: res.status, json: text ? JSON.parse(text) : null };
}

// ------------------------------------------------------------------- прогон
if (!existsSync(ENGINE)) {
  console.error(`нет ${ENGINE} — сначала: cargo build --release --manifest-path engine/Cargo.toml`);
  process.exit(2);
}

selfSigned();
const keys = realityKeys();
// Маска REALITY — настоящий TLS: на него сервер уведёт отвергнутый hello.
const tlsMask = await import("node:tls");
const maskTls = tlsMask.createServer(
  {
    key: (await import("node:fs")).readFileSync(path.join(dir, "key.pem")),
    cert: (await import("node:fs")).readFileSync(path.join(dir, "cert.pem")),
    ALPNProtocols: ["h2", "http/1.1"],
  },
  (s) => s.on("error", () => {}),
);
maskTls.on("tlsClientError", () => {});
await new Promise((r) => maskTls.listen(P.mask, "127.0.0.1", r));

writeFileSync(path.join(dir, "xray.json"), JSON.stringify(xrayConfig(keys)));
writeFileSync(path.join(dir, "sb-server.json"), JSON.stringify(singboxServerConfig()));
const xray = start(XRAY, ["run", "-c", "xray.json"], "xray");
const sbServer = start(SINGBOX, ["run", "-c", "sb-server.json"], "sing-box-server");
await waitPort(P.vless_plain);
await sleep(800);
if (xray.exitCode !== null || sbServer.exitCode !== null) {
  console.error("сервер не поднялся:\n" + xray.lines.join("\n") + sbServer.lines.join("\n"));
  process.exit(1);
}

const only = process.env.STAND_ONLY;
const nodes = outbounds(keys).filter((n) => !only || n.tag.includes(only));
const MIXED = 39050;
const API = 39051;
writeFileSync(path.join(dir, "client.json"), JSON.stringify(clientConfig(nodes, MIXED, API, nodes[0].tag)));

const check = spawn(ENGINE, ["check", "-c", "client.json"], { cwd: dir });
const checkCode = await new Promise((r) => check.on("close", r));
console.log(`check → код ${checkCode}`);

const engine = start(ENGINE, ["run", "-c", "client.json", "-D", dir], "aura-engine");
if (!(await waitPort(API))) {
  console.error("движок не поднялся:\n" + engine.lines.join("\n"));
  process.exit(1);
}
const version = await api(API, "GET", "/version");
console.log(`версия: ${version.json.version}\n`);

let failed = 0;
const results = [];
for (const node of nodes) {
  const tag = node.tag;
  const line = { tag };
  try {
    const sel = await api(API, "PUT", "/proxies/proxy", { name: tag });
    if (sel.status !== 204) throw new Error(`селектор ответил ${sel.status}`);

    // 8 МиБ вниз: Vision переключается в прямой режим именно на длинном потоке.
    const t0 = Date.now();
    line.step = "big";
    const big = await fetchThrough(MIXED, "/big");
    line.step = "echo";
    const ms = Date.now() - t0;
    const sha = createHash("sha256").update(big.body).digest("hex");
    if (sha !== PAYLOAD_SHA) throw new Error(`содержимое разошлось: ${big.body.length} Б из ${PAYLOAD.length}`);
    line.mbps = Math.round((PAYLOAD.length * 8) / 1e6 / (ms / 1000));

    // Вверх и обратно: проверка записи и чтения на одной сессии.
    const up = randomBytes(256 * 1024);
    const echo = await fetchThrough(MIXED, "/echo", "POST", up);
    if (!echo.body.equals(up)) throw new Error(`эхо разошлось: ${echo.body.length} Б из ${up.length}`);

    const delay = await api(API, "GET", `/proxies/${encodeURIComponent(tag)}/delay?timeout=5000&url=${encodeURIComponent(`http://${TARGET}/generate_204`)}`);
    if (delay.status !== 200) throw new Error(`замер: ${JSON.stringify(delay.json)}`);
    line.delay = delay.json.delay;
    line.ok = true;
  } catch (e) {
    line.ok = false;
    line.error = `[${line.step}] ${e.message}`;
    failed++;
  }
  results.push(line);
  const status = line.ok ? "ok " : "FAIL";
  console.log(`${status} ${tag.padEnd(32)} ${line.ok ? `${String(line.mbps).padStart(6)} Мбит/с  замер ${line.delay} мс` : line.error}`);
}

// Clash API: то, чем пользуется приложение.
await api(API, "PUT", "/proxies/proxy", { name: "vless-plain" });
const held = await socksConnect(MIXED, "127.0.0.1", ORIGIN_PORT);
await sleep(200);
const conns = await api(API, "GET", "/connections");
const listed = conns.json.connections.find((c) => c.chains.includes("vless-plain"));
const apiChecks = [
  ["/connections видит соединение", Boolean(listed)],
  ["chains от узла к группе", JSON.stringify(listed?.chains) === JSON.stringify(["vless-plain", "proxy"])],
  ["счётчик трафика растёт", conns.json.downloadTotal > PAYLOAD.length],
  ["неверный токен отвергнут", (await fetch(`http://127.0.0.1:${API}/version`, { headers: { authorization: "Bearer no" } })).status === 401],
];
if (listed) {
  const closed = new Promise((r) => held.on("close", r));
  const del = await api(API, "DELETE", `/connections/${listed.id}`);
  const timed = await Promise.race([closed.then(() => true), sleep(2000).then(() => false)]);
  apiChecks.push(["DELETE рвёт соединение", del.status === 204 && timed]);
}
const mode = await api(API, "PATCH", "/configs", { mode: "Global" });
apiChecks.push(["PATCH /configs меняет режим", mode.status === 204 && (await api(API, "GET", "/configs")).json.mode === "Global"]);
apiChecks.push(["чужой член группы отвергнут", (await api(API, "PUT", "/proxies/proxy", { name: "нет такого" })).status === 400]);

console.log("");
for (const [name, ok] of apiChecks) {
  console.log(`${ok ? "ok " : "FAIL"} ${name}`);
  if (!ok) failed++;
}

// Неверный ключ REALITY не должен зацикливаться на повторных дозвонах.
{
  const wrong = { ...nodes[0], tag: "wrong-key", tls: { ...nodes[0].tls, reality: { enabled: true, public_key: realityKeys().pub, short_id: "abcd1234" } } };
  writeFileSync(path.join(dir, "wrong.json"), JSON.stringify(clientConfig([wrong], 39052, 39053, "wrong-key")));
  const e = start(ENGINE, ["run", "-c", "wrong.json", "-D", dir], "wrong");
  await waitPort(39053);
  const t0 = Date.now();
  const delay = await api(39053, "GET", `/proxies/wrong-key/delay?timeout=5000&url=${encodeURIComponent(`http://${TARGET}/generate_204`)}`);
  const quick = Date.now() - t0 < 4500;
  const ok = delay.status !== 200 && quick;
  console.log(`${ok ? "ok " : "FAIL"} неверный ключ REALITY: честный отказ за ${Date.now() - t0} мс (${delay.json.message ?? ""})`);
  if (!ok) failed++;
  e.kill();
}

const warned = engine.lines.filter((l) => /WARN|ERROR|panic/i.test(l));
if (warned.length) console.log("\nжурнал движка:\n" + warned.slice(-15).join("\n"));

// ------------------------------------------------------------------ стресс
// Параллельные запросы с коротким таймаутом: зависшее соединение видно сразу, а не
// как странная скорость. Тот же прогон через sing-box — контроль: виноват движок
// или сервер.
async function stress(mixed, apiPort, tag, parallel = 8, rounds = 12) {
  await api(apiPort, "PUT", "/proxies/proxy", { name: tag });
  await sleep(100);
  const result = { ok: 0, bad: [] };
  const one = (path, method, body, check) =>
    new Promise(async (resolve) => {
      let s;
      try {
        s = await socksConnect(mixed, "127.0.0.1", ORIGIN_PORT);
      } catch (e) {
        result.bad.push("socks: " + e.message);
        return resolve();
      }
      let got = 0, wanted = -1, head = Buffer.alloc(0), done = false;
      const finish = (why) => {
        if (done) return;
        done = true;
        clearTimeout(timer);
        s.destroy();
        if (why) result.bad.push(why + " (" + got + "/" + wanted + ")");
        else result.ok++;
        resolve();
      };
      const timer = setTimeout(() => finish(path + ": завис"), 8000);
      s.on("data", (d) => {
        if (wanted < 0) {
          head = Buffer.concat([head, d]);
          const at = head.indexOf("\r\n\r\n");
          if (at < 0) return;
          const m = head.subarray(0, at).toString().match(/content-length: (\d+)/i);
          wanted = m ? Number(m[1]) : 0;
          got = head.length - at - 4;
        } else got += d.length;
        if (got >= wanted) finish(check && got !== check ? "длина" : null);
      });
      s.on("error", (e) => finish(path + ": " + e.message));
      s.on("close", () => finish(path + ": закрыто раньше времени"));
      s.write(method + " " + path + " HTTP/1.1\r\nHost: o\r\n" + (body ? "Content-Length: " + body.length + "\r\n" : "") + "\r\n");
      if (body) s.write(body);
    });
  const small = randomBytes(64 * 1024);
  const workers = Array.from({ length: parallel }, async (_, w) => {
    for (let i = 0; i < rounds; i++) {
      await (w % 2 ? one("/big", "GET", null, PAYLOAD.length) : one("/echo", "POST", small, small.length));
    }
  });
  await Promise.all(workers);
  return result;
}

if (process.argv.includes("stress")) {
  writeFileSync(path.join(dir, "sb-client.json"), JSON.stringify(clientConfig(nodes, 39060, 39061, nodes[0].tag)));
  const sb = spawn(SINGBOX, ["run", "-c", "sb-client.json", "-D", dir], { cwd: dir, stdio: "ignore" });
  children.push(sb);
  await waitPort(39061);
  console.log("\n=== стресс: 8 потоков, 12 кругов, таймаут 8 с ===");
  for (const node of nodes) {
    const a = await stress(MIXED, API, node.tag);
    const b = await stress(39060, 39061, node.tag);
    const fmt = (r) => (r.ok + " ok, " + r.bad.length + " сбоев").padEnd(20);
    console.log(node.tag.padEnd(32), "aura:", fmt(a), "sing-box:", fmt(b), a.bad.slice(0, 2).join("; "));
    if (a.bad.length) failed++;
  }
}

// ------------------------------------------------------------------ замеры
function sample(pid) {
  const script = `$p=Get-Process -Id ${pid}; "$($p.CPU) $($p.WorkingSet64) $($p.PrivateMemorySize64) $($p.Threads.Count) $($p.HandleCount)"`;
  const out = execFileSync("powershell", ["-NoProfile", "-Command", script]).toString().trim().split(/\s+/).map(Number);
  return { cpu: out[0], ws: out[1] / 1048576, priv: out[2] / 1048576, threads: out[3], handles: out[4] };
}

async function loadTest(label, pid, mixed, parallel = 8, seconds = 20) {
  const before = sample(pid);
  let bytes = 0;
  const errors = [];
  let peakWs = before.ws;
  let peakPriv = before.priv;
  const stopAt = Date.now() + seconds * 1000;
  const worker = async () => {
    while (Date.now() < stopAt) {
      try {
        const res = await fetchThrough(mixed, "/big");
        bytes += res.body.length;
      } catch (e) {
        errors.push(e.message);
      }
    }
  };
  const watcher = (async () => {
    while (Date.now() < stopAt) {
      await sleep(1500);
      const s = sample(pid);
      peakWs = Math.max(peakWs, s.ws);
      peakPriv = Math.max(peakPriv, s.priv);
    }
  })();
  const t0 = Date.now();
  await Promise.all(Array.from({ length: parallel }, worker));
  await watcher;
  const secs = (Date.now() - t0) / 1000;
  await sleep(1500);
  const after = sample(pid);
  const cpu = after.cpu - before.cpu;
  const gb = bytes / 1e9;
  return {
    label,
    errors: errors.length,
    firstError: errors[0],
    secs: Math.round(secs),
    mbps: Math.round((bytes * 8) / 1e6 / secs),
    cpuPerGb: +(cpu / gb).toFixed(2),
    idleWs: Math.round(before.ws),
    peakWs: Math.round(peakWs),
    idlePriv: Math.round(before.priv),
    peakPriv: Math.round(peakPriv),
    threads: after.threads,
    handles: after.handles,
  };
}

if (bench) {
  console.log("\n=== замер: одни и те же узлы, одна нагрузка (8 потоков, 20 с) ===");
  const singNodes = nodes.map((n) => ({ ...n }));
  writeFileSync(path.join(dir, "sb-client.json"), JSON.stringify(clientConfig(singNodes, 39060, 39061, singNodes[0].tag)));
  const env = { ...process.env, GOGC: "40", GOMEMLIMIT: "128MiB" };
  const sbChild = spawn(SINGBOX, ["run", "-c", "sb-client.json", "-D", dir], { cwd: dir, stdio: "ignore", env });
  children.push(sbChild);
  await waitPort(39061);

  const rows = [];
  const benchTags = process.env.STAND_BENCH ? process.env.STAND_BENCH.split(",") : ["vless-plain", "vless-reality-vision-chrome", "trojan-tls", "ss-chacha", "vmess-plain", "hysteria2"];
  for (const tag of benchTags) {
    await api(API, "PATCH", "/configs", { mode: "Rule" });
    await api(API, "PUT", "/proxies/proxy", { name: tag });
    await api(39061, "PUT", "/proxies/proxy", { name: tag });
    await sleep(1000);
    const a = await loadTest(`${tag} aura`, engine.pid, MIXED);
    await sleep(1000);
    const b = await loadTest(`${tag} sing-box`, sbChild.pid, 39060);
    rows.push(a, b);
    console.log(
      [a, b]
        .map((r) => `${r.label.padEnd(40)} ${String(r.mbps).padStart(6)} Мбит/с  CPU ${String(r.cpuPerGb).padStart(6)} с/ГБ  RAM ${r.idleWs}→${r.peakWs} МБ  private ${r.idlePriv}→${r.peakPriv}  потоков ${r.threads}  сбоев ${r.errors}  за ${r.secs} с ${r.firstError ?? ""}`)
        .join("\n"),
    );
  }
  writeFileSync(path.join(here, "bench-last.json"), JSON.stringify(rows, null, 1));
}

console.log(failed ? `\nНЕ ПРОШЛО: ${failed}` : "\nвсё прошло");
cleanup();
process.exit(failed ? 1 : 0);
