/**
 * A stand-in for the Rust backend, so the interface can be opened in a plain
 * browser tab without building the app: `npm run dev`, then
 * http://localhost:1420/dev.html — add `?platform=macos` (or `linux`,
 * `android`) to see another OS's chrome and wording. Loaded by dev.html only;
 * index.html, and therefore the real app, never touches this file.
 *
 * Commands return canned data; writes update it in memory so toggles and
 * pickers behave, and events are wired to the mock's own bus.
 */
import { invoke } from "@tauri-apps/api/core";
import { mockIPC, mockWindows } from "@tauri-apps/api/mocks";

import type { LogLine, ResourceGroup, ServerNode, Snapshot } from "../lib/types";

mockWindows("main");

function node(id: string, name: string, address: string): ServerNode {
  return {
    id,
    name,
    protocol: "vless",
    address,
    port: 443,
    uuid: "00000000-0000-4000-8000-000000000000",
    password: "",
    method: "",
    alterId: 0,
    vmessSecurity: "auto",
    network: "tcp",
    path: "",
    host: "",
    serviceName: "",
    security: "reality",
    sni: "www.example.com",
    alpn: [],
    fingerprint: "chrome",
    publicKey: "",
    shortId: "",
    allowInsecure: false,
    flow: "xtls-rprx-vision",
    mux: false,
    obfs: "",
    obfsPassword: "",
    hopPorts: [],
    privateKey: "",
    peerPublicKey: "",
    localV4: "",
    localV6: "",
    reserved: [],
    mtu: 1280,
    keepalive: 30,
    preSharedKey: "",
    username: "",
    subscriptionId: null,
    rawLink: "",
  };
}

const platform = new URLSearchParams(location.search).get("platform") ?? "windows";
const unix = platform === "macos" || platform === "linux";

const snapshot: Snapshot = {
  settings: {
    language: "system",
    tunnelMode: "tun",
    mixedPort: 2080,
    clashPort: 9191,
    allowLan: false,
    tunStack: "mixed",
    tunMtu: 9000,
    strictRoute: true,
    ipv6: false,
    logLevel: "info",
    dnsRemote: "https://1.1.1.1/dns-query",
    dnsDirect: "https://77.88.8.8/dns-query",
    dnsStrategy: "prefer_ipv4",
    fakeIp: true,
    warpOverProxy: false,
    autoConnect: false,
    startMinimized: false,
    launchAtLogin: false,
    closeToTray: true,
    theme: "dark",
    themeDark: true,
    themeBackground: "#0a0c12",
    latencyUrl: "https://www.gstatic.com/generate_204",
    balancer: "manual",
    balancerIntervalMin: 5,
    balancerToleranceMs: 100,
    subAutoUpdateMin: 360,
  },
  nodes: [
    node("a", "Amsterdam", "nl.example.net"),
    node("b", "Helsinki", "fi.example.net"),
    {
      ...node("c", "Amsterdam AWG", "nl.example.net"),
      protocol: "amneziawg",
      port: 51820,
      security: "none",
      mtu: 1376,
      awg: {
        jc: 4, jmin: 65, jmax: 220, s1: 87, s2: 44, s3: 21, s4: 12,
        h1: "463065432", h2: "912345678", h3: "1345678901-1345679901", h4: "1987654321",
        i1: "<r 148>", i2: "", i3: "", i4: "", i5: "",
        headerProtectionKey: "8Iu83eHDA3fMKKSGaEsVW9Ycd2lYYzc0MYlk1jJTvE4=",
        contentPaddingAddition: "17-49", rekeyAfterTime: "", rekeyTimeout: "",
        rejectAfterTime: "", keepaliveTimeout: "", maxHandshakeAttempts: "",
        randomTrailers: true, disableCookies: true, keepaliveRange: "",
      },
    },
    {
      ...node("d", "Amsterdam MASQUE", "nl.example.net"),
      protocol: "masque",
      port: 8443,
      security: "tls",
      alpn: ["h2"],
      username: "ivy@example.net",
      password: "secret",
      flow: "",
    },
    ...["Hysteria", "tls", "vless-reality"].map((name, i) => ({
      ...node(`panel-${i}`, name, "panel.example.net"),
      subscriptionId: "panel",
    })),
  ],
  // Подписка с тарифом — рядом с собственными серверами: так видны оба вида
  // разделов в списке и карточка на «Обзоре».
  subscriptions: [
    {
      id: "panel",
      name: "panel.example.net",
      url: "https://panel.example.net/sub/demo",
      enabled: true,
      lastUpdated: new Date(Date.now() - 24 * 60_000).toISOString(),
      nodeCount: 3,
      lastError: "",
      upload: 3_000_000_000,
      download: 200_000_000_000,
      total: 0,
      expire: 0,
      updateIntervalHours: 6,
      hasUsage: true,
      free: false,
    },
  ],
  split: {
    mode: "off",
    apps: [],
    directDomains: [],
    directIps: [],
    proxyDomains: [],
    proxyIps: [],
    blockDomains: [],
    bypassPrivate: true,
    bypassRu: true,
    bypassCn: false,
    blockAds: false,
  },
  status: {
    state: "disconnected",
    message: "",
    sinceMs: null,
    mode: "Rule",
    tunnelMode: "tun",
    activeId: "a",
    routedId: "",
    link: "connecting",
    elevated: false,
    systemProxy: false,
  },
  traffic: { upload: 0, download: 0, upSpeed: 0, downSpeed: 0, connections: 0 },
  latency: { a: 48, b: 61 },
  activeId: "a",
  coreVersion: "sing-box version 1.14.0",
  autostart: "off",
  rootCommand: unix
    ? platform === "macos"
      ? 'sudo "/Applications/Aurora VPN.app/Contents/MacOS/aurora-vpn"'
      : 'sudo "/home/user/Downloads/AuroraVPN-0.4.2-x86_64.AppImage"'
    : null,
};

const usage: ResourceGroup[] = [
  { id: "app", processes: 1, memory: 96_100_000, cpu: 0.2 },
  ...(platform === "linux"
    ? [{ id: "ui" as const, processes: 2, memory: 141_000_000, cpu: 0.4 }]
    : []),
];

const logs: LogLine[] = [
  { seq: 1, level: "info", text: "mock backend ready" },
];

const androidApps = [
  ["EOBD Facile", "org.eobdfacile.android"],
  ["ReComics - Читай мангу!", "com.remanga.remangaapp"],
  ["ABP for Samsung Internet", "org.adblockplus.adblockplussbrowser"],
  ["Delivio", "im.ringl.delivio.food"],
  ["VK", "com.vkontakte.android"],
  ["Telegram", "org.telegram.messenger"],
  ["Samsung Internet Browser Beta", "com.sec.android.app.sbrowser.beta.experimental"],
  ["YouTube", "com.google.android.youtube"],
].map(([name, path]) => ({ name, path, instances: 1, system: false }));

/** The Cloudflare account the WARP switch asks about. */
const warp = {
  registered: false,
  accountType: "free",
  license: "",
  created: new Date().toISOString(),
  hasNode: false,
};

mockIPC(
  (cmd, args) => {
    const a = (args ?? {}) as Record<string, unknown>;
    switch (cmd) {
      case "get_snapshot":
        return snapshot;
      case "get_logs":
        return logs;
      case "plugin:app|version":
        return "0.4.2-mock";
      case "resource_usage":
        return usage;
      case "get_autostart":
        return snapshot.autostart;
      case "set_autostart":
        snapshot.autostart = a.mode as Snapshot["autostart"];
        return snapshot.autostart;
      case "save_settings":
        Object.assign(snapshot.settings, a.settings as object);
        return undefined;
      case "set_split":
        Object.assign(snapshot.split, a.split as object);
        return { ...snapshot.split };
      case "set_active_server":
        snapshot.activeId = String(a.id);
        snapshot.status.activeId = snapshot.activeId;
        return false;
      case "grant_core_root":
        // The real command answers through the status event; so does the mock
        // (the emit goes back into mockIPC's own event bus).
        snapshot.status.elevated = true;
        void invoke("plugin:event|emit", {
          event: "app://status",
          payload: snapshot.status,
        });
        return undefined;
      // The scanner's three sources. Nothing is really decoded in a browser
      // tab — the detector lives in Rust — so the screen and the file answer
      // with a canned link and the camera keeps looking, which is what makes
      // every state of the dialog reachable here.
      case "scan_qr_screen":
      case "scan_qr_image":
        return [
          "vless://00000000-0000-4000-8000-000000000000@qr.example.com:443" +
            "?type=tcp&security=reality&pbk=demo&sni=www.example.com#QR",
        ];
      case "scan_qr_frame":
        return [];
      // A browser tab has no window to shrink; the bar still draws over it.
      case "set_screen_scan":
        return undefined;
      // The paste button. In a browser tab the plugin is not there, so the
      // mock stands in for the clipboard itself.
      case "plugin:clipboard-manager|read_text":
        return "vless://00000000-0000-4000-8000-000000000000@paste.example.com:443" +
          "?type=tcp&security=reality&pbk=demo&sni=www.example.com#Clipboard";
      case "check_update":
        return null;
      case "warp_status":
      case "enable_warp":
      case "reset_warp":
        // Registered from the second call on, so the consent dialog shows once
        // and the switch behaves the way it does against the real backend.
        warp.registered = cmd !== "warp_status" || warp.registered;
        return { ...warp };
      case "add_warp_node":
        return undefined;
      // Пул FREE: подписка с горсткой серверов, как после настоящего сбора.
      // Повторное нажатие лишь освежает дату — второго пула не бывает.
      case "add_free_pool": {
        const id = "free";
        let pool = snapshot.subscriptions.find((sub) => sub.free);
        if (!pool) {
          pool = {
            id,
            name: "FREE",
            url: "https://github.com/igareck/vpn-configs-for-russia",
            enabled: true,
            lastUpdated: "",
            nodeCount: 3,
            lastError: "",
            upload: 0,
            download: 0,
            total: 0,
            expire: 0,
            updateIntervalHours: 1,
            hasUsage: false,
            free: true,
          };
          snapshot.subscriptions.push(pool);
          snapshot.nodes.push(
            ...["🇳🇱 Netherlands", "🇩🇪 Germany", "🇫🇮 Finland"].map((name, i) => ({
              ...node(`free-${i}`, name, `198.51.100.${i + 10}`),
              subscriptionId: id,
            })),
          );
        }
        pool.lastUpdated = new Date().toISOString();
        void invoke("plugin:event|emit", { event: "app://nodes", payload: [...snapshot.nodes] });
        void invoke("plugin:event|emit", {
          event: "app://subscriptions",
          payload: [...snapshot.subscriptions],
        });
        return { added: 3, skipped: 493, errors: [] };
      }
      case "delete_subscription":
        snapshot.subscriptions = snapshot.subscriptions.filter((sub) => sub.id !== a.id);
        snapshot.nodes = snapshot.nodes.filter((n) => n.subscriptionId !== a.id);
        void invoke("plugin:event|emit", { event: "app://nodes", payload: [...snapshot.nodes] });
        void invoke("plugin:event|emit", {
          event: "app://subscriptions",
          payload: [...snapshot.subscriptions],
        });
        return undefined;
      case "reorder_servers": {
        const ids = (args as { ids: string[] }).ids;
        const rank = new Map(ids.map((id, index) => [id, index] as const));
        snapshot.nodes.sort(
          (a, b) => (rank.get(a.id) ?? ids.length) - (rank.get(b.id) ?? ids.length),
        );
        void invoke("plugin:event|emit", {
          event: "app://nodes",
          payload: [...snapshot.nodes],
        });
        return undefined;
      }
      // A phone lists packages, whose long unbreakable names are what once
      // pushed the picker off the screen; the desktop keeps an empty list.
      case "list_running_apps":
        return platform === "android" ? androidApps : [];
      // Round tiles in the package's own hue — enough to see an icon land in
      // its row without shipping real ones.
      case "app_icons":
        return Object.fromEntries(
          (a.packages as string[]).map((pkg) => {
            const hue = [...pkg].reduce((h, c) => (h * 31 + c.charCodeAt(0)) % 360, 0);
            const svg =
              `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 30 30">` +
              `<circle cx="15" cy="15" r="15" fill="hsl(${hue} 65% 52%)"/></svg>`;
            return [pkg, `data:image/svg+xml,${encodeURIComponent(svg)}`];
          }),
        );
      case "test_latency":
        return snapshot.latency;
      case "connect":
        // Rights first, as on the desktop: the dashboard's grant flow retries
        // this and expects it to go through the second time.
        if (!snapshot.status.elevated) throw "ELEVATION_REQUIRED";
        snapshot.status.state = "connected";
        snapshot.status.sinceMs = Date.now();
        snapshot.status.routedId = snapshot.activeId;
        snapshot.status.link = "up";
        void invoke("plugin:event|emit", {
          event: "app://status",
          payload: { ...snapshot.status },
        });
        return undefined;
      case "disconnect":
        snapshot.status.state = "disconnected";
        snapshot.status.sinceMs = null;
        snapshot.status.routedId = "";
        snapshot.status.link = "connecting";
        void invoke("plugin:event|emit", {
          event: "app://status",
          payload: { ...snapshot.status },
        });
        return undefined;
      default:
        return undefined;
    }
  },
  { shouldMockEvents: true },
);
