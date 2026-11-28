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

import type {
  AppStats,
  ChartPoint,
  LogLine,
  ResourceGroup,
  ServerNode,
  Snapshot,
  StatsQuery,
  StatsReport,
  StorageInfo,
} from "../lib/types";

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
    latencyUrl: "http://www.gstatic.com/generate_204",
    balancer: "manual",
    balancerIntervalMin: 5,
    balancerToleranceMs: 100,
    subAutoUpdateMin: 360,
    statsRetentionDays: 30,
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
    ruAppsDirect: true,
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

let mockStatsCleared = false;

function mockStatsStorage(): StorageInfo {
  const retentionDays = snapshot.settings.statsRetentionDays ?? 30;
  if (mockStatsCleared || retentionDays === 0) {
    return { bytesOnDisk: 0, daysStored: 0, retentionDays };
  }
  return { bytesOnDisk: 1_842_000, daysStored: Math.min(12, retentionDays), retentionDays };
}

function buildMockStatsReport(query: StatsQuery): StatsReport {
  const storage = mockStatsStorage();
  if (mockStatsCleared) {
    return {
      summary: {
        downBytes: 0,
        upBytes: 0,
        totalBytes: 0,
        proxyBytes: 0,
        directBytes: 0,
        avgDownBps: 0,
        peakDownBps: 0,
        avgUpBps: 0,
        peakUpBps: 0,
        avgLatencyMs: null,
        minLatencyMs: null,
        maxLatencyMs: null,
        jitterMs: null,
        lossPct: 0,
        packetsLost: 0,
        retransEvents: 0,
        tunDrops: 0,
        udpDrops: 0,
        dialFails: 0,
        relayErrors: 0,
        probeFails: 0,
        probeTotal: 0,
        durationS: 0,
        hasData: false,
        fromMs: 0,
        toMs: 0,
      },
      points: [],
      apps: [],
      pinnedPoint: null,
      pinnedApps: [],
      servers: [],
      sessions: [],
      storage,
    };
  }

  const now = Date.now();
  const count = 48;
  const stepMs =
    query.range === "days30"
      ? 15 * 3600_000
      : query.range === "days7"
        ? 3.5 * 3600_000
        : query.range === "hours24"
          ? 30 * 60_000
          : query.range === "hour1"
            ? 75_000
            : 10_000;
  const startMs = now - count * stepMs;

  const mockApps: AppStats[] = [
    {
      key: "chrome.exe",
      name: "Google Chrome",
      path: "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
      downBytes: 1_620_000_000,
      upBytes: 145_000_000,
      totalBytes: 1_765_000_000,
      proxyBytes: 1_580_000_000,
      directBytes: 185_000_000,
      peakBps: 6_400_000,
      sharePct: 54.2,
      vpnPct: 89.5,
      activeConns: 28,
      totalConns: 412,
      errors: 1,
    },
    {
      key: "steam.exe",
      name: "Steam",
      path: "C:\\Program Files (x86)\\Steam\\steam.exe",
      downBytes: 940_000_000,
      upBytes: 62_000_000,
      totalBytes: 1_002_000_000,
      proxyBytes: 210_000_000,
      directBytes: 792_000_000,
      peakBps: 11_200_000,
      sharePct: 30.8,
      vpnPct: 21.0,
      activeConns: 9,
      totalConns: 84,
      errors: 0,
    },
    {
      key: "telegram.exe",
      name: "Telegram",
      path: "C:\\Users\\user\\AppData\\Roaming\\Telegram Desktop\\Telegram.exe",
      downBytes: 280_000_000,
      upBytes: 94_000_000,
      totalBytes: 374_000_000,
      proxyBytes: 374_000_000,
      directBytes: 0,
      peakBps: 2_300_000,
      sharePct: 11.5,
      vpnPct: 100,
      activeConns: 6,
      totalConns: 51,
      errors: 3,
    },
    {
      key: "discord.exe",
      name: "Discord",
      path: "C:\\Users\\user\\AppData\\Local\\Discord\\Discord.exe",
      downBytes: 72_000_000,
      upBytes: 42_000_000,
      totalBytes: 114_000_000,
      proxyBytes: 114_000_000,
      directBytes: 0,
      peakBps: 420_000,
      sharePct: 3.5,
      vpnPct: 100,
      activeConns: 4,
      totalConns: 39,
      errors: 5,
    },
  ];

  const allPoints: ChartPoint[] = Array.from({ length: count }, (_, i) => {
    const onB = i >= 20 && i < 34;
    const sid = onB ? "b" : "a";
    const sname = onB ? "Helsinki" : "Amsterdam";
    const wave = Math.sin(i * 0.45) * 0.5 + 0.5;
    const spike = i === 12 || i === 28 || i === 41 ? 2.4 : 1;
    const downBps = Math.round((450_000 + wave * 2_400_000) * spike);
    const upBps = Math.round(downBps * 0.18);
    const lossPct = onB ? Number((2.2 + wave * 3.1).toFixed(2)) : Number((0.1 + wave * 0.25).toFixed(2));
    const latencyMs = onB ? Math.round(135 + wave * 70) : Math.round(46 + wave * 18);
    const appShare = query.appKey === "chrome.exe" ? 0.55 : query.appKey === "steam.exe" ? 0.3 : 0.15;
    return {
      tsMs: startMs + i * stepMs,
      endMs: startMs + (i + 1) * stepMs,
      durS: Math.max(1, Math.round(stepMs / 1000)),
      downBps,
      upBps,
      proxyDownBps: Math.round(downBps * 0.75),
      proxyUpBps: Math.round(upBps * 0.8),
      appDownBps: query.appKey ? Math.round(downBps * appShare) : 0,
      appUpBps: query.appKey ? Math.round(upBps * appShare) : 0,
      downBytes: Math.round(downBps * (stepMs / 1000)),
      upBytes: Math.round(upBps * (stepMs / 1000)),
      latencyMs,
      lossPct,
      packetsLost: onB ? Math.round(14 + wave * 22) : Math.round(wave * 2),
      errors: onB && i % 4 === 0 ? 1 : 0,
      connections: 36 + (i % 18),
      serverId: sid,
      serverName: sname,
      serverProto: "vless",
      topApps: [
        {
          key: "chrome.exe",
          name: "Google Chrome",
          path: mockApps[0].path,
          bytes: Math.round(downBps * 0.52 * 10),
          downBytes: Math.round(downBps * 0.48 * 10),
          upBytes: Math.round(upBps * 0.4 * 10),
        },
        {
          key: onB ? "discord.exe" : "steam.exe",
          name: onB ? "Discord" : "Steam",
          path: onB ? mockApps[3].path : mockApps[1].path,
          bytes: Math.round(downBps * 0.31 * 10),
          downBytes: Math.round(downBps * 0.28 * 10),
          upBytes: Math.round(upBps * 0.35 * 10),
        },
      ],
    };
  });

  const points = query.serverId
    ? allPoints.filter((p) => p.serverId === query.serverId)
    : allPoints;
  const pinnedPoint =
    query.pinnedIndex !== null &&
    query.pinnedIndex !== undefined &&
    points[query.pinnedIndex]
      ? points[query.pinnedIndex]
      : null;

  const pinnedApps: AppStats[] = pinnedPoint
    ? pinnedPoint.topApps.map((a, idx) => ({
        key: a.key,
        name: a.name,
        path: a.path,
        downBytes: a.downBytes,
        upBytes: a.upBytes,
        totalBytes: a.bytes,
        proxyBytes: Math.round(a.bytes * 0.85),
        directBytes: Math.round(a.bytes * 0.15),
        peakBps: Math.round(a.bytes / Math.max(1, pinnedPoint.durS)),
        sharePct: idx === 0 ? 63 : 37,
        vpnPct: 85,
        activeConns: 12 - idx * 4,
        totalConns: 18 - idx * 5,
        errors: pinnedPoint.errors,
      }))
    : [];

  return {
    summary: {
      downBytes: 2_912_000_000,
      upBytes: 343_000_000,
      totalBytes: 3_255_000_000,
      proxyBytes: 2_278_000_000,
      directBytes: 977_000_000,
      avgDownBps: 1_820_000,
      peakDownBps: 11_200_000,
      avgUpBps: 290_000,
      peakUpBps: 1_940_000,
      avgLatencyMs: query.serverId === "b" ? 168 : 64,
      minLatencyMs: 42,
      maxLatencyMs: 210,
      jitterMs: query.serverId === "b" ? 28 : 7,
      lossPct: query.serverId === "b" ? 3.84 : query.serverId === "a" ? 0.18 : 1.12,
      packetsLost: query.serverId === "b" ? 248 : 264,
      retransEvents: 39,
      tunDrops: 4,
      udpDrops: 2,
      dialFails: 3,
      relayErrors: 6,
      probeFails: 2,
      probeTotal: 64,
      durationS: Math.round((count * stepMs) / 1000),
      hasData: points.length > 0,
      fromMs: points[0]?.tsMs ?? 0,
      toMs: points[points.length - 1]?.endMs ?? 0,
    },
    points,
    apps: mockApps,
    pinnedPoint,
    pinnedApps,
    servers: [
      {
        serverId: "a",
        serverName: "Amsterdam",
        serverProto: "vless",
        durationS: 3420,
        downBytes: 2_280_000_000,
        upBytes: 256_000_000,
        totalBytes: 2_536_000_000,
        avgDownBps: 2_150_000,
        peakDownBps: 11_200_000,
        avgUpBps: 310_000,
        peakUpBps: 1_940_000,
        avgLatencyMs: 52,
        minLatencyMs: 42,
        maxLatencyMs: 74,
        jitterMs: 6,
        lossPct: 0.18,
        packetsLost: 16,
        retransEvents: 5,
        dialFails: 0,
        relayErrors: 1,
        probeFails: 0,
        probeTotal: 42,
        health: "good",
      },
      {
        serverId: "b",
        serverName: "Helsinki",
        serverProto: "vless",
        durationS: 1410,
        downBytes: 632_000_000,
        upBytes: 87_000_000,
        totalBytes: 719_000_000,
        avgDownBps: 980_000,
        peakDownBps: 3_600_000,
        avgUpBps: 185_000,
        peakUpBps: 620_000,
        avgLatencyMs: 168,
        minLatencyMs: 121,
        maxLatencyMs: 210,
        jitterMs: 28,
        lossPct: 3.84,
        packetsLost: 248,
        retransEvents: 34,
        dialFails: 3,
        relayErrors: 5,
        probeFails: 2,
        probeTotal: 22,
        health: "bad",
      },
    ],
    sessions: [
      {
        id: "sess-now",
        startedMs: now - 48 * 60_000,
        endedMs: now,
        active: true,
        durationS: 48 * 60,
        primaryServerId: "a",
        primaryServerName: "Amsterdam",
        serverCount: 2,
        downBytes: 2_912_000_000,
        upBytes: 343_000_000,
        peakDownBps: 11_200_000,
        avgLatencyMs: 64,
        lossPct: 1.12,
        packetsLost: 264,
        errors: 9,
      },
      {
        id: "sess-prev",
        startedMs: now - 26 * 3600_000,
        endedMs: now - 23 * 3600_000,
        active: false,
        durationS: 3 * 3600,
        primaryServerId: "b",
        primaryServerName: "Helsinki",
        serverCount: 1,
        downBytes: 1_420_000_000,
        upBytes: 164_000_000,
        peakDownBps: 4_800_000,
        avgLatencyMs: 158,
        lossPct: 3.45,
        packetsLost: 412,
        errors: 14,
      },
    ],
    storage,
  };
}

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
      case "reorder_subscriptions": {
        const ids = (args as { ids: string[] }).ids;
        const rank = new Map(ids.map((id, index) => [id, index] as const));
        snapshot.subscriptions.sort(
          (a, b) => (rank.get(a.id) ?? ids.length) - (rank.get(b.id) ?? ids.length),
        );
        void invoke("plugin:event|emit", {
          event: "app://subscriptions",
          payload: [...snapshot.subscriptions],
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
      case "get_stats_report":
        return buildMockStatsReport((a.query as StatsQuery) ?? { range: "session" });
      case "get_stats_storage":
        return mockStatsStorage();
      case "clear_stats_history":
        mockStatsCleared = true;
        return mockStatsStorage();
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
