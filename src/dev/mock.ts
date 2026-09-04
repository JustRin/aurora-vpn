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
  nodes: [node("a", "Amsterdam", "nl.example.net"), node("b", "Helsinki", "fi.example.net")],
  subscriptions: [],
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
        return undefined;
      case "set_active_server":
        snapshot.activeId = String(a.id);
        snapshot.status.activeId = snapshot.activeId;
        return false;
      case "check_update":
        return null;
      case "list_running_apps":
        return [];
      case "test_latency":
        return snapshot.latency;
      case "connect":
      case "disconnect":
        throw "ELEVATION_REQUIRED";
      default:
        return undefined;
    }
  },
  { shouldMockEvents: true },
);
