/** Mirrors the serde representations in `src-tauri/src`. Keep them in sync. */

export type Protocol =
  | "vless"
  | "vmess"
  | "trojan"
  | "shadowsocks"
  | "hysteria2"
  | "tuic";

export type Network = "tcp" | "ws" | "grpc" | "http" | "httpupgrade";
export type Security = "none" | "tls" | "reality";

export interface ServerNode {
  id: string;
  name: string;
  protocol: Protocol;
  address: string;
  port: number;
  uuid: string;
  password: string;
  method: string;
  alterId: number;
  vmessSecurity: string;
  network: Network;
  path: string;
  host: string;
  serviceName: string;
  security: Security;
  sni: string;
  alpn: string[];
  fingerprint: string;
  publicKey: string;
  shortId: string;
  allowInsecure: boolean;
  flow: string;
  mux: boolean;
  /** hysteria2: QUIC-обфускация («salamander») и её пароль; пусто — без неё. */
  obfs: string;
  obfsPassword: string;
  /** hysteria2: диапазоны прыжковых портов в форме sing-box («20000:50000»). */
  hopPorts: string[];
  subscriptionId: string | null;
  rawLink: string;
}

export type TunnelMode = "tun" | "systemProxy";
export type TunStack = "mixed" | "system" | "gvisor";

// The shipped languages live next to the dictionaries; re-exported here so the
// settings shape below still reads as one piece. `import type` is erased, so
// this does not pull i18n (and the store behind it) into a runtime cycle.
import type { LangChoice } from "./i18n";
export type { LangChoice };

export interface Settings {
  /** `system` follows the OS locale; mirrored to Rust for the tray menu. */
  language: LangChoice;
  tunnelMode: TunnelMode;
  mixedPort: number;
  clashPort: number;
  allowLan: boolean;
  tunStack: TunStack;
  tunMtu: number;
  strictRoute: boolean;
  ipv6: boolean;
  logLevel: string;
  dnsRemote: string;
  dnsDirect: string;
  dnsStrategy: string;
  fakeIp: boolean;
  autoConnect: boolean;
  startMinimized: boolean;
  launchAtLogin: boolean;
  closeToTray: boolean;
  theme: ThemeChoice;
  /** Resolved palette details, mirrored so Rust can paint the window before the
   *  WebView loads. Written by the frontend whenever the theme changes. */
  themeDark: boolean;
  themeBackground: string;
  latencyUrl: string;
  /** Who picks the server; strategies are described in core/balancer.rs. */
  balancer: Balancer;
  /** Minutes between full sweeps of every server. */
  balancerIntervalMin: number;
  /** `fastest` only: another server must beat the current one by this much. */
  balancerToleranceMs: number;
  subAutoUpdateMin: number;
}

/** `manual` — the pinned server; the rest let the app switch on its own. */
export type Balancer = "manual" | "failover" | "fastest" | "rotate";

export type ThemeChoice =
  | "system"
  | "dark"
  | "light"
  | "midnight"
  | "crimson"
  | "emerald"
  | "swamp";

/**
 * `normal` is a registry Run entry; `elevated` is a scheduled task, the only
 * mechanism Windows allows to start a program with administrator rights at
 * logon without a UAC prompt.
 */
export type AutostartMode = "off" | "normal" | "elevated";

export type SplitMode = "off" | "include" | "exclude";

export interface AppRule {
  id: string;
  name: string;
  path: string;
  enabled: boolean;
}

export interface SplitConfig {
  mode: SplitMode;
  apps: AppRule[];
  directDomains: string[];
  directIps: string[];
  proxyDomains: string[];
  proxyIps: string[];
  blockDomains: string[];
  bypassPrivate: boolean;
  bypassRu: boolean;
  bypassCn: boolean;
  blockAds: boolean;
}

export interface Subscription {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  lastUpdated: string;
  nodeCount: number;
  lastError: string;

  /** Plan status from the panel's `subscription-userinfo` header. */
  upload: number;
  download: number;
  /** Bytes allowed; 0 means unlimited. */
  total: number;
  /** Unix seconds; 0 means the plan never expires. */
  expire: number;
  updateIntervalHours: number;
  /** False when the provider has never reported a quota. */
  hasUsage: boolean;
}

export type ConnState = "disconnected" | "connecting" | "connected" | "error";
export type ClashMode = "Rule" | "Global" | "Direct";

export interface Status {
  state: ConnState;
  message: string;
  sinceMs: number | null;
  mode: ClashMode;
  tunnelMode: TunnelMode;
  /** The server the user picked; with a balancer, the primary. */
  activeId: string;
  /** The node traffic goes through right now; empty while disconnected. */
  routedId: string;
  /** The link through the current server, on top of "the tunnel is up". */
  link: Link;
  elevated: boolean;
  systemProxy: boolean;
}

/**
 * What the app knows about the server carrying traffic: `connecting` — the
 * tunnel just came up and the first check is pending; `switching` — the server
 * changed and the new one is unchecked; `up` — the last check passed; `down` —
 * two misses in a row, no traffic flows.
 */
export type Link = "connecting" | "switching" | "up" | "down";

/** The node worth showing: the routed one while connected, else the pick. */
export function shownServerId(status: Status): string {
  return status.state === "connected" && status.routedId
    ? status.routedId
    : status.activeId;
}

export interface Traffic {
  upload: number;
  download: number;
  upSpeed: number;
  downSpeed: number;
  connections: number;
}

export interface LogLine {
  seq: number;
  level: string;
  text: string;
}

export interface RunningApp {
  name: string;
  path: string;
  instances: number;
  system: boolean;
}

/** One row of the in-app resource monitor: a group of related processes. */
export interface ResourceGroup {
  id: "app" | "ui" | "core" | "xray";
  processes: number;
  /** Resident memory, bytes. */
  memory: number;
  /** Share of the whole machine's CPU, percent. */
  cpu: number;
}

export type LatencyMap = Record<string, number | null>;

export interface Snapshot {
  settings: Settings;
  nodes: ServerNode[];
  subscriptions: Subscription[];
  split: SplitConfig;
  status: Status;
  traffic: Traffic;
  latency: LatencyMap;
  activeId: string;
  coreVersion: string;
  autostart: AutostartMode;
}

export interface ImportReport {
  added: number;
  skipped: number;
  /** `[source line, reason]` for links that could not be imported. */
  errors: [string, string][];
}

/** Sentinel the backend returns when TUN mode is requested without elevation. */
export const ELEVATION_REQUIRED = "ELEVATION_REQUIRED";

/** A published release the running build can be upgraded to. */
export interface UpdateInfo {
  version: string;
  url: string;
  notes: string;
}

/** Download ticks for an in-flight update install; `total` is `null` when the
 * server sent no Content-Length. */
export interface UpdateProgress {
  downloaded: number;
  total: number | null;
}
