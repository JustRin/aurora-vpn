import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

import type {
  AutostartMode,
  ClashMode,
  ImportReport,
  LatencyMap,
  LogLine,
  ResourceGroup,
  RunningApp,
  ServerNode,
  Settings,
  Snapshot,
  SplitConfig,
  Status,
  Subscription,
  Traffic,
  UpdateInfo,
  UpdateProgress,
} from "./types";

export const EVT = {
  status: "app://status",
  traffic: "app://traffic",
  log: "app://log",
  nodes: "app://nodes",
  subscriptions: "app://subscriptions",
  latency: "app://latency",
  updateProgress: "app://update-progress",
} as const;

export const api = {
  snapshot: () => invoke<Snapshot>("get_snapshot"),

  connect: () => invoke<void>("connect"),
  disconnect: () => invoke<void>("disconnect"),

  saveSettings: (settings: Settings) => invoke<void>("save_settings", { settings }),
  setSplit: (split: SplitConfig) => invoke<void>("set_split", { split }),
  setActiveServer: (id: string) => invoke<void>("set_active_server", { id }),
  setClashMode: (mode: ClashMode) => invoke<void>("set_clash_mode", { mode }),

  addLinks: (text: string) => invoke<ImportReport>("add_links", { text }),
  deleteServer: (id: string) => invoke<void>("delete_server", { id }),
  updateServer: (node: ServerNode) => invoke<void>("update_server", { node }),

  addSubscription: (name: string, url: string) =>
    invoke<ImportReport>("add_subscription", { input: { name, url } }),
  refreshSubscription: (id: string) =>
    invoke<ImportReport>("refresh_subscription", { id }),
  refreshAllSubscriptions: () => invoke<ImportReport>("refresh_all_subscriptions"),
  deleteSubscription: (id: string) => invoke<void>("delete_subscription", { id }),

  /** Reveals the main window; called once the UI has actually painted. */
  appReady: () => invoke<void>("app_ready"),

  /** Empty `ids` measures every node. */
  testLatency: (ids: string[] = []) => invoke<LatencyMap>("test_latency", { ids }),

  listRunningApps: (includeSystem: boolean) =>
    invoke<RunningApp[]>("list_running_apps", { includeSystem }),

  /** Memory/CPU of the app's whole process family, grouped for display. */
  resourceUsage: () => invoke<ResourceGroup[]>("resource_usage"),

  closeConnections: () => invoke<void>("close_connections"),

  logs: () => invoke<LogLine[]>("get_logs"),
  clearLogs: () => invoke<void>("clear_logs"),
  previewConfig: () => invoke<string>("preview_config"),

  getAutostart: () => invoke<AutostartMode>("get_autostart"),
  /** Returns the mode actually in force after the change. */
  setAutostart: (mode: AutostartMode) =>
    invoke<AutostartMode>("set_autostart", { mode }),
  setWindowTheme: (dark: boolean, background: string) =>
    invoke<void>("set_window_theme", { dark, background }),

  isElevated: () => invoke<boolean>("is_elevated"),
  relaunchElevated: () => invoke<void>("relaunch_elevated"),
  openConfigDir: () => invoke<void>("open_config_dir"),
  /** Windows: the elevated window hides PrtScn from the Snipping Tool (UIPI),
   * so the frontend relays the key press and the overlay is opened by hand. */
  openScreenSnip: () => invoke<void>("open_screen_snip"),

  /** `null` when the running build is already the newest release. */
  checkUpdate: () => invoke<UpdateInfo | null>("check_update"),
  /** Streams download ticks via `EVT.updateProgress`; on Windows the app then
   * exits into a silent installer that relaunches it. */
  installUpdate: (url: string) => invoke<void>("install_update", { url }),
};

export function onStatus(cb: (value: Status) => void): Promise<UnlistenFn> {
  return listen<Status>(EVT.status, (e) => cb(e.payload));
}

export function onTraffic(cb: (value: Traffic) => void): Promise<UnlistenFn> {
  return listen<Traffic>(EVT.traffic, (e) => cb(e.payload));
}

export function onLog(cb: (value: LogLine) => void): Promise<UnlistenFn> {
  return listen<LogLine>(EVT.log, (e) => cb(e.payload));
}

export function onNodes(cb: (value: ServerNode[]) => void): Promise<UnlistenFn> {
  return listen<ServerNode[]>(EVT.nodes, (e) => cb(e.payload));
}

export function onSubscriptions(
  cb: (value: Subscription[]) => void,
): Promise<UnlistenFn> {
  return listen<Subscription[]>(EVT.subscriptions, (e) => cb(e.payload));
}

export function onLatency(cb: (value: LatencyMap) => void): Promise<UnlistenFn> {
  return listen<LatencyMap>(EVT.latency, (e) => cb(e.payload));
}

export function onUpdateProgress(
  cb: (value: UpdateProgress) => void,
): Promise<UnlistenFn> {
  return listen<UpdateProgress>(EVT.updateProgress, (e) => cb(e.payload));
}

/** Tauri rejects with whatever the command serialized; normalise it to a string. */
export function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  return String(e);
}
