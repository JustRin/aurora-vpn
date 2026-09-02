import { getVersion } from "@tauri-apps/api/app";
import { create } from "zustand";

import {
  api,
  errText,
  onLatency,
  onLog,
  onNodes,
  onStatus,
  onSubscriptions,
  onTraffic,
} from "./lib/api";
import { tNow } from "./lib/i18n";
import { applyTheme, watchSystemTheme } from "./lib/theme";
import { paletteFor } from "./lib/themes";
import type {
  AutostartMode,
  ClashMode,
  LatencyMap,
  LogLine,
  ServerNode,
  Settings,
  SplitConfig,
  Status,
  Subscription,
  Traffic,
} from "./lib/types";

export interface Toast {
  id: number;
  kind: "info" | "success" | "error";
  text: string;
  detail?: string;
}

/** Samples kept for the throughput sparkline (one per second). */
const HISTORY_LENGTH = 60;
const MAX_LOG_LINES = 3000;

export interface TrafficSample {
  up: number;
  down: number;
}

/** Sidebar destinations. The current page lives in the store rather than in
 * App's local state so pages can send the user elsewhere — the dashboard's
 * empty state links straight to Servers. */
export type PageId =
  | "dashboard"
  | "servers"
  | "split"
  | "routing"
  | "logs"
  | "settings";

interface AppStore {
  ready: boolean;
  loadError: string;
  page: PageId;

  settings: Settings;
  nodes: ServerNode[];
  subscriptions: Subscription[];
  split: SplitConfig;
  status: Status;
  traffic: Traffic;
  latency: LatencyMap;
  coreVersion: string;
  appVersion: string;
  autostart: AutostartMode;

  logs: LogLine[];
  history: TrafficSample[];
  toasts: Toast[];
  busy: Record<string, boolean>;

  init: () => Promise<void>;
  navigate: (page: PageId) => void;
  toast: (kind: Toast["kind"], text: string, detail?: string) => void;
  dismissToast: (id: number) => void;
  setBusy: (key: string, value: boolean) => void;

  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  saveSettings: (patch: Partial<Settings>) => Promise<void>;
  setAutostart: (mode: AutostartMode) => Promise<void>;
  saveSplit: (patch: Partial<SplitConfig>) => Promise<void>;
  selectServer: (id: string) => Promise<void>;
  setMode: (mode: ClashMode) => Promise<void>;
  refreshLatency: (ids?: string[]) => Promise<void>;
  reload: () => Promise<void>;
  clearLogs: () => Promise<void>;
}

let toastSeq = 0;

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error(tNow("toast.backendTimeout", { label, s: ms / 1000 }))),
        ms,
      ),
    ),
  ]);
}

export const useStore = create<AppStore>((set, get) => ({
  ready: false,
  loadError: "",
  page: "dashboard",

  settings: {} as Settings,
  nodes: [],
  subscriptions: [],
  split: {} as SplitConfig,
  status: {
    state: "disconnected",
    message: "",
    sinceMs: null,
    mode: "Rule",
    tunnelMode: "tun",
    activeId: "",
    routedId: "",
    link: "connecting",
    elevated: false,
    systemProxy: false,
  },
  traffic: { upload: 0, download: 0, upSpeed: 0, downSpeed: 0, connections: 0 },
  latency: {},
  coreVersion: "",
  appVersion: "",
  autostart: "off",

  logs: [],
  history: [],
  toasts: [],
  busy: {},

  async init() {
    // Independent of the snapshot: a failure here must not block start-up,
    // it only leaves the version rows empty.
    void getVersion()
      .then((appVersion) => set({ appVersion }))
      .catch(() => {});
    try {
      // A hung IPC call must surface as a diagnosable error, never as an
      // indefinite splash screen.
      const [snapshot, logs] = await Promise.all([
        withTimeout(api.snapshot(), 15000, "get_snapshot"),
        withTimeout(api.logs(), 15000, "get_logs"),
      ]);
      set({
        ready: true,
        settings: snapshot.settings,
        nodes: snapshot.nodes,
        subscriptions: snapshot.subscriptions,
        split: snapshot.split,
        status: snapshot.status,
        traffic: snapshot.traffic,
        latency: snapshot.latency,
        coreVersion: snapshot.coreVersion,
        autostart: snapshot.autostart,
        logs,
      });
      // Paint before the window is revealed, so the first frame is already in
      // the user's theme.
      applyTheme(snapshot.settings.theme);
      watchSystemTheme(() => get().settings.theme);
    } catch (e) {
      set({ ready: true, loadError: errText(e) });
      return;
    }

    void onStatus((status: Status) => {
      // Leaving the connected state should also flatten the graph, otherwise the
      // last spike stays frozen on screen.
      if (status.state !== "connected") set({ history: [] });
      set({ status });
    });

    void onTraffic((traffic: Traffic) => {
      set((s) => ({
        traffic,
        history: [
          ...s.history.slice(-(HISTORY_LENGTH - 1)),
          { up: traffic.upSpeed, down: traffic.downSpeed },
        ],
      }));
    });

    void onLog((line: LogLine) => {
      set((s) => ({ logs: [...s.logs.slice(-(MAX_LOG_LINES - 1)), line] }));
    });

    void onNodes((nodes: ServerNode[]) => set({ nodes }));
    // Subscriptions also refresh on a timer, with no UI action to reload from.
    void onSubscriptions((subscriptions: Subscription[]) => set({ subscriptions }));
    void onLatency((latency: LatencyMap) => set((s) => ({ latency: { ...s.latency, ...latency } })));
  },

  navigate(page) {
    set({ page });
  },

  toast(kind, text, detail) {
    const id = ++toastSeq;
    set((s) => ({ toasts: [...s.toasts, { id, kind, text, detail }] }));
    // Errors carry detail worth reading, so they linger longer.
    window.setTimeout(() => get().dismissToast(id), kind === "error" ? 9000 : 4000);
  },

  dismissToast(id) {
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
  },

  setBusy(key, value) {
    set((s) => ({ busy: { ...s.busy, [key]: value } }));
  },

  async connect() {
    get().setBusy("connection", true);
    try {
      await api.connect();
    } catch (e) {
      // ELEVATION_REQUIRED is handled by the dashboard, which can offer the
      // restart prompt; everything else is a plain failure.
      throw e;
    } finally {
      get().setBusy("connection", false);
    }
  },

  async disconnect() {
    get().setBusy("connection", true);
    try {
      await api.disconnect();
    } catch (e) {
      get().toast("error", tNow("toast.disconnectFailed"), errText(e));
    } finally {
      get().setBusy("connection", false);
    }
  },

  async saveSettings(patch) {
    if (patch.theme) {
      // Mirror the resolved palette into settings so the Rust side can paint the
      // window on the next launch without waiting for the frontend.
      const palette = paletteFor(patch.theme);
      patch = {
        ...patch,
        themeDark: palette.dark,
        themeBackground: palette.background,
      };
    }
    const next = { ...get().settings, ...patch };
    set({ settings: next });
    // Repaint immediately: waiting for the round-trip would show a visible lag
    // between clicking a theme and seeing it.
    if (patch.theme) applyTheme(patch.theme);
    try {
      await api.saveSettings(next);
    } catch (e) {
      get().toast("error", tNow("toast.settingsFailed"), errText(e));
      await get().reload();
    }
  },

  async setAutostart(mode) {
    const previous = get().autostart;
    set({ autostart: mode });
    try {
      // The backend reports what the OS ended up with, which may differ from
      // what was asked if part of the change was refused.
      set({ autostart: await api.setAutostart(mode) });
    } catch (e) {
      set({ autostart: previous });
      throw e;
    }
  },

  async saveSplit(patch) {
    const next = { ...get().split, ...patch };
    set({ split: next });
    try {
      await api.setSplit(next);
    } catch (e) {
      get().toast("error", tNow("toast.rulesFailed"), errText(e));
      await get().reload();
    }
  },

  async selectServer(id) {
    const { activeId, routedId, state } = get().status;
    set((s) => ({
      status: {
        ...s.status,
        activeId: id,
        // Connected, the pick takes over the traffic at once.
        routedId: state === "connected" ? id : s.status.routedId,
      },
    }));
    try {
      const balancerOff = await api.setActiveServer(id);
      // A pick under «fastest» / «rotation» turns the balancer off on the
      // backend — mirror it here, or the settings page keeps lying.
      if (balancerOff) {
        set((s) => ({ settings: { ...s.settings, balancer: "manual" } }));
        get().toast("info", tNow("toast.balancerOff"));
      }
    } catch (e) {
      set((s) => ({ status: { ...s.status, activeId, routedId } }));
      get().toast("error", tNow("toast.serverSwitchFailed"), errText(e));
    }
  },

  async setMode(mode) {
    const previous = get().status.mode;
    set((s) => ({ status: { ...s.status, mode } }));
    try {
      await api.setClashMode(mode);
    } catch (e) {
      set((s) => ({ status: { ...s.status, mode: previous } }));
      get().toast("error", tNow("toast.modeSwitchFailed"), errText(e));
    }
  },

  async refreshLatency(ids = []) {
    get().setBusy("latency", true);
    try {
      const result = await api.testLatency(ids);
      set((s) => ({ latency: { ...s.latency, ...result } }));
    } catch (e) {
      get().toast("error", tNow("toast.latencyFailed"), errText(e));
    } finally {
      get().setBusy("latency", false);
    }
  },

  async reload() {
    try {
      const snapshot = await api.snapshot();
      set({
        settings: snapshot.settings,
        nodes: snapshot.nodes,
        subscriptions: snapshot.subscriptions,
        split: snapshot.split,
        status: snapshot.status,
        traffic: snapshot.traffic,
        latency: snapshot.latency,
        coreVersion: snapshot.coreVersion,
        autostart: snapshot.autostart,
      });
    } catch (e) {
      get().toast("error", tNow("toast.reloadFailed"), errText(e));
    }
  },

  async clearLogs() {
    await api.clearLogs();
    set({ logs: [] });
  },
}));
