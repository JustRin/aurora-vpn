import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { getCurrentWindow } from "@tauri-apps/api/window";
import {
  Cpu,
  Download,
  Gauge,
  Info,
  ListTree,
  ScrollText,
  Server,
  Settings as SettingsIcon,
  Split,
} from "lucide-react";

import { api, errText, onUpdateProgress } from "../lib/api";
import { useT, type MsgKey } from "../lib/i18n";
import { IS_ANDROID } from "../lib/platform";
import type { UpdateInfo, UpdateProgress } from "../lib/types";
import { useStore } from "../store";

const UPDATE_CHECK_INTERVAL = 10 * 60 * 1000;
/** A window focus re-checks at most this often: the GitHub API is
 * unauthenticated and rate-limited per IP. */
const FOCUS_CHECK_MIN_GAP = 10 * 60 * 1000;

/** Bottom-left release watcher: quiet until a newer build is published, then
 * a single click downloads the installer and restarts into it. */
function UpdateBadge() {
  const t = useT();
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [progress, setProgress] = useState<UpdateProgress | null>(null);
  const [error, setError] = useState("");
  const toast = useStore((s) => s.toast);

  useEffect(() => {
    let disposed = false;
    let lastCheck = 0;
    const check = () => {
      lastCheck = Date.now();
      api
        .checkUpdate()
        .then((info) => {
          if (!disposed) setUpdate(info);
        })
        // Offline or rate-limited — try again on the next tick.
        .catch(() => {});
    };
    // Let the app finish its own start-up before touching the network.
    const first = setTimeout(check, 5000);
    const timer = setInterval(check, UPDATE_CHECK_INTERVAL);
    // A release published mid-session used to stay invisible until the next
    // slow tick; coming back to the window is the natural moment to look
    // again. Native window focus, not the DOM event — restoring from the tray
    // must count too.
    const unfocus = getCurrentWindow().onFocusChanged(({ payload }) => {
      if (payload && Date.now() - lastCheck >= FOCUS_CHECK_MIN_GAP) check();
    });
    return () => {
      disposed = true;
      clearTimeout(first);
      clearInterval(timer);
      void unfocus.then((f) => f());
    };
  }, []);

  useEffect(() => {
    let disposed = false;
    const unlisten = onUpdateProgress((p) => {
      if (!disposed) setProgress(p);
    });
    return () => {
      disposed = true;
      void unlisten.then((f) => f());
    };
  }, []);

  if (!update) return null;

  // Mirrors the backend branch: only this combination downloads in-app and
  // exits into a silent installer; every other platform opens the browser
  // and the app keeps running.
  const exitsIntoInstaller = !IS_ANDROID && update.url.endsWith("-setup.exe");

  const install = () => {
    setBusy(true);
    setError("");
    setProgress(null);
    api
      .installUpdate(update.url)
      // Keep the badge in its «installing» state while the app exits into
      // the installer — flipping back to «Update» would read as a failure.
      .then(() => {
        if (!exitsIntoInstaller) setBusy(false);
      })
      .catch((e) => {
        setBusy(false);
        setProgress(null);
        setError(errText(e));
        toast("error", t("side.updateFailed"), errText(e));
      });
  };

  const pct =
    busy && progress && progress.total
      ? Math.min(100, Math.round((progress.downloaded / progress.total) * 100))
      : null;
  const installing = pct === 100;
  const label = busy
    ? installing
      ? t("side.installing")
      : t("side.downloading")
    : t("side.update");

  return (
    <button
      type="button"
      className="update-badge"
      disabled={busy}
      title={error || t("side.installVersion", { version: update.version })}
      onClick={install}
    >
      <Download size={15} className={busy ? "pulse" : undefined} />
      <span className="grow truncate">{label}</span>
      {!busy && <span className="update-version">{update.version}</span>}
      {pct !== null && !installing && (
        <span className="update-version">{pct}%</span>
      )}
      {pct !== null && (
        <span className="update-progress" style={{ width: `${pct}%` }} />
      )}
    </button>
  );
}

export type PageId =
  | "dashboard"
  | "servers"
  | "split"
  | "routing"
  | "logs"
  | "settings";

const ITEMS: { id: PageId; labelKey: MsgKey; icon: typeof Gauge }[] = [
  { id: "dashboard", labelKey: "nav.dashboard", icon: Gauge },
  { id: "servers", labelKey: "nav.servers", icon: Server },
  { id: "split", labelKey: "nav.split", icon: Split },
  { id: "routing", labelKey: "nav.routing", icon: ListTree },
  { id: "logs", labelKey: "nav.logs", icon: ScrollText },
  { id: "settings", labelKey: "nav.settings", icon: SettingsIcon },
];

type Pill = { x: number; y: number; w: number; h: number };

/** Geometry of the active row, for the pill that slides between them.
 * The first placement lands without a transition: on open the selection is
 * already home, it does not fly in from the corner. */
function useNavPill(page: PageId) {
  const navRef = useRef<HTMLElement>(null);
  const [pill, setPill] = useState<Pill | null>(null);
  const [placed, setPlaced] = useState(false);

  useLayoutEffect(() => {
    const nav = navRef.current;
    const el = nav?.querySelector<HTMLElement>(".nav-item.active");
    if (!nav || !el) return;
    const measure = () => {
      const next = {
        x: el.offsetLeft,
        y: el.offsetTop,
        w: el.offsetWidth,
        h: el.offsetHeight,
      };
      // Identical numbers must not re-render: the observer below would
      // otherwise see its own write and loop.
      setPill((prev) =>
        prev &&
        prev.x === next.x &&
        prev.y === next.y &&
        prev.w === next.w &&
        prev.h === next.h
          ? prev
          : next,
      );
    };
    measure();
    // The rows move under us on a window resize, across the phone breakpoint,
    // and when a translation changes how wide a label sits.
    const ro = new ResizeObserver(measure);
    ro.observe(nav);
    ro.observe(el);
    return () => ro.disconnect();
  }, [page]);

  useEffect(() => {
    if (!pill || placed) return;
    // One frame parked at the starting position, then transitions may run.
    const frame = requestAnimationFrame(() => setPlaced(true));
    return () => cancelAnimationFrame(frame);
  }, [pill, placed]);

  return { navRef, pill, placed };
}

export function Sidebar({
  page,
  onNavigate,
}: {
  page: PageId;
  onNavigate: (page: PageId) => void;
}) {
  const t = useT();
  const nodeCount = useStore((s) => s.nodes.length);
  const coreVersion = useStore((s) => s.coreVersion);
  const appVersion = useStore((s) => s.appVersion);
  const elevated = useStore((s) => s.status.elevated);
  const { navRef, pill, placed } = useNavPill(page);

  return (
    <aside className="sidebar">
      <nav className="nav" ref={navRef}>
        {/* The active row's backdrop lives out here rather than on the button,
         * so switching pages slides one element instead of repainting two. */}
        {pill && (
          <span
            aria-hidden="true"
            className={`nav-pill${placed ? " sliding" : ""}`}
            style={{
              transform: `translate3d(${pill.x}px, ${pill.y}px, 0)`,
              width: pill.w,
              height: pill.h,
            }}
          />
        )}
        {ITEMS.map(({ id, labelKey, icon: Icon }) => (
          <button
            key={id}
            type="button"
            className={`nav-item${page === id ? " active" : ""}`}
            onClick={() => onNavigate(id)}
          >
            <Icon size={17} />
            <span className="grow truncate">{t(labelKey)}</span>
            {id === "servers" && nodeCount > 0 && (
              <span className="badge">{nodeCount}</span>
            )}
          </button>
        ))}
      </nav>

      <UpdateBadge />
      <div className="sidebar-footer">
        <div className="core-line">
          <Info size={13} />
          <span className="truncate" title={t("side.appVersion")}>
            {appVersion ? `Aurora VPN ${appVersion}` : "Aurora VPN"}
          </span>
        </div>
        <div className="core-line">
          <Cpu size={13} />
          <span className="truncate" title={coreVersion}>
            {coreVersion || t("side.noCore")}
          </span>
        </div>
        {!IS_ANDROID && (
          <div className="core-line">
            <span className={`dot ${elevated ? "good" : "ok"}`} />
            <span>{elevated ? t("side.admin") : t("side.user")}</span>
          </div>
        )}
      </div>
    </aside>
  );
}
