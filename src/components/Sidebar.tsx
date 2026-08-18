import { useEffect, useState } from "react";
import {
  Cpu,
  Download,
  Gauge,
  ListTree,
  ScrollText,
  Server,
  Settings as SettingsIcon,
  Split,
} from "lucide-react";

import { api, errText } from "../lib/api";
import { useT, type MsgKey } from "../lib/i18n";
import { IS_ANDROID } from "../lib/platform";
import type { UpdateInfo } from "../lib/types";
import { useStore } from "../store";

const UPDATE_CHECK_INTERVAL = 6 * 60 * 60 * 1000;

/** Bottom-left release watcher: quiet until a newer build is published, then
 * a single click downloads the installer and restarts into it. */
function UpdateBadge() {
  const t = useT();
  const [update, setUpdate] = useState<UpdateInfo | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const toast = useStore((s) => s.toast);

  useEffect(() => {
    let disposed = false;
    const check = () =>
      api
        .checkUpdate()
        .then((info) => {
          if (!disposed) setUpdate(info);
        })
        // Offline or rate-limited — try again on the next tick.
        .catch(() => {});
    // Let the app finish its own start-up before touching the network.
    const first = setTimeout(check, 5000);
    const timer = setInterval(check, UPDATE_CHECK_INTERVAL);
    return () => {
      disposed = true;
      clearTimeout(first);
      clearInterval(timer);
    };
  }, []);

  if (!update) return null;

  const install = () => {
    setBusy(true);
    setError("");
    api
      .installUpdate(update.url)
      // On Windows the app exits into the installer; elsewhere the package
      // opens in the browser and the app keeps running.
      .then(() => setBusy(false))
      .catch((e) => {
        setBusy(false);
        setError(errText(e));
        toast("error", t("side.updateFailed"), errText(e));
      });
  };

  return (
    <button
      type="button"
      className="update-badge"
      disabled={busy}
      title={error || t("side.installVersion", { version: update.version })}
      onClick={install}
    >
      <Download size={15} className={busy ? "pulse" : undefined} />
      <span className="grow truncate">
        {busy ? t("side.downloading") : t("side.update")}
      </span>
      {!busy && <span className="update-version">{update.version}</span>}
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
  const elevated = useStore((s) => s.status.elevated);

  return (
    <aside className="sidebar">
      <nav className="nav">
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
