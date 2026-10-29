import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { FolderOpen, Plus, RefreshCw, Search, Split as SplitIcon, Trash2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { Empty, Modal, Segmented, Switch } from "../components/ui";
import { api, errText } from "../lib/api";
import { osKey, useT, type MsgKey } from "../lib/i18n";
import { IS_ANDROID, OS_NAME } from "../lib/platform";
import type { AppRule, RunningApp, SplitMode } from "../lib/types";
import { useStore } from "../store";

const MODE_HELP: Record<SplitMode, MsgKey> = {
  off: "split.modeOffHelp",
  include: "split.modeIncludeHelp",
  exclude: "split.modeExcludeHelp",
};

function newId() {
  return `app-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

/** What makes two entries the same app: the package on Android, the
 *  executable name on desktop (see how the picker builds rules). */
function ruleKey(app: { name: string; path: string }) {
  return (IS_ANDROID ? app.path : app.name).toLowerCase();
}

// Launcher icons — Android only, where a package name is something the OS can
// draw. Rows ask as they scroll into view and the asks of one frame go out as
// one call, so a few hundred packages neither wait for every icon nor cost a
// round trip each. Promises are cached rather than results, so a row that
// mounts while its icon is in flight joins that request instead of repeating it.
const iconRequests = new Map<string, Promise<string | null>>();
const iconsReady = new Map<string, string | null>();
let iconBatch: string[] | null = null;
let iconBatchResult: Promise<Record<string, string>> | null = null;

function appIcon(pkg: string): Promise<string | null> {
  const known = iconRequests.get(pkg);
  if (known) return known;
  if (!iconBatch || !iconBatchResult) {
    const batch: string[] = [];
    iconBatch = batch;
    iconBatchResult = new Promise((resolve) =>
      setTimeout(() => {
        iconBatch = iconBatchResult = null;
        api.appIcons(batch).then(resolve, () => {
          // Cosmetic: the letter stays, and the next mount asks again.
          batch.forEach((p) => iconRequests.delete(p));
          resolve({});
        });
      }, 16),
    );
  }
  iconBatch.push(pkg);
  const request = iconBatchResult.then((icons) => {
    const url = icons[pkg] ?? null;
    iconsReady.set(pkg, url);
    return url;
  });
  iconRequests.set(pkg, request);
  return request;
}

function AppIcon({ name, pkg }: { name: string; pkg: string }) {
  const ref = useRef<HTMLDivElement>(null);
  const [src, setSrc] = useState(() => iconsReady.get(pkg) ?? null);

  useEffect(() => {
    const el = ref.current;
    if (!IS_ANDROID || !pkg || !el || iconsReady.has(pkg)) return;
    let alive = true;
    const seen = new IntersectionObserver((entries) => {
      if (!entries.some((e) => e.isIntersecting)) return;
      seen.disconnect();
      void appIcon(pkg).then((url) => alive && setSrc(url));
    });
    seen.observe(el);
    return () => {
      alive = false;
      seen.disconnect();
    };
  }, [pkg]);

  return (
    <div ref={ref} className={src ? "app-icon image" : "app-icon"}>
      {src ? <img src={src} alt="" draggable={false} /> : name.slice(0, 1)}
    </div>
  );
}

export function SplitTunnel() {
  const t = useT();
  const split = useStore((s) => s.split);
  const saveSplit = useStore((s) => s.saveSplit);
  const tunnelMode = useStore((s) => s.status.tunnelMode);
  const toast = useStore((s) => s.toast);

  const [pickerOpen, setPickerOpen] = useState(false);
  // The help line follows the cursor, so a mode can be read before it is picked.
  const [hoveredMode, setHoveredMode] = useState<SplitMode | null>(null);

  const apps = split.apps ?? [];

  function setApps(next: AppRule[]) {
    void saveSplit({ apps: next });
  }

  async function addByPath() {
    const picked = await openDialog({
      multiple: false,
      title: t("split.exeDialogTitle"),
      filters: [{ name: t("split.exeDialogFilter"), extensions: ["exe"] }],
    });
    if (typeof picked !== "string") return;
    const name = picked.split(/[\\/]/).pop() ?? picked;
    if (apps.some((a) => a.path.toLowerCase() === picked.toLowerCase())) {
      toast("info", t("split.alreadyInList"));
      return;
    }
    setApps([...apps, { id: newId(), name, path: picked, enabled: true }]);
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{t("split.title")}</h1>
          <p className="page-sub">{t("split.subtitle")}</p>
        </div>
        {/* The mode switcher lives in the header — the space to the right of
            the title is otherwise empty, and the mode is the page's one
            top-level decision. */}
        <div className="mode-head">
          <Segmented<SplitMode>
            value={split.mode ?? "off"}
            onChange={(mode) => void saveSplit({ mode })}
            onHover={setHoveredMode}
            options={[
              { value: "off", label: t("split.modeOff") },
              { value: "include", label: t("split.modeInclude") },
              { value: "exclude", label: t("split.modeExclude") },
            ]}
          />
          <div className="mode-help">
            {t(MODE_HELP[hoveredMode ?? split.mode ?? "off"])}
          </div>
        </div>
      </div>

      {tunnelMode !== "tun" && (
        <div className="alert" style={{ marginBottom: 18 }}>
          <SplitIcon size={17} color="var(--warn)" style={{ flexShrink: 0 }} />
          <div>
            <div className="alert-title">{t("split.tunOnlyTitle")}</div>
            <div className="alert-text">{t("split.tunOnlyText")}</div>
          </div>
        </div>
      )}

      <div className="section-title">
        <span className="row between">
          <span>{t("split.appsCount", { count: apps.length })}</span>
        </span>
      </div>

      <div className="row" style={{ marginBottom: 12 }}>
        <button
          type="button"
          className="btn primary"
          onClick={() => setPickerOpen(true)}
        >
          <Plus size={15} />
          {t(osKey("split.addFromRunning"))}
        </button>
        {/* Android routes by package name, and the picker already lists every
            installed one — there is no executable to browse for. */}
        {!IS_ANDROID && (
          <button type="button" className="btn" onClick={() => void addByPath()}>
            <FolderOpen size={15} />
            {t("split.pickExe")}
          </button>
        )}
        <div className="grow" />
        {apps.length > 0 && (
          <button
            type="button"
            className="btn ghost sm"
            onClick={() => setApps([])}
          >
            {t("split.clearList")}
          </button>
        )}
      </div>

      {apps.length === 0 ? (
        <Empty
          icon={<SplitIcon size={34} color="var(--text-muted)" />}
          title={t("split.emptyTitle")}
          text={t(osKey("split.emptyText"))}
        />
      ) : (
        <div className="list">
          {apps.map((app) => (
            <div key={app.id} className="app-row">
              <AppIcon name={app.name} pkg={app.path} />
              <div className="grow" style={{ minWidth: 0 }}>
                <div className="node-name truncate">{app.name}</div>
                <div className="node-meta">
                  <span className="truncate" title={app.path}>
                    {/* On Android only rules saved before packages were
                        recorded lack one, and those never reach the tunnel. */}
                    {app.path || t(osKey("split.matchByName"))}
                  </span>
                </div>
              </div>
              <Switch
                checked={app.enabled}
                onChange={(enabled) =>
                  setApps(apps.map((a) => (a.id === app.id ? { ...a, enabled } : a)))
                }
              />
              <button
                type="button"
                className="btn ghost icon"
                onClick={() => setApps(apps.filter((a) => a.id !== app.id))}
              >
                <Trash2 size={14} />
              </button>
            </div>
          ))}
        </div>
      )}

      <ProcessPicker
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        existing={apps}
        onAdd={(picked) => {
          const additions = picked
            .filter(
              (p) =>
                !apps.some(
                  (a) =>
                    a.path.toLowerCase() === p.path.toLowerCase() ||
                    (!a.path && a.name.toLowerCase() === p.name.toLowerCase()),
                ),
            )
            .map<AppRule>((p) => ({
              id: newId(),
              name: p.name,
              // Desktop: match by name so the rule keeps working after an
              // update moves the binary into a new versioned directory.
              // Android: `path` is the package name, the only thing the tun
              // inbound's per-app lists match on — left empty, the rule
              // never reached the tunnel at all.
              path: IS_ANDROID ? p.path : "",
              enabled: true,
            }));
          if (additions.length) setApps([...apps, ...additions]);
        }}
      />
    </>
  );
}

function ProcessPicker({
  open,
  onClose,
  existing,
  onAdd,
}: {
  open: boolean;
  onClose: () => void;
  existing: AppRule[];
  onAdd: (apps: RunningApp[]) => void;
}) {
  const t = useT();
  const [apps, setApps] = useState<RunningApp[]>([]);
  const [query, setQuery] = useState("");
  const [includeSystem, setIncludeSystem] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(false);
  const toast = useStore((s) => s.toast);

  async function load(withSystem: boolean) {
    setLoading(true);
    try {
      setApps(await api.listRunningApps(withSystem));
    } catch (e) {
      toast("error", t(osKey("split.procsFailed")), errText(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    if (open) {
      setSelected(new Set());
      setQuery("");
      void load(includeSystem);
    }
    // `includeSystem` intentionally re-runs the fetch while the dialog is open.
  }, [open, includeSystem]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return apps;
    return apps.filter(
      (a) => a.name.toLowerCase().includes(q) || a.path.toLowerCase().includes(q),
    );
  }, [apps, query]);

  const alreadyAdded = useMemo(
    () => new Set(existing.map(ruleKey)),
    [existing],
  );

  return (
    <Modal
      open={open}
      wide
      title={t(osKey("split.runningApps"))}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t("split.cancel")}
          </button>
          <button
            type="button"
            className="btn primary"
            disabled={selected.size === 0}
            onClick={() => {
              onAdd(apps.filter((a) => selected.has(a.path)));
              onClose();
            }}
          >
            {t("split.addCount", { count: selected.size })}
          </button>
        </>
      }
    >
      <div className="picker-tools">
        <div style={{ position: "relative" }}>
          <Search
            size={14}
            color="var(--text-muted)"
            style={{ position: "absolute", left: 10, top: 10 }}
          />
          <input
            className="input"
            style={{ paddingLeft: 31 }}
            placeholder={t(osKey("split.searchPlaceholder"))}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <button
          type="button"
          className="btn icon"
          title={t("split.refresh")}
          onClick={() => void load(includeSystem)}
        >
          <RefreshCw size={15} className={loading ? "spin" : ""} />
        </button>
        <div className="row picker-system" style={{ gap: 8 }}>
          <Switch checked={includeSystem} onChange={setIncludeSystem} />
          <span style={{ fontSize: 12.5, color: "var(--text-dim)" }}>
            {t(osKey("split.showSystemProcs"), { os: OS_NAME })}
          </span>
        </div>
      </div>

      <div className="list picker-list">
        {filtered.length === 0 && (
          <div className="empty" style={{ padding: 28 }}>
            <p>{loading ? t("split.loading") : t("split.nothingFound")}</p>
          </div>
        )}
        {filtered.map((app) => {
          const isSelected = selected.has(app.path);
          const added = alreadyAdded.has(ruleKey(app));
          return (
            <button
              key={app.path}
              type="button"
              className="app-row"
              style={{
                textAlign: "left",
                cursor: "default",
                borderColor: isSelected ? "var(--accent)" : undefined,
                opacity: added ? 0.5 : 1,
              }}
              disabled={added}
              onClick={() =>
                setSelected((prev) => {
                  const next = new Set(prev);
                  if (next.has(app.path)) next.delete(app.path);
                  else next.add(app.path);
                  return next;
                })
              }
            >
              <AppIcon name={app.name} pkg={app.path} />
              <div className="grow" style={{ minWidth: 0 }}>
                <div className="node-name truncate">{app.name}</div>
                <div className="node-meta">
                  <span className="truncate" title={app.path}>
                    {app.path}
                  </span>
                </div>
              </div>
              {app.instances > 1 && (
                <span className="chip">
                  {t("split.instancesCount", { count: app.instances })}
                </span>
              )}
              {added && <span className="chip">{t("split.alreadyAdded")}</span>}
              {isSelected && !added && (
                <span className="chip accent">{t("split.selectedChip")}</span>
              )}
            </button>
          );
        })}
      </div>
    </Modal>
  );
}
