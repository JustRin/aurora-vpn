import { open as openDialog } from "@tauri-apps/plugin-dialog";
import { FolderOpen, Plus, RefreshCw, Search, Split as SplitIcon, Trash2 } from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { Empty, Modal, Segmented, Switch } from "../components/ui";
import { api, errText } from "../lib/api";
import type { AppRule, RunningApp, SplitMode } from "../lib/types";
import { useStore } from "../store";

const MODE_HELP: Record<SplitMode, string> = {
  off: "Весь трафик системы идёт через VPN.",
  include:
    "Через VPN пойдут только выбранные приложения. Все остальные — напрямую, минуя туннель.",
  exclude:
    "Выбранные приложения пойдут напрямую, минуя VPN. Весь остальной трафик — через туннель.",
};

function newId() {
  return `app-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

export function SplitTunnel() {
  const split = useStore((s) => s.split);
  const saveSplit = useStore((s) => s.saveSplit);
  const tunnelMode = useStore((s) => s.status.tunnelMode);
  const toast = useStore((s) => s.toast);

  const [pickerOpen, setPickerOpen] = useState(false);

  const apps = split.apps ?? [];

  function setApps(next: AppRule[]) {
    void saveSplit({ apps: next });
  }

  async function addByPath() {
    const picked = await openDialog({
      multiple: false,
      title: "Выберите программу",
      filters: [{ name: "Программы", extensions: ["exe"] }],
    });
    if (typeof picked !== "string") return;
    const name = picked.split(/[\\/]/).pop() ?? picked;
    if (apps.some((a) => a.path.toLowerCase() === picked.toLowerCase())) {
      toast("info", "Эта программа уже в списке");
      return;
    }
    setApps([...apps, { id: newId(), name, path: picked, enabled: true }]);
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Раздельный туннель</h1>
          <p className="page-sub">
            Правила по конкретным приложениям. Маршрут и DNS-запросы программы
            всегда идут одним путём — так адрес не утекает мимо туннеля.
          </p>
        </div>
      </div>

      {tunnelMode !== "tun" && (
        <div className="alert" style={{ marginBottom: 18 }}>
          <SplitIcon size={17} color="var(--warn)" style={{ flexShrink: 0 }} />
          <div>
            <div className="alert-title">Работает только в режиме TUN</div>
            <div className="alert-text">
              Сейчас включён режим системного прокси. Определить, какому
              приложению принадлежит соединение, можно только когда трафик
              проходит через виртуальный адаптер — переключите режим в
              настройках.
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <div className="row between" style={{ marginBottom: 12 }}>
          <div>
            <div className="toggle-label">Режим</div>
            <div className="toggle-desc">{MODE_HELP[split.mode ?? "off"]}</div>
          </div>
          <Segmented<SplitMode>
            value={split.mode ?? "off"}
            onChange={(mode) => void saveSplit({ mode })}
            options={[
              { value: "off", label: "Выключен" },
              { value: "include", label: "Только выбранные" },
              { value: "exclude", label: "Кроме выбранных" },
            ]}
          />
        </div>
      </div>

      <div className="section-title">
        <span className="row between">
          <span>Приложения ({apps.length})</span>
        </span>
      </div>

      <div className="row" style={{ marginBottom: 12 }}>
        <button
          type="button"
          className="btn primary"
          onClick={() => setPickerOpen(true)}
        >
          <Plus size={15} />
          Из запущенных
        </button>
        <button type="button" className="btn" onClick={() => void addByPath()}>
          <FolderOpen size={15} />
          Выбрать .exe
        </button>
        <div className="grow" />
        {apps.length > 0 && (
          <button
            type="button"
            className="btn ghost sm"
            onClick={() => setApps([])}
          >
            Очистить список
          </button>
        )}
      </div>

      {apps.length === 0 ? (
        <Empty
          icon={<SplitIcon size={34} color="var(--text-muted)" />}
          title="Список пуст"
          text="Добавьте приложения — например, банковский клиент и Steam мимо VPN, либо только браузер через VPN."
        />
      ) : (
        <div className="list">
          {apps.map((app) => (
            <div key={app.id} className="app-row">
              <div className="app-icon">{app.name.slice(0, 1)}</div>
              <div className="grow" style={{ minWidth: 0 }}>
                <div className="node-name truncate">{app.name}</div>
                <div className="node-meta">
                  <span className="truncate" title={app.path}>
                    {app.path || "совпадение по имени процесса"}
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
              // Match by name so the rule keeps working after an update moves
              // the binary into a new versioned directory.
              path: "",
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
      toast("error", "Не удалось получить список процессов", errText(e));
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
    () => new Set(existing.map((a) => a.name.toLowerCase())),
    [existing],
  );

  return (
    <Modal
      open={open}
      wide
      title="Запущенные приложения"
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            Отмена
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
            Добавить ({selected.size})
          </button>
        </>
      }
    >
      <div className="row">
        <div className="grow" style={{ position: "relative" }}>
          <Search
            size={14}
            color="var(--text-muted)"
            style={{ position: "absolute", left: 10, top: 10 }}
          />
          <input
            className="input"
            style={{ paddingLeft: 31 }}
            placeholder="Поиск по имени или пути"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
        </div>
        <button
          type="button"
          className="btn icon"
          title="Обновить"
          onClick={() => void load(includeSystem)}
        >
          <RefreshCw size={15} className={loading ? "spin" : ""} />
        </button>
      </div>

      <div className="row" style={{ gap: 8 }}>
        <Switch checked={includeSystem} onChange={setIncludeSystem} />
        <span style={{ fontSize: 12.5, color: "var(--text-dim)" }}>
          Показывать системные процессы Windows
        </span>
      </div>

      <div style={{ maxHeight: "46vh", overflowY: "auto" }} className="list">
        {filtered.length === 0 && (
          <div className="empty" style={{ padding: 28 }}>
            <p>{loading ? "Загрузка…" : "Ничего не найдено"}</p>
          </div>
        )}
        {filtered.map((app) => {
          const isSelected = selected.has(app.path);
          const added = alreadyAdded.has(app.name.toLowerCase());
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
              <div className="app-icon">{app.name.slice(0, 1)}</div>
              <div className="grow" style={{ minWidth: 0 }}>
                <div className="node-name truncate">{app.name}</div>
                <div className="node-meta">
                  <span className="truncate" title={app.path}>
                    {app.path}
                  </span>
                </div>
              </div>
              {app.instances > 1 && (
                <span className="chip">{app.instances} проц.</span>
              )}
              {added && <span className="chip">уже добавлено</span>}
              {isSelected && !added && <span className="chip accent">выбрано</span>}
            </button>
          );
        })}
      </div>
    </Modal>
  );
}
