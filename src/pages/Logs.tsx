import { ArrowDownToLine, Copy, Trash2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { Segmented } from "../components/ui";
import { useStore } from "../store";

type Filter = "all" | "info" | "warn" | "error";

const RANK: Record<string, number> = {
  trace: 0,
  debug: 1,
  info: 2,
  warn: 3,
  error: 4,
  fatal: 5,
  panic: 5,
};

const MIN_RANK: Record<Filter, number> = { all: 0, info: 2, warn: 3, error: 4 };

export function Logs() {
  const logs = useStore((s) => s.logs);
  const clear = useStore((s) => s.clearLogs);
  const toast = useStore((s) => s.toast);

  const [filter, setFilter] = useState<Filter>("all");
  const [follow, setFollow] = useState(true);
  const viewRef = useRef<HTMLDivElement>(null);

  const visible = useMemo(
    () => logs.filter((line) => (RANK[line.level] ?? 2) >= MIN_RANK[filter]),
    [logs, filter],
  );

  useEffect(() => {
    if (!follow) return;
    const view = viewRef.current;
    if (view) view.scrollTop = view.scrollHeight;
  }, [visible, follow]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Журнал ядра</h1>
          <p className="page-sub">
            Вывод sing-box в реальном времени. Сюда стоит смотреть, если
            подключение обрывается.
          </p>
        </div>
        <div className="row">
          <Segmented<Filter>
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: "Все" },
              { value: "info", label: "Инфо" },
              { value: "warn", label: "Предупр." },
              { value: "error", label: "Ошибки" },
            ]}
          />
          <button
            type="button"
            className="btn icon"
            title="Скопировать всё"
            onClick={async () => {
              await navigator.clipboard.writeText(
                visible.map((l) => `${l.level.toUpperCase()} ${l.text}`).join("\n"),
              );
              toast("success", "Журнал скопирован");
            }}
          >
            <Copy size={15} />
          </button>
          <button
            type="button"
            className="btn icon"
            title="Очистить"
            onClick={() => void clear()}
          >
            <Trash2 size={15} />
          </button>
        </div>
      </div>

      <div
        className="log-view"
        ref={viewRef}
        onScroll={(e) => {
          const el = e.currentTarget;
          // Re-arm auto-scroll only when the user returns to the bottom.
          setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 40);
        }}
      >
        {visible.length === 0 ? (
          <div style={{ color: "var(--text-muted)", padding: 12 }}>
            Журнал пуст — записи появятся после подключения.
          </div>
        ) : (
          visible.map((line) => (
            <div key={line.seq} className="log-line" data-level={line.level}>
              <span className="log-level">{line.level}</span>
              <span className="log-text">{line.text}</span>
            </div>
          ))
        )}
      </div>

      {!follow && (
        <div className="row" style={{ marginTop: 10, justifyContent: "center" }}>
          <button
            type="button"
            className="btn sm"
            onClick={() => {
              setFollow(true);
              const view = viewRef.current;
              if (view) view.scrollTop = view.scrollHeight;
            }}
          >
            <ArrowDownToLine size={14} />
            К последним записям
          </button>
        </div>
      )}
    </>
  );
}
