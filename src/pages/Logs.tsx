import { ArrowDownToLine, Copy, Trash2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";

import { Segmented } from "../components/ui";
import { useT } from "../lib/i18n";
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
  const t = useT();
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
          <h1 className="page-title">{t("logs.title")}</h1>
          <p className="page-sub">{t("logs.subtitle")}</p>
        </div>
        <div className="row">
          <Segmented<Filter>
            value={filter}
            onChange={setFilter}
            options={[
              { value: "all", label: t("logs.filterAll") },
              { value: "info", label: t("logs.filterInfo") },
              { value: "warn", label: t("logs.filterWarn") },
              { value: "error", label: t("logs.filterErrors") },
            ]}
          />
          <button
            type="button"
            className="btn icon"
            title={t("logs.copyAll")}
            onClick={async () => {
              await navigator.clipboard.writeText(
                visible.map((l) => `${l.level.toUpperCase()} ${l.text}`).join("\n"),
              );
              toast("success", t("logs.copied"));
            }}
          >
            <Copy size={15} />
          </button>
          <button
            type="button"
            className="btn icon"
            title={t("logs.clear")}
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
            {t("logs.empty")}
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
            {t("logs.toLatest")}
          </button>
        </div>
      )}
    </>
  );
}
