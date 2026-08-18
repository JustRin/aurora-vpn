import { Check, ChevronDown, Gauge } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { latencyTier, protocolLabel, transportLabel } from "../lib/format";
import { useT } from "../lib/i18n";
import { useStore } from "../store";

/**
 * Server switcher for the hero panel.
 *
 * Switching while connected retargets the core's selector over its control API,
 * so the tunnel never drops — which is the whole reason this belongs on the main
 * screen rather than only in the server list.
 */
export function ServerPicker() {
  const t = useT();
  const nodes = useStore((s) => s.nodes);
  const activeId = useStore((s) => s.status.activeId);
  const latency = useStore((s) => s.latency);
  const testing = useStore((s) => s.busy.latency);
  const selectServer = useStore((s) => s.selectServer);
  const refreshLatency = useStore((s) => s.refreshLatency);

  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const active = nodes.find((n) => n.id === activeId);
  const ping = active ? latency[active.id] : undefined;

  if (nodes.length === 0) {
    return <div className="hero-server">{t("pick.noServer")}</div>;
  }

  return (
    <div className="picker" ref={box}>
      <button
        type="button"
        className="picker-btn"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <span className="truncate">{active ? active.name : t("pick.select")}</span>
        {ping != null && (
          <>
            <span className={`dot ${latencyTier(ping)}`} />
            <span className="picker-ms">{t("dash.pingMs", { ping })}</span>
          </>
        )}
        <ChevronDown size={14} className="picker-caret" data-open={open} />
      </button>

      {open && (
        <div className="picker-menu">
          <div className="picker-list">
            {nodes.map((node) => {
              const ms = latency[node.id];
              return (
                <button
                  key={node.id}
                  type="button"
                  className={`picker-item${node.id === activeId ? " on" : ""}`}
                  onClick={() => {
                    void selectServer(node.id);
                    setOpen(false);
                  }}
                >
                  <span className="picker-check">
                    {node.id === activeId && <Check size={13} />}
                  </span>
                  <span className="grow" style={{ minWidth: 0 }}>
                    <span className="picker-name truncate">{node.name}</span>
                    <span className="picker-meta truncate">
                      {protocolLabel(node.protocol)} ·{" "}
                      {transportLabel(node.security, node.network)}
                    </span>
                  </span>
                  <span className={`dot ${latencyTier(ms)}`} />
                  <span className="picker-ms">
                    {ms === undefined ? "—" : ms === null ? t("dash.na") : t("dash.pingMs", { ping: ms })}
                  </span>
                </button>
              );
            })}
          </div>

          <div className="picker-foot">
            <button
              type="button"
              className="btn ghost sm"
              disabled={testing}
              onClick={() => void refreshLatency()}
            >
              <Gauge size={13} className={testing ? "spin" : ""} />
              {t("pick.testAll")}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
