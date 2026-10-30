import { Check, ChevronDown, Gauge, Server } from "lucide-react";
import { useEffect, useRef, useState, useSyncExternalStore } from "react";
import { createPortal } from "react-dom";

import { BALANCERS, balancerEntry, balancerMeta, onBackup } from "../lib/balancers";
import { latencyTier, protocolLabel, transportLabel } from "../lib/format";
import { useT } from "../lib/i18n";
import { shownServerId } from "../lib/types";
import { useStore } from "../store";
import { Modal } from "./ui";

const TOUCH_QUERY = "(hover: none)";

function subscribeTouch(onChange: () => void) {
  const media = window.matchMedia(TOUCH_QUERY);
  media.addEventListener("change", onChange);
  return () => media.removeEventListener("change", onChange);
}

/**
 * Server switcher for the hero panel.
 *
 * Switching while connected retargets the core's selector over its control API,
 * so the tunnel never drops — which is the whole reason this belongs on the main
 * screen rather than only in the server list.
 *
 * The balancer strategies sit in the same list as the servers, above them,
 * each with its own icon: picking one hands the choice of server to the app,
 * picking a server takes it back. Exactly one row is highlighted — whichever
 * is in charge — and under a balancer the server carrying traffic only gets a
 * «now» marker.
 *
 * On a touch screen, phone or tablet alike, the list is a dialog: hung off a
 * trigger in the middle of the page it ran past the bottom of a phone, and
 * sideways there is no height for it at all.
 */
export function ServerPicker() {
  const t = useT();
  const nodes = useStore((s) => s.nodes);
  const status = useStore((s) => s.status);
  const balancer = useStore((s) => s.settings.balancer ?? "manual");
  const latency = useStore((s) => s.latency);
  const testing = useStore((s) => s.busy.latency);
  const selectServer = useStore((s) => s.selectServer);
  const saveSettings = useStore((s) => s.saveSettings);
  const refreshLatency = useStore((s) => s.refreshLatency);

  const touch = useSyncExternalStore(subscribeTouch, () => window.matchMedia(TOUCH_QUERY).matches);
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (e: MouseEvent) => {
      // The dialog lives outside the box and dismisses itself: closing here
      // would unmount the row under the finger before its click lands.
      if (!touch && box.current && !box.current.contains(e.target as Node)) setOpen(false);
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
  }, [open, touch]);

  // Connected, the row shown is the node carrying traffic: a balancer may have
  // moved it away from the pick.
  const shownId = shownServerId(status);
  const active = nodes.find((n) => n.id === shownId);
  const ping = active ? latency[active.id] : undefined;
  const strategy = balancerEntry(balancer);
  const backup = onBackup(balancer, status);
  // Strategies need something to choose from.
  const withBalancers = nodes.length >= 2;
  const ButtonIcon = strategy?.icon ?? Server;

  if (nodes.length === 0) {
    return <div className="hero-server">{t("pick.noServer")}</div>;
  }

  const list = (
    <div className={touch ? "picker-list in-modal" : "picker-list"}>
      {withBalancers && (
        <>
          <div className="picker-section micro">{t("pick.balancers")}</div>
          {BALANCERS.map((entry) => {
            const on = balancer === entry.id;
            const alarmed = on && backup;
            const Icon = entry.icon;
            return (
              <button
                key={entry.id}
                type="button"
                className={`picker-item${on ? " on" : ""}`}
                onClick={() => {
                  void saveSettings({ balancer: entry.id });
                  setOpen(false);
                }}
              >
                <span className={`picker-icon ${alarmed ? "warn" : "balancer"}`}>
                  <Icon size={14} />
                </span>
                <span className="grow" style={{ minWidth: 0 }}>
                  <span className="picker-name truncate">{t(entry.label)}</span>
                  <span className={`picker-meta truncate${alarmed ? " warn" : ""}`}>
                    {balancerMeta(t, entry, balancer, status, nodes)}
                  </span>
                </span>
                <span className="picker-check">{on && <Check size={13} />}</span>
              </button>
            );
          })}
          <div className="picker-section micro">{t("pick.servers")}</div>
        </>
      )}
      {nodes.map((node) => {
        const ms = latency[node.id];
        const on = !strategy && node.id === shownId;
        const routed = !!strategy && node.id === shownId;
        return (
          <button
            key={node.id}
            type="button"
            className={`picker-item${on ? " on" : ""}`}
            onClick={() => {
              void selectServer(node.id);
              setOpen(false);
            }}
          >
            <span className="picker-icon">
              <Server size={14} />
            </span>
            <span className="grow" style={{ minWidth: 0 }}>
              <span className="picker-name truncate">{node.name}</span>
              <span className="picker-meta truncate">
                {protocolLabel(node.protocol)} ·{" "}
                {transportLabel(node.security, node.network, node.protocol, node.alpn)}
              </span>
            </span>
            {routed && <span className="chip accent">{t("pick.nowChip")}</span>}
            <span className={`dot ${latencyTier(ms)}`} />
            <span className="picker-ms">
              {ms === undefined ? "—" : ms === null ? t("dash.na") : t("dash.pingMs", { ping: ms })}
            </span>
            <span className="picker-check">{on && <Check size={13} />}</span>
          </button>
        );
      })}
    </div>
  );

  const testAll = (
    <button
      type="button"
      className="btn ghost sm"
      disabled={testing}
      onClick={() => void refreshLatency()}
    >
      <Gauge size={13} className={testing ? "spin" : ""} />
      {t("pick.testAll")}
    </button>
  );

  return (
    <div className="picker" ref={box}>
      <button
        type="button"
        className="picker-btn"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        <ButtonIcon
          size={15}
          className={`picker-btn-icon${backup ? " warn" : strategy ? " balancer" : ""}`}
        />
        <span className="truncate">
          {!active
            ? t("pick.select")
            : strategy
              ? `${t(strategy.label)} · ${active.name}`
              : active.name}
        </span>
        {ping != null && (
          <>
            <span className={`dot ${latencyTier(ping)}`} />
            <span className="picker-ms">{t("dash.pingMs", { ping })}</span>
          </>
        )}
        <ChevronDown size={14} className="picker-caret" data-open={open} />
      </button>

      {open &&
        (touch ? (
          // Portalled to the body: the hero carries a `backdrop-filter`, which
          // would trap a `position: fixed` overlay inside the card.
          createPortal(
            <Modal open title={t("pick.select")} onClose={() => setOpen(false)} footer={testAll}>
              {list}
            </Modal>,
            document.body,
          )
        ) : (
          <div className="picker-menu">
            {list}
            <div className="picker-foot">{testAll}</div>
          </div>
        ))}
    </div>
  );
}
