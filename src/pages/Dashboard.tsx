import {
  ArrowDownToLine,
  ArrowUpFromLine,
  Gauge,
  Link2,
  Plus,
  Power,
  Server,
  ShieldAlert,
  Timer,
  Waypoints,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { ElevateModal } from "../components/ElevateModal";
import { ServerPicker } from "../components/ServerPicker";
import { SubscriptionCard } from "../components/SubscriptionCard";
import { TrafficGraph } from "../components/TrafficGraph";
import { Empty, Segmented } from "../components/ui";
import { api, errText } from "../lib/api";
import { onBackup } from "../lib/balancers";
import { bytes, duration, speed } from "../lib/format";
import { type MsgKey, useT } from "../lib/i18n";
import { ELEVATION_REQUIRED, type ClashMode, shownServerId } from "../lib/types";
import { useStore } from "../store";

const STATE_KEY: Record<string, MsgKey> = {
  disconnected: "dash.stateDisconnected",
  connecting: "dash.stateConnecting",
  connected: "dash.stateConnected",
  error: "dash.stateError",
};

// The core's third mode, Direct, is not offered: "everything past the VPN" is
// what turning the tunnel off already does, and the power button says it more
// plainly. Should it arrive from outside (the Clash API is open to any
// dashboard), the switch falls back to showing Rules.
type SwitchMode = Exclude<ClashMode, "Direct">;

// Two words on a switch say nothing to someone opening the client for the first
// time, so the chosen — or merely hovered — mode explains itself below.
const MODE_HELP: Record<SwitchMode, MsgKey> = {
  Rule: "dash.modeRuleHelp",
  Global: "dash.modeGlobalHelp",
};

function switchMode(mode: ClashMode): SwitchMode {
  return mode === "Global" ? "Global" : "Rule";
}

export function Dashboard() {
  const t = useT();
  const status = useStore((s) => s.status);
  const traffic = useStore((s) => s.traffic);
  const history = useStore((s) => s.history);
  const nodes = useStore((s) => s.nodes);
  const latency = useStore((s) => s.latency);
  const allSubs = useStore((s) => s.subscriptions);
  const balancer = useStore((s) => s.settings.balancer);
  const busy = useStore((s) => s.busy.connection);
  const testing = useStore((s) => s.busy.latency);
  const refreshLatency = useStore((s) => s.refreshLatency);
  const connect = useStore((s) => s.connect);
  const disconnect = useStore((s) => s.disconnect);
  const setMode = useStore((s) => s.setMode);
  const navigate = useStore((s) => s.navigate);
  const toast = useStore((s) => s.toast);

  const [askElevate, setAskElevate] = useState(false);
  const [hoveredMode, setHoveredMode] = useState<SwitchMode | null>(null);
  const [, forceTick] = useState(0);

  // The uptime counter derives from a timestamp, so it needs its own heartbeat.
  useEffect(() => {
    if (status.state !== "connected") return;
    const id = window.setInterval(() => forceTick((n) => n + 1), 1000);
    return () => window.clearInterval(id);
  }, [status.state]);

  // The latency tile and the picker agree on one node: the one carrying
  // traffic, which a balancer may have moved away from the pick.
  const activeNode = nodes.find((n) => n.id === shownServerId(status));
  const connected = status.state === "connected";
  const ping = activeNode ? latency[activeNode.id] : undefined;

  // Whatever lapses first is what the user needs to see first; plans with no
  // reported expiry sort last.
  const subscriptions = useMemo(
    () => [...allSubs].sort((a, b) => (a.expire || Infinity) - (b.expire || Infinity)),
    [allSubs],
  );

  async function onPower() {
    if (connected || status.state === "connecting") {
      await disconnect();
      return;
    }
    try {
      await connect();
    } catch (e) {
      const text = errText(e);
      if (text.includes(ELEVATION_REQUIRED)) {
        setAskElevate(true);
        return;
      }
      toast("error", t("dash.connectFailed"), text);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{t("dash.title")}</h1>
          <p className="page-sub">{t("dash.subtitle")}</p>
        </div>
        <div className="mode-head">
          <Segmented<SwitchMode>
            value={switchMode(status.mode)}
            onChange={(mode) => void setMode(mode)}
            onHover={setHoveredMode}
            options={[
              { value: "Rule", label: t("dash.modeRule") },
              { value: "Global", label: t("dash.modeGlobal") },
            ]}
          />
          <div className="mode-help">
            {t(MODE_HELP[hoveredMode ?? switchMode(status.mode)])}
          </div>
        </div>
      </div>

      {!status.elevated && status.tunnelMode === "tun" && (
        <div className="notice">
          <ShieldAlert size={15} color="var(--warn)" style={{ flexShrink: 0 }} />
          <span className="grow">{t("dash.tunNeedsAdmin")}</span>
          <button
            type="button"
            className="btn sm"
            onClick={() => setAskElevate(true)}
          >
            {t("dash.restart")}
          </button>
        </div>
      )}

      {nodes.length === 0 ? (
        /* No servers means the power button would be a dead control — swap the
           whole hero for an explicit empty state that says why and leads to
           the fix. */
        <div className="card hero-empty">
          <Empty
            icon={<Server size={34} color="var(--text-muted)" />}
            title={t("dash.noServersTitle")}
            text={t("dash.noServersText")}
            action={
              <button
                type="button"
                className="btn primary"
                onClick={() => navigate("servers")}
              >
                <Plus size={15} />
                {t("srv.addServers")}
              </button>
            }
          />
        </div>
      ) : (
        <div className={`card hero${history.length === 0 ? " flat" : ""}`}>
          <button
            type="button"
            className="power"
            data-state={status.state}
            disabled={busy}
            onClick={() => void onPower()}
            aria-label={connected ? t("dash.disconnect") : t("dash.connect")}
          >
            <span className="power-ring" />
            <span className="power-core">
              <Power size={34} strokeWidth={1.7} />
            </span>
          </button>

          <div className="hero-id">
            <div className="hero-state">{t(STATE_KEY[status.state])}</div>

            <ServerPicker />

            {status.message ? (
              <div className="hero-note">{status.message}</div>
            ) : connected ? (
              <div style={{ marginTop: 10, display: "flex", gap: 8, alignItems: "center" }}>
                <span className="uptime-chip">
                  <Timer size={12} />
                  {duration(status.sinceMs)}
                </span>
                {/* Failover is on a stand-in: the pick stopped answering. Down
                    here rather than in the picker button, which has no room
                    for a chip next to the server name. */}
                {onBackup(balancer, status) && (
                  <span className="chip warn">{t("pick.badgeBackup")}</span>
                )}
              </div>
            ) : null}
          </div>

          <div className="hero-rates">
            <div>
              <div className="micro">
                <ArrowDownToLine size={11} style={{ verticalAlign: -1 }} /> {t("dash.trafficDown")}
              </div>
              <div className="rate-value">{speed(traffic.downSpeed)}</div>
            </div>
            <div>
              <div className="micro">
                <ArrowUpFromLine size={11} style={{ verticalAlign: -1 }} /> {t("dash.trafficUp")}
              </div>
              <div className="rate-value">{speed(traffic.upSpeed)}</div>
            </div>
          </div>

          {history.length > 0 && (
            <div className="hero-spark">
              <TrafficGraph history={history} bleed />
            </div>
          )}
        </div>
      )}

      {/* Three tiles of identical shape. The subscription card has a different
          structure — two metrics plus a meter — so it gets its own row rather
          than stretching the counters to match its height. */}
      <div className="tile-grid">
        <div className="stat">
          <div className="stat-label micro">
            <Waypoints size={12} /> {t("dash.thisSession")}
          </div>
          <div className="stat-value">{bytes(traffic.download + traffic.upload)}</div>
          <div className="stat-foot">
            ↓&nbsp;{bytes(traffic.download)} · ↑&nbsp;{bytes(traffic.upload)}
          </div>
        </div>

        <button
          type="button"
          className="stat"
          title={t("dash.closeAllConns")}
          disabled={!connected}
          onClick={async () => {
            try {
              await api.closeConnections();
              toast("success", t("dash.connsClosed"));
            } catch (e) {
              toast("error", t("dash.connsCloseFailed"), errText(e));
            }
          }}
        >
          <div className="stat-label micro">
            <Link2 size={12} /> {t("dash.connections")}
          </div>
          <div className="stat-value">{traffic.connections}</div>
          <div className="stat-foot">
            {connected ? t("dash.clickToClose") : t("dash.notConnected")}
          </div>
        </button>

        <button
          type="button"
          className="stat"
          title={t("dash.testLatency")}
          disabled={nodes.length === 0 || testing}
          onClick={() => void refreshLatency(activeNode ? [activeNode.id] : [])}
        >
          <div className="stat-label micro">
            <Gauge size={12} className={testing ? "spin" : ""} /> {t("dash.latency")}
          </div>
          <div className="stat-value">
            {ping === undefined ? "—" : ping === null ? t("dash.na") : t("dash.pingMs", { ping })}
          </div>
          <div className="stat-foot">
            {activeNode ? t("dash.clickToTest") : t("dash.noServer")}
          </div>
        </button>
      </div>

      {subscriptions.map((sub) => (
        <div key={sub.id} style={{ marginTop: 14 }}>
          <SubscriptionCard sub={sub} />
        </div>
      ))}

      <ElevateModal
        open={askElevate}
        reason="tunnel"
        onClose={() => setAskElevate(false)}
      />
    </>
  );
}
