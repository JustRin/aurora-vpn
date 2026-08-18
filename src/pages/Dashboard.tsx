import {
  ArrowDownToLine,
  ArrowUpFromLine,
  Gauge,
  Link2,
  Power,
  ShieldAlert,
  Timer,
  Waypoints,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";

import { ElevateModal } from "../components/ElevateModal";
import { ServerPicker } from "../components/ServerPicker";
import { SubscriptionCard } from "../components/SubscriptionCard";
import { TrafficGraph } from "../components/TrafficGraph";
import { Segmented } from "../components/ui";
import { api, errText } from "../lib/api";
import { bytes, duration, speed } from "../lib/format";
import { ELEVATION_REQUIRED, type ClashMode } from "../lib/types";
import { useStore } from "../store";

const STATE_LABEL: Record<string, string> = {
  disconnected: "Отключено",
  connecting: "Подключение",
  connected: "Подключено",
  error: "Ошибка",
};

export function Dashboard() {
  const status = useStore((s) => s.status);
  const traffic = useStore((s) => s.traffic);
  const history = useStore((s) => s.history);
  const nodes = useStore((s) => s.nodes);
  const latency = useStore((s) => s.latency);
  const allSubs = useStore((s) => s.subscriptions);
  const busy = useStore((s) => s.busy.connection);
  const testing = useStore((s) => s.busy.latency);
  const refreshLatency = useStore((s) => s.refreshLatency);
  const connect = useStore((s) => s.connect);
  const disconnect = useStore((s) => s.disconnect);
  const setMode = useStore((s) => s.setMode);
  const toast = useStore((s) => s.toast);

  const [askElevate, setAskElevate] = useState(false);
  const [, forceTick] = useState(0);

  // The uptime counter derives from a timestamp, so it needs its own heartbeat.
  useEffect(() => {
    if (status.state !== "connected") return;
    const id = window.setInterval(() => forceTick((n) => n + 1), 1000);
    return () => window.clearInterval(id);
  }, [status.state]);

  const activeNode = nodes.find((n) => n.id === status.activeId);
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
      toast("error", "Не удалось подключиться", text);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Обзор</h1>
          <p className="page-sub">
            Состояние туннеля, скорость и режим маршрутизации.
          </p>
        </div>
        <Segmented<ClashMode>
          value={status.mode}
          onChange={(mode) => void setMode(mode)}
          options={[
            { value: "Rule", label: "По правилам" },
            { value: "Global", label: "Всё через VPN" },
            { value: "Direct", label: "Напрямую" },
          ]}
        />
      </div>

      {!status.elevated && status.tunnelMode === "tun" && (
        <div className="notice">
          <ShieldAlert size={15} color="var(--warn)" style={{ flexShrink: 0 }} />
          <span className="grow">
            Режим TUN требует прав администратора — иначе доступен только
            системный прокси.
          </span>
          <button
            type="button"
            className="btn sm"
            onClick={() => setAskElevate(true)}
          >
            Перезапустить
          </button>
        </div>
      )}

      <div className={`card hero${history.length === 0 ? " flat" : ""}`}>
        <button
          type="button"
          className="power"
          data-state={status.state}
          disabled={busy || nodes.length === 0}
          onClick={() => void onPower()}
          aria-label={connected ? "Отключить" : "Подключить"}
        >
          <span className="power-ring" />
          <span className="power-core">
            <Power size={34} strokeWidth={1.7} />
          </span>
        </button>

        <div className="hero-id">
          <div className="hero-state">{STATE_LABEL[status.state]}</div>

          <ServerPicker />

          {status.message ? (
            <div className="hero-note">{status.message}</div>
          ) : nodes.length === 0 ? (
            <div className="hero-note">
              Добавьте сервер на вкладке «Серверы», чтобы начать.
            </div>
          ) : connected ? (
            <div style={{ marginTop: 10 }}>
              <span className="uptime-chip">
                <Timer size={12} />
                {duration(status.sinceMs)}
              </span>
            </div>
          ) : null}
        </div>

        <div className="hero-rates">
          <div>
            <div className="micro">
              <ArrowDownToLine size={11} style={{ verticalAlign: -1 }} /> Приём
            </div>
            <div className="rate-value">{speed(traffic.downSpeed)}</div>
          </div>
          <div>
            <div className="micro">
              <ArrowUpFromLine size={11} style={{ verticalAlign: -1 }} /> Отдача
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

      {/* Three tiles of identical shape. The subscription card has a different
          structure — two metrics plus a meter — so it gets its own row rather
          than stretching the counters to match its height. */}
      <div className="tile-grid">
        <div className="stat">
          <div className="stat-label micro">
            <Waypoints size={12} /> За сессию
          </div>
          <div className="stat-value">{bytes(traffic.download + traffic.upload)}</div>
          <div className="stat-foot">
            ↓&nbsp;{bytes(traffic.download)} · ↑&nbsp;{bytes(traffic.upload)}
          </div>
        </div>

        <button
          type="button"
          className="stat"
          title="Разорвать все активные соединения"
          disabled={!connected}
          onClick={async () => {
            try {
              await api.closeConnections();
              toast("success", "Соединения разорваны");
            } catch (e) {
              toast("error", "Не удалось разорвать соединения", errText(e));
            }
          }}
        >
          <div className="stat-label micro">
            <Link2 size={12} /> Соединений
          </div>
          <div className="stat-value">{traffic.connections}</div>
          <div className="stat-foot">
            {connected ? "нажмите, чтобы разорвать" : "нет подключения"}
          </div>
        </button>

        <button
          type="button"
          className="stat"
          title="Проверить задержку"
          disabled={nodes.length === 0 || testing}
          onClick={() => void refreshLatency(activeNode ? [activeNode.id] : [])}
        >
          <div className="stat-label micro">
            <Gauge size={12} className={testing ? "spin" : ""} /> Задержка
          </div>
          <div className="stat-value">
            {ping === undefined ? "—" : ping === null ? "н/д" : `${ping} мс`}
          </div>
          <div className="stat-foot">
            {activeNode ? "нажмите, чтобы измерить" : "сервер не выбран"}
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
