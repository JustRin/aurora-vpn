import {
  Activity,
  AlertTriangle,
  ArrowLeft,
  BarChart3,
  Gauge,
  Search,
  Server,
  Waypoints,
  X,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Empty, Segmented } from "../components/ui";
import { api } from "../lib/api";
import { bytes, protocolLabel, speed } from "../lib/format";
import { intlTag, useLang, useT } from "../lib/i18n";
import { IS_ANDROID } from "../lib/platform";
import type {
  AppStats,
  ChartPoint,
  ServerStats,
  SessionRecord,
  StatsRange,
  StatsReport,
} from "../lib/types";
import { useStore } from "../store";

type MetricMode = "speed" | "loss" | "latency";
type DetailTab = "apps" | "servers" | "sessions";
type RouteFilter = "all" | "vpn" | "direct";
type PresetRange = Exclude<StatsRange, "custom">;

const SVG_W = 760;
const SVG_H = 186;
const PAD_TOP = 16;
const PAD_BOTTOM = 10;

const SERVER_COLORS = [
  "var(--accent)",
  "var(--chart-down)",
  "var(--ok)",
  "var(--warn)",
  "var(--chart-up)",
];

function formatDuration(secs: number): string {
  const s = Math.max(0, Math.floor(secs));
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const rem = s % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  if (h > 0) return `${h}:${pad(m)}:${pad(rem)}`;
  return `${pad(m)}:${pad(rem)}`;
}

function formatAxisTime(tsMs: number, range: StatsRange, locale: string): string {
  if (!tsMs) return "";
  const d = new Date(tsMs);
  if (range === "session" || range === "hour1") {
    return d.toLocaleTimeString(locale, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }
  if (range === "hours24") {
    return d.toLocaleTimeString(locale, { hour: "2-digit", minute: "2-digit" });
  }
  return d.toLocaleString(locale, {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatSessionDate(tsMs: number, locale: string): string {
  if (!tsMs) return "—";
  return new Date(tsMs).toLocaleString(locale, {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function lossTier(pct: number): "good" | "ok" | "bad" {
  if (pct < 0.5) return "good";
  if (pct < 2.5) return "ok";
  return "bad";
}

function buildLinePath(values: (number | null)[], maxVal: number): string {
  if (values.length === 0) return "";
  const usable = SVG_H - PAD_TOP - PAD_BOTTOM;
  const step = values.length > 1 ? SVG_W / (values.length - 1) : 0;
  const parts: string[] = [];
  let penDown = false;
  for (let i = 0; i < values.length; i++) {
    const v = values[i];
    if (v === null || !Number.isFinite(v)) {
      penDown = false;
      continue;
    }
    const x = values.length === 1 ? SVG_W / 2 : i * step;
    const ratio = maxVal > 0 ? Math.min(1, Math.max(0, v / maxVal)) : 0;
    const y = SVG_H - PAD_BOTTOM - ratio * usable;
    parts.push(`${penDown ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`);
    penDown = true;
  }
  return parts.join(" ");
}

function buildAreaPath(values: number[], maxVal: number): string {
  if (values.length === 0) return "";
  const line = buildLinePath(values, maxVal);
  if (!line) return "";
  const baseY = SVG_H - PAD_BOTTOM;
  const startX = values.length === 1 ? SVG_W / 2 : 0;
  const endX = values.length === 1 ? SVG_W / 2 : SVG_W;
  return `${line} L${endX.toFixed(1)},${baseY} L${startX.toFixed(1)},${baseY} Z`;
}

function pointX(idx: number, count: number): number {
  if (count <= 1) return SVG_W / 2;
  return (idx / (count - 1)) * SVG_W;
}

function pointY(val: number, maxVal: number): number {
  const usable = SVG_H - PAD_TOP - PAD_BOTTOM;
  const ratio = maxVal > 0 ? Math.min(1, Math.max(0, val / maxVal)) : 0;
  return SVG_H - PAD_BOTTOM - ratio * usable;
}

interface ServerBand {
  startFrac: number;
  widthFrac: number;
  color: string;
  name: string;
}

function computeServerBands(points: ChartPoint[]): ServerBand[] {
  if (points.length === 0) return [];
  const palette = new Map<string, string>();
  let nextColor = 0;
  const colorFor = (sid: string) => {
    let c = palette.get(sid);
    if (!c) {
      c = SERVER_COLORS[nextColor % SERVER_COLORS.length];
      nextColor++;
      palette.set(sid, c);
    }
    return c;
  };

  const n = points.length;
  const bands: ServerBand[] = [];
  let start = 0;
  while (start < n) {
    const sid = points[start].serverId;
    let end = start + 1;
    while (end < n && points[end].serverId === sid) end++;
    if (sid) {
      bands.push({
        startFrac: start / n,
        widthFrac: (end - start) / n,
        color: colorFor(sid),
        name: points[start].serverName || sid,
      });
    }
    start = end;
  }
  return bands;
}

export function StatsPage() {
  const t = useT();
  const lang = useLang();
  const locale = intlTag(lang);
  const navigate = useStore((s) => s.navigate);
  const nodes = useStore((s) => s.nodes);

  const [range, setRange] = useState<StatsRange>("session");
  const [customWindow, setCustomWindow] = useState<{ from: number; to: number } | null>(null);
  const [serverId, setServerId] = useState<string>("");
  const [appKey, setAppKey] = useState<string>("");
  const [pinnedIdx, setPinnedIdx] = useState<number | null>(null);
  const [hoverIdx, setHoverIdx] = useState<number | null>(null);

  const [metric, setMetric] = useState<MetricMode>("speed");
  const [tab, setTab] = useState<DetailTab>("apps");
  const [routeFilter, setRouteFilter] = useState<RouteFilter>("all");
  const [appSearch, setAppSearch] = useState("");
  const [report, setReport] = useState<StatsReport | null>(null);
  const [icons, setIcons] = useState<Record<string, string>>({});

  const reqSeq = useRef(0);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const fetchReport = useCallback(async () => {
    const seq = ++reqSeq.current;
    try {
      const next = await api.getStatsReport({
        range,
        customFromMs: range === "custom" ? customWindow?.from ?? null : null,
        customToMs: range === "custom" ? customWindow?.to ?? null : null,
        serverId: serverId || null,
        appKey: appKey || null,
        pinnedIndex: pinnedIdx,
        maxPoints: 96,
      });
      if (seq === reqSeq.current) {
        setReport(next);
      }
    } catch {
      // Keep last good snapshot on transient IPC hiccup.
    }
  }, [range, customWindow, serverId, appKey, pinnedIdx]);

  useEffect(() => {
    void fetchReport();
  }, [fetchReport]);

  // Live 1s heartbeat while watching the active session unpinned.
  useEffect(() => {
    if (range !== "session" || pinnedIdx !== null) return;
    const id = window.setInterval(() => void fetchReport(), 1000);
    return () => window.clearInterval(id);
  }, [range, pinnedIdx, fetchReport]);

  // Escape unpins the inspected chart moment.
  useEffect(() => {
    if (pinnedIdx === null) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setPinnedIdx(null);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [pinnedIdx]);

  // Android launcher icons for apps in the list.
  const activeAppsRaw = useMemo(() => {
    if (!report) return [];
    return pinnedIdx !== null && report.pinnedPoint ? report.pinnedApps : report.apps;
  }, [report, pinnedIdx]);

  useEffect(() => {
    if (!IS_ANDROID || activeAppsRaw.length === 0) return;
    const missing = activeAppsRaw
      .map((a) => a.path)
      .filter((p) => p && p !== "__other__" && !(p in icons));
    if (missing.length === 0) return;
    let alive = true;
    void api.appIcons(missing).then(
      (res) => {
        if (alive && Object.keys(res).length > 0) {
          setIcons((prev) => ({ ...prev, ...res }));
        }
      },
      () => {},
    );
    return () => {
      alive = false;
    };
  }, [activeAppsRaw, icons]);

  const points = report?.points ?? [];
  const summary = report?.summary;
  const hasData = Boolean(summary?.hasData);

  // Server selector combines servers observed in the stats report + configured nodes.
  const serverOptions = useMemo(() => {
    const map = new Map<string, string>();
    for (const s of report?.servers ?? []) {
      if (s.serverId) map.set(s.serverId, s.serverName || s.serverId);
    }
    for (const n of nodes) {
      if (!map.has(n.id)) map.set(n.id, n.name);
    }
    return [...map.entries()];
  }, [report?.servers, nodes]);

  const selectedAppName = useMemo(() => {
    if (!appKey) return "";
    const hit =
      report?.apps.find((a) => a.key === appKey) ??
      report?.pinnedApps.find((a) => a.key === appKey);
    if (hit) return hit.key === "__other__" ? t("stats.systemOther") : hit.name;
    return appKey === "__other__" ? t("stats.systemOther") : appKey;
  }, [appKey, report, t]);

  const filteredApps = useMemo(() => {
    const q = appSearch.trim().toLowerCase();
    return activeAppsRaw.filter((a) => {
      if (routeFilter === "vpn" && a.proxyBytes === 0) return false;
      if (routeFilter === "direct" && a.directBytes === 0) return false;
      if (q) {
        const displayName = a.key === "__other__" ? t("stats.systemOther") : a.name;
        return (
          displayName.toLowerCase().includes(q) ||
          a.path.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [activeAppsRaw, routeFilter, appSearch, t]);

  const maxAppBytes = useMemo(
    () => Math.max(1, ...filteredApps.map((a) => a.totalBytes)),
    [filteredApps],
  );

  // Chart geometry for the active metric.
  const chart = useMemo(() => {
    if (points.length === 0) {
      return {
        primaryLine: "",
        primaryArea: "",
        secondaryLine: "",
        secondaryArea: "",
        appLine: "",
        maxVal: 1,
        yMaxLabel: "",
        yMidLabel: "",
      };
    }

    if (metric === "speed") {
      const down = points.map((p) => p.downBps);
      const up = points.map((p) => p.upBps);
      const appSeries = appKey ? points.map((p) => p.appDownBps + p.appUpBps) : [];
      const maxVal = Math.max(64 * 1024, ...down, ...up, ...appSeries);
      return {
        primaryLine: buildLinePath(down, maxVal),
        primaryArea: buildAreaPath(down, maxVal),
        secondaryLine: buildLinePath(up, maxVal),
        secondaryArea: buildAreaPath(up, maxVal),
        appLine: appKey ? buildLinePath(appSeries, maxVal) : "",
        maxVal,
        yMaxLabel: speed(maxVal),
        yMidLabel: speed(maxVal / 2),
      };
    }

    if (metric === "loss") {
      const loss = points.map((p) => p.lossPct);
      const maxVal = Math.max(5, ...loss);
      return {
        primaryLine: buildLinePath(loss, maxVal),
        primaryArea: buildAreaPath(loss, maxVal),
        secondaryLine: "",
        secondaryArea: "",
        appLine: "",
        maxVal,
        yMaxLabel: `${maxVal.toFixed(1)}%`,
        yMidLabel: `${(maxVal / 2).toFixed(1)}%`,
      };
    }

    const latNullable = points.map((p) => p.latencyMs);
    const latZero = points.map((p) => p.latencyMs ?? 0);
    const maxVal = Math.max(100, ...latZero);
    return {
      primaryLine: buildLinePath(latNullable, maxVal),
      primaryArea: buildAreaPath(latZero, maxVal),
      secondaryLine: "",
      secondaryArea: "",
      appLine: "",
      maxVal,
      yMaxLabel: t("dash.pingMs", { ping: Math.round(maxVal) }),
      yMidLabel: t("dash.pingMs", { ping: Math.round(maxVal / 2) }),
    };
  }, [points, metric, appKey, t]);

  const bands = useMemo(() => computeServerBands(points), [points]);

  const indexFromClientX = useCallback(
    (clientX: number): number | null => {
      if (!svgRef.current || points.length === 0) return null;
      const rect = svgRef.current.getBoundingClientRect();
      if (rect.width <= 0) return null;
      const frac = Math.min(1, Math.max(0, (clientX - rect.left) / rect.width));
      return Math.round(frac * (points.length - 1));
    },
    [points.length],
  );

  const inspectedIdx = hoverIdx !== null ? hoverIdx : pinnedIdx;
  const inspectedPoint: ChartPoint | null =
    inspectedIdx !== null && inspectedIdx < points.length
      ? points[inspectedIdx]
      : null;

  const periodSubtitle = useMemo(() => {
    if (!summary?.hasData || !summary.fromMs) return t("stats.subtitle");
    const from = formatAxisTime(summary.fromMs, range, locale);
    const to = formatAxisTime(summary.toMs, range, locale);
    return `${from} — ${to} · ${formatDuration(summary.durationS)}`;
  }, [summary, range, locale, t]);

  const selectPresetRange = (next: PresetRange) => {
    setRange(next);
    setCustomWindow(null);
    setPinnedIdx(null);
    setHoverIdx(null);
  };

  const zoomToSession = (sess: SessionRecord) => {
    const end = sess.endedMs > sess.startedMs ? sess.endedMs : Date.now();
    setRange("custom");
    setCustomWindow({ from: sess.startedMs, to: end });
    setPinnedIdx(null);
    setHoverIdx(null);
    setTab("apps");
  };

  const totalErrors = summary
    ? summary.dialFails + summary.relayErrors + summary.probeFails
    : 0;
  const summaryLossTier = summary ? lossTier(summary.lossPct) : "good";

  return (
    <>
      <div className="page-head stats-head">
        <div className="row" style={{ gap: 12, minWidth: 0 }}>
          <button
            type="button"
            className="btn ghost sm"
            onClick={() => navigate("dashboard")}
          >
            <ArrowLeft size={15} />
            {t("stats.back")}
          </button>
          <div style={{ minWidth: 0 }}>
            <h1 className="page-title">{t("stats.title")}</h1>
            <p className="page-sub truncate">{periodSubtitle}</p>
          </div>
        </div>

        <div className="row wrap stats-head-controls">
          <Segmented<PresetRange>
            value={range === "custom" ? "session" : range}
            onChange={selectPresetRange}
            options={[
              { value: "session", label: t("stats.rangeSession") },
              { value: "hour1", label: t("stats.range1h") },
              { value: "hours24", label: t("stats.range24h") },
              { value: "days7", label: t("stats.range7d") },
              { value: "days30", label: t("stats.range30d") },
            ]}
          />
          {serverOptions.length > 0 && (
            <select
              className="select stats-server-select"
              value={serverId}
              onChange={(e) => {
                setServerId(e.target.value);
                setPinnedIdx(null);
              }}
            >
              <option value="">{t("stats.allServers")}</option>
              {serverOptions.map(([id, name]) => (
                <option key={id} value={id}>
                  {name}
                </option>
              ))}
            </select>
          )}
        </div>
      </div>

      {!hasData ? (
        <div className="card">
          <Empty
            icon={<BarChart3 size={34} color="var(--text-muted)" />}
            title={t("stats.emptyTitle")}
            text={t("stats.emptyText")}
          />
        </div>
      ) : (
        <>
          {/* 4 KPI cards */}
          <div className="stats-kpi-grid">
            <div className="stat">
              <div className="stat-label micro">
                <Waypoints size={12} /> {t("stats.kpiTraffic")}
              </div>
              <div className="stat-value">{bytes(summary!.totalBytes)}</div>
              <div className="stat-foot truncate">
                {t("stats.vpnDirectFmt", {
                  vpn: bytes(summary!.proxyBytes),
                  direct: bytes(summary!.directBytes),
                })}
              </div>
            </div>

            <div className="stat">
              <div className="stat-label micro">
                <Activity size={12} /> {t("stats.kpiSpeed")}
              </div>
              <div className="stat-value">{speed(summary!.avgDownBps)}</div>
              <div className="stat-foot truncate">
                {t("stats.speedFootFmt", {
                  down: speed(summary!.peakDownBps),
                  up: speed(summary!.peakUpBps),
                })}
              </div>
            </div>

            <div className="stat">
              <div className="stat-label micro">
                <Gauge size={12} /> {t("stats.kpiLatency")}
              </div>
              <div className="stat-value">
                {summary!.avgLatencyMs !== null
                  ? t("dash.pingMs", { ping: summary!.avgLatencyMs })
                  : "—"}
              </div>
              <div className="stat-foot truncate">
                {summary!.jitterMs !== null
                  ? t("stats.jitterFmt", { ms: summary!.jitterMs })
                  : summary!.minLatencyMs !== null && summary!.maxLatencyMs !== null
                    ? `${summary!.minLatencyMs}–${summary!.maxLatencyMs} ms`
                    : "—"}
              </div>
            </div>

            <div className="stat">
              <div className="stat-label micro">
                <AlertTriangle size={12} /> {t("stats.kpiLoss")}
              </div>
              <div className={`stat-value stats-tier-${summaryLossTier}`}>
                <span className={`dot ${summaryLossTier}`} />
                {summary!.lossPct.toFixed(2)}%
              </div>
              <div className="stat-foot truncate">
                {t("stats.dropsFmt", {
                  lost: summary!.packetsLost,
                  err: totalErrors,
                })}
              </div>
            </div>
          </div>

          {/* Interactive Argus-style chart card */}
          <div className="card stats-chart-card">
            <div className="row between wrap" style={{ gap: 10, marginBottom: 10 }}>
              <Segmented<MetricMode>
                value={metric}
                onChange={setMetric}
                options={[
                  { value: "speed", label: t("stats.metricSpeed") },
                  { value: "loss", label: t("stats.metricLoss") },
                  { value: "latency", label: t("stats.metricLatency") },
                ]}
              />

              <div className="row wrap" style={{ gap: 8 }}>
                {metric === "speed" && (
                  <div className="legend">
                    <span>
                      <i style={{ background: "var(--chart-down)" }} /> {t("graph.down")}
                    </span>
                    <span>
                      <i style={{ background: "var(--chart-up)" }} /> {t("graph.up")}
                    </span>
                    {selectedAppName && (
                      <span>
                        <i style={{ background: "var(--ok)" }} /> {selectedAppName}
                      </span>
                    )}
                  </div>
                )}

                {selectedAppName && (
                  <button
                    type="button"
                    className="chip accent stats-chip-btn"
                    onClick={() => setAppKey("")}
                  >
                    {selectedAppName}
                    <X size={12} />
                  </button>
                )}

                {pinnedIdx !== null && report?.pinnedPoint && (
                  <button
                    type="button"
                    className="chip ok stats-chip-btn"
                    onClick={() => setPinnedIdx(null)}
                  >
                    {t("stats.momentPrefix")}{" "}
                    {formatAxisTime(report.pinnedPoint.tsMs, range, locale)}
                    <X size={12} />
                  </button>
                )}
              </div>
            </div>

            {/* Live hover / pinned readout bar */}
            <div className={`stats-readout${pinnedIdx !== null ? " pinned" : ""}`}>
              {!inspectedPoint ? (
                <span className="stats-readout-hint">{t("stats.chartHint")}</span>
              ) : (
                <>
                  <span className="stats-readout-time mono">
                    {formatAxisTime(inspectedPoint.tsMs, range, locale)}
                  </span>
                  {inspectedPoint.serverName && (
                    <span className="chip">{inspectedPoint.serverName}</span>
                  )}
                  <span className="stats-readout-metric mono">
                    {metric === "speed"
                      ? `↓ ${speed(inspectedPoint.downBps)} · ↑ ${speed(inspectedPoint.upBps)}`
                      : metric === "loss"
                        ? `${t("stats.lossWord")} ${inspectedPoint.lossPct.toFixed(2)}% (${inspectedPoint.packetsLost})`
                        : inspectedPoint.latencyMs !== null
                          ? t("dash.pingMs", { ping: inspectedPoint.latencyMs })
                          : "—"}
                  </span>
                  <span className="stats-readout-meta mono">
                    {inspectedPoint.connections} {t("stats.connsShort")}
                    {metric === "speed" && inspectedPoint.lossPct > 0
                      ? ` · ${inspectedPoint.lossPct.toFixed(1)}%`
                      : ""}
                  </span>
                  {inspectedPoint.topApps.length > 0 && (
                    <span className="stats-readout-apps truncate">
                      {inspectedPoint.topApps
                        .slice(0, 3)
                        .map(
                          (a) =>
                            `${a.key === "__other__" ? t("stats.systemOther") : a.name} ${bytes(a.bytes)}`,
                        )
                        .join(" · ")}
                    </span>
                  )}
                </>
              )}
            </div>

            {/* Interactive SVG plot */}
            <div className="stats-svg-wrap">
              <div className="stats-y-labels" aria-hidden="true">
                <span>{chart.yMaxLabel}</span>
                <span>{chart.yMidLabel}</span>
              </div>
              <svg
                ref={svgRef}
                viewBox={`0 0 ${SVG_W} ${SVG_H}`}
                preserveAspectRatio="none"
                className="stats-svg"
                onPointerMove={(e) => {
                  const idx = indexFromClientX(e.clientX);
                  if (idx !== null) setHoverIdx(idx);
                }}
                onPointerLeave={() => setHoverIdx(null)}
                onClick={(e) => {
                  const idx = indexFromClientX(e.clientX);
                  if (idx === null) return;
                  setPinnedIdx((prev) => (prev === idx ? null : idx));
                }}
              >
                <defs>
                  <linearGradient id="st-down" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" style={{ stopColor: "var(--chart-down)" }} stopOpacity="0.34" />
                    <stop offset="100%" style={{ stopColor: "var(--chart-down)" }} stopOpacity="0" />
                  </linearGradient>
                  <linearGradient id="st-up" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" style={{ stopColor: "var(--chart-up)" }} stopOpacity="0.26" />
                    <stop offset="100%" style={{ stopColor: "var(--chart-up)" }} stopOpacity="0" />
                  </linearGradient>
                  <linearGradient id="st-loss" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" style={{ stopColor: "var(--danger)" }} stopOpacity="0.34" />
                    <stop offset="100%" style={{ stopColor: "var(--danger)" }} stopOpacity="0" />
                  </linearGradient>
                  <linearGradient id="st-lat" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" style={{ stopColor: "var(--warn)" }} stopOpacity="0.3" />
                    <stop offset="100%" style={{ stopColor: "var(--warn)" }} stopOpacity="0" />
                  </linearGradient>
                </defs>

                {[0.25, 0.5, 0.75].map((f) => (
                  <line
                    key={f}
                    x1="0"
                    x2={SVG_W}
                    y1={SVG_H * f}
                    y2={SVG_H * f}
                    style={{ stroke: "var(--grid-line)" }}
                    strokeWidth="1"
                  />
                ))}

                {chart.primaryArea && (
                  <path
                    d={chart.primaryArea}
                    fill={
                      metric === "loss"
                        ? "url(#st-loss)"
                        : metric === "latency"
                          ? "url(#st-lat)"
                          : "url(#st-down)"
                    }
                  />
                )}
                {metric === "speed" && chart.secondaryArea && (
                  <path d={chart.secondaryArea} fill="url(#st-up)" />
                )}

                {chart.primaryLine && (
                  <path
                    d={chart.primaryLine}
                    fill="none"
                    style={{
                      stroke:
                        metric === "loss"
                          ? "var(--danger)"
                          : metric === "latency"
                            ? "var(--warn)"
                            : "var(--chart-down)",
                    }}
                    strokeWidth="1.9"
                    vectorEffect="non-scaling-stroke"
                    strokeLinejoin="round"
                  />
                )}
                {metric === "speed" && chart.secondaryLine && (
                  <path
                    d={chart.secondaryLine}
                    fill="none"
                    style={{ stroke: "var(--chart-up)" }}
                    strokeWidth="1.6"
                    vectorEffect="non-scaling-stroke"
                    strokeLinejoin="round"
                  />
                )}
                {metric === "speed" && chart.appLine && (
                  <path
                    d={chart.appLine}
                    fill="none"
                    style={{ stroke: "var(--ok)" }}
                    strokeWidth="2.2"
                    vectorEffect="non-scaling-stroke"
                    strokeLinejoin="round"
                  />
                )}

                {/* Server color strip along the bottom edge */}
                {bands.map((b, i) => (
                  <rect
                    key={`${b.name}-${i}`}
                    x={b.startFrac * SVG_W}
                    y={SVG_H - 4}
                    width={Math.max(2, b.widthFrac * SVG_W)}
                    height="4"
                    style={{ fill: b.color }}
                  >
                    <title>{b.name}</title>
                  </rect>
                ))}

                {/* Hover / pinned vertical crosshair */}
                {inspectedIdx !== null && inspectedPoint && (
                  <>
                    <line
                      x1={pointX(inspectedIdx, points.length)}
                      x2={pointX(inspectedIdx, points.length)}
                      y1="0"
                      y2={SVG_H}
                      style={{
                        stroke:
                          pinnedIdx !== null && hoverIdx === null
                            ? "var(--accent-hi)"
                            : "var(--text-dim)",
                      }}
                      strokeWidth={pinnedIdx !== null && hoverIdx === null ? "1.8" : "1"}
                      strokeDasharray={pinnedIdx !== null && hoverIdx === null ? undefined : "3 3"}
                      vectorEffect="non-scaling-stroke"
                    />
                    <circle
                      cx={pointX(inspectedIdx, points.length)}
                      cy={pointY(
                        metric === "speed"
                          ? inspectedPoint.downBps
                          : metric === "loss"
                            ? inspectedPoint.lossPct
                            : (inspectedPoint.latencyMs ?? 0),
                        chart.maxVal,
                      )}
                      r="3.8"
                      style={{
                        fill:
                          metric === "loss"
                            ? "var(--danger)"
                            : metric === "latency"
                              ? "var(--warn)"
                              : "var(--chart-down)",
                        stroke: "var(--bg)",
                      }}
                      strokeWidth="1.5"
                      vectorEffect="non-scaling-stroke"
                    />
                  </>
                )}
              </svg>
            </div>

            {points.length > 0 && (
              <div className="stats-x-axis mono">
                <span>{formatAxisTime(points[0].tsMs, range, locale)}</span>
                <span>
                  {formatAxisTime(
                    points[Math.floor(points.length / 2)].tsMs,
                    range,
                    locale,
                  )}
                </span>
                <span>
                  {formatAxisTime(points[points.length - 1].tsMs, range, locale)}
                </span>
              </div>
            )}
          </div>

          {/* Breakdown tabs + toolbar */}
          <div className="row between wrap" style={{ gap: 12, marginTop: 18, marginBottom: 12 }}>
            <Segmented<DetailTab>
              value={tab}
              onChange={setTab}
              options={[
                { value: "apps", label: `${t("stats.tabApps")} (${activeAppsRaw.length})` },
                {
                  value: "servers",
                  label: `${t("stats.tabServers")} (${report?.servers.length ?? 0})`,
                },
                {
                  value: "sessions",
                  label: `${t("stats.tabSessions")} (${report?.sessions.length ?? 0})`,
                },
              ]}
            />

            {tab === "apps" && (
              <div className="row wrap" style={{ gap: 10 }}>
                <Segmented<RouteFilter>
                  value={routeFilter}
                  onChange={setRouteFilter}
                  options={[
                    { value: "all", label: t("stats.routeAll") },
                    { value: "vpn", label: t("stats.routeVpn") },
                    { value: "direct", label: t("stats.routeDirect") },
                  ]}
                />
                <div className="stats-search">
                  <Search size={14} className="stats-search-icon" />
                  <input
                    className="input"
                    value={appSearch}
                    onChange={(e) => setAppSearch(e.target.value)}
                    placeholder={t("stats.searchApp")}
                  />
                </div>
              </div>
            )}
          </div>

          {/* Tab 1: Applications */}
          {tab === "apps" && (
            <div className="card stats-list-card">
              {pinnedIdx !== null && report?.pinnedPoint && (
                <div className="stats-pinned-strip">
                  <span>
                    {t("stats.momentPrefix")}{" "}
                    <strong className="mono">
                      {formatAxisTime(report.pinnedPoint.tsMs, range, locale)}
                    </strong>
                    {report.pinnedPoint.serverName
                      ? ` · ${report.pinnedPoint.serverName}`
                      : ""}
                  </span>
                  <button
                    type="button"
                    className="btn ghost sm"
                    onClick={() => setPinnedIdx(null)}
                  >
                    {t("stats.pinnedReset")}
                  </button>
                </div>
              )}

              {filteredApps.length === 0 ? (
                <Empty
                  icon={<BarChart3 size={28} color="var(--text-muted)" />}
                  title={t("split.nothingFound")}
                  text=""
                />
              ) : (
                <div className="stats-list">
                  {filteredApps.map((app) => (
                    <AppRow
                      key={app.key}
                      app={app}
                      iconUrl={icons[app.path]}
                      maxBytes={maxAppBytes}
                      selected={appKey === app.key}
                      onClick={() =>
                        setAppKey((prev) => (prev === app.key ? "" : app.key))
                      }
                    />
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab 2: VPN Servers comparison */}
          {tab === "servers" && (
            <div className="card stats-list-card">
              {(report?.servers.length ?? 0) === 0 ? (
                <Empty
                  icon={<Server size={28} color="var(--text-muted)" />}
                  title={t("split.nothingFound")}
                  text=""
                />
              ) : (
                <div className="stats-list">
                  {report!.servers.map((srv) => (
                    <ServerRow
                      key={srv.serverId}
                      srv={srv}
                      selected={serverId === srv.serverId}
                      onClick={() => {
                        setServerId((prev) =>
                          prev === srv.serverId ? "" : srv.serverId,
                        );
                        setPinnedIdx(null);
                      }}
                    />
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Tab 3: Sessions history */}
          {tab === "sessions" && (
            <div className="card stats-list-card">
              {(report?.sessions.length ?? 0) === 0 ? (
                <Empty
                  icon={<Activity size={28} color="var(--text-muted)" />}
                  title={t("split.nothingFound")}
                  text=""
                />
              ) : (
                <div className="stats-list">
                  {report!.sessions.map((sess) => (
                    <SessionRow
                      key={sess.id}
                      sess={sess}
                      locale={locale}
                      onClick={() => zoomToSession(sess)}
                    />
                  ))}
                </div>
              )}
            </div>
          )}
        </>
      )}

      <div style={{ height: 20 }} />
    </>
  );
}

function AppRow({
  app,
  iconUrl,
  maxBytes,
  selected,
  onClick,
}: {
  app: AppStats;
  iconUrl?: string;
  maxBytes: number;
  selected: boolean;
  onClick: () => void;
}) {
  const t = useT();
  const displayName = app.key === "__other__" ? t("stats.systemOther") : app.name;
  const initial = (displayName.trim()[0] ?? "?").toUpperCase();
  const totalFrac = Math.max(0.02, Math.min(1, app.totalBytes / maxBytes));
  const vpnFrac = Math.max(0, Math.min(1, app.vpnPct / 100));

  return (
    <button
      type="button"
      className={`stats-row${selected ? " active" : ""}`}
      onClick={onClick}
    >
      <div className={`app-icon${iconUrl ? " image" : ""}`}>
        {iconUrl ? <img src={iconUrl} alt="" /> : initial}
      </div>

      <div className="stats-row-main">
        <div className="row between" style={{ gap: 8 }}>
          <span className="stats-row-name truncate">{displayName}</span>
          <div className="row" style={{ gap: 6, flexShrink: 0 }}>
            {app.errors > 0 && <span className="chip warn">! {app.errors}</span>}
            <span className="stats-row-sub mono">
              VPN {Math.round(app.vpnPct)}%
            </span>
          </div>
        </div>

        <div className="stats-bar-track">
          <div
            className="stats-bar-total"
            style={{ width: `${(totalFrac * 100).toFixed(1)}%` }}
          >
            <div
              className="stats-bar-vpn"
              style={{ width: `${(vpnFrac * 100).toFixed(1)}%` }}
            />
          </div>
        </div>
      </div>

      <div className="stats-row-col stats-row-rates mono">
        <div>
          ↓ {bytes(app.downBytes)} · ↑ {bytes(app.upBytes)}
        </div>
        <div className="stats-row-sub">
          {app.totalConns > 0
            ? `${app.totalConns} ${t("stats.connsShort")}`
            : app.peakBps > 0
              ? `${t("graph.peak")} ${speed(app.peakBps)}`
              : ""}
        </div>
      </div>

      <div className="stats-row-col stats-row-total mono">
        <div className="stats-row-val">{bytes(app.totalBytes)}</div>
        <div className="stats-row-sub">{app.sharePct.toFixed(1)}%</div>
      </div>
    </button>
  );
}

function ServerRow({
  srv,
  selected,
  onClick,
}: {
  srv: ServerStats;
  selected: boolean;
  onClick: () => void;
}) {
  const t = useT();
  const tier = lossTier(srv.lossPct);
  const dotTier = srv.health === "bad" ? "bad" : srv.health === "warn" ? "ok" : "good";
  const errs = srv.dialFails + srv.relayErrors + srv.probeFails;

  return (
    <button
      type="button"
      className={`stats-row stats-server-row${selected ? " active" : ""}`}
      onClick={onClick}
    >
      <span className={`dot ${dotTier}`} />

      <div className="stats-row-main">
        <div className="row" style={{ gap: 8 }}>
          <span className="stats-row-name truncate">{srv.serverName}</span>
          {srv.serverProto && (
            <span className="chip">{protocolLabel(srv.serverProto)}</span>
          )}
        </div>
        <div className="stats-row-sub truncate">
          ↓ {speed(srv.avgDownBps)} ({t("graph.peak")} {speed(srv.peakDownBps)}) ·{" "}
          {formatDuration(srv.durationS)}
        </div>
      </div>

      <div className="stats-row-col mono">
        <div className="stats-row-val">
          {srv.avgLatencyMs !== null
            ? t("dash.pingMs", { ping: srv.avgLatencyMs })
            : "—"}
          {srv.jitterMs !== null ? ` ±${srv.jitterMs}` : ""}
        </div>
        <div className="stats-row-sub">{bytes(srv.totalBytes)}</div>
      </div>

      <div className="stats-row-col stats-row-loss mono">
        <div className={`stats-row-val stats-tier-${tier}`}>
          {t("stats.lossWord")} {srv.lossPct.toFixed(2)}%
        </div>
        <div className="stats-row-sub">
          {t("stats.dropsFmt", { lost: srv.packetsLost, err: errs })}
        </div>
      </div>
    </button>
  );
}

function SessionRow({
  sess,
  locale,
  onClick,
}: {
  sess: SessionRecord;
  locale: string;
  onClick: () => void;
}) {
  const t = useT();
  const tier = lossTier(sess.lossPct);
  const serverLabel =
    sess.serverCount > 1
      ? `${sess.primaryServerName} +${sess.serverCount - 1}`
      : sess.primaryServerName || "—";

  return (
    <button type="button" className="stats-row" onClick={onClick}>
      <div className="stats-row-main">
        <div className="row" style={{ gap: 8 }}>
          <span className="stats-row-name">{formatSessionDate(sess.startedMs, locale)}</span>
          {sess.active && <span className="chip ok">{t("stats.activeBadge")}</span>}
        </div>
        <div className="stats-row-sub truncate">
          {serverLabel} · {formatDuration(sess.durationS)}
        </div>
      </div>

      <div className="stats-row-col mono">
        <div className="stats-row-val">{bytes(sess.downBytes + sess.upBytes)}</div>
        <div className="stats-row-sub">
          {sess.avgLatencyMs !== null
            ? t("dash.pingMs", { ping: sess.avgLatencyMs })
            : "—"}
        </div>
      </div>

      <div className="stats-row-col mono" style={{ minWidth: 74 }}>
        <div className={`stats-row-val stats-tier-${tier}`}>
          {sess.lossPct.toFixed(2)}%
        </div>
        <div className="stats-row-sub">{t("stats.lossWord")}</div>
      </div>
    </button>
  );
}
