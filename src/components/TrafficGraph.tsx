import { useMemo } from "react";

import { speed } from "../lib/format";
import { useT } from "../lib/i18n";
import type { TrafficSample } from "../store";

const WIDTH = 560;
const HEIGHT = 132;
/** Headroom so a peak never collides with the legend floating over the chart. */
const PAD_TOP = 26;
const PAD_BOTTOM = 2;

/**
 * Build an SVG path for one series, scaled to the shared peak.
 *
 * The x-axis spans whatever samples exist rather than the buffer's capacity: a
 * fresh connection would otherwise squeeze its handful of points into the last
 * sixth of the panel and read as a broken, empty chart. Once the buffer fills,
 * the two are identical and it becomes an ordinary scrolling window.
 */
function toPath(values: number[], peak: number): string {
  if (values.length === 0) return "";
  const usable = HEIGHT - PAD_TOP - PAD_BOTTOM;
  const step = WIDTH / Math.max(1, values.length - 1);

  return values
    .map((value, i) => {
      const x = i * step;
      const y = HEIGHT - PAD_BOTTOM - (peak === 0 ? 0 : (value / peak) * usable);
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
}

function toArea(path: string): string {
  if (!path) return "";
  return `${path} L${WIDTH},${HEIGHT} L0,${HEIGHT} Z`;
}

export function TrafficGraph({
  history,
  bleed,
}: {
  history: TrafficSample[];
  /** Fill the container edge to edge, without the legend header. */
  bleed?: boolean;
}) {
  const t = useT();
  const { downPath, upPath, downArea, upArea, peak } = useMemo(() => {
    const down = history.map((h) => h.down);
    const up = history.map((h) => h.up);
    // A shared, non-zero floor keeps an idle tunnel from rendering as noise.
    const peak = Math.max(...down, ...up, 64 * 1024);
    const downPath = toPath(down, peak);
    const upPath = toPath(up, peak);
    return {
      downPath,
      upPath,
      downArea: toArea(downPath),
      upArea: toArea(upPath),
      peak,
    };
  }, [history]);

  return (
    <div className={bleed ? "spark-wrap" : undefined}>
      {!bleed && (
        <div className="row between" style={{ marginBottom: 8 }}>
          <div className="legend">
            <span>
              <i style={{ background: "var(--chart-down)" }} /> {t("graph.down")}
            </span>
            <span>
              <i style={{ background: "var(--chart-up)" }} /> {t("graph.up")}
            </span>
          </div>
          <div style={{ fontSize: "var(--t-xs)", color: "var(--text-muted)" }}>
            {t("graph.peak")} {speed(peak)}
          </div>
        </div>
      )}

      {bleed && (
        <div className="spark-meta">
          <div className="legend">
            <span>
              <i style={{ background: "var(--chart-down)" }} /> {t("graph.down")}
            </span>
            <span>
              <i style={{ background: "var(--chart-up)" }} /> {t("graph.up")}
            </span>
          </div>
          <span>{t("graph.peak")} {speed(peak)}</span>
        </div>
      )}

      <svg
        viewBox={`0 0 ${WIDTH} ${HEIGHT}`}
        preserveAspectRatio="none"
        style={{ width: "100%", height: bleed ? "100%" : HEIGHT, display: "block" }}
        role="img"
        aria-label={t("graph.aria")}
      >
        {/* Colours come through `style`, not attributes: SVG presentation
            attributes cannot resolve CSS custom properties, so a themed palette
            has to be applied as inline style. */}
        <defs>
          <linearGradient id="down-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" style={{ stopColor: "var(--chart-down)" }} stopOpacity="0.32" />
            <stop offset="100%" style={{ stopColor: "var(--chart-down)" }} stopOpacity="0" />
          </linearGradient>
          <linearGradient id="up-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" style={{ stopColor: "var(--chart-up)" }} stopOpacity="0.26" />
            <stop offset="100%" style={{ stopColor: "var(--chart-up)" }} stopOpacity="0" />
          </linearGradient>
        </defs>

        {[0.25, 0.5, 0.75].map((fraction) => (
          <line
            key={fraction}
            x1="0"
            x2={WIDTH}
            y1={HEIGHT * fraction}
            y2={HEIGHT * fraction}
            style={{ stroke: "var(--grid-line)" }}
            strokeWidth="1"
          />
        ))}

        {downArea && <path d={downArea} fill="url(#down-fill)" />}
        {upArea && <path d={upArea} fill="url(#up-fill)" />}
        {downPath && (
          <path
            d={downPath}
            fill="none"
            style={{ stroke: "var(--chart-down)" }}
            strokeWidth="1.8"
            vectorEffect="non-scaling-stroke"
            strokeLinejoin="round"
          />
        )}
        {upPath && (
          <path
            d={upPath}
            fill="none"
            style={{ stroke: "var(--chart-up)" }}
            strokeWidth="1.8"
            vectorEffect="non-scaling-stroke"
            strokeLinejoin="round"
          />
        )}
      </svg>
    </div>
  );
}
