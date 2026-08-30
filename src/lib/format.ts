import { intlTag, langNow, tNow } from "./i18n";

/** `fmt.byteUnits` is a pipe-separated list so one key covers the whole row. */
function units(): string[] {
  return tNow("fmt.byteUnits").split("|");
}

export function bytes(value: number): string {
  const names = units();
  if (!Number.isFinite(value) || value <= 0) return `0 ${names[0]}`;
  const i = Math.min(Math.floor(Math.log(value) / Math.log(1024)), names.length - 1);
  const scaled = value / 1024 ** i;
  // Keep the column width stable: more precision only where it fits.
  return `${scaled.toFixed(i === 0 ? 0 : scaled < 10 ? 2 : 1)} ${names[i]}`;
}

export function speed(bytesPerSecond: number): string {
  return `${bytes(bytesPerSecond)}${tNow("fmt.perSecond")}`;
}

export function duration(sinceMs: number | null): string {
  if (!sinceMs) return "—";
  const total = Math.max(0, Math.floor((Date.now() - sinceMs) / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = total % 60;
  const pad = (n: number) => String(n).padStart(2, "0");
  return h > 0 ? `${h}:${pad(m)}:${pad(s)}` : `${pad(m)}:${pad(s)}`;
}

export function relativeTime(iso: string): string {
  if (!iso) return tNow("fmt.never");
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return tNow("fmt.never");
  const seconds = Math.floor((Date.now() - then) / 1000);
  if (seconds < 60) return tNow("fmt.justNow");
  if (seconds < 3600) return tNow("fmt.minAgo", { n: Math.floor(seconds / 60) });
  if (seconds < 86400) return tNow("fmt.hoursAgo", { n: Math.floor(seconds / 3600) });
  return tNow("fmt.daysAgo", { n: Math.floor(seconds / 86400) });
}

/**
 * Whole days until a plan lapses. Negative once it already has; `null` when the
 * provider reports no expiry at all.
 */
export function daysLeft(expireSeconds: number): number | null {
  if (!expireSeconds) return null;
  const ms = expireSeconds * 1000 - Date.now();
  return Math.floor(ms / 86_400_000);
}

/**
 * Numeral agreement across the shipped languages: 1 сервер, 2 сервера,
 * 5 серверов — but also 1 servidor / 21 servidores, where the Russian
 * tail-digit rule would wrongly pick the singular. `Intl.PluralRules` carries
 * the CLDR rule for whichever language is active; the three slots we have are
 * enough for all of them. Languages without agreement (zh, ja, ko) simply pass
 * the same word three times.
 */
export function plural(n: number, one: string, few: string, many: string): string {
  const category = new Intl.PluralRules(intlTag(langNow())).select(n);
  // `two` and `few` share the dual/paucal slot; everything else is the plural.
  return category === "one" ? one : category === "two" || category === "few" ? few : many;
}

/** `fmt.dayForms` carries the pipe-separated forms: "день|дня|дней" / "day|days|days". */
function pluralDays(n: number): string {
  const [one, few, many] = tNow("fmt.dayForms").split("|");
  return plural(n, one, few, many);
}

export function expiryLabel(expireSeconds: number): string {
  const days = daysLeft(expireSeconds);
  if (days === null) return tNow("fmt.noExpiry");
  if (days < 0) return tNow("fmt.expired");
  if (days === 0) return tNow("fmt.expiresToday");
  return `${days} ${pluralDays(days)}`;
}

/** How urgently the plan needs attention — drives colour, not wording. */
export function expiryTier(expireSeconds: number): "good" | "ok" | "bad" | "none" {
  const days = daysLeft(expireSeconds);
  if (days === null) return "none";
  if (days < 0) return "bad";
  if (days <= 3) return "bad";
  if (days <= 10) return "ok";
  return "good";
}

/** Fraction of the traffic allowance consumed, or `null` when unlimited. */
export function quotaUsed(used: number, total: number): number | null {
  if (!total) return null;
  return Math.min(1, Math.max(0, used / total));
}

/**
 * `40.0 / 100 ГБ` — both figures share the allowance's unit so the pair reads as
 * one measurement and stays on a single line inside a tile.
 */
export function quotaLabel(used: number, total: number): string {
  // Unlimited plans show the consumed amount alone — the absent progress bar
  // already says there is no ceiling, and spelling it out overflows the tile.
  if (!total) return bytes(used);

  const names = units();
  const i = Math.min(Math.floor(Math.log(total) / Math.log(1024)), names.length - 1);
  const scale = 1024 ** i;
  const format = (value: number) => {
    const scaled = value / scale;
    return scaled < 10 && i > 0 ? scaled.toFixed(1) : Math.round(scaled).toString();
  };
  return `${format(used)} / ${format(total)} ${names[i]}`;
}

/** Latency buckets drive the colour of the signal dot. */
export function latencyTier(ms: number | null | undefined): "good" | "ok" | "bad" | "none" {
  if (ms === null || ms === undefined) return "none";
  if (ms < 200) return "good";
  if (ms < 500) return "ok";
  return "bad";
}

export function protocolLabel(protocol: string): string {
  switch (protocol) {
    case "vless":
      return "VLESS";
    case "vmess":
      return "VMess";
    case "trojan":
      return "Trojan";
    case "shadowsocks":
      return "Shadowsocks";
    case "hysteria2":
      return "Hysteria2";
    case "tuic":
      return "TUIC";
    default:
      return protocol;
  }
}

/** Compact description of a node's transport, e.g. `REALITY · ws`. */
export function transportLabel(security: string, network: string): string {
  const sec =
    security === "reality"
      ? "REALITY"
      : security === "tls"
        ? "TLS"
        : tNow("fmt.noTls");
  return network === "tcp" ? sec : `${sec} · ${network}`;
}
