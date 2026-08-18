import { CalendarClock, RefreshCw, Rss } from "lucide-react";
import { useState } from "react";

import { api, errText } from "../lib/api";
import {
  expiryLabel,
  expiryTier,
  plural,
  quotaLabel,
  quotaUsed,
  relativeTime,
} from "../lib/format";
import type { Subscription } from "../lib/types";
import { useStore } from "../store";

/**
 * Plan status for one subscription: days remaining and traffic consumed.
 *
 * Both numbers come from the panel's `subscription-userinfo` header, so they are
 * only shown once a refresh has actually reported them — inventing a "0 из 0"
 * bar for a provider that sends nothing would be worse than showing nothing.
 */
export function SubscriptionCard({
  sub,
  compact,
}: {
  sub: Subscription;
  compact?: boolean;
}) {
  const toast = useStore((s) => s.toast);
  const [busy, setBusy] = useState(false);

  const fraction = quotaUsed(sub.upload + sub.download, sub.total);
  const tier = expiryTier(sub.expire);
  const expired = sub.expire > 0 && sub.expire * 1000 < Date.now();
  const exhausted = fraction !== null && fraction >= 1;

  async function refresh() {
    setBusy(true);
    try {
      await api.refreshSubscription(sub.id);
    } catch (e) {
      toast("error", `Не удалось обновить «${sub.name}»`, errText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className={`card sub-card${compact ? " compact" : ""}`}>
      <div className="row between" style={{ gap: 10 }}>
        <div className="row grow" style={{ gap: 8, minWidth: 0 }}>
          <Rss size={15} color="var(--text-muted)" style={{ flexShrink: 0 }} />
          <span className="node-name truncate" title={sub.name}>
            {sub.name}
          </span>
        </div>
        <button
          type="button"
          className="btn ghost icon sm"
          title="Обновить сейчас"
          disabled={busy}
          onClick={() => void refresh()}
        >
          <RefreshCw size={14} className={busy ? "spin" : ""} />
        </button>
      </div>

      {sub.hasUsage ? (
        <>
          <div className="sub-metrics">
            <div>
              <div className="sub-metric-label micro">
                <CalendarClock size={11} /> Осталось
              </div>
              <div className={`sub-metric-value ${tier}`}>
                {expiryLabel(sub.expire)}
              </div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div className="sub-metric-label micro" style={{ justifyContent: "flex-end" }}>
                Трафик
              </div>
              <div className="sub-metric-value">
                {quotaLabel(sub.upload + sub.download, sub.total)}
              </div>
            </div>
          </div>

          {fraction !== null && (
            <div className="meter" title={`${Math.round(fraction * 100)}%`}>
              <span
                className={exhausted ? "bad" : fraction > 0.85 ? "ok" : ""}
                style={{ width: `${Math.max(2, fraction * 100)}%` }}
              />
            </div>
          )}

          {(expired || exhausted) && (
            <div className="sub-warning">
              {expired
                ? "Срок действия истёк — серверы, скорее всего, уже не отвечают."
                : "Трафик исчерпан — продлите тариф в панели."}
            </div>
          )}
        </>
      ) : (
        <div className="sub-metric-label" style={{ marginTop: 6 }}>
          Панель не сообщает лимиты и срок действия
        </div>
      )}

      <div className="sub-foot">
        <span>
          {sub.nodeCount} {plural(sub.nodeCount, "сервер", "сервера", "серверов")}
        </span>
        <span>·</span>
        <span>обновлено {relativeTime(sub.lastUpdated)}</span>
      </div>

      {/* Kept in the card, not only in a toast: a subscription that fetched fine
          but produced nothing usable must keep explaining itself. */}
      {sub.lastError && <div className="sub-warning">{sub.lastError}</div>}
    </div>
  );
}
