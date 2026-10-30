import {
  CalendarClock,
  ChevronDown,
  Gift,
  GripVertical,
  RefreshCw,
  Rss,
  Server,
  Trash2,
} from "lucide-react";
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
import { useT } from "../lib/i18n";
import type { GripProps } from "../lib/reorder";
import type { Subscription } from "../lib/types";
import { useStore } from "../store";

/** «3 сервера» — подпись раздела в списке и низа карточки подписки. */
function ServerCount({ count }: { count: number }) {
  const t = useT();
  return (
    <span>
      {count} {plural(count, t("srv.serverOne"), t("srv.serverFew"), t("srv.serverMany"))}
    </span>
  );
}

/** Шапка раздела своих серверов: подписки нет, поэтому нет ни срока, ни кнопок. */
export function OwnServersHead({
  count,
  open,
  onToggle,
}: {
  count: number;
  open: boolean;
  onToggle: () => void;
}) {
  const t = useT();
  return (
    <div className="card sub-card group" onClick={onToggle}>
      <button type="button" className="sub-toggle" aria-expanded={open}>
        <ChevronDown size={14} className="picker-caret" data-open={open} />
        <Server size={15} color="var(--text-muted)" style={{ flexShrink: 0 }} />
        <span className="node-name truncate">{t("srv.ownGroup")}</span>
      </button>
      <div className="sub-foot">
        <ServerCount count={count} />
      </div>
    </div>
  );
}

/**
 * Plan status for one subscription: days remaining and traffic consumed.
 *
 * Both numbers come from the panel's `subscription-userinfo` header, so they are
 * only shown once a refresh has actually reported them — inventing a "0 из 0"
 * bar for a provider that sends nothing would be worse than showing nothing.
 *
 * With `onToggle` it heads that subscription's section of the server list: a
 * tap anywhere but its buttons folds the servers under it.
 */
export function SubscriptionCard({
  sub,
  compact,
  onDelete,
  open,
  onToggle,
  grip,
}: {
  sub: Subscription;
  compact?: boolean;
  onDelete?: () => void;
  open?: boolean;
  onToggle?: () => void;
  /** Ручка, за которую раздел перетаскивают среди других. */
  grip?: GripProps;
}) {
  const t = useT();
  const toast = useStore((s) => s.toast);
  const [busy, setBusy] = useState(false);

  const fraction = quotaUsed(sub.upload + sub.download, sub.total);
  const tier = expiryTier(sub.expire);
  const expired = sub.expire > 0 && sub.expire * 1000 < Date.now();
  const exhausted = fraction !== null && fraction >= 1;
  // Пул FREE — не подписка провайдера: свой значок, как на кнопке, что его
  // включила, и вместо тарифа — откуда серверы и как часто они меняются.
  const Icon = sub.free ? Gift : Rss;

  async function refresh() {
    setBusy(true);
    try {
      await api.refreshSubscription(sub.id);
    } catch (e) {
      toast("error", t("srv.subRefreshFailed", { name: sub.name }), errText(e));
    } finally {
      setBusy(false);
    }
  }

  const title = (
    <>
      <Icon size={15} color="var(--text-muted)" style={{ flexShrink: 0 }} />
      <span className="node-name truncate" title={sub.name}>
        {sub.name}
      </span>
    </>
  );

  return (
    <div
      className={`card sub-card${compact ? " compact" : ""}${onToggle ? " group" : ""}`}
      onClick={onToggle}
    >
      <div className="row between sub-head" style={{ gap: 10 }}>
        {onToggle ? (
          <div className="sub-title">
            {grip && (
              <span
                className="node-grip"
                role="button"
                tabIndex={-1}
                aria-label={t("srv.reorderHandle")}
                title={t("srv.reorderHandle")}
                onClick={(e) => e.stopPropagation()}
                {...grip}
              >
                <GripVertical size={15} />
              </span>
            )}
            <button type="button" className="sub-toggle" aria-expanded={open}>
              <ChevronDown size={14} className="picker-caret" data-open={open} />
              {title}
            </button>
          </div>
        ) : (
          <div className="row grow" style={{ gap: 8, minWidth: 0 }}>
            {title}
          </div>
        )}
        {/* Обновить и удалить — не повод сворачивать раздел. */}
        <div
          className="row sub-actions"
          style={{ gap: 2, flexShrink: 0 }}
          onClick={(e) => e.stopPropagation()}
        >
          {onDelete && (
            <button
              type="button"
              className="btn ghost icon sm"
              title={t("srv.deleteSubTitle")}
              onClick={onDelete}
            >
              <Trash2 size={14} />
            </button>
          )}
          <button
            type="button"
            className="btn ghost icon sm"
            title={t("srv.refreshNow")}
            disabled={busy}
            onClick={() => void refresh()}
          >
            <RefreshCw size={14} className={busy ? "spin" : ""} />
          </button>
        </div>
      </div>

      {sub.hasUsage ? (
        <>
          <div className="sub-metrics">
            <div>
              <div className="sub-metric-label micro">
                <CalendarClock size={11} /> {t("srv.remaining")}
              </div>
              <div className={`sub-metric-value ${tier}`}>
                {expiryLabel(sub.expire)}
              </div>
            </div>
            <div style={{ textAlign: "right" }}>
              <div className="sub-metric-label micro" style={{ justifyContent: "flex-end" }}>
                {t("srv.trafficLabel")}
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
              {expired ? t("srv.expiredWarning") : t("srv.exhaustedWarning")}
            </div>
          )}
        </>
      ) : (
        <div className="sub-metric-label" style={{ marginTop: 6 }}>
          {t(sub.free ? "free.cardNote" : "srv.noUsageInfo")}
        </div>
      )}

      <div className="sub-foot">
        <ServerCount count={sub.nodeCount} />
        <span>·</span>
        <span>{t("srv.updatedWhen", { when: relativeTime(sub.lastUpdated) })}</span>
      </div>

      {/* Kept in the card, not only in a toast: a subscription that fetched fine
          but produced nothing usable must keep explaining itself. */}
      {sub.lastError && <div className="sub-warning">{sub.lastError}</div>}
    </div>
  );
}
