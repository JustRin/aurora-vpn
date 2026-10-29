import { openUrl } from "@tauri-apps/plugin-opener";
import { Gift, ShieldAlert } from "lucide-react";
import { useState } from "react";

import { api, errText } from "../lib/api";
import { useT } from "../lib/i18n";
import type { ImportReport } from "../lib/types";
import { useStore } from "../store";
import { Modal } from "./ui";

/** Откуда берутся серверы пула — то же, что `free::SOURCE` в Rust. */
const SOURCE_URL = "https://github.com/igareck/vpn-configs-for-russia";

/**
 * Кнопка пула FREE: публичные серверы из открытых списков, сведённые в одну
 * подписку. Невключённый пул сперва показывает соглашение — серверы чужие, и
 * сказать об этом надо до, а не после; включённый кнопка просто обновляет.
 * Отказ — удаление подписки FREE, как любой другой.
 */
export function FreePoolButton({ onReport }: { onReport: (report: ImportReport) => void }) {
  const t = useT();
  const enabled = useStore((s) => s.subscriptions.some((sub) => sub.free));
  const reload = useStore((s) => s.reload);
  const toast = useStore((s) => s.toast);

  const [asking, setAsking] = useState(false);
  const [busy, setBusy] = useState(false);

  async function gather() {
    setAsking(false);
    setBusy(true);
    try {
      onReport(await api.addFreePool());
      await reload();
    } catch (e) {
      toast("error", t("free.failed"), errText(e));
    } finally {
      setBusy(false);
    }
  }

  /** Списки лежат на GitHub — и читаются там, в системном браузере. */
  async function showSource() {
    try {
      await openUrl(SOURCE_URL);
    } catch {
      await navigator.clipboard.writeText(SOURCE_URL).catch(() => {});
      toast("info", t("srv.linkCopied"), SOURCE_URL);
    }
  }

  return (
    <>
      <button
        type="button"
        className="btn"
        disabled={busy}
        title={t(enabled ? "free.btnRefreshTitle" : "free.btnTitle")}
        onClick={() => (enabled ? void gather() : setAsking(true))}
      >
        <Gift size={15} className={busy ? "spin" : ""} />
        FREE
      </button>

      <Modal
        open={asking}
        title={t("free.consentTitle")}
        onClose={() => setAsking(false)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setAsking(false)}>
              {t("srv.cancel")}
            </button>
            <button type="button" className="btn primary" onClick={() => void gather()}>
              {t("free.accept")}
            </button>
          </>
        }
      >
        <p className="hint" style={{ marginTop: 0 }}>
          {t("free.consentText")}
        </p>
        <div className="alert">
          <ShieldAlert size={17} color="var(--warn)" style={{ flexShrink: 0 }} />
          <div>
            <div className="alert-title">{t("free.riskTitle")}</div>
            <div className="alert-text">{t("free.consentRisk")}</div>
          </div>
        </div>
        <p className="hint">{t("free.consentOptout")}</p>
        <div className="row">
          <button type="button" className="btn sm" onClick={() => void showSource()}>
            {t("free.source")}
          </button>
        </div>
      </Modal>
    </>
  );
}
