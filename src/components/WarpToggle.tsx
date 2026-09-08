import { openUrl } from "@tauri-apps/plugin-opener";
import { Cloud } from "lucide-react";
import { useEffect, useState } from "react";

import { api, errText } from "../lib/api";
import { useT } from "../lib/i18n";
import type { WarpInfo } from "../lib/types";
import { useStore } from "../store";
import { Modal, Switch } from "./ui";

const TERMS_URL = "https://www.cloudflare.com/application/terms/";
const PRIVACY_URL = "https://www.cloudflare.com/application/privacypolicy/";

/**
 * The one switch that puts Cloudflare WARP on top of whichever server is in
 * use: traffic reaches the server as before and leaves it wrapped in WireGuard,
 * so the server sees only an encrypted stream to Cloudflare and the site on the
 * far end sees Cloudflare's address rather than the server's.
 *
 * Registering with Cloudflare is deferred until the first time it is switched
 * on — an install that never wants WARP never announces itself — and needs the
 * user's agreement first, because it is Cloudflare's service, not ours.
 */
export function WarpToggle() {
  const t = useT();
  const wanted = useStore((s) => s.settings.warpOverProxy ?? false);
  const saveSettings = useStore((s) => s.saveSettings);
  const toast = useStore((s) => s.toast);

  const [info, setInfo] = useState<WarpInfo | null>(null);
  const [asking, setAsking] = useState(false);
  const [busy, setBusy] = useState(false);

  // Settings carried over from another machine can ask for the layer without
  // bringing the account it is built from, and the backend then quietly builds
  // no layer at all. Showing the switch off says what is actually happening,
  // and flipping it registers an account the ordinary way.
  const on = wanted && (info?.registered ?? true);

  useEffect(() => {
    // Whether an account already exists decides between "just switch it on" and
    // "ask first"; failing to find out is not worth a toast, the consent dialog
    // simply appears once more than it had to.
    void api.warpStatus().then(setInfo).catch(() => {});
  }, []);

  async function toggle(next: boolean) {
    if (next && !info?.registered) {
      setAsking(true);
      return;
    }
    setBusy(true);
    try {
      await saveSettings({ warpOverProxy: next });
    } finally {
      setBusy(false);
    }
  }

  /** The terms belong to Cloudflare, so they are read at Cloudflare — in the
   *  system browser, never inside the app's own window. */
  async function show(url: string) {
    try {
      await openUrl(url);
    } catch {
      // A dead button that says nothing happened is worse than the address in
      // the clipboard.
      await navigator.clipboard.writeText(url).catch(() => {});
      toast("info", t("warp.linkCopied"), url);
    }
  }

  async function accept() {
    setAsking(false);
    setBusy(true);
    try {
      setInfo(await api.enableWarp());
      await saveSettings({ warpOverProxy: true });
      toast("success", t("warp.enabled"));
    } catch (e) {
      toast("error", t("warp.registerFailed"), errText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <div className="warp-row">
        <span className="warp-icon">
          <Cloud size={16} />
        </span>
        <div className="grow" style={{ minWidth: 0 }}>
          <div className="toggle-label">{t("warp.title")}</div>
          <div className="toggle-desc">
            {busy ? t("warp.working") : t("warp.desc")}
          </div>
        </div>
        <Switch checked={on} onChange={(next) => void toggle(next)} disabled={busy} />
      </div>

      <Modal
        open={asking}
        title={t("warp.consentTitle")}
        onClose={() => setAsking(false)}
        footer={
          <>
            <button type="button" className="btn" onClick={() => setAsking(false)}>
              {t("srv.cancel")}
            </button>
            <button type="button" className="btn primary" onClick={() => void accept()}>
              {t("warp.accept")}
            </button>
          </>
        }
      >
        <p className="hint" style={{ marginTop: 0 }}>
          {t("warp.consentText")}
        </p>
        <div className="row" style={{ gap: 8 }}>
          <button type="button" className="btn sm" onClick={() => void show(TERMS_URL)}>
            {t("warp.terms")}
          </button>
          <button type="button" className="btn sm" onClick={() => void show(PRIVACY_URL)}>
            {t("warp.privacy")}
          </button>
        </div>
      </Modal>
    </>
  );
}
