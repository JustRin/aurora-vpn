import { FileJson2 } from "lucide-react";
import { useState } from "react";

import { Modal, StringList, ToggleRow } from "../components/ui";
import { api, errText } from "../lib/api";
import { useT } from "../lib/i18n";
import { useStore } from "../store";

export function Routing() {
  const t = useT();
  const split = useStore((s) => s.split);
  const saveSplit = useStore((s) => s.saveSplit);
  const toast = useStore((s) => s.toast);

  const [preview, setPreview] = useState<string | null>(null);

  async function showConfig() {
    try {
      setPreview(await api.previewConfig());
    } catch (e) {
      toast("error", t("route.buildFailed"), errText(e));
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{t("route.title")}</h1>
          <p className="page-sub">{t("route.subtitle")}</p>
        </div>
        <button type="button" className="btn" onClick={() => void showConfig()}>
          <FileJson2 size={15} />
          {t("route.showConfig")}
        </button>
      </div>

      <div className="section-title">{t("route.presets")}</div>
      <div className="card">
        <ToggleRow
          label={t("route.bypassLan")}
          desc={t("route.bypassLanDesc")}
          checked={split.bypassPrivate ?? true}
          onChange={(bypassPrivate) => void saveSplit({ bypassPrivate })}
        />
        <ToggleRow
          label={t("route.bypassRu")}
          desc={t("route.bypassRuDesc")}
          checked={split.bypassRu ?? false}
          onChange={(bypassRu) => void saveSplit({ bypassRu })}
        />
        <ToggleRow
          label={t("route.bypassCn")}
          desc={t("route.bypassCnDesc")}
          checked={split.bypassCn ?? false}
          onChange={(bypassCn) => void saveSplit({ bypassCn })}
        />
        <ToggleRow
          label={t("route.blockAds")}
          desc={t("route.blockAdsDesc")}
          checked={split.blockAds ?? false}
          onChange={(blockAds) => void saveSplit({ blockAds })}
        />
      </div>

      <div className="section-title">{t("route.customRules")}</div>
      <div className="grid-2">
        <StringList
          label={t("route.directDomains")}
          hint={t("route.directDomainsHint")}
          placeholder={"gosuslugi.ru\nsberbank.ru"}
          value={split.directDomains ?? []}
          onChange={(directDomains) => void saveSplit({ directDomains })}
        />
        <StringList
          label={t("route.proxyDomains")}
          hint={t("route.proxyDomainsHint")}
          placeholder={"youtube.com\nopenai.com"}
          value={split.proxyDomains ?? []}
          onChange={(proxyDomains) => void saveSplit({ proxyDomains })}
        />
        <StringList
          label={t("route.directIps")}
          hint={t("route.directIpsHint")}
          placeholder={"192.168.1.0/24\n1.2.3.4"}
          value={split.directIps ?? []}
          onChange={(directIps) => void saveSplit({ directIps })}
        />
        <StringList
          label={t("route.proxyIps")}
          hint={t("route.proxyIpsHint")}
          value={split.proxyIps ?? []}
          onChange={(proxyIps) => void saveSplit({ proxyIps })}
        />
        <StringList
          label={t("route.blockDomains")}
          hint={t("route.blockDomainsHint")}
          placeholder={"ads.example.com"}
          value={split.blockDomains ?? []}
          onChange={(blockDomains) => void saveSplit({ blockDomains })}
        />
      </div>

      <Modal
        open={preview !== null}
        wide
        title={t("route.configTitle")}
        onClose={() => setPreview(null)}
        footer={
          <>
            <button
              type="button"
              className="btn"
              onClick={async () => {
                if (preview) await navigator.clipboard.writeText(preview);
                toast("success", t("route.copied"));
              }}
            >
              {t("route.copy")}
            </button>
            <button
              type="button"
              className="btn primary"
              onClick={() => setPreview(null)}
            >
              {t("route.close")}
            </button>
          </>
        }
      >
        <pre
          className="mono"
          style={{
            margin: 0,
            maxHeight: "60vh",
            overflow: "auto",
            userSelect: "text",
            background: "var(--sunken-deep)",
            border: "1px solid var(--border)",
            borderRadius: 10,
            padding: 12,
            lineHeight: 1.6,
          }}
        >
          {preview}
        </pre>
      </Modal>
    </>
  );
}
