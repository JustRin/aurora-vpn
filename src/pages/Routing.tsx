import { FileJson2 } from "lucide-react";
import { useState } from "react";

import { Modal, StringList, ToggleRow } from "../components/ui";
import { api, errText } from "../lib/api";
import { useStore } from "../store";

export function Routing() {
  const split = useStore((s) => s.split);
  const saveSplit = useStore((s) => s.saveSplit);
  const toast = useStore((s) => s.toast);

  const [preview, setPreview] = useState<string | null>(null);

  async function showConfig() {
    try {
      setPreview(await api.previewConfig());
    } catch (e) {
      toast("error", "Не удалось собрать конфигурацию", errText(e));
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Маршрутизация</h1>
          <p className="page-sub">
            Правила применяются сверху вниз, побеждает первое совпадение:
            блокировки → локальная сеть → ваши списки → гео-правила → правила по
            приложениям.
          </p>
        </div>
        <button type="button" className="btn" onClick={() => void showConfig()}>
          <FileJson2 size={15} />
          Показать конфиг
        </button>
      </div>

      <div className="section-title">Готовые наборы</div>
      <div className="card">
        <ToggleRow
          label="Не трогать локальную сеть"
          desc="Роутер, принтеры, NAS и localhost идут напрямую. Отключать стоит только осознанно — иначе перестанут открываться устройства в домашней сети."
          checked={split.bypassPrivate ?? true}
          onChange={(bypassPrivate) => void saveSplit({ bypassPrivate })}
        />
        <ToggleRow
          label="Российские сайты — мимо VPN"
          desc="Домены и адреса из списка geosite/geoip ru идут напрямую. Ускоряет доступ к локальным сервисам и снимает капчи."
          checked={split.bypassRu ?? false}
          onChange={(bypassRu) => void saveSplit({ bypassRu })}
        />
        <ToggleRow
          label="Китайские сайты — мимо VPN"
          desc="То же самое для списка geosite/geoip cn."
          checked={split.bypassCn ?? false}
          onChange={(bypassCn) => void saveSplit({ bypassCn })}
        />
        <ToggleRow
          label="Блокировать рекламу и трекеры"
          desc="Запросы к доменам из списка category-ads-all отклоняются на уровне ядра и DNS."
          checked={split.blockAds ?? false}
          onChange={(blockAds) => void saveSplit({ blockAds })}
        />
      </div>

      <div className="section-title">Свои правила</div>
      <div className="grid-2">
        <StringList
          label="Всегда напрямую — домены"
          hint="По одному на строку. Совпадение по суффиксу: example.com покроет и sub.example.com."
          placeholder={"gosuslugi.ru\nsberbank.ru"}
          value={split.directDomains ?? []}
          onChange={(directDomains) => void saveSplit({ directDomains })}
        />
        <StringList
          label="Всегда через VPN — домены"
          hint="Имеет приоритет над гео-правилами, но уступает списку «всегда напрямую»."
          placeholder={"youtube.com\nopenai.com"}
          value={split.proxyDomains ?? []}
          onChange={(proxyDomains) => void saveSplit({ proxyDomains })}
        />
        <StringList
          label="Всегда напрямую — адреса"
          hint="IP или CIDR, например 10.0.0.0/8."
          placeholder={"192.168.1.0/24\n1.2.3.4"}
          value={split.directIps ?? []}
          onChange={(directIps) => void saveSplit({ directIps })}
        />
        <StringList
          label="Всегда через VPN — адреса"
          hint="IP или CIDR."
          value={split.proxyIps ?? []}
          onChange={(proxyIps) => void saveSplit({ proxyIps })}
        />
        <StringList
          label="Блокировать домены"
          hint="Соединения отклоняются, DNS-ответ не выдаётся."
          placeholder={"ads.example.com"}
          value={split.blockDomains ?? []}
          onChange={(blockDomains) => void saveSplit({ blockDomains })}
        />
      </div>

      <Modal
        open={preview !== null}
        wide
        title="Сгенерированная конфигурация sing-box"
        onClose={() => setPreview(null)}
        footer={
          <>
            <button
              type="button"
              className="btn"
              onClick={async () => {
                if (preview) await navigator.clipboard.writeText(preview);
                toast("success", "Скопировано");
              }}
            >
              Скопировать
            </button>
            <button
              type="button"
              className="btn primary"
              onClick={() => setPreview(null)}
            >
              Закрыть
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
