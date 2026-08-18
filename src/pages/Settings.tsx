import { FolderOpen } from "lucide-react";
import { useState } from "react";

import { ElevateModal } from "../components/ElevateModal";
import { Field, Segmented, ToggleRow } from "../components/ui";
import { api, errText } from "../lib/api";
import { THEMES } from "../lib/themes";
import {
  ELEVATION_REQUIRED,
  type AutostartMode,
  type TunStack,
  type TunnelMode,
} from "../lib/types";
import { useStore } from "../store";

export function Settings() {
  const settings = useStore((s) => s.settings);
  const save = useStore((s) => s.saveSettings);
  const elevated = useStore((s) => s.status.elevated);
  const autostart = useStore((s) => s.autostart);
  const setAutostart = useStore((s) => s.setAutostart);
  const toast = useStore((s) => s.toast);

  const [askElevate, setAskElevate] = useState(false);

  async function changeAutostart(mode: AutostartMode) {
    try {
      await setAutostart(mode);
    } catch (e) {
      const text = errText(e);
      // Registering — or removing — a scheduled task needs administrator
      // rights; offer the same restart flow the tunnel uses.
      if (text.includes(ELEVATION_REQUIRED)) {
        setAskElevate(true);
        return;
      }
      toast("error", "Не удалось изменить автозапуск", text);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">Настройки</h1>
          <p className="page-sub">
            Изменения применяются сразу; при активном подключении ядро
            перезапускается автоматически.
          </p>
        </div>
        <button
          type="button"
          className="btn"
          onClick={() => void api.openConfigDir()}
        >
          <FolderOpen size={15} />
          Папка данных
        </button>
      </div>

      <div className="section-title">Туннель</div>
      <div className="card">
        <div className="toggle-row">
          <div className="grow">
            <div className="toggle-label">Режим работы</div>
            <div className="toggle-desc">
              {settings.tunnelMode === "tun"
                ? "TUN — виртуальный адаптер Wintun перехватывает трафик всей системы. Нужны права администратора, зато работают правила по приложениям."
                : "Системный прокси — без прав администратора, но охватывает только приложения, которые читают системные настройки прокси."}
            </div>
          </div>
          <Segmented<TunnelMode>
            value={settings.tunnelMode}
            onChange={(tunnelMode) => void save({ tunnelMode })}
            options={[
              { value: "tun", label: "TUN" },
              { value: "systemProxy", label: "Системный прокси" },
            ]}
          />
        </div>

        {settings.tunnelMode === "tun" && !elevated && (
          <div className="alert" style={{ marginTop: 12 }}>
            <div className="alert-text">
              Приложение запущено без прав администратора — подключение в режиме
              TUN предложит перезапуск.
            </div>
          </div>
        )}
      </div>

      {settings.tunnelMode === "tun" && (
        <>
          <div className="section-title">Параметры TUN</div>
          <div className="card">
            <div className="grid-2">
              <Field
                label="Сетевой стек"
                hint="mixed — gVisor для TCP и системный для UDP: лучший баланс скорости и совместимости."
              >
                <select
                  className="select"
                  value={settings.tunStack}
                  onChange={(e) => void save({ tunStack: e.target.value as TunStack })}
                >
                  <option value="mixed">mixed (рекомендуется)</option>
                  <option value="system">system</option>
                  <option value="gvisor">gvisor</option>
                </select>
              </Field>
              <Field label="MTU" hint="По умолчанию 9000.">
                <input
                  className="input"
                  type="number"
                  defaultValue={settings.tunMtu}
                  onBlur={(e) => void save({ tunMtu: Number(e.target.value) || 9000 })}
                />
              </Field>
            </div>
            <ToggleRow
              label="Строгая маршрутизация"
              desc="Блокирует попытки трафика уйти в обход туннеля. Отключите, если перестают работать VirtualBox/WSL или сетевые игры."
              checked={settings.strictRoute}
              onChange={(strictRoute) => void save({ strictRoute })}
            />
            <ToggleRow
              label="Поддержка IPv6"
              desc="Выключено — DNS отдаёт только A-записи. Включайте, если провайдер и сервер действительно поддерживают IPv6."
              checked={settings.ipv6}
              onChange={(ipv6) => void save({ ipv6 })}
            />
            <ToggleRow
              label="Fake-IP"
              desc="Ускоряет открытие сайтов: домен резолвится мгновенно, а настоящий адрес узнаёт уже сервер. Может мешать некоторым локальным сервисам."
              checked={settings.fakeIp}
              onChange={(fakeIp) => void save({ fakeIp })}
            />
          </div>
        </>
      )}

      <div className="section-title">DNS</div>
      <div className="card">
        <div className="grid-2">
          <Field
            label="DNS через VPN"
            hint="Используется для доменов, идущих в туннель. Можно указать tls:// или https://."
          >
            <input
              className="input mono"
              defaultValue={settings.dnsRemote}
              onBlur={(e) => void save({ dnsRemote: e.target.value.trim() })}
            />
          </Field>
          <Field
            label="DNS напрямую"
            hint="Для доменов в обход туннеля и для резолва адреса самого сервера."
          >
            <input
              className="input mono"
              defaultValue={settings.dnsDirect}
              onBlur={(e) => void save({ dnsDirect: e.target.value.trim() })}
            />
          </Field>
        </div>
      </div>

      <div className="section-title">Подключение</div>
      <div className="card">
        <div className="grid-2">
          <Field label="Порт SOCKS/HTTP" hint="Локальный смешанный прокси.">
            <input
              className="input"
              type="number"
              defaultValue={settings.mixedPort}
              onBlur={(e) => void save({ mixedPort: Number(e.target.value) || 2080 })}
            />
          </Field>
          <Field label="Порт панели управления ядром" hint="Clash API на 127.0.0.1.">
            <input
              className="input"
              type="number"
              defaultValue={settings.clashPort}
              onBlur={(e) => void save({ clashPort: Number(e.target.value) || 9191 })}
            />
          </Field>
          <Field
            label="URL для проверки задержки"
            hint="Запрос уходит через выбранный сервер."
          >
            <input
              className="input mono"
              defaultValue={settings.latencyUrl}
              onBlur={(e) => void save({ latencyUrl: e.target.value.trim() })}
            />
          </Field>
          <Field label="Уровень журнала">
            <select
              className="select"
              value={settings.logLevel}
              onChange={(e) => void save({ logLevel: e.target.value })}
            >
              {["trace", "debug", "info", "warn", "error"].map((level) => (
                <option key={level} value={level}>
                  {level}
                </option>
              ))}
            </select>
          </Field>
        </div>

        <ToggleRow
          label="Доступ из локальной сети"
          desc="Прокси слушает 0.0.0.0 — другие устройства в сети смогут им пользоваться. Включайте только в доверенной сети."
          checked={settings.allowLan}
          onChange={(allowLan) => void save({ allowLan })}
        />
        <ToggleRow
          label="Выбирать самый быстрый сервер"
          desc="Ядро само переключается на сервер с наименьшей задержкой и перепроверяет раз в 3 минуты."
          checked={settings.autoSelect}
          onChange={(autoSelect) => void save({ autoSelect })}
        />
      </div>

      <div className="section-title">Подписки</div>
      <div className="card">
        <div className="toggle-row">
          <div className="grow">
            <div className="toggle-label">Обновлять автоматически</div>
            <div className="toggle-desc">
              Список серверов, остаток трафика и срок действия подтягиваются с
              панели в фоне. Устаревший список — самая частая причина, по которой
              клиент внезапно перестаёт подключаться.
            </div>
          </div>
          <select
            className="select"
            style={{ width: 190 }}
            value={String(settings.subAutoUpdateMin)}
            onChange={(e) =>
              void save({ subAutoUpdateMin: Number(e.target.value) })
            }
          >
            <option value="0">Не обновлять</option>
            <option value="180">каждые 3 часа</option>
            <option value="360">каждые 6 часов</option>
            <option value="720">каждые 12 часов</option>
            <option value="1440">раз в сутки</option>
          </select>
        </div>
      </div>

      <div className="section-title">Внешний вид</div>
      <div className="card">
        <div className="toggle-label">Тема оформления</div>
        <div className="toggle-desc" style={{ marginBottom: 14 }}>
          «Как в системе» следует за настройкой Windows и переключается сама, в
          том числе по её расписанию светлой и тёмной темы.
        </div>

        <div className="theme-grid">
          {THEMES.map((theme) => (
            <button
              key={theme.id}
              type="button"
              className={`theme-tile${settings.theme === theme.id ? " on" : ""}`}
              onClick={() => void save({ theme: theme.id })}
            >
              <span className="theme-swatch" style={{ background: theme.preview }} />
              <span className="truncate">{theme.label}</span>
            </button>
          ))}

          <button
            type="button"
            className={`theme-tile${settings.theme === "system" ? " on" : ""}`}
            onClick={() => void save({ theme: "system" })}
          >
            <span
              className="theme-swatch"
              style={{
                background:
                  "linear-gradient(135deg, #0a0c12 0 50%, #eef1f8 50% 100%)",
              }}
            />
            <span className="truncate">Как в системе</span>
          </button>
        </div>
      </div>

      <div className="section-title">Запуск</div>
      <div className="card">
        <ToggleRow
          label="Запускать вместе с Windows"
          desc="Приложение стартует при входе в систему."
          checked={autostart !== "off"}
          onChange={(on) => void changeAutostart(on ? "normal" : "off")}
        />

        {autostart !== "off" && (
          <ToggleRow
            label="Запускать сразу с правами администратора"
            desc={
              elevated
                ? "Создаст задачу в планировщике Windows: приложение будет стартовать с правами администратора и сразу поднимать TUN — без запроса UAC при каждом входе."
                : "Требуется однократный перезапуск с правами администратора, чтобы зарегистрировать задачу в планировщике."
            }
            checked={autostart === "elevated"}
            onChange={(on) => void changeAutostart(on ? "elevated" : "normal")}
          />
        )}

        {autostart === "normal" && (
          <div className="alert" style={{ marginTop: 12 }}>
            <div className="alert-text">
              Обычная автозагрузка не может поднять режим TUN: после входа в
              систему приложение запросит права. Включите переключатель выше,
              чтобы этого не происходило.
            </div>
          </div>
        )}

        <ToggleRow
          label="Подключаться при запуске"
          checked={settings.autoConnect}
          onChange={(autoConnect) => void save({ autoConnect })}
        />
        <ToggleRow
          label="Запускать свёрнутым в трей"
          checked={settings.startMinimized}
          onChange={(startMinimized) => void save({ startMinimized })}
        />
        <ToggleRow
          label="Закрытие окна сворачивает в трей"
          desc="Выключено — крестик полностью завершает работу и разрывает соединение."
          checked={settings.closeToTray}
          onChange={(closeToTray) => void save({ closeToTray })}
        />
      </div>

      <ElevateModal
        open={askElevate}
        reason="autostart"
        onClose={() => setAskElevate(false)}
      />

      <div style={{ height: 20 }} />
    </>
  );
}

export { Settings as SettingsPage };
