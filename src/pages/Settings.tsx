import { FolderOpen } from "lucide-react";
import { useState } from "react";

import { ElevateModal } from "../components/ElevateModal";
import { Field, Segmented, ToggleRow } from "../components/ui";
import { api, errText } from "../lib/api";
import { useT } from "../lib/i18n";
import { IS_ANDROID } from "../lib/platform";
import { THEMES } from "../lib/themes";
import {
  ELEVATION_REQUIRED,
  type AutostartMode,
  type LangChoice,
  type TunStack,
  type TunnelMode,
} from "../lib/types";
import { useStore } from "../store";

/** The two decks of the page: everything sing-box (tunnel, DNS, ports,
 * subscriptions) versus everything client-side (language, theme, startup,
 * about) — one flat page held all of it and finding anything took scrolling. */
type SettingsTab = "core" | "client";

export function Settings() {
  const t = useT();
  const settings = useStore((s) => s.settings);
  const save = useStore((s) => s.saveSettings);
  const elevated = useStore((s) => s.status.elevated);
  const autostart = useStore((s) => s.autostart);
  const setAutostart = useStore((s) => s.setAutostart);
  const toast = useStore((s) => s.toast);
  const appVersion = useStore((s) => s.appVersion);
  const coreVersion = useStore((s) => s.coreVersion);

  const [askElevate, setAskElevate] = useState(false);
  const [tab, setTab] = useState<SettingsTab>("core");

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
      toast("error", t("set.autostartFailed"), text);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1 className="page-title">{t("set.title")}</h1>
          <p className="page-sub">{t("set.subtitle")}</p>
        </div>
        {!IS_ANDROID && (
          <button
            type="button"
            className="btn"
            onClick={() => void api.openConfigDir()}
          >
            <FolderOpen size={15} />
            {t("set.dataFolder")}
          </button>
        )}
      </div>

      <div>
        <Segmented<SettingsTab>
          value={tab}
          onChange={setTab}
          options={[
            { value: "core", label: t("set.tabCore") },
            { value: "client", label: t("set.tabClient") },
          ]}
        />
      </div>

      {tab === "core" && (
        <>
          {/* Android has exactly one tunnel — VpnService; there is nothing to choose. */}
          {!IS_ANDROID && (
            <>
              <div className="section-title">{t("set.tunnelSection")}</div>
              <div className="card">
                <div className="toggle-row">
                  <div className="grow">
                    <div className="toggle-label">{t("set.tunnelMode")}</div>
                    <div className="toggle-desc">
                      {settings.tunnelMode === "tun"
                        ? t("set.tunnelModeTunDesc")
                        : t("set.tunnelModeProxyDesc")}
                    </div>
                  </div>
                  <Segmented<TunnelMode>
                    value={settings.tunnelMode}
                    onChange={(tunnelMode) => void save({ tunnelMode })}
                    options={[
                      { value: "tun", label: "TUN" },
                      { value: "systemProxy", label: t("set.systemProxy") },
                    ]}
                  />
                </div>

                {settings.tunnelMode === "tun" && !elevated && (
                  <div className="alert" style={{ marginTop: 12 }}>
                    <div className="alert-text">{t("set.tunNeedsAdmin")}</div>
                  </div>
                )}
              </div>
            </>
          )}

          {(IS_ANDROID || settings.tunnelMode === "tun") && (
            <>
              <div className="section-title">{t("set.tunSection")}</div>
              <div className="card">
                <div className="grid-2">
                  <Field label={t("set.tunStack")} hint={t("set.tunStackHint")}>
                    <select
                      className="select"
                      value={settings.tunStack}
                      onChange={(e) =>
                        void save({ tunStack: e.target.value as TunStack })
                      }
                    >
                      <option value="mixed">{t("set.tunStackMixed")}</option>
                      <option value="system">system</option>
                      <option value="gvisor">gvisor</option>
                    </select>
                  </Field>
                  <Field label="MTU" hint={t("set.mtuHint")}>
                    <input
                      className="input"
                      type="number"
                      defaultValue={settings.tunMtu}
                      onBlur={(e) =>
                        void save({ tunMtu: Number(e.target.value) || 9000 })
                      }
                    />
                  </Field>
                </div>
                <ToggleRow
                  label={t("set.strictRoute")}
                  desc={t("set.strictRouteDesc")}
                  checked={settings.strictRoute}
                  onChange={(strictRoute) => void save({ strictRoute })}
                />
                <ToggleRow
                  label={t("set.ipv6")}
                  desc={t("set.ipv6Desc")}
                  checked={settings.ipv6}
                  onChange={(ipv6) => void save({ ipv6 })}
                />
                <ToggleRow
                  label="Fake-IP"
                  desc={t("set.fakeIpDesc")}
                  checked={settings.fakeIp}
                  onChange={(fakeIp) => void save({ fakeIp })}
                />
              </div>
            </>
          )}

          <div className="section-title">DNS</div>
          <div className="card">
            <div className="grid-2">
              <Field label={t("set.dnsRemote")} hint={t("set.dnsRemoteHint")}>
                <input
                  className="input mono"
                  defaultValue={settings.dnsRemote}
                  onBlur={(e) => void save({ dnsRemote: e.target.value.trim() })}
                />
              </Field>
              <Field label={t("set.dnsDirect")} hint={t("set.dnsDirectHint")}>
                <input
                  className="input mono"
                  defaultValue={settings.dnsDirect}
                  onBlur={(e) => void save({ dnsDirect: e.target.value.trim() })}
                />
              </Field>
            </div>
          </div>

          <div className="section-title">{t("set.connSection")}</div>
          <div className="card">
            <div className="grid-2">
              <Field label={t("set.mixedPort")} hint={t("set.mixedPortHint")}>
                <input
                  className="input"
                  type="number"
                  defaultValue={settings.mixedPort}
                  onBlur={(e) =>
                    void save({ mixedPort: Number(e.target.value) || 2080 })
                  }
                />
              </Field>
              <Field label={t("set.clashPort")} hint={t("set.clashPortHint")}>
                <input
                  className="input"
                  type="number"
                  defaultValue={settings.clashPort}
                  onBlur={(e) =>
                    void save({ clashPort: Number(e.target.value) || 9191 })
                  }
                />
              </Field>
              <Field label={t("set.latencyUrl")} hint={t("set.latencyUrlHint")}>
                <input
                  className="input mono"
                  defaultValue={settings.latencyUrl}
                  onBlur={(e) => void save({ latencyUrl: e.target.value.trim() })}
                />
              </Field>
              <Field label={t("set.logLevel")}>
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
              label={t("set.allowLan")}
              desc={t("set.allowLanDesc")}
              checked={settings.allowLan}
              onChange={(allowLan) => void save({ allowLan })}
            />
            <ToggleRow
              label={t("set.autoSelect")}
              desc={t("set.autoSelectDesc")}
              checked={settings.autoSelect}
              onChange={(autoSelect) => void save({ autoSelect })}
            />
          </div>

          <div className="section-title">{t("set.subsSection")}</div>
          <div className="card">
            <div className="toggle-row">
              <div className="grow">
                <div className="toggle-label">{t("set.subAuto")}</div>
                <div className="toggle-desc">{t("set.subAutoDesc")}</div>
              </div>
              <select
                className="select"
                style={{ width: 190 }}
                value={String(settings.subAutoUpdateMin)}
                onChange={(e) =>
                  void save({ subAutoUpdateMin: Number(e.target.value) })
                }
              >
                <option value="0">{t("set.subEveryOff")}</option>
                <option value="180">{t("set.subEvery3h")}</option>
                <option value="360">{t("set.subEvery6h")}</option>
                <option value="720">{t("set.subEvery12h")}</option>
                <option value="1440">{t("set.subEveryDay")}</option>
              </select>
            </div>
          </div>
        </>
      )}

      {tab === "client" && (
        <>
          <div className="section-title">{t("set.languageSection")}</div>
          <div className="card">
            <div className="toggle-row">
              <div className="grow">
                <div className="toggle-label">{t("set.language")}</div>
                <div className="toggle-desc">{t("set.languageDesc")}</div>
              </div>
              <Segmented<LangChoice>
                value={settings.language ?? "system"}
                onChange={(language) => void save({ language })}
                options={[
                  { value: "system", label: t("set.langSystem") },
                  { value: "ru", label: "Русский" },
                  { value: "en", label: "English" },
                ]}
              />
            </div>
          </div>

          <div className="section-title">{t("set.themeSection")}</div>
          <div className="card">
            <div className="toggle-label">{t("set.theme")}</div>
            <div className="toggle-desc" style={{ marginBottom: 14 }}>
              {t("set.themeDesc")}
            </div>

            <div className="theme-grid">
              {THEMES.map((theme) => (
                <button
                  key={theme.id}
                  type="button"
                  className={`theme-tile${settings.theme === theme.id ? " on" : ""}`}
                  onClick={() => void save({ theme: theme.id })}
                >
                  <span
                    className="theme-swatch"
                    style={{ background: theme.preview }}
                  />
                  <span className="truncate">{t(theme.labelKey)}</span>
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
                <span className="truncate">{t("theme.system")}</span>
              </button>
            </div>
          </div>

          <div className="section-title">{t("set.startupSection")}</div>
          <div className="card">
            {!IS_ANDROID && (
              <>
                <ToggleRow
                  label={t("set.autostart")}
                  desc={t("set.autostartDesc")}
                  checked={autostart !== "off"}
                  onChange={(on) => void changeAutostart(on ? "normal" : "off")}
                />

                {autostart !== "off" && (
                  <ToggleRow
                    label={t("set.autostartElevated")}
                    desc={
                      elevated
                        ? t("set.autostartElevatedDesc")
                        : t("set.autostartElevatedNeedsAdmin")
                    }
                    checked={autostart === "elevated"}
                    onChange={(on) =>
                      void changeAutostart(on ? "elevated" : "normal")
                    }
                  />
                )}

                {autostart === "normal" && (
                  <div className="alert" style={{ marginTop: 12 }}>
                    <div className="alert-text">{t("set.autostartNormalWarn")}</div>
                  </div>
                )}
              </>
            )}

            <ToggleRow
              label={t("set.autoConnect")}
              checked={settings.autoConnect}
              onChange={(autoConnect) => void save({ autoConnect })}
            />
            {!IS_ANDROID && (
              <>
                <ToggleRow
                  label={t("set.startMinimized")}
                  checked={settings.startMinimized}
                  onChange={(startMinimized) => void save({ startMinimized })}
                />
                <ToggleRow
                  label={t("set.closeToTray")}
                  desc={t("set.closeToTrayDesc")}
                  checked={settings.closeToTray}
                  onChange={(closeToTray) => void save({ closeToTray })}
                />
              </>
            )}
          </div>

          {/* The sidebar footer with the same numbers is hidden on the phone
              layout, so this card is the only version display on Android. */}
          <div className="section-title">{t("set.aboutSection")}</div>
          <div className="card">
            <div className="toggle-row">
              <div className="grow">
                <div className="toggle-label">{t("set.appVersion")}</div>
              </div>
              <span className="mono">{appVersion || "—"}</span>
            </div>
            <div className="toggle-row">
              <div className="grow">
                <div className="toggle-label">{t("set.coreVersion")}</div>
              </div>
              <span className="mono truncate" title={coreVersion}>
                {coreVersion || t("side.noCore")}
              </span>
            </div>
          </div>
        </>
      )}

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
