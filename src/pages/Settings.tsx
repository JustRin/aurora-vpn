import { FolderOpen } from "lucide-react";
import { useEffect, useState } from "react";

import { ElevateModal } from "../components/ElevateModal";
import { Field, Segmented, ToggleRow } from "../components/ui";
import { api, errText } from "../lib/api";
import { bytes } from "../lib/format";
import { LANGS, LANG_NAMES, useT, type MsgKey } from "../lib/i18n";
import { IS_ANDROID } from "../lib/platform";
import { THEMES } from "../lib/themes";
import {
  ELEVATION_REQUIRED,
  type AutostartMode,
  type Balancer,
  type LangChoice,
  type ResourceGroup,
  type TunStack,
  type TunnelMode,
} from "../lib/types";
import { useStore } from "../store";

/** One explanation per strategy, shown under the picker for the chosen one. */
const BALANCER_HELP: Record<Balancer, MsgKey> = {
  manual: "set.balancerManualDesc",
  failover: "set.balancerFailoverDesc",
  fastest: "set.balancerFastestDesc",
  rotate: "set.balancerRotateDesc",
};

/** Sweep periods offered, in minutes, and «fastest» thresholds, in ms. */
const BALANCER_MINUTES = [1, 3, 5, 10, 30];
const BALANCER_TOLERANCE = [50, 100, 200, 300];

/** The two decks of the page: everything sing-box (tunnel, DNS, ports,
 * subscriptions) versus everything client-side (language, theme, startup,
 * about) — one flat page held all of it and finding anything took scrolling. */
type SettingsTab = "core" | "client";

/** Typed against the dictionary so a new backend group cannot silently render
 * as a raw key. */
const RESOURCE_LABELS: Record<ResourceGroup["id"], MsgKey> = {
  app: "set.resApp",
  ui: "set.resUi",
  core: "set.resCore",
  xray: "set.resXray",
};

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
  const [tab, setTab] = useState<SettingsTab>("client");
  const [usage, setUsage] = useState<ResourceGroup[]>([]);

  // Live only while its tab is on screen — no point enumerating the process
  // table for a card nobody is looking at.
  useEffect(() => {
    if (tab !== "client" || IS_ANDROID) return;
    let alive = true;
    const tick = () => {
      api.resourceUsage().then(
        (groups) => {
          if (alive) setUsage(groups);
        },
        () => {},
      );
    };
    tick();
    const timer = setInterval(tick, 2000);
    return () => {
      alive = false;
      clearInterval(timer);
    };
  }, [tab]);

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
            { value: "client", label: t("set.tabClient") },
            { value: "core", label: t("set.tabCore") },
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
                <div className="toggle-row stack">
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
            {/* Who picks the server. The description follows the chosen
                strategy: each one behaves differently enough that a single
                line could not explain them all. */}
            <div className="toggle-row stack">
              <div className="grow">
                <div className="toggle-label">{t("set.balancer")}</div>
                <div className="toggle-desc">{t(BALANCER_HELP[settings.balancer ?? "manual"])}</div>
              </div>
              <select
                className="select"
                value={settings.balancer ?? "manual"}
                onChange={(e) => void save({ balancer: e.target.value as Balancer })}
              >
                <option value="manual">{t("set.balancerManual")}</option>
                <option value="failover">{t("set.balancerFailover")}</option>
                <option value="fastest">{t("set.balancerFastest")}</option>
                <option value="rotate">{t("set.balancerRotate")}</option>
              </select>
            </div>
            {settings.balancer && settings.balancer !== "manual" && (
              <div className="grid-2" style={{ marginTop: 4 }}>
                <Field label={t("set.balancerInterval")} hint={t("set.balancerIntervalHint")}>
                  <select
                    className="select"
                    value={String(settings.balancerIntervalMin)}
                    onChange={(e) =>
                      void save({ balancerIntervalMin: Number(e.target.value) })
                    }
                  >
                    {BALANCER_MINUTES.map((n) => (
                      <option key={n} value={n}>
                        {t("set.everyMin", { n })}
                      </option>
                    ))}
                  </select>
                </Field>
                {/* Only «fastest» compares latencies; the others have no use
                    for a threshold. */}
                {settings.balancer === "fastest" && (
                  <Field label={t("set.balancerTolerance")} hint={t("set.balancerToleranceHint")}>
                    <select
                      className="select"
                      value={String(settings.balancerToleranceMs)}
                      onChange={(e) =>
                        void save({ balancerToleranceMs: Number(e.target.value) })
                      }
                    >
                      {BALANCER_TOLERANCE.map((ms) => (
                        <option key={ms} value={ms}>
                          {t("dash.pingMs", { ping: ms })}
                        </option>
                      ))}
                    </select>
                  </Field>
                )}
              </div>
            )}
          </div>

          <div className="section-title">{t("set.subsSection")}</div>
          <div className="card">
            <div className="toggle-row stack">
              <div className="grow">
                <div className="toggle-label">{t("set.subAuto")}</div>
                <div className="toggle-desc">{t("set.subAutoDesc")}</div>
              </div>
              <select
                className="select"
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
            <div className="toggle-row stack">
              <div className="grow">
                <div className="toggle-label">{t("set.language")}</div>
                <div className="toggle-desc">{t("set.languageDesc")}</div>
              </div>
              {/* A select rather than a segmented track: seven languages plus
                  “follow system” do not fit on one row. */}
              <select
                className="select"
                value={settings.language ?? "system"}
                onChange={(e) =>
                  void save({ language: e.target.value as LangChoice })
                }
              >
                <option value="system">{t("set.langSystem")}</option>
                {LANGS.map((lang) => (
                  <option key={lang} value={lang}>
                    {LANG_NAMES[lang]}
                  </option>
                ))}
              </select>
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

          {usage.length > 0 && (
            <>
              <div className="section-title">{t("set.resourcesSection")}</div>
              <div className="card">
                <div className="toggle-desc" style={{ marginBottom: 4 }}>
                  {t("set.resourcesDesc")}
                </div>
                {usage.map((group) => (
                  <div className="toggle-row" key={group.id}>
                    <div className="grow">
                      <div className="toggle-label">
                        {t(RESOURCE_LABELS[group.id])}
                      </div>
                      {group.processes > 1 && (
                        <div className="toggle-desc">
                          {t("set.resProcs", { n: group.processes })}
                        </div>
                      )}
                    </div>
                    <span className="mono">{group.cpu.toFixed(1)}%</span>
                    <span className="mono" style={{ minWidth: 76, textAlign: "right" }}>
                      {bytes(group.memory)}
                    </span>
                  </div>
                ))}
                <div className="toggle-row">
                  <div className="grow">
                    <div className="toggle-label">{t("set.resTotal")}</div>
                  </div>
                  <span className="mono">
                    {usage.reduce((sum, g) => sum + g.cpu, 0).toFixed(1)}%
                  </span>
                  <span className="mono" style={{ minWidth: 76, textAlign: "right" }}>
                    {bytes(usage.reduce((sum, g) => sum + g.memory, 0))}
                  </span>
                </div>
              </div>
            </>
          )}

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
