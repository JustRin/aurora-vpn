import { useEffect, type ComponentType } from "react";

import { api } from "./lib/api";
import { isRtl, useLang, useT } from "./lib/i18n";

import { Sidebar } from "./components/Sidebar";
import { TitleBar } from "./components/TitleBar";
import { Toasts } from "./components/Toasts";
import { Dashboard } from "./pages/Dashboard";
import { Logs } from "./pages/Logs";
import { Routing } from "./pages/Routing";
import { Servers } from "./pages/Servers";
import { SettingsPage } from "./pages/Settings";
import { SplitTunnel } from "./pages/SplitTunnel";
import { useStore, type PageId } from "./store";

const PAGES: Record<PageId, ComponentType> = {
  dashboard: Dashboard,
  servers: Servers,
  split: SplitTunnel,
  routing: Routing,
  logs: Logs,
  settings: SettingsPage,
};

export default function App() {
  const t = useT();
  const lang = useLang();
  const page = useStore((s) => s.page);
  const navigate = useStore((s) => s.navigate);
  const ready = useStore((s) => s.ready);
  const loadError = useStore((s) => s.loadError);

  // Writing direction follows the language: the stylesheet is built on logical
  // properties, so flipping `dir` mirrors the whole layout on its own.
  useEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = isRtl(lang) ? "rtl" : "ltr";
  }, [lang]);

  // PrintScreen reaches the webview only as a keyup. While the app runs
  // elevated, UIPI hides the key from the unelevated Snipping Tool listener,
  // so the system overlay never opens on its own — relay the press ourselves.
  // Bare PrtScn only: Alt+PrtScn and Win+PrtScn are handled by the OS itself
  // and still work over an elevated window.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "PrintScreen" && !e.altKey && !e.ctrlKey && !e.metaKey) {
        void api.openScreenSnip();
      }
    };
    window.addEventListener("keyup", onKey);
    return () => window.removeEventListener("keyup", onKey);
  }, []);

  // The window is created hidden to avoid a white WebView flash. Reveal it only
  // after the browser has actually painted a frame — two nested rAF callbacks
  // put us safely past the first commit.
  useEffect(() => {
    if (!ready) return;
    let inner = 0;
    const outer = requestAnimationFrame(() => {
      inner = requestAnimationFrame(() => void api.appReady());
    });
    return () => {
      cancelAnimationFrame(outer);
      cancelAnimationFrame(inner);
    };
  }, [ready]);

  if (!ready) {
    return (
      <>
        <Ambient />
        <div className="app">
          <TitleBar />
          <div className="splash">{t("app.loading")}</div>
        </div>
      </>
    );
  }

  if (loadError) {
    return (
      <>
        <Ambient />
        <div className="app">
          <TitleBar />
          <div className="splash">
            <div className="card" style={{ maxWidth: 520 }}>
              <div className="alert danger">
                <div>
                  <div className="alert-title">{t("app.loadFailed")}</div>
                  <div className="alert-text">{loadError}</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </>
    );
  }

  const Page = PAGES[page];

  return (
    <>
      <Ambient />
      <div className="app">
        <TitleBar />
        <div className="body">
          <Sidebar page={page} onNavigate={navigate} />
          <main className="content">
            <Page />
          </main>
        </div>
        <Toasts />
      </div>
    </>
  );
}

/**
 * Drifting light behind the interface. Purely decorative and driven entirely by
 * the palette's `--glow-*` tokens, so it changes with the theme for free.
 */
function Ambient() {
  return <div className="ambient" aria-hidden="true" />;
}
