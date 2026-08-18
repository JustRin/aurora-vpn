import { useEffect, useState, type ComponentType } from "react";

import { api } from "./lib/api";

import { Sidebar, type PageId } from "./components/Sidebar";
import { TitleBar } from "./components/TitleBar";
import { Toasts } from "./components/Toasts";
import { Dashboard } from "./pages/Dashboard";
import { Logs } from "./pages/Logs";
import { Routing } from "./pages/Routing";
import { Servers } from "./pages/Servers";
import { SettingsPage } from "./pages/Settings";
import { SplitTunnel } from "./pages/SplitTunnel";
import { useStore } from "./store";

const PAGES: Record<PageId, ComponentType> = {
  dashboard: Dashboard,
  servers: Servers,
  split: SplitTunnel,
  routing: Routing,
  logs: Logs,
  settings: SettingsPage,
};

export default function App() {
  const [page, setPage] = useState<PageId>("dashboard");
  const ready = useStore((s) => s.ready);
  const loadError = useStore((s) => s.loadError);

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
          <div className="splash">Загрузка…</div>
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
                  <div className="alert-title">Не удалось запустить приложение</div>
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
          <Sidebar page={page} onNavigate={setPage} />
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
