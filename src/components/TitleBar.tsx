import { getCurrentWindow } from "@tauri-apps/api/window";
import { Minus, Square, X } from "lucide-react";

import { IS_ANDROID } from "../lib/platform";
import { useStore } from "../store";

const appWindow = getCurrentWindow();

export function TitleBar() {
  const state = useStore((s) => s.status.state);
  const tunnelMode = useStore((s) => s.status.tunnelMode);

  const label =
    state === "connected"
      ? tunnelMode === "tun"
        ? "TUN"
        : "Системный прокси"
      : state === "connecting"
        ? "подключение…"
        : "отключено";

  return (
    <div className="titlebar">
      <div className="titlebar-drag" data-tauri-drag-region>
        <div className="titlebar-title" data-tauri-drag-region>
          Aurora VPN
        </div>
        <div className="titlebar-badge" data-tauri-drag-region>
          {label}
        </div>
      </div>
      {!IS_ANDROID && (
        <div className="win-buttons">
          <button className="win-button" onClick={() => void appWindow.minimize()}>
            <Minus size={15} />
          </button>
          <button
            className="win-button"
            onClick={() => void appWindow.toggleMaximize()}
          >
            <Square size={12} />
          </button>
          <button
            className="win-button close"
            // Closing routes through the Rust side, which decides between hiding
            // to tray and a real shutdown.
            onClick={() => void appWindow.close()}
          >
            <X size={15} />
          </button>
        </div>
      )}
    </div>
  );
}
