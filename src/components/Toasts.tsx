import { AlertCircle, CheckCircle2, Info, X } from "lucide-react";

import { useStore } from "../store";

const ICONS = {
  info: Info,
  success: CheckCircle2,
  error: AlertCircle,
} as const;

const COLORS = {
  info: "var(--text-dim)",
  success: "var(--ok)",
  error: "var(--danger)",
} as const;

export function Toasts() {
  const toasts = useStore((s) => s.toasts);
  const dismiss = useStore((s) => s.dismissToast);

  if (toasts.length === 0) return null;

  return (
    <div className="toasts">
      {toasts.map((toast) => {
        const Icon = ICONS[toast.kind];
        return (
          <div key={toast.id} className={`toast ${toast.kind}`}>
            <Icon size={16} color={COLORS[toast.kind]} style={{ flexShrink: 0, marginTop: 1 }} />
            <div className="grow">
              <div className="toast-text">{toast.text}</div>
              {toast.detail && <div className="toast-detail">{toast.detail}</div>}
            </div>
            <button
              type="button"
              className="btn ghost icon sm"
              onClick={() => dismiss(toast.id)}
            >
              <X size={13} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
