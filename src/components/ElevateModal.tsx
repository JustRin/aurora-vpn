import { Modal } from "./ui";
import { api, errText } from "../lib/api";
import { useT } from "../lib/i18n";
import { useStore } from "../store";

/**
 * Offers to relaunch through UAC. Shown from two places: connecting in TUN mode
 * without rights, and registering elevated autostart (which writes a scheduled
 * task and therefore needs them once).
 */
export function ElevateModal({
  open,
  onClose,
  reason,
}: {
  open: boolean;
  onClose: () => void;
  reason: "tunnel" | "autostart";
}) {
  const t = useT();
  const toast = useStore((s) => s.toast);

  async function relaunch() {
    try {
      await api.relaunchElevated();
    } catch (e) {
      toast("error", t("elev.relaunchFailed"), errText(e));
      onClose();
    }
  }

  return (
    <Modal
      open={open}
      title={t("elev.title")}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={onClose}>
            {t("elev.cancel")}
          </button>
          <button
            type="button"
            className="btn primary"
            onClick={() => void relaunch()}
          >
            {t("elev.restart")}
          </button>
        </>
      }
    >
      {reason === "tunnel" ? (
        <>
          <p style={{ margin: 0, color: "var(--text-dim)", fontSize: 13 }}>
            {t("elev.tunnelWhy")}
          </p>
          <p style={{ margin: 0, color: "var(--text-muted)", fontSize: 12.5 }}>
            {t("elev.tunnelAlt")}
          </p>
        </>
      ) : (
        <>
          <p style={{ margin: 0, color: "var(--text-dim)", fontSize: 13 }}>
            {t("elev.autostartWhy")}
          </p>
          <p style={{ margin: 0, color: "var(--text-muted)", fontSize: 12.5 }}>
            {t("elev.autostartOnce")}
          </p>
        </>
      )}
    </Modal>
  );
}
