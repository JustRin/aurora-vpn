import { useState } from "react";

import { Modal } from "./ui";
import { api, errText } from "../lib/api";
import { osKey, useT } from "../lib/i18n";
import { IS_MAC, IS_UNIX_DESKTOP, OS_NAME } from "../lib/platform";
import { useStore } from "../store";

/**
 * What to do about missing rights. On Windows it offers to relaunch through
 * UAC, from two places: connecting in TUN mode without rights, and registering
 * elevated autostart (a scheduled task, which needs them once). On macOS the
 * app itself stays unprivileged and the core gets root instead — one system
 * password dialog, after which TUN works on every launch (`onGranted` lets the
 * caller retry what it was doing). On Linux nothing can raise a running
 * process, so the dialog shows the `sudo` command to start the app with.
 */
export function ElevateModal({
  open,
  onClose,
  reason,
  onGranted,
}: {
  open: boolean;
  onClose: () => void;
  reason: "tunnel" | "autostart";
  onGranted?: () => void;
}) {
  const t = useT();
  const toast = useStore((s) => s.toast);
  const rootCommand = useStore((s) => s.rootCommand);
  const [busy, setBusy] = useState(false);

  async function relaunch() {
    try {
      await api.relaunchElevated();
    } catch (e) {
      toast("error", t("elev.relaunchFailed"), errText(e));
      onClose();
    }
  }

  async function grant() {
    setBusy(true);
    try {
      await api.grantCoreRoot();
      toast("success", t("elev.granted"));
      onClose();
      onGranted?.();
    } catch (e) {
      toast("error", t("elev.grantFailed"), errText(e));
    } finally {
      setBusy(false);
    }
  }

  async function copyCommand() {
    try {
      await navigator.clipboard.writeText(rootCommand);
      toast("success", t("elev.copied"));
    } catch {
      // The command stays selectable in the dialog, so the fallback is manual.
      toast("error", t("elev.copyFailed"));
    }
  }

  if (IS_UNIX_DESKTOP) {
    return (
      <Modal
        open={open}
        title={t(osKey("elev.title"))}
        onClose={onClose}
        footer={
          IS_MAC ? (
            <>
              <button type="button" className="btn" onClick={() => void copyCommand()}>
                {t("elev.copy")}
              </button>
              <button
                type="button"
                className="btn primary"
                disabled={busy}
                onClick={() => void grant()}
              >
                {t("elev.grant")}
              </button>
            </>
          ) : (
            <>
              <button type="button" className="btn" onClick={onClose}>
                {t("elev.close")}
              </button>
              <button
                type="button"
                className="btn primary"
                onClick={() => void copyCommand()}
              >
                {t("elev.copy")}
              </button>
            </>
          )
        }
      >
        <p style={{ margin: 0, color: "var(--text-dim)", fontSize: 13 }}>
          {t(osKey("elev.tunnelWhy"), { os: OS_NAME })}
        </p>
        {IS_MAC && (
          <p style={{ margin: 0, color: "var(--text-muted)", fontSize: 12.5 }}>
            {t("elev.altTerminal")}
          </p>
        )}
        <code className="mono cmd">{rootCommand}</code>
      </Modal>
    );
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
