import {
  Camera,
  Image as ImageIcon,
  Maximize2,
  Minimize2,
  Monitor,
  ScanLine,
  SwitchCamera,
  X,
} from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import { api, errText } from "../lib/api";
import { useT } from "../lib/i18n";
import {
  CAMERA_SUPPORTED,
  SCREEN_SUPPORTED,
  scanImageFile,
  scanScreen,
  scanVideoFrame,
} from "../lib/qr";
import { useStore } from "../store";

/**
 * How often the preview is read. Four times a second is faster than a hand can
 * steady a phone over a code, and it leaves the frames in between to the
 * WebView — a tighter loop only makes the picture stutter.
 */
const SCAN_INTERVAL_MS = 250;

/** How long the scanning bar keeps «no code found» before the hint returns. */
const EMPTY_NOTICE_MS = 3000;

/** Why the camera did not open. Kept as a code, not a sentence, so switching
 *  language re-renders the message instead of restarting the camera. */
type CameraError = "" | "denied" | "missing" | "failed";

/**
 * The three ways a code reaches the import box.
 *
 * Rendered as a bare group of buttons rather than a row of its own: it shares
 * one row with «Paste», and that button belongs to the box, not to the scanner.
 *
 * Whatever is found is handed back as text and lands in the same box a link
 * would be pasted into: a code carrying a share link, a subscription URL or a
 * base64 blob needs no special case, and the user sees what was read before
 * anything is imported.
 */
export function QrSources({ onFound }: { onFound: (texts: string[]) => void }) {
  const t = useT();
  const toast = useStore((s) => s.toast);
  const [busy, setBusy] = useState(false);
  const [camera, setCamera] = useState(false);
  const [screenMode, setScreenMode] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  function report(found: string[]): boolean {
    if (found.length === 0) {
      toast("info", t("qr.nothing"));
      return false;
    }
    onFound(found);
    toast(
      "success",
      found.length === 1 ? t("qr.foundOne") : t("qr.foundMany", { n: found.length }),
    );
    return true;
  }

  /**
   * Not a single shot: the window shrinks into a bar above every other window,
   * and the shot waits for its button. The code has to be found first — opened
   * in a browser, scrolled to in a chat — and until then there is nothing on
   * screen worth photographing.
   */
  async function fromScreen() {
    setBusy(true);
    try {
      await api.setScreenScan(true);
      setScreenMode(true);
    } catch (e) {
      toast("error", t("qr.screenFailed"), errText(e));
    } finally {
      setBusy(false);
    }
  }

  async function fromFile(file: File | undefined) {
    if (!file) return;
    setBusy(true);
    try {
      report(await scanImageFile(file));
    } catch (e) {
      toast("error", t("qr.fileFailed"), errText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <span className="qr-sources-label">
        <ScanLine size={14} />
        {t("qr.scan")}
      </span>
      {SCREEN_SUPPORTED && (
        <button
          type="button"
          className="btn sm"
          disabled={busy}
          onClick={() => void fromScreen()}
        >
          <Monitor size={14} />
          {t("qr.screen")}
        </button>
      )}
      <button
        type="button"
        className="btn sm"
        disabled={busy}
        onClick={() => fileRef.current?.click()}
      >
        <ImageIcon size={14} />
        {t("qr.file")}
      </button>
      {CAMERA_SUPPORTED && (
        <button
          type="button"
          className="btn sm"
          disabled={busy}
          onClick={() => setCamera(true)}
        >
          <Camera size={14} />
          {t("qr.camera")}
        </button>
      )}

      {/* The picker is the platform's own: on Android that is the gallery, and
          `accept` keeps it to pictures without pulling in the camera app. */}
      <input
        ref={fileRef}
        type="file"
        accept="image/*"
        hidden
        onChange={(e) => {
          void fromFile(e.target.files?.[0]);
          // Cleared so picking the same file twice fires `change` again.
          e.target.value = "";
        }}
      />

      {camera && (
        <CameraScanner
          onClose={() => setCamera(false)}
          onFound={(found) => {
            setCamera(false);
            report(found);
          }}
        />
      )}

      {screenMode && (
        <ScanBar
          onClose={() => setScreenMode(false)}
          onFound={(found) => {
            setScreenMode(false);
            report(found);
          }}
        />
      )}
    </>
  );
}

/**
 * The bar the window becomes while «scan from the screen» is on: a scan button,
 * a line that doubles as the hint and as the verdict, and a way out.
 *
 * It fills the window, because in this mode the window is 270×80 — everything
 * else the page has drawn is behind it and out of sight.
 */
function ScanBar({
  onFound,
  onClose,
}: {
  onFound: (texts: string[]) => void;
  onClose: () => void;
}) {
  const t = useT();
  const [busy, setBusy] = useState(false);
  const [empty, setEmpty] = useState(false);
  const [failure, setFailure] = useState("");

  // However the bar goes away — the button, a code found, the import dialog
  // closing under it — the window has to come back to the size it was.
  //
  // The interface itself is taken out of the flow rather than unmounted: at
  // 270x80 its own minimum widths would push the document wider than the
  // window, and the import box behind the bar has to keep whatever is in it.
  useEffect(() => {
    document.documentElement.dataset.scan = "on";
    return () => {
      delete document.documentElement.dataset.scan;
      void api.setScreenScan(false);
    };
  }, []);

  // «Nothing found» steps aside on its own, so it cannot be read as the verdict
  // on the next attempt.
  useEffect(() => {
    if (!empty) return;
    const timer = window.setTimeout(() => setEmpty(false), EMPTY_NOTICE_MS);
    return () => window.clearTimeout(timer);
  }, [empty]);

  async function shoot() {
    setBusy(true);
    setEmpty(false);
    setFailure("");
    try {
      const found = await scanScreen();
      // Nothing found keeps the mode: the code is probably not open yet, and
      // trying again has to be one button away.
      if (found.length === 0) setEmpty(true);
      else onFound(found);
    } catch (e) {
      setFailure(errText(e));
    } finally {
      setBusy(false);
    }
  }

  const notice = failure || (empty ? t("qr.nothing") : t("qr.overlayHint"));

  return createPortal(
    // Draggable by its own background: the bar can easily come to rest on top
    // of the very code it is pointed at.
    <div className="scan-bar" data-tauri-drag-region>
      <div className="scan-bar-row" data-tauri-drag-region>
        <button
          type="button"
          className="btn primary sm"
          disabled={busy}
          onClick={() => void shoot()}
        >
          <ScanLine size={14} />
          {t("qr.overlayScan")}
        </button>
        <button
          type="button"
          className="btn ghost icon"
          title={t("srv.cancel")}
          onClick={onClose}
        >
          <X size={15} />
        </button>
      </div>
      <div
        className={failure || empty ? "scan-bar-hint warn" : "scan-bar-hint"}
        data-tauri-drag-region
      >
        {notice}
      </div>
    </div>,
    document.body,
  );
}

/**
 * The live preview. Closes itself the moment a code is read — there is nothing
 * to confirm, and the import box behind it shows what was found.
 */
function CameraScanner({
  onFound,
  onClose,
}: {
  onFound: (texts: string[]) => void;
  onClose: () => void;
}) {
  const t = useT();
  const videoRef = useRef<HTMLVideoElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const [cameras, setCameras] = useState<MediaDeviceInfo[]>([]);
  // The device to open; empty means «whichever faces away from the user»,
  // which is the one pointed at a code on someone else's screen.
  const [wanted, setWanted] = useState("");
  // Which one that turned out to be. Only the running track knows, and it is
  // kept out of state on purpose: assigning it to `wanted` would restart the
  // camera that has just started.
  const activeRef = useRef("");
  const [error, setError] = useState<CameraError>("");
  const [live, setLive] = useState(false);
  const [expanded, setExpanded] = useState(false);

  // Read through a ref so a re-render of the parent cannot restart the loop
  // below, which would drop the frame it is in the middle of decoding.
  const foundRef = useRef(onFound);
  foundRef.current = onFound;

  useEffect(() => {
    let cancelled = false;
    setLive(false);
    setError("");

    async function open() {
      try {
        const video: MediaTrackConstraints = wanted
          ? { deviceId: { exact: wanted } }
          : { facingMode: { ideal: "environment" } };
        // A code fills a small part of the frame; 720p is what makes its
        // modules more than one pixel wide at arm's length.
        video.width = { ideal: 1280 };
        video.height = { ideal: 720 };

        const stream = await navigator.mediaDevices.getUserMedia({ video, audio: false });
        if (cancelled) {
          for (const track of stream.getTracks()) track.stop();
          return;
        }
        streamRef.current = stream;
        activeRef.current = stream.getVideoTracks()[0]?.getSettings().deviceId ?? wanted;
        const element = videoRef.current;
        if (element) {
          element.srcObject = stream;
          // A rejected play() is an autoplay policy, not a broken camera: the
          // preview stays dark, the frames still arrive.
          try {
            await element.play();
          } catch {
            /* ignored */
          }
        }
        if (cancelled) return;
        setLive(true);

        // Device labels exist only once access has been granted, so the list
        // is worth reading after the first stream and not before.
        const all = await navigator.mediaDevices.enumerateDevices();
        if (!cancelled) setCameras(all.filter((device) => device.kind === "videoinput"));
      } catch (e) {
        if (cancelled) return;
        const name = e instanceof Error ? e.name : "";
        setError(
          name === "NotAllowedError" || name === "SecurityError"
            ? "denied"
            : name === "NotFoundError" || name === "OverconstrainedError"
              ? "missing"
              : "failed",
        );
      }
    }
    void open();

    return () => {
      cancelled = true;
      const stream = streamRef.current;
      streamRef.current = null;
      // Every track has to be stopped by hand, or the camera indicator stays
      // lit for as long as the app runs.
      if (stream) for (const track of stream.getTracks()) track.stop();
      if (videoRef.current) videoRef.current.srcObject = null;
    };
  }, [wanted]);

  useEffect(() => {
    if (!live) return;
    let stopped = false;
    let decoding = false;

    const timer = window.setInterval(() => {
      if (stopped || decoding) return;
      const video = videoRef.current;
      const canvas = canvasRef.current;
      if (!video || !canvas) return;
      decoding = true;
      void scanVideoFrame(video, canvas)
        .then((found) => {
          if (stopped || !found || found.length === 0) return;
          stopped = true;
          foundRef.current(found);
        })
        // A frame that failed to decode is the normal case, not an error.
        .catch(() => {})
        .finally(() => {
          decoding = false;
        });
    }, SCAN_INTERVAL_MS);

    return () => {
      stopped = true;
      window.clearInterval(timer);
    };
  }, [live]);

  function nextCamera() {
    if (cameras.length < 2) return;
    const at = cameras.findIndex((device) => device.deviceId === activeRef.current);
    setWanted(cameras[(at + 1) % cameras.length].deviceId);
  }

  const message =
    error === "denied"
      ? t("qr.denied")
      : error === "missing"
        ? t("qr.noCamera")
        : error === "failed"
          ? t("qr.cameraFailed")
          : live
            ? ""
            : t("qr.starting");

  // Portalled to the body: the preview is opened from inside the import
  // dialog, and that dialog carries a `backdrop-filter` — which makes it the
  // containing block for every `position: fixed` descendant, so an overlay
  // left in place would be trapped inside the dialog instead of covering the
  // window it is meant to cover.
  return createPortal(
    <div
      className="modal-backdrop qr-cam-backdrop"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div className={expanded ? "qr-cam expanded" : "qr-cam"}>
        <div className="modal-head">
          <div className="modal-title">{t("qr.title")}</div>
          <div className="row">
            {cameras.length > 1 && (
              <button
                type="button"
                className="btn ghost icon"
                title={t("qr.switch")}
                onClick={nextCamera}
              >
                <SwitchCamera size={16} />
              </button>
            )}
            <button
              type="button"
              className="btn ghost icon"
              title={expanded ? t("qr.collapse") : t("qr.expand")}
              onClick={() => setExpanded(!expanded)}
            >
              {expanded ? <Minimize2 size={16} /> : <Maximize2 size={16} />}
            </button>
            <button type="button" className="btn ghost icon" onClick={onClose}>
              <X size={16} />
            </button>
          </div>
        </div>

        <div className="qr-cam-view">
          <video ref={videoRef} playsInline muted autoPlay />
          {/* The corner brackets are the only aiming aid there is; a code has
              to sit inside them for its modules to survive the downscale. */}
          {live && !error && <span className="qr-cam-target" aria-hidden="true" />}
          {message && <div className="qr-cam-message">{message}</div>}
        </div>

        <div className="qr-cam-foot">{!error && t("qr.hint")}</div>
        <canvas ref={canvasRef} hidden />
      </div>
    </div>,
    document.body,
  );
}
