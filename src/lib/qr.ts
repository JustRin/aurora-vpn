/**
 * QR codes as an import source.
 *
 * The reading itself happens in Rust — the same detector the native Windows
 * build uses — so this module is only the plumbing: how a picture or a preview
 * frame gets there, and what the page is allowed to ask for on this OS.
 *
 * Pixels travel as a raw IPC body rather than as JSON. A megapixel written out
 * as a list of numbers would cost more to parse than the detection itself.
 */

import { invoke } from "@tauri-apps/api/core";

import { IS_ANDROID } from "./platform";

/**
 * Longest side a preview frame is scaled to before it is sent for decoding.
 * A code close enough to fill a fair part of the frame still spans several
 * pixels per module at this size, while the plane stays under a megabyte —
 * which matters on a phone, where this runs several times a second.
 */
const FRAME_LONG_SIDE = 960;

/**
 * Whether a live camera can be reached from this WebView at all.
 *
 * `mediaDevices` is missing outside a secure context, and Tauri's own page
 * origin is not one everywhere — rather than offering a button that can only
 * fail, the camera is left out where the API is not there.
 */
export const CAMERA_SUPPORTED =
  typeof navigator !== "undefined" &&
  typeof navigator.mediaDevices?.getUserMedia === "function";

/** Reading the desktop is a desktop idea; a phone has the camera instead. */
export const SCREEN_SUPPORTED = !IS_ANDROID;

/** Every code found in an encoded picture: PNG, JPEG, BMP, GIF or WebP. */
export async function scanImageFile(file: File): Promise<string[]> {
  return invoke<string[]>("scan_qr_image", await file.arrayBuffer());
}

/** Every code visible on the desktop. The window steps aside for the shot. */
export function scanScreen(): Promise<string[]> {
  return invoke<string[]>("scan_qr_screen");
}

/**
 * Every code in the frame the preview is showing right now, or `null` while
 * the camera has not produced one yet.
 */
export async function scanVideoFrame(
  video: HTMLVideoElement,
  canvas: HTMLCanvasElement,
): Promise<string[] | null> {
  const frame = takeFrame(video, canvas);
  if (!frame) return null;
  return invoke<string[]>("scan_qr_frame", frame);
}

/**
 * The current video frame as the backend wants it: width and height as
 * little-endian `u32`, then one luminance byte per pixel.
 */
function takeFrame(
  video: HTMLVideoElement,
  canvas: HTMLCanvasElement,
): Uint8Array | null {
  const sourceWidth = video.videoWidth;
  const sourceHeight = video.videoHeight;
  if (!sourceWidth || !sourceHeight) return null;

  const scale = Math.min(1, FRAME_LONG_SIDE / Math.max(sourceWidth, sourceHeight));
  const width = Math.max(1, Math.round(sourceWidth * scale));
  const height = Math.max(1, Math.round(sourceHeight * scale));
  canvas.width = width;
  canvas.height = height;

  // `willReadFrequently` keeps the canvas on the CPU: every frame is read back,
  // and a GPU-backed one pays a full pipeline flush for each of those reads.
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) return null;
  context.drawImage(video, 0, 0, width, height);
  const { data } = context.getImageData(0, 0, width, height);

  const frame = new Uint8Array(8 + width * height);
  const header = new DataView(frame.buffer, 0, 8);
  header.setUint32(0, width, true);
  header.setUint32(4, height, true);
  // BT.601 luma in integer arithmetic, matching `qr::luma_from_pixels`.
  for (let source = 0, target = 8; source < data.length; source += 4, target += 1) {
    frame[target] =
      (77 * data[source] + 150 * data[source + 1] + 29 * data[source + 2]) >> 8;
  }
  return frame;
}
