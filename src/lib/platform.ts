/**
 * Which OS the WebView runs on, decided once at load. The chrome and the
 * dictionaries branch on it: Windows draws its own title bar and talks about
 * UAC, macOS keeps the native traffic lights and asks for sudo, Linux leaves
 * the frame to the window manager, Android drops the desktop chrome entirely.
 */
export type Platform = "windows" | "macos" | "linux" | "android";

const PLATFORMS: readonly Platform[] = ["windows", "macos", "linux", "android"];

function detect(): Platform {
  // Dev only: `?platform=macos` on the Vite URL previews another OS's layout
  // and wording without booting the app there (see dev.html).
  if (import.meta.env.DEV) {
    const forced = new URLSearchParams(location.search).get("platform");
    if (PLATFORMS.includes(forced as Platform)) return forced as Platform;
  }
  const ua = navigator.userAgent;
  if (/android/i.test(ua)) return "android";
  if (/mac/i.test(navigator.platform) || /Macintosh|Mac OS X/.test(ua)) return "macos";
  if (/win/i.test(navigator.platform) || /Windows/.test(ua)) return "windows";
  return "linux";
}

export const PLATFORM: Platform = detect();

export const IS_ANDROID = PLATFORM === "android";
export const IS_WINDOWS = PLATFORM === "windows";
export const IS_MAC = PLATFORM === "macos";
export const IS_LINUX = PLATFORM === "linux";
/** Desktop Unix: root instead of UAC, `sudo` instead of a relaunch prompt. */
export const IS_UNIX_DESKTOP = IS_MAC || IS_LINUX;

/** The OS as the interface names it («Start with macOS»). */
export const OS_NAME: string = {
  windows: "Windows",
  macos: "macOS",
  linux: "Linux",
  android: "Android",
}[PLATFORM];

/** The engine behind this page, for the resource monitor's row label. */
export const WEBVIEW_ENGINE: string = {
  windows: "WebView2",
  macos: "WebKit",
  linux: "WebKitGTK",
  android: "WebView",
}[PLATFORM];
