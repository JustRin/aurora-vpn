import { api } from "./api";
import { paletteFor } from "./themes";
import type { ThemeChoice } from "./types";

const SYSTEM_QUERY = "(prefers-color-scheme: light)";

/**
 * Paint the page and the native window frame in one go.
 *
 * The Rust side stores the resolved colour as the window's pre-render
 * background, so the next launch opens on the right shade instead of flashing
 * the previous palette.
 */
export function applyTheme(choice: ThemeChoice): void {
  const palette = paletteFor(choice);
  document.documentElement.dataset.theme = palette.id;
  void api.setWindowTheme(palette.dark, palette.background);
}

/**
 * Follow the OS while the user is on "system". Registered once for the lifetime
 * of the app; `getChoice` is read at event time so it always sees the current
 * preference.
 */
export function watchSystemTheme(getChoice: () => ThemeChoice): void {
  const media = window.matchMedia(SYSTEM_QUERY);
  media.addEventListener("change", () => {
    if (getChoice() === "system") applyTheme("system");
  });
}
