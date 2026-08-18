import type { MsgKey } from "./i18n";
import type { ThemeChoice } from "./types";

export interface ThemeDef {
  id: Exclude<ThemeChoice, "system">;
  labelKey: MsgKey;
  /** Drives the native window frame and the pre-render background. */
  dark: boolean;
  /** Must equal the palette's `--bg`; used before the WebView paints. */
  background: string;
  /** Miniature of the palette's ambience, used as the picker swatch. */
  preview: string;
}

/** Build a swatch that mirrors what the ambient layer actually renders. */
function preview(surface: string, glowA: string, glowB: string): string {
  return [
    `radial-gradient(circle at 22% 20%, ${glowA}, transparent 58%)`,
    `radial-gradient(circle at 82% 78%, ${glowB}, transparent 58%)`,
    surface,
  ].join(", ");
}

/** Keep in sync with the `[data-theme=...]` blocks in `styles.css`. */
export const THEMES: ThemeDef[] = [
  {
    id: "dark",
    labelKey: "theme.dark",
    dark: true,
    background: "#0a0c12",
    preview: preview("#0a0c12", "#7c3aedcc", "#22d3ee99"),
  },
  {
    id: "midnight",
    labelKey: "theme.midnight",
    dark: true,
    background: "#050813",
    preview: preview("#050813", "#4f6bffcc", "#38bdf899"),
  },
  {
    id: "crimson",
    labelKey: "theme.crimson",
    dark: true,
    background: "#0f080a",
    preview: preview("#0f080a", "#d01838cc", "#fb923c99"),
  },
  {
    id: "emerald",
    labelKey: "theme.emerald",
    dark: true,
    background: "#040f0b",
    preview: preview("#040f0b", "#0f9b6ccc", "#22d3ee99"),
  },
  {
    id: "swamp",
    labelKey: "theme.swamp",
    dark: true,
    background: "#0e1005",
    preview: preview("#0e1005", "#76861fdd", "#9ccc6599"),
  },
  {
    id: "light",
    labelKey: "theme.light",
    dark: false,
    background: "#eef1f8",
    preview: preview("#eef1f8", "#7c3aed66", "#0ea5e955"),
  },
];

const BY_ID = new Map(THEMES.map((theme) => [theme.id, theme]));

/** Which concrete palette "system" currently means. */
export function systemPalette(): ThemeDef {
  const light = window.matchMedia("(prefers-color-scheme: light)").matches;
  return BY_ID.get(light ? "light" : "dark")!;
}

/** Resolve any choice — including `system` — to a concrete palette. */
export function paletteFor(choice: ThemeChoice): ThemeDef {
  if (choice === "system") return systemPalette();
  return BY_ID.get(choice) ?? BY_ID.get("dark")!;
}
