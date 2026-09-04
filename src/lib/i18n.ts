/**
 * Dictionary-based i18n, deliberately tiny: a flat key → string map per
 * language, a hook that re-renders on language change, and `{var}`
 * interpolation. Russian is the reference dictionary — every other one is
 * type-checked against it, so a missing translation is a compile error.
 *
 * The choice (`system` or one of `LANGS`) lives in Settings and is persisted by
 * the backend; `system` follows the WebView locale.
 */

import { useStore } from "../store";
import { ar } from "./locales/ar";
import { en } from "./locales/en";
import { ja } from "./locales/ja";
import { ko } from "./locales/ko";
import { pt } from "./locales/pt";
import { ru } from "./locales/ru";
import { zh } from "./locales/zh";
import { PLATFORM, type Platform } from "./platform";

/** Every shipped language, in the order the settings picker shows them. */
export const LANGS = ["ru", "en", "zh", "ja", "ko", "ar", "pt"] as const;

export type Lang = (typeof LANGS)[number];
export type LangChoice = "system" | Lang;
export type MsgKey = keyof typeof ru;

const DICTS: Record<Lang, Record<MsgKey, string>> = { ru, en, zh, ja, ko, ar, pt };

/** Endonyms for the picker: a language is named in its own script. */
export const LANG_NAMES: Record<Lang, string> = {
  ru: "Русский",
  en: "English",
  zh: "简体中文",
  ja: "日本語",
  ko: "한국어",
  ar: "العربية",
  pt: "Português",
};

/** The only right-to-left language so far; drives `dir` on <html>. */
const RTL: ReadonlySet<Lang> = new Set<Lang>(["ar"]);

export function isRtl(lang: Lang): boolean {
  return RTL.has(lang);
}

/**
 * BCP-47 tags for `Intl`. The dictionaries are keyed by the bare subtag, but
 * Chinese needs the script to pick Simplified rules.
 */
const INTL_TAG: Record<Lang, string> = {
  ru: "ru",
  en: "en",
  zh: "zh-Hans",
  ja: "ja",
  ko: "ko",
  ar: "ar",
  pt: "pt",
};

export function intlTag(lang: Lang): string {
  return INTL_TAG[lang];
}

/**
 * WebView locale → shipped language. `navigator.language` hands out full tags
 * ("pt-BR", "zh-Hans-CN"), so the match runs on the primary subtag alone.
 */
function systemLang(): Lang {
  const tags = navigator.languages?.length ? navigator.languages : [navigator.language ?? ""];
  for (const tag of tags) {
    const primary = String(tag).toLowerCase().split("-")[0];
    const hit = LANGS.find((lang) => lang === primary);
    if (hit) return hit;
  }
  return "en";
}

export function resolveLang(choice: LangChoice): Lang {
  return choice === "system" ? systemLang() : choice;
}

function format(
  lang: Lang,
  key: MsgKey,
  vars?: Record<string, string | number>,
): string {
  let text = DICTS[lang][key] ?? DICTS.ru[key] ?? key;
  if (vars) {
    for (const [name, value] of Object.entries(vars)) {
      text = text.replaceAll(`{${name}}`, String(value));
    }
  }
  return text;
}

/**
 * Wording that depends on the OS. The bare key carries the Windows text (the
 * original audience); `key.mac`, `key.linux`, `key.unix` and `key.android`
 * next to it override it where the mechanism differs — root instead of UAC,
 * the menu bar instead of the tray. The most specific variant the reference
 * dictionary defines wins, so a language cannot miss one: every dictionary is
 * type-checked against the Russian key set.
 */
const OS_VARIANTS: Record<Platform, readonly string[]> = {
  windows: [],
  macos: ["mac", "unix"],
  linux: ["linux", "unix"],
  android: ["android"],
};

export function osKey(key: MsgKey): MsgKey {
  for (const suffix of OS_VARIANTS[PLATFORM]) {
    const candidate = `${key}.${suffix}`;
    if (candidate in ru) return candidate as MsgKey;
  }
  return key;
}

/** Current resolved language, for the rare places that branch on it. */
export function useLang(): Lang {
  const choice = useStore((s) => s.settings.language ?? "system");
  return resolveLang(choice as LangChoice);
}

/** The translator hook: `const t = useT(); t("dashboard.connect")`. */
export function useT() {
  const choice = useStore((s) => s.settings.language ?? "system");
  const lang = resolveLang(choice as LangChoice);
  return (key: MsgKey, vars?: Record<string, string | number>) =>
    format(lang, key, vars);
}

/** For code outside React (store actions, timers). Reads the store directly. */
export function tNow(key: MsgKey, vars?: Record<string, string | number>): string {
  const choice = (useStore.getState().settings.language ??
    "system") as LangChoice;
  return format(resolveLang(choice), key, vars);
}

/** Same, for the formatters that need the language itself rather than a string. */
export function langNow(): Lang {
  const choice = (useStore.getState().settings.language ??
    "system") as LangChoice;
  return resolveLang(choice);
}
