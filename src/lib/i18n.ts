/**
 * Dictionary-based i18n, deliberately tiny: a flat key → string map per
 * language, a hook that re-renders on language change, and `{var}`
 * interpolation. Russian is the reference dictionary — the English one is
 * type-checked against it, so a missing translation is a compile error.
 *
 * The choice (`system` | `ru` | `en`) lives in Settings and is persisted by
 * the backend; `system` follows the WebView locale.
 */

import { useStore } from "../store";
import { en } from "./locales/en";
import { ru } from "./locales/ru";

export type LangChoice = "system" | "ru" | "en";
export type Lang = "ru" | "en";
export type MsgKey = keyof typeof ru;

const DICTS: Record<Lang, Record<MsgKey, string>> = { ru, en };

export function resolveLang(choice: LangChoice): Lang {
  if (choice === "ru" || choice === "en") return choice;
  return /^ru\b/i.test(navigator.language) ? "ru" : "en";
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
