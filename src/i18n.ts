// UI texts. The German dictionary is the source; every other one is typed as
// `Record<MessageKey, string>`, so missing or extra keys are type errors.
// Placeholders: `{name}`, identical in all languages (checked by i18n.test.ts).
//
// The languages, their order and the form of address are the same as in Hangar: informal "you"
// wherever software in that language uses it (de, en, es, fr, el, it, pl, pt, ru, tr), otherwise a
// neutral imperative. Japanese and Chinese stay neutrally polite and avoid direct address where
// possible. Portuguese means Brazilian Portuguese (pt-BR).

import { createContext, useContext } from "react";

export type Language =
  "de" | "en" | "el" | "es" | "fr" | "it" | "ja" | "pl" | "pt" | "ru" | "tr" | "zh";

/**
 * Order of the picker: German and English first (source and fallback language), then by
 * language code. Codes sort independently of the script; sorting by native names would have to
 * order Latin, Greek, Cyrillic and CJK scripts against each other and would look random.
 */
export const LANGUAGES: readonly Language[] = [
  "de",
  "en",
  "el",
  "es",
  "fr",
  "it",
  "ja",
  "pl",
  "pt",
  "ru",
  "tr",
  "zh",
];

const de = {
  // The product name; the same in every language, kept here so no text spells it on its own.
  "app.name": "Hangar Drive",
  "empty.title": "Noch nichts synchronisiert",
  "empty.body":
    "{app} ist noch in einer frühen Entwicklungsphase. Deine synchronisierten Ordner erscheinen später hier.",
} as const satisfies Record<string, string>;

export type MessageKey = keyof typeof de;

const en: Record<MessageKey, string> = {
  "app.name": "Hangar Drive",
  "empty.title": "Nothing synced yet",
  "empty.body": "{app} is in early development. Your synced folders will appear here later.",
};

const el: Record<MessageKey, string> = {
  "app.name": "Hangar Drive",
  "empty.title": "Δεν έχει συγχρονιστεί τίποτα ακόμα",
  "empty.body":
    "Το {app} βρίσκεται σε πρώιμο στάδιο ανάπτυξης. Οι συγχρονισμένοι φάκελοί σου θα εμφανιστούν εδώ αργότερα.",
};

const es: Record<MessageKey, string> = {
  "app.name": "Hangar Drive",
  "empty.title": "Aún no hay nada sincronizado",
  "empty.body":
    "{app} está en una fase temprana de desarrollo. Tus carpetas sincronizadas aparecerán aquí más adelante.",
};

const fr: Record<MessageKey, string> = {
  "app.name": "Hangar Drive",
  "empty.title": "Rien n’est encore synchronisé",
  "empty.body":
    "{app} est en tout début de développement. Tes dossiers synchronisés apparaîtront ici plus tard.",
};

const it: Record<MessageKey, string> = {
  "app.name": "Hangar Drive",
  "empty.title": "Ancora nulla di sincronizzato",
  "empty.body":
    "{app} è in una fase iniziale di sviluppo. Le tue cartelle sincronizzate appariranno qui più avanti.",
};

const ja: Record<MessageKey, string> = {
  "app.name": "Hangar Drive",
  "empty.title": "まだ同期されたものはありません",
  "empty.body": "{app} は開発の初期段階です。同期したフォルダーは今後ここに表示されます。",
};

const pl: Record<MessageKey, string> = {
  "app.name": "Hangar Drive",
  "empty.title": "Nic jeszcze nie zsynchronizowano",
  "empty.body":
    "{app} jest na wczesnym etapie rozwoju. Twoje zsynchronizowane foldery pojawią się tu później.",
};

const pt: Record<MessageKey, string> = {
  "app.name": "Hangar Drive",
  "empty.title": "Nada sincronizado ainda",
  "empty.body":
    "{app} está no início do desenvolvimento. Suas pastas sincronizadas vão aparecer aqui mais tarde.",
};

const ru: Record<MessageKey, string> = {
  "app.name": "Hangar Drive",
  "empty.title": "Пока ничего не синхронизировано",
  "empty.body":
    "{app} находится на ранней стадии разработки. Твои синхронизированные папки появятся здесь позже.",
};

const tr: Record<MessageKey, string> = {
  "app.name": "Hangar Drive",
  "empty.title": "Henüz hiçbir şey eşitlenmedi",
  "empty.body":
    "{app} geliştirmenin erken aşamasında. Eşitlenen klasörlerin daha sonra burada görünecek.",
};

const zh: Record<MessageKey, string> = {
  "app.name": "Hangar Drive",
  "empty.title": "尚未同步任何内容",
  "empty.body": "{app} 仍处于早期开发阶段。同步的文件夹以后会显示在这里。",
};

export const DICTIONARIES: Record<Language, Record<MessageKey, string>> = {
  de,
  en,
  el,
  es,
  fr,
  it,
  ja,
  pl,
  pt,
  ru,
  tr,
  zh,
};

/**
 * Native names of the languages, each in its own language and the same in every UI (so you can
 * find your own language).
 */
export const LANGUAGE_NAMES: Record<Language, string> = {
  de: "Deutsch",
  en: "English",
  el: "Ελληνικά",
  es: "Español",
  fr: "Français",
  it: "Italiano",
  ja: "日本語",
  pl: "Polski",
  pt: "Português",
  ru: "Русский",
  tr: "Türkçe",
  zh: "简体中文",
};

export type Params = Readonly<Record<string, string | number>>;
export type Translate = (key: MessageKey, params?: Params) => string;

export function translate(language: Language, key: MessageKey, params?: Params): string {
  const text = DICTIONARIES[language][key];
  if (!params) return text;
  return text.replace(/\{(\w+)\}/g, (match, name: string) => {
    const value = params[name];
    return value === undefined ? match : String(value);
  });
}

export function createTranslator(language: Language): Translate {
  return (key, params) => translate(language, key, params);
}

/**
 * Language from a BCP 47 tag such as `de-AT`, `pt-BR` or `zh-Hant-TW`: only the primary
 * subtag before `-` or `_` matters. Chinese in any variant maps to Simplified Chinese because
 * there is no Traditional translation; unknown languages map to English.
 */
export function detectLanguage(tag: string | undefined): Language {
  const primary = tag?.trim().toLowerCase().split(/[-_]/)[0];
  return LANGUAGES.find((language) => language === primary) ?? "en";
}

export function isLanguage(value: unknown): value is Language {
  return LANGUAGES.some((language) => language === value);
}

/** Placeholder names of a text, sorted (for the completeness check). */
export function placeholders(text: string): string[] {
  return Array.from(text.matchAll(/\{(\w+)\}/g), (m) => m[1] ?? "").sort();
}

// For code outside React (error texts). React uses the context.
let currentLanguage: Language = detectLanguage(
  typeof navigator === "undefined" ? undefined : navigator.language,
);

export function setCurrentLanguage(language: Language): void {
  currentLanguage = language;
}

export function t(key: MessageKey, params?: Params): string {
  return translate(currentLanguage, key, params);
}

export const I18nContext = createContext<Translate>(createTranslator(currentLanguage));

export function useT(): Translate {
  return useContext(I18nContext);
}
