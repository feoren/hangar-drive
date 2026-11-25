import { describe, expect, it } from "vitest";

import {
  DICTIONARIES,
  detectLanguage,
  isLanguage,
  LANGUAGE_NAMES,
  LANGUAGES,
  placeholders,
  translate,
} from "./i18n";

const de = DICTIONARIES.de;
const deKeys = Object.keys(de).sort();

/** En and em dash, by code so this file contains neither character. */
const DASHES = new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]`);

/** Headings that have to fit on one line of a narrow window. */
const SHORT_KEYS = ["app.name", "empty.title"] as const;

describe("dictionaries", () => {
  it("exist for every offered language and only for those", () => {
    expect(Object.keys(DICTIONARIES).sort()).toEqual([...LANGUAGES].sort());
    expect(Object.keys(LANGUAGE_NAMES).sort()).toEqual([...LANGUAGES].sort());
  });

  it("offer the twelve languages of Hangar, German and English first", () => {
    expect(LANGUAGES).toEqual([
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
    ]);
  });

  it("have exactly the keys of the German one in every language", () => {
    for (const language of LANGUAGES) {
      expect(Object.keys(DICTIONARIES[language]).sort(), language).toEqual(deKeys);
    }
  });

  it("contain no empty texts", () => {
    for (const language of LANGUAGES) {
      for (const [key, text] of Object.entries(DICTIONARIES[language])) {
        expect(text.trim(), `${language}:${key}`).not.toBe("");
      }
    }
  });

  it("contain no en or em dashes", () => {
    for (const language of LANGUAGES) {
      for (const [key, text] of Object.entries(DICTIONARIES[language])) {
        expect(DASHES.test(text), `${language}:${key}`).toBe(false);
      }
    }
  });

  it("use the same placeholders as German in every language", () => {
    const german = new Map<string, string>(Object.entries(de));
    const mismatches: string[] = [];
    for (const language of LANGUAGES) {
      for (const [key, text] of Object.entries(DICTIONARIES[language])) {
        const expected = placeholders(german.get(key) ?? "");
        const actual = placeholders(text);
        if (JSON.stringify(actual) !== JSON.stringify(expected)) {
          mismatches.push(
            `${language}:${key} ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`,
          );
        }
      }
    }
    expect(mismatches).toEqual([]);
  });

  it("keep the product name the same in every language", () => {
    for (const language of LANGUAGES) {
      expect(DICTIONARIES[language]["app.name"], language).toBe("Hangar Drive");
    }
  });

  it("keep headings short", () => {
    for (const language of LANGUAGES) {
      for (const key of SHORT_KEYS) {
        const text = translate(language, key);
        expect(text.length, `${language}:${key} "${text}"`).toBeLessThanOrEqual(40);
      }
    }
  });

  // Project rule: German UI texts address the reader with the informal "du".
  it("address the reader informally in German", () => {
    for (const [key, text] of Object.entries(de)) {
      expect(/\b(Sie|Ihnen|Ihre?[mnrs]?)\b/.test(text), `de:${key}`).toBe(false);
    }
  });
});

describe("language selection", () => {
  it("has a distinct, non-empty name for every language", () => {
    const names = LANGUAGES.map((language) => LANGUAGE_NAMES[language].trim());
    expect(names.every((name) => name.length > 0)).toBe(true);
    expect(new Set(names).size).toBe(LANGUAGES.length);
  });

  it("recognizes exactly the offered languages", () => {
    expect(LANGUAGES.every(isLanguage)).toBe(true);
    expect(isLanguage("xx")).toBe(false);
    expect(isLanguage("pt-BR")).toBe(false);
    expect(isLanguage(undefined)).toBe(false);
    expect(isLanguage(42)).toBe(false);
  });
});

describe("translate", () => {
  it("fills in placeholders", () => {
    expect(translate("de", "empty.body", { app: "Hangar Drive" })).toBe(
      "Hangar Drive ist noch in einer frühen Entwicklungsphase. Deine synchronisierten Ordner erscheinen später hier.",
    );
    expect(translate("en", "empty.body", { app: "X" })).toBe(
      "X is in early development. Your synced folders will appear here later.",
    );
  });

  it("leaves missing placeholders visible", () => {
    expect(translate("en", "empty.body")).toMatch(/^\{app\} is in early development\./);
    expect(translate("en", "empty.body", { other: 1 })).toMatch(/^\{app\} /);
  });

  it("returns texts without placeholders unchanged", () => {
    expect(translate("fr", "empty.title", { app: "X" })).toBe("Rien n’est encore synchronisé");
  });
});

describe("detectLanguage", () => {
  it("detects German in all variants", () => {
    expect(detectLanguage("de")).toBe("de");
    expect(detectLanguage("de-AT")).toBe("de");
    expect(detectLanguage("DE-de")).toBe("de");
    expect(detectLanguage("de_CH")).toBe("de");
    expect(detectLanguage("en-US")).toBe("en");
  });

  it("detects every offered language by the primary subtag", () => {
    for (const language of LANGUAGES) {
      expect(detectLanguage(language)).toBe(language);
      expect(detectLanguage(`${language.toUpperCase()}-XX`)).toBe(language);
    }
    expect(detectLanguage("es-419")).toBe("es");
    expect(detectLanguage("ja-JP")).toBe("ja");
  });

  it("maps Portuguese and Chinese in every variant", () => {
    expect(detectLanguage("pt-BR")).toBe("pt");
    expect(detectLanguage("pt-PT")).toBe("pt");
    expect(detectLanguage("zh-Hans-CN")).toBe("zh");
    expect(detectLanguage("zh-TW")).toBe("zh");
    expect(detectLanguage("zh-Hant-HK")).toBe("zh");
  });

  it("falls back to English for other languages and nonsense", () => {
    expect(detectLanguage("nl-NL")).toBe("en");
    expect(detectLanguage("")).toBe("en");
    expect(detectLanguage("deu")).toBe("en");
    expect(detectLanguage(undefined)).toBe("en");
  });
});
