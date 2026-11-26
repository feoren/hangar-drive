import { describe, expect, it } from "vitest";

import {
  DICTIONARIES,
  detectLanguage,
  isLanguage,
  isPluralKey,
  LANGUAGE_NAMES,
  LANGUAGES,
  LOCALES,
  PLURAL_CATEGORIES,
  placeholders,
  pluralKeys,
  pluralRules,
  textKeys,
  translate,
  type Language,
} from "./i18n";

/** En and em dash, by code so this file contains neither character. */
const DASHES = new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]`);

/** Headings and buttons that have to fit on one line of the narrow window. */
const SHORT_KEYS = [
  "app.name",
  "main.devices",
  "main.settings",
  "main.addFolder",
  "setup.next",
  "setup.back",
  "setup.done",
  "tray.state.upToDate",
  "tray.state.attention",
  "restore.tab.versions",
  "restore.tab.trash",
  "devices.add",
] as const;

function entries(language: Language): [string, string][] {
  return Object.entries(DICTIONARIES[language]);
}

function categories(language: Language): string[] {
  return [...pluralRules(language).resolvedOptions().pluralCategories].sort();
}

describe("dictionaries", () => {
  it("exist for every offered language and only for those", () => {
    expect(Object.keys(DICTIONARIES).sort()).toEqual([...LANGUAGES].sort());
    expect(Object.keys(LANGUAGE_NAMES).sort()).toEqual([...LANGUAGES].sort());
    expect(Object.keys(LOCALES).sort()).toEqual([...LANGUAGES].sort());
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

  it("have every plain text of German in every language, and nothing else", () => {
    const plain = textKeys().sort();
    for (const language of LANGUAGES) {
      const keys = Object.keys(DICTIONARIES[language]).filter(
        (key) =>
          !PLURAL_CATEGORIES.some(
            (category) =>
              key.endsWith(`.${category}`) && isPluralKey(key.slice(0, -category.length - 1)),
          ),
      );
      expect(keys.sort(), language).toEqual(plain);
    }
  });

  it("have exactly the plural forms each language's plural rules report", () => {
    const problems: string[] = [];
    for (const language of LANGUAGES) {
      const expected = categories(language);
      for (const base of pluralKeys()) {
        const present = PLURAL_CATEGORIES.filter((category) =>
          Object.hasOwn(DICTIONARIES[language], `${base}.${category}`),
        ).sort();
        if (JSON.stringify(present) !== JSON.stringify(expected)) {
          problems.push(
            `${language}:${base} has ${present.join(",")}, needs ${expected.join(",")}`,
          );
        }
      }
    }
    expect(problems).toEqual([]);
  });

  it("always have the .other form", () => {
    for (const language of LANGUAGES) {
      for (const base of pluralKeys()) {
        expect(DICTIONARIES[language][`${base}.other`], `${language}:${base}`).toBeTruthy();
      }
    }
  });

  it("contain no empty texts", () => {
    for (const language of LANGUAGES) {
      for (const [key, value] of entries(language)) {
        expect(value.trim(), `${language}:${key}`).not.toBe("");
      }
    }
  });

  it("contain no en or em dashes", () => {
    for (const language of LANGUAGES) {
      for (const [key, value] of entries(language)) {
        expect(DASHES.test(value), `${language}:${key}`).toBe(false);
      }
    }
  });

  it("use the same placeholders as German in every language and every plural form", () => {
    const german = new Map<string, string>(entries("de"));
    const baseOf = (key: string): string => {
      for (const category of PLURAL_CATEGORIES) {
        const base = key.slice(0, -category.length - 1);
        if (key.endsWith(`.${category}`) && isPluralKey(base)) return `${base}.other`;
      }
      return key;
    };
    const mismatches: string[] = [];
    for (const language of LANGUAGES) {
      for (const [key, value] of entries(language)) {
        const expected = placeholders(german.get(baseOf(key)) ?? "");
        const actual = placeholders(value);
        if (JSON.stringify(actual) !== JSON.stringify(expected)) {
          mismatches.push(
            `${language}:${key} ${JSON.stringify(actual)} != ${JSON.stringify(expected)}`,
          );
        }
      }
    }
    expect(mismatches).toEqual([]);
  });

  it("let every plural text name the number it depends on", () => {
    for (const base of pluralKeys()) {
      const names = placeholders(DICTIONARIES.de[`${base}.other`]);
      expect(names.includes("count") || names.includes("days"), base).toBe(true);
    }
  });

  it("keep the product name the same in every language", () => {
    for (const language of LANGUAGES) {
      expect(DICTIONARIES[language]["app.name"], language).toBe("Hangar Drive");
    }
  });

  it("keep headings and buttons short", () => {
    for (const language of LANGUAGES) {
      for (const key of SHORT_KEYS) {
        const value = translate(language, key);
        expect(value.length, `${language}:${key} "${value}"`).toBeLessThanOrEqual(40);
      }
    }
  });

  it("use file-name safe words for conflict and restored copies", () => {
    for (const language of LANGUAGES) {
      for (const key of ["conflict.fileWord", "restore.fileWord"] as const) {
        expect(/[<>:"/\\|?*]/.test(translate(language, key)), `${language}:${key}`).toBe(false);
      }
    }
  });

  // Project rule: German UI texts address the reader with the informal "du".
  it("address the reader informally in German", () => {
    for (const [key, value] of entries("de")) {
      expect(/\b(Sie|Ihnen|Ihre?[mnrs]?)\b/.test(value), `de:${key}`).toBe(false);
    }
  });

  it("never show the words the concept keeps internal (UX 2)", () => {
    for (const language of ["de", "en"] as const) {
      for (const [key, value] of entries(language)) {
        expect(
          /\b(commit|token|hash|chunk|manifest|SPKI|epoch|frontier)\b/i.test(value),
          `${language}:${key}`,
        ).toBe(false);
      }
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
    expect(translate("de", "welcome.title", { app: "Hangar Drive" })).toBe(
      "Willkommen bei Hangar Drive",
    );
    expect(translate("en", "welcome.title", { app: "X" })).toBe("Welcome to X");
  });

  it("leaves missing placeholders visible", () => {
    expect(translate("en", "welcome.title")).toBe("Welcome to {app}");
    expect(translate("en", "welcome.title", { other: 1 })).toBe("Welcome to {app}");
  });

  it("picks the plural form from {count}", () => {
    expect(translate("de", "names.banner", { count: 1 })).toBe(
      "1 Datei kann auf diesem Gerät nicht gespeichert werden",
    );
    expect(translate("de", "names.banner", { count: 3 })).toBe(
      "3 Dateien können auf diesem Gerät nicht gespeichert werden",
    );
    expect(translate("en", "tray.state.syncing", { count: 1 })).toBe("Syncing 1 file");
    expect(translate("en", "tray.state.syncing", { count: 2 })).toBe("Syncing 2 files");
  });

  it("picks the plural form from {days} when there is no count", () => {
    expect(translate("de", "trash.info", { days: 1 })).toContain("1 Tag,");
    expect(translate("de", "trash.info", { days: 30 })).toContain("30 Tage,");
  });

  it("uses the few and many forms where the language has them", () => {
    const few = translate("pl", "restore.entry.changed", { count: 3 });
    const many = translate("pl", "restore.entry.changed", { count: 5 });
    expect(few).toBe(DICTIONARIES.pl["restore.entry.changed.few"]?.replace("{count}", "3"));
    expect(many).toBe(DICTIONARIES.pl["restore.entry.changed.many"]?.replace("{count}", "5"));
  });

  it("formats numbers for the language", () => {
    expect(translate("de", "deletes.title", { count: 1234 })).toBe("1.234 Dateien gelöscht");
    expect(translate("en", "deletes.title", { count: 1234 })).toBe("1,234 files deleted");
  });

  it("isolates a name with right-to-left letters or bidi controls", () => {
    const fsi = String.fromCharCode(0x2068);
    const pdi = String.fromCharCode(0x2069);
    const override = `Laptop${String.fromCharCode(0x202e)}fdp.exe`;
    expect(translate("en", "pair.added", { device: override })).toBe(
      `“${fsi}${override}${pdi}” has been added.`,
    );
    const hebrew = String.fromCharCode(0x05d0, 0x05d1);
    expect(translate("en", "pair.added", { device: hebrew })).toBe(
      `“${fsi}${hebrew}${pdi}” has been added.`,
    );
  });

  it("leaves plain left-to-right names untouched", () => {
    expect(translate("de", "pair.added", { device: "Arbeitslaptop" })).toBe(
      "„Arbeitslaptop“ ist jetzt dabei.",
    );
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
  });

  it("maps Portuguese and Chinese in every variant", () => {
    expect(detectLanguage("pt-BR")).toBe("pt");
    expect(detectLanguage("pt-PT")).toBe("pt");
    expect(detectLanguage("zh-Hant-HK")).toBe("zh");
  });

  it("falls back to English for other languages and nonsense", () => {
    expect(detectLanguage("nl-NL")).toBe("en");
    expect(detectLanguage("")).toBe("en");
    expect(detectLanguage(undefined)).toBe("en");
  });
});
