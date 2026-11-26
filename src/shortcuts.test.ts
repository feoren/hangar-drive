import { describe, expect, it } from "vitest";

import { createTranslator } from "./i18n";
import {
  FIXED_KEYS,
  formatCombo,
  isReservedForText,
  matches,
  SHORTCUTS,
  shortcutFor,
  type KeyInput,
} from "./shortcuts";

function press(key: string, mods: Partial<KeyInput> = {}): KeyInput {
  return { key, ctrlKey: false, metaKey: false, shiftKey: false, altKey: false, ...mods };
}

describe("shortcuts", () => {
  it("never use Ctrl plus a letter alone (project rule)", () => {
    for (const shortcut of SHORTCUTS)
      expect(isReservedForText(shortcut.combo), shortcut.id).toBe(false);
  });

  it("are unique", () => {
    const combos = [...SHORTCUTS.map((s) => s.combo), ...FIXED_KEYS.map((k) => k.combo)].map((c) =>
      JSON.stringify(c),
    );
    expect(new Set(combos).size).toBe(combos.length);
    expect(new Set(SHORTCUTS.map((s) => s.id)).size).toBe(SHORTCUTS.length);
  });

  it("know what a text field needs", () => {
    expect(isReservedForText({ key: "c", ctrl: true })).toBe(true);
    expect(isReservedForText({ key: "D", ctrl: true, shift: true })).toBe(false);
    expect(isReservedForText({ key: ",", ctrl: true })).toBe(false);
    expect(isReservedForText({ key: "F1" })).toBe(false);
  });

  it("find the shortcut of a key press", () => {
    expect(shortcutFor(press("F1"))).toBe("help");
    expect(shortcutFor(press(",", { ctrlKey: true }))).toBe("settings");
    expect(shortcutFor(press(",", { metaKey: true }))).toBe("settings");
    expect(shortcutFor(press("D", { ctrlKey: true, shiftKey: true }))).toBe("devices");
    expect(shortcutFor(press("d", { ctrlKey: true, shiftKey: true }))).toBe("devices");
    expect(shortcutFor(press("d", { ctrlKey: true }))).toBeNull();
    expect(shortcutFor(press("F1", { shiftKey: true }))).toBeNull();
    expect(shortcutFor(press(","))).toBeNull();
  });

  it("match modifiers exactly", () => {
    expect(matches({ key: "F1" }, press("F1", { altKey: true }))).toBe(false);
  });

  it("are written in the UI language", () => {
    const de = createTranslator("de");
    const en = createTranslator("en");
    expect(formatCombo({ key: "D", ctrl: true, shift: true }, de)).toBe("Strg+Umschalt+D");
    expect(formatCombo({ key: ",", ctrl: true }, en)).toBe("Ctrl+,");
    expect(formatCombo({ key: "Escape" }, de)).toBe("Esc");
    expect(formatCombo({ key: "F10", shift: true }, en)).toBe("Shift+F10");
  });
});
