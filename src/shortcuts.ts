// Every keyboard shortcut of the window in one place (project rule). None is Ctrl plus a letter
// alone, because text fields need those; shortcuts.test.ts checks that rule for every entry.
// Shortcuts work inside the window only; nothing is registered system-wide.

import type { MessageKey, Translate } from "./i18n";

export interface KeyCombo {
  /** `KeyboardEvent.key`, compared case-insensitively for letters. */
  readonly key: string;
  /** Ctrl on Windows and Linux; Cmd counts as well on macOS. */
  readonly ctrl?: boolean;
  readonly shift?: boolean;
  readonly alt?: boolean;
}

export type ShortcutId = "help" | "settings" | "devices";

export interface Shortcut {
  readonly id: ShortcutId;
  readonly combo: KeyCombo;
  /** What the help dialog says it does. */
  readonly label: MessageKey;
}

export const SHORTCUTS: readonly Shortcut[] = [
  { id: "help", combo: { key: "F1" }, label: "help.key.help" },
  { id: "settings", combo: { key: ",", ctrl: true }, label: "help.key.settings" },
  { id: "devices", combo: { key: "D", ctrl: true, shift: true }, label: "help.key.devices" },
];

/** Keys the window handles everywhere but that are not shortcuts of their own (help dialog). */
export const FIXED_KEYS: readonly { readonly combo: KeyCombo; readonly label: MessageKey }[] = [
  { combo: { key: "Escape" }, label: "help.key.close" },
  { combo: { key: "F10", shift: true }, label: "help.key.menu" },
];

export interface KeyInput {
  readonly key: string;
  readonly ctrlKey: boolean;
  readonly metaKey: boolean;
  readonly shiftKey: boolean;
  readonly altKey: boolean;
}

export function matches(combo: KeyCombo, event: KeyInput): boolean {
  const ctrl = event.ctrlKey || event.metaKey;
  return (
    event.key.toLowerCase() === combo.key.toLowerCase() &&
    ctrl === (combo.ctrl ?? false) &&
    event.shiftKey === (combo.shift ?? false) &&
    event.altKey === (combo.alt ?? false)
  );
}

/** The shortcut a key press triggers, or null. */
export function shortcutFor(event: KeyInput): ShortcutId | null {
  return SHORTCUTS.find((shortcut) => matches(shortcut.combo, event))?.id ?? null;
}

/** True for a combination a text field needs: Ctrl (or Cmd) plus one letter, nothing else. */
export function isReservedForText(combo: KeyCombo): boolean {
  return (combo.ctrl ?? false) && !combo.shift && !combo.alt && /^[a-z]$/i.test(combo.key);
}

/** "Strg+Umschalt+D", in the UI language. */
export function formatCombo(combo: KeyCombo, t: Translate): string {
  const parts: string[] = [];
  if (combo.ctrl) parts.push(t("keys.ctrl"));
  if (combo.shift) parts.push(t("keys.shift"));
  if (combo.alt) parts.push(t("keys.alt"));
  parts.push(
    combo.key === "Escape"
      ? t("keys.escape")
      : combo.key.length === 1
        ? combo.key.toUpperCase()
        : combo.key,
  );
  return parts.join("+");
}
