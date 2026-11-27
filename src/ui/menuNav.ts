// Keyboard control of the main menu following the WAI-ARIA menu pattern, the same as Hangar's app
// menu. Pure logic: a key and the entries yield a command that the component carries out.

/** An entry as seen by navigation; `null` is a separator. */
export type NavEntry = {
  readonly label: string;
  readonly enabled: boolean;
  readonly submenu: boolean;
} | null;

export type MenuCommand =
  | { readonly kind: "focus"; readonly index: number }
  /** Enter or Space on an action. */
  | { readonly kind: "activate" }
  /** Open the submenu and focus its first entry. */
  | { readonly kind: "openSubmenu" }
  /** Close the submenu, focus back on the entry that opened it. */
  | { readonly kind: "closeSubmenu" }
  /** Close the whole menu (Escape at the top level, Tab). */
  | { readonly kind: "closeAll" }
  | { readonly kind: "none" };

function usable(entry: NavEntry | undefined): boolean {
  return entry !== null && entry !== undefined && entry.enabled;
}

/** The next operable entry in direction `step`; past the end it wraps around. */
export function stepIndex(entries: readonly NavEntry[], current: number, step: 1 | -1): number {
  const count = entries.length;
  if (count === 0) return -1;
  let index = current < 0 ? (step === 1 ? -1 : count) : current;
  for (let tries = 0; tries < count; tries += 1) {
    index = (((index + step) % count) + count) % count;
    if (usable(entries[index])) return index;
  }
  return current < count && usable(entries[current]) ? current : -1;
}

export function firstIndex(entries: readonly NavEntry[]): number {
  return stepIndex(entries, -1, 1);
}

export function lastIndex(entries: readonly NavEntry[]): number {
  return stepIndex(entries, -1, -1);
}

/** The next entry after `current` whose name starts with `char` (case insensitive), else -1. */
export function typeaheadIndex(
  entries: readonly NavEntry[],
  current: number,
  char: string,
): number {
  const wanted = char.toLocaleLowerCase();
  const count = entries.length;
  for (let offset = 1; offset <= count; offset += 1) {
    const index = (((current + offset) % count) + count) % count;
    const entry = entries[index];
    if (usable(entry) && entry?.label.trim().toLocaleLowerCase().startsWith(wanted) === true) {
      return index;
    }
  }
  return -1;
}

/** A single printable character (a first letter). */
function printable(key: string): boolean {
  return Array.from(key).length === 1 && key.trim() !== "";
}

export interface KeyInput {
  readonly key: string;
  readonly ctrlKey?: boolean;
  readonly altKey?: boolean;
  readonly metaKey?: boolean;
}

/**
 * The command for a key. `nested`: the menu is a submenu, so Left arrow and Escape close only
 * this one.
 */
export function menuCommand(
  input: KeyInput,
  entries: readonly NavEntry[],
  current: number,
  nested: boolean,
): MenuCommand {
  const entry = entries[current];
  const focus = (index: number): MenuCommand =>
    index < 0 ? { kind: "none" } : { kind: "focus", index };
  switch (input.key) {
    case "ArrowDown":
      return focus(stepIndex(entries, current, 1));
    case "ArrowUp":
      return focus(stepIndex(entries, current, -1));
    case "Home":
    case "PageUp":
      return focus(firstIndex(entries));
    case "End":
    case "PageDown":
      return focus(lastIndex(entries));
    case "ArrowRight":
      return usable(entry) && entry?.submenu === true ? { kind: "openSubmenu" } : { kind: "none" };
    case "ArrowLeft":
      return nested ? { kind: "closeSubmenu" } : { kind: "none" };
    case "Escape":
      return nested ? { kind: "closeSubmenu" } : { kind: "closeAll" };
    case "Tab":
      return { kind: "closeAll" };
    case "Enter":
    case " ":
      if (!usable(entry)) return { kind: "none" };
      return entry?.submenu === true ? { kind: "openSubmenu" } : { kind: "activate" };
    default:
      if (input.ctrlKey === true || input.altKey === true || input.metaKey === true) {
        return { kind: "none" };
      }
      return printable(input.key)
        ? focus(typeaheadIndex(entries, current, input.key))
        : { kind: "none" };
  }
}

/**
 * The submenu after the keyboard moved focus to `index`: one already open there stays, any other
 * closes. Arrow keys never open a submenu by themselves.
 */
export function submenuAfterFocus(openIndex: number | null, index: number): number | null {
  return openIndex === index ? index : null;
}

export interface PointerPoint {
  readonly x: number;
  readonly y: number;
}

/**
 * Whether the pointer really moved since the last event (`last`; `null`: none seen yet in this
 * menu). A pointer resting where the menu appeared is no hover, nor is a move the browser sends
 * after layout without any movement.
 */
export function pointerMoved(last: PointerPoint | null, next: PointerPoint): boolean {
  return last !== null && (last.x !== next.x || last.y !== next.y);
}
