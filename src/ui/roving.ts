// Lists as one tab stop with arrow keys inside (roving tabindex, UX 12). Items carry
// `data-roving`; the list moves focus between them and remembers the last one.

import { useState } from "react";

export interface Roving {
  /** tabIndex for item `index`: 0 for the remembered one, -1 for the rest. */
  tabIndex: (index: number) => 0 | -1;
  /** Remember the item that got focus (mouse or keyboard). */
  onItemFocus: (index: number) => void;
  /** Arrow keys, Home and End on the list. */
  onKeyDown: (event: React.KeyboardEvent<HTMLElement>) => void;
}

export function useRoving(count: number): Roving {
  const [active, setActive] = useState(0);
  const current = Math.min(active, Math.max(0, count - 1));
  return {
    tabIndex: (index) => (index === current ? 0 : -1),
    onItemFocus: setActive,
    onKeyDown: (event) => {
      const keys: Record<string, (index: number, last: number) => number> = {
        ArrowDown: (index, last) => Math.min(last, index + 1),
        ArrowUp: (index) => Math.max(0, index - 1),
        Home: () => 0,
        End: (_, last) => last,
      };
      const step = keys[event.key];
      if (!step) return;
      const items = Array.from(event.currentTarget.querySelectorAll<HTMLElement>("[data-roving]"));
      const from = items.findIndex((item) => item === document.activeElement);
      if (from === -1) return;
      event.preventDefault();
      const to = step(from, items.length - 1);
      items[to]?.focus();
    },
  };
}

/** Shift+F10 or the context menu key: open the row menu (UX 12). */
export function isMenuKey(event: React.KeyboardEvent): boolean {
  return event.key === "ContextMenu" || (event.key === "F10" && event.shiftKey);
}
