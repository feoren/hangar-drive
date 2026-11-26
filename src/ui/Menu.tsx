// The row menu ("…"): a button that opens a menu below it. Arrow keys move, Enter runs, Escape
// closes and returns focus to the button. The row itself can open it with Shift+F10 or the
// context menu key (UX 12), through `open` and `onOpenChange`.

import { useEffect, useId, useLayoutEffect, useRef, useState, type RefObject } from "react";
import { createPortal } from "react-dom";

import { MoreIcon } from "./icons";

export interface MenuItem {
  readonly id: string;
  readonly label: string;
  readonly onSelect: () => void;
  readonly danger?: boolean;
  /** Draws a separator above this item. */
  readonly separated?: boolean;
}

interface Props {
  readonly items: readonly MenuItem[];
  /** Accessible name of the "…" button, such as "Actions for “Fotos”". */
  readonly label: string;
  readonly open: boolean;
  readonly onOpenChange: (open: boolean) => void;
  /** Focus target after closing without a choice; the button itself by default. */
  readonly returnFocus?: RefObject<HTMLElement | null>;
}

export function RowMenu({ items, label, open, onOpenChange, returnFocus }: Props) {
  const button = useRef<HTMLButtonElement>(null);
  const menu = useRef<HTMLDivElement>(null);
  const menuId = useId();
  const [position, setPosition] = useState<{ top: number; right: number; up: boolean } | null>(
    null,
  );

  useLayoutEffect(() => {
    if (!open || !button.current) return;
    const rect = button.current.getBoundingClientRect();
    const below = window.innerHeight - rect.bottom;
    const up = below < 40 + items.length * 34 && rect.top > below;
    const next = {
      top: up ? rect.top - 4 : rect.bottom + 4,
      right: Math.max(8, window.innerWidth - rect.right),
      up,
    };
    // Measured from the layout of this frame; a state update here is the documented pattern.
    setPosition(next);
  }, [open, items.length]);

  // The estimate above can miss (long labels, larger text); the measured menu is moved fully into
  // the window, and scrolls when the window is lower than the menu (UX 12: nothing cut off).
  useLayoutEffect(() => {
    const element = menu.current;
    if (!open || !position || !element) return;
    const margin = 8;
    const room = window.innerHeight - 2 * margin;
    element.style.maxHeight = `${String(room)}px`;
    const rect = element.getBoundingClientRect();
    if (rect.top >= margin && rect.bottom <= window.innerHeight - margin) return;
    const top = Math.max(margin, Math.min(rect.top, window.innerHeight - margin - rect.height));
    element.classList.remove("menu-up");
    element.style.top = `${String(top)}px`;
  }, [open, position]);

  useLayoutEffect(() => {
    if (open && position) menu.current?.querySelector<HTMLElement>('[role="menuitem"]')?.focus();
  }, [open, position]);

  useEffect(() => {
    if (!open) return;
    const close = (event: MouseEvent) => {
      const target = event.target;
      if (!(target instanceof Node)) return;
      if (menu.current?.contains(target) || button.current?.contains(target)) return;
      onOpenChange(false);
    };
    const onResize = () => {
      onOpenChange(false);
    };
    document.addEventListener("mousedown", close);
    window.addEventListener("resize", onResize);
    return () => {
      document.removeEventListener("mousedown", close);
      window.removeEventListener("resize", onResize);
    };
  }, [open, onOpenChange]);

  const closeAndFocus = () => {
    onOpenChange(false);
    (returnFocus?.current ?? button.current)?.focus();
  };

  const onKeyDown = (event: React.KeyboardEvent) => {
    const entries = Array.from(
      menu.current?.querySelectorAll<HTMLElement>('[role="menuitem"]') ?? [],
    );
    const index = entries.findIndex((entry) => entry === document.activeElement);
    const move = (to: number) => {
      event.preventDefault();
      entries[(to + entries.length) % entries.length]?.focus();
    };
    switch (event.key) {
      case "ArrowDown":
        move(index + 1);
        break;
      case "ArrowUp":
        move(index - 1);
        break;
      case "Home":
        move(0);
        break;
      case "End":
        move(entries.length - 1);
        break;
      case "Escape":
        event.preventDefault();
        event.stopPropagation();
        closeAndFocus();
        break;
      case "Tab":
        event.preventDefault();
        closeAndFocus();
        break;
    }
  };

  return (
    <>
      <button
        ref={button}
        type="button"
        className="icon-button row-menu-button"
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={open}
        aria-controls={open ? menuId : undefined}
        tabIndex={-1}
        onClick={(event) => {
          event.stopPropagation();
          onOpenChange(!open);
        }}
        onDoubleClick={(event) => {
          event.stopPropagation();
        }}
      >
        <MoreIcon />
      </button>
      {open &&
        position &&
        createPortal(
          <div
            ref={menu}
            id={menuId}
            className={position.up ? "menu menu-up" : "menu"}
            role="menu"
            aria-label={label}
            style={{
              top: position.top,
              right: position.right,
            }}
            onKeyDown={onKeyDown}
          >
            {items.map((item) => (
              <div key={item.id} role="none">
                {item.separated && <div className="menu-separator" role="separator" />}
                <button
                  type="button"
                  role="menuitem"
                  tabIndex={-1}
                  className={item.danger ? "menu-item danger" : "menu-item"}
                  onClick={() => {
                    // Focus goes back to the row first, so a dialog opened by the item returns
                    // there when it closes.
                    closeAndFocus();
                    item.onSelect();
                  }}
                >
                  {item.label}
                </button>
              </div>
            ))}
          </div>,
          document.body,
        )}
    </>
  );
}
