// The window's main menu behind the "≡" button: File, View, Help with submenus, the same component
// and behaviour as Hangar's app menu. It follows the WAI-ARIA menu pattern: on open the first entry
// has focus (no submenu opens by itself), Up and Down arrows move, Right, Enter or Space opens a
// submenu, Left closes it, Home and End jump, a first letter jumps to the matching entry, Escape
// closes one level and Tab the whole menu. With the mouse, a submenu opens on click or once the
// pointer moves onto its entry. Closing by keyboard or by a choice gives the focus back to the
// button, so a dialog opened from the menu returns there too.

import { useEffect, useLayoutEffect, useRef, useState } from "react";

import { CheckIcon, MenuIcon } from "./icons";
import {
  firstIndex,
  menuCommand,
  pointerMoved,
  submenuAfterFocus,
  type NavEntry,
  type PointerPoint,
} from "./menuNav";

export type AppMenuItem =
  | {
      readonly type: "action";
      readonly id: string;
      readonly label: string;
      /** The shortcut as shown, such as "Strg+,", and for `aria-keyshortcuts`, "Control+,". */
      readonly shortcut?: { readonly text: string; readonly aria: string } | undefined;
      readonly run: () => void;
    }
  /** One of a group of choices, such as the folder view; `checked` marks the current one. */
  | {
      readonly type: "radio";
      readonly id: string;
      readonly label: string;
      readonly checked: boolean;
      readonly run: () => void;
    }
  | { readonly type: "separator"; readonly id: string };

export interface AppMenuGroup {
  readonly id: string;
  readonly label: string;
  readonly items: readonly AppMenuItem[];
}

type PanelItem =
  | AppMenuItem
  | {
      readonly type: "submenu";
      readonly id: string;
      readonly label: string;
      readonly items: readonly AppMenuItem[];
    };

/** The keyboard navigation's view of the entries (menuNav.ts). */
function navEntries(items: readonly PanelItem[]): NavEntry[] {
  return items.map((item) =>
    item.type === "separator"
      ? null
      : {
          label: item.label,
          enabled: item.type !== "submenu" || item.items.length > 0,
          submenu: item.type === "submenu",
        },
  );
}

export function AppMenu({
  groups,
  label,
}: {
  readonly groups: readonly AppMenuGroup[];
  /** The button's accessible name and the menu's, "Menü". */
  readonly label: string;
}) {
  const [open, setOpen] = useState(false);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    if (!open) return;
    // Closed from outside: the focus stays wherever the person put it.
    const close = () => {
      setOpen(false);
    };
    const onPointer = (event: PointerEvent) => {
      if (event.target instanceof Node && root.current?.contains(event.target)) return;
      close();
    };
    document.addEventListener("pointerdown", onPointer);
    window.addEventListener("blur", close);
    window.addEventListener("resize", close);
    return () => {
      document.removeEventListener("pointerdown", onPointer);
      window.removeEventListener("blur", close);
      window.removeEventListener("resize", close);
    };
  }, [open]);

  const done = () => {
    setOpen(false);
    button.current?.focus();
  };

  const items: PanelItem[] = groups.map((group) => ({
    type: "submenu",
    id: group.id,
    label: group.label,
    items: group.items,
  }));

  return (
    <div className="app-menu" ref={root}>
      <button
        ref={button}
        type="button"
        className="icon-button menu-button"
        aria-label={label}
        title={label}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={() => {
          setOpen((current) => !current);
        }}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown" && !open) {
            event.preventDefault();
            setOpen(true);
          }
        }}
      >
        <MenuIcon size={18} />
      </button>
      {open && <MenuPanel items={items} label={label} root autoFocus onDone={done} />}
    </div>
  );
}

function MenuPanel({
  items,
  label,
  root = false,
  autoFocus,
  onDone,
  onBack,
}: {
  readonly items: readonly PanelItem[];
  readonly label: string;
  readonly root?: boolean;
  /** Focus the first entry on mount (opening the menu, or a submenu by keyboard). */
  readonly autoFocus: boolean;
  /** Close the whole menu and give the focus back to the button. */
  readonly onDone: () => void;
  /** Close this submenu via Left arrow or Escape; the parent entry takes the focus. */
  readonly onBack?: () => void;
}) {
  const entries = navEntries(items);
  const [current, setCurrent] = useState(() => firstIndex(entries));
  const [openIndex, setOpenIndex] = useState<number | null>(null);
  const [childFocus, setChildFocus] = useState(false);
  const buttons = useRef(new Map<number, HTMLButtonElement>());
  /** The last pointer position over this level, to tell real movement from a resting pointer. */
  const lastPointer = useRef<PointerPoint | null>(null);

  useLayoutEffect(() => {
    if (autoFocus) buttons.current.get(current)?.focus();
    // Only on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const focusAt = (index: number) => {
    setCurrent(index);
    buttons.current.get(index)?.focus();
    // Arrows only move; Right arrow or Enter opens a submenu.
    const next = submenuAfterFocus(openIndex, index);
    if (next !== openIndex) {
      setChildFocus(false);
      setOpenIndex(next);
    }
  };

  /** The pointer moved over an entry: it takes the focus, a submenu entry opens its submenu. */
  const hover = (event: React.PointerEvent<HTMLLIElement>, index: number) => {
    // Moves inside an open submenu bubble up through this entry; that level handles them.
    if (
      event.target instanceof Element &&
      event.target.closest(".menu-entry") !== event.currentTarget
    ) {
      return;
    }
    const point = { x: event.clientX, y: event.clientY };
    const moved = pointerMoved(lastPointer.current, point);
    lastPointer.current = point;
    const item = items[index];
    if (!moved || item === undefined || item.type === "separator") return;
    const wanted = item.type === "submenu" ? index : null;
    if (index === current && openIndex === wanted) return;
    setCurrent(index);
    buttons.current.get(index)?.focus();
    setChildFocus(false);
    setOpenIndex(wanted);
  };

  const openSubmenu = (index: number, focusChild: boolean) => {
    setCurrent(index);
    setChildFocus(focusChild);
    setOpenIndex(index);
  };

  const activate = (index: number) => {
    const item = items[index];
    if (!item || (item.type !== "action" && item.type !== "radio")) return;
    // The focus goes back to the button first, so a dialog opened by the item returns there.
    onDone();
    item.run();
  };

  const onKeyDown = (event: React.KeyboardEvent) => {
    // Submenus sit in the DOM inside their parent entry: each level handles only its own keys and
    // does not let them bubble up.
    event.stopPropagation();
    const command = menuCommand(event, entries, current, !root);
    switch (command.kind) {
      case "none":
        return;
      case "focus":
        focusAt(command.index);
        break;
      case "activate":
        activate(current);
        break;
      case "openSubmenu":
        openSubmenu(current, true);
        break;
      case "closeSubmenu":
        onBack?.();
        break;
      case "closeAll":
        onDone();
        break;
    }
    // Tab only closes; the focus goes back to the button, not on to the next element.
    event.preventDefault();
  };

  return (
    <ul
      className={root ? "menu-panel menu-root" : "menu-panel menu-sub"}
      role="menu"
      aria-label={label}
      onKeyDown={onKeyDown}
    >
      {items.map((item, index) => {
        if (item.type === "separator") {
          return <li key={item.id} role="separator" className="menu-separator" />;
        }
        const isOpen = item.type === "submenu" && openIndex === index;
        const checked = item.type === "radio" ? item.checked : undefined;
        return (
          <li
            key={item.id}
            className="menu-entry"
            role="none"
            onPointerMove={(event) => {
              hover(event, index);
            }}
          >
            <button
              type="button"
              role={item.type === "radio" ? "menuitemradio" : "menuitem"}
              aria-checked={checked}
              aria-keyshortcuts={item.type === "action" ? item.shortcut?.aria : undefined}
              ref={(element) => {
                if (element) buttons.current.set(index, element);
                else buttons.current.delete(index);
              }}
              tabIndex={index === current ? 0 : -1}
              className={
                "menu-item" + (isOpen ? " open" : "") + (checked === true ? " current" : "")
              }
              aria-haspopup={item.type === "submenu" ? "menu" : undefined}
              aria-expanded={item.type === "submenu" ? isOpen : undefined}
              onClick={(event) => {
                if (item.type === "submenu") {
                  // Triggered by keyboard (detail 0): go straight into the submenu.
                  openSubmenu(index, event.detail === 0);
                  return;
                }
                activate(index);
              }}
            >
              <span className="menu-label">{item.label}</span>
              <span className="menu-hint" aria-hidden="true">
                {item.type === "submenu"
                  ? "›"
                  : item.type === "radio"
                    ? checked === true && <CheckIcon size={16} />
                    : (item.shortcut?.text ?? "")}
              </span>
            </button>
            {isOpen && item.items.length > 0 && (
              <MenuPanel
                // Remount when the preview turns into an open with focus.
                key={childFocus ? "focus" : "preview"}
                items={item.items}
                label={item.label}
                autoFocus={childFocus}
                onDone={onDone}
                onBack={() => {
                  setOpenIndex(null);
                  setChildFocus(false);
                  buttons.current.get(index)?.focus();
                }}
              />
            )}
          </li>
        );
      })}
    </ul>
  );
}
