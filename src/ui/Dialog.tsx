// Modal dialog in the shape of the sister app: focus moves in on open (to the element marked
// `data-autofocus`, else the first control), Tab stays inside, Escape closes without deciding,
// and focus returns to the element that opened it (UX 12).

import { useLayoutEffect, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";

const FOCUSABLE = [
  "button:not(:disabled)",
  "input:not(:disabled)",
  "select:not(:disabled)",
  "textarea:not(:disabled)",
  "[href]",
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

export function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (element) =>
      element.tabIndex >= 0 && !element.closest("[hidden]") && !element.closest("[inert]"),
  );
}

interface Props {
  readonly labelledBy: string;
  readonly describedBy?: string;
  /** "small" for questions, "medium" for lists, "large" for whole views (restore, devices). */
  readonly size?: "small" | "medium" | "large";
  readonly className?: string;
  /** Escape, a click beside the dialog, or a close button. */
  readonly onClose: () => void;
  /** Whether a click beside the dialog closes it; off where a stray click would lose input. */
  readonly closeOnOutside?: boolean;
  /** "alertdialog" for questions that need a decision. */
  readonly role?: "dialog" | "alertdialog";
  /** When this changes, focus moves in again as on open (a dialog that shows a next step). */
  readonly focusKey?: string;
  readonly children: ReactNode;
}

function focusInitial(element: HTMLElement): void {
  const target =
    element.querySelector<HTMLElement>("[data-autofocus]") ?? focusables(element)[0] ?? element;
  target.focus();
}

export function Dialog({
  labelledBy,
  describedBy,
  size = "small",
  className,
  onClose,
  closeOnOutside = true,
  role = "dialog",
  focusKey,
  children,
}: Props) {
  const panel = useRef<HTMLDivElement>(null);
  const shownKey = useRef(focusKey);

  useLayoutEffect(() => {
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    if (panel.current) focusInitial(panel.current);
    return () => {
      // Back to where the person was, if that element still exists.
      if (opener?.isConnected) opener.focus();
    };
  }, []);

  useLayoutEffect(() => {
    if (focusKey === shownKey.current) return;
    shownKey.current = focusKey;
    if (panel.current) focusInitial(panel.current);
  }, [focusKey]);

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (event.key === "Escape") {
      event.stopPropagation();
      event.preventDefault();
      onClose();
      return;
    }
    if (event.key !== "Tab" || !panel.current) return;
    event.stopPropagation();
    const items = focusables(panel.current);
    const first = items[0];
    const last = items[items.length - 1];
    if (!first || !last) {
      event.preventDefault();
      return;
    }
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  };

  const classes = ["dialog", `dialog-${size}`, className].filter(Boolean).join(" ");
  return createPortal(
    <div
      className="overlay"
      role="presentation"
      onMouseDown={(event) => {
        if (closeOnOutside && event.target === event.currentTarget) onClose();
      }}
    >
      <div
        ref={panel}
        className={classes}
        role={role}
        aria-modal="true"
        aria-labelledby={labelledBy}
        aria-describedby={describedBy}
        tabIndex={-1}
        onKeyDown={onKeyDown}
      >
        {children}
      </div>
    </div>,
    document.body,
  );
}
