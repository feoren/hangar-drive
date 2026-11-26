// Keeps the keyboard focus inside a view when the element that had it goes away or is busy for a
// moment: a restored row leaves the list, a step of the setup is replaced by the next one, a
// button is disabled while its action runs. Without this the focus falls back to the page, and a
// keyboard or screen reader user has to start again from the top (UX 12).

import { useLayoutEffect, useRef, type RefObject } from "react";

const FOCUSABLE = [
  "button:not(:disabled)",
  "input:not(:disabled)",
  "select:not(:disabled)",
  "textarea:not(:disabled)",
  "[href]",
  '[tabindex]:not([tabindex="-1"])',
].join(", ");

/** The elements of `root` that Tab reaches, in order. */
export function focusables(root: HTMLElement): HTMLElement[] {
  return Array.from(root.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (element) =>
      element.tabIndex >= 0 && !element.closest("[hidden]") && !element.closest("[inert]"),
  );
}

export interface KeeperOptions {
  /** Where the focus goes when the element that had it is gone. */
  readonly fallback: (root: HTMLElement) => HTMLElement | null;
  /** Whether nothing (a dialog) lies above this view; only the view in front keeps the focus. */
  readonly inFront: (root: HTMLElement) => boolean;
  /**
   * Whether the element now at the same place in the tab order takes over first: right for lists
   * (the next row), wrong for a setup step that was replaced as a whole.
   */
  readonly near: boolean;
}

function isDisabled(element: HTMLElement): boolean {
  return element.matches(":disabled") || element.closest("[inert]") !== null;
}

function focusIsLost(): boolean {
  const active = document.activeElement;
  return active === null || active === document.body;
}

export function useFocusKeeper(root: RefObject<HTMLElement | null>, options: KeeperOptions): void {
  const optionsRef = useRef(options);
  useLayoutEffect(() => {
    optionsRef.current = options;
  });

  useLayoutEffect(() => {
    const view = root.current;
    if (!view) return;
    let last: HTMLElement | null = null;
    let lastIndex = -1;
    // The element was disabled while it had the focus; it gets the focus back once it is enabled.
    let waiting = false;
    let queued = false;

    const remember = (element: EventTarget | null) => {
      if (!(element instanceof HTMLElement) || !view.contains(element)) return;
      last = element;
      lastIndex = focusables(view).indexOf(element);
      waiting = false;
    };
    const onFocusIn = (event: FocusEvent) => {
      remember(event.target);
    };
    // A control with autoFocus takes the focus while React commits, before this effect listens.
    remember(document.activeElement);

    const check = () => {
      queued = false;
      const { fallback, inFront, near } = optionsRef.current;
      if (!last || !focusIsLost() || !inFront(view)) return;
      if (last.isConnected && view.contains(last)) {
        if (isDisabled(last)) {
          waiting = true;
          return;
        }
        // Enabled again after its action; a focus the person moved away on purpose stays away.
        if (waiting) {
          waiting = false;
          last.focus();
        }
        return;
      }
      const items = focusables(view);
      const nearby = near && lastIndex >= 0 ? items[Math.min(lastIndex, items.length - 1)] : null;
      const target = nearby ?? fallback(view);
      if (target) target.focus();
    };

    const schedule = () => {
      if (queued) return;
      queued = true;
      queueMicrotask(check);
    };

    const observer = new MutationObserver(schedule);
    observer.observe(view, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ["disabled", "hidden", "inert"],
    });
    view.addEventListener("focusin", onFocusIn);
    return () => {
      observer.disconnect();
      view.removeEventListener("focusin", onFocusIn);
    };
  }, [root]);
}

/** True when no modal overlay is open in the document (the setup page is then in front). */
export function noOverlay(): boolean {
  return document.querySelector(".overlay") === null;
}

/** True when the overlay around `panel` is the last one, so no other dialog lies above it. */
export function topOverlay(panel: HTMLElement): boolean {
  const overlays = document.querySelectorAll(".overlay");
  const top = overlays[overlays.length - 1];
  return top !== undefined && top.contains(panel);
}
