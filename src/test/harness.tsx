// Test harness for the views: renders the whole app on the mock backend in happy-dom and offers
// small helpers to find and press things by their visible text or accessible name.

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { vi } from "vitest";

import { App } from "../App";
import { MockBackend, type MockOptions } from "../backend/mock/mockBackend";
import type { ScenarioId } from "../backend/mock/scenarios";
import type { Backend } from "../backend/types";

Reflect.set(globalThis, "IS_REACT_ACT_ENVIRONMENT", true);

export interface Harness {
  readonly host: HTMLElement;
  readonly mock: MockBackend;
  unmount: () => void;
}

let mounted: { root: Root; host: HTMLElement } | null = null;

/** Lets pending promises, effects and zero-delay timers run. */
export async function flush(rounds = 4): Promise<void> {
  for (let i = 0; i < rounds; i += 1) {
    await act(async () => {
      if (vi.isFakeTimers()) await vi.advanceTimersByTimeAsync(0);
      else await new Promise((resolve) => setTimeout(resolve, 0));
    });
  }
}

/** Moves fake time forward and lets everything settle. */
export async function advance(ms: number): Promise<void> {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(ms);
  });
  await flush();
}

export async function renderApp(
  scenario: ScenarioId = "upToDate",
  options: MockOptions = {},
): Promise<Harness> {
  const mock = new MockBackend({ scenario, ...options });
  // Tests read German, the source language; happy-dom reports en-US as the system language.
  await mock.setLanguage("de");
  mock.calls.length = 0;
  const harness = await renderWith(mock);
  return { ...harness, mock };
}

export async function renderWith(
  backend: Backend,
): Promise<{ host: HTMLElement; unmount: () => void }> {
  cleanup();
  const host = document.createElement("div");
  document.body.append(host);
  const root = createRoot(host);
  mounted = { root, host };
  await act(async () => {
    root.render(<App backend={backend} />);
    await Promise.resolve();
  });
  await flush();
  return { host, unmount: cleanup };
}

export function cleanup(): void {
  if (!mounted) return;
  const { root, host } = mounted;
  act(() => {
    root.unmount();
  });
  host.remove();
  mounted = null;
  document.body.replaceChildren();
}

function visibleText(element: Element): string {
  return element.textContent.replace(/\s+/g, " ").trim();
}

function nameOf(element: Element): string {
  return element.getAttribute("aria-label") ?? visibleText(element);
}

/** All elements matching `selector` in the whole document (dialogs live in portals). */
export function all(selector: string): HTMLElement[] {
  return Array.from(document.querySelectorAll<HTMLElement>(selector));
}

/** The button (or menu item, tab, option) whose name contains `text`. Throws when missing. */
export function button(text: string | RegExp): HTMLElement {
  // Inside an open dialog or menu first: that is where the person is.
  const scope = all('[role="menu"]').at(-1) ?? dialog();
  const selector = 'button, [role="menuitem"], [role="tab"], [role="option"], summary';
  const candidates = [
    ...(scope ? Array.from(scope.querySelectorAll<HTMLElement>(selector)) : []),
    ...all(selector),
  ];
  const found = candidates.find((element) => {
    const name = nameOf(element);
    return typeof text === "string" ? name.includes(text) : text.test(name);
  });
  if (!found) {
    const names = all("button").map(nameOf).join(" | ");
    throw new Error(`No button "${String(text)}". Buttons: ${names}`);
  }
  return found;
}

export function maybeButton(text: string): HTMLElement | undefined {
  return all('button, [role="menuitem"]').find((element) => nameOf(element).includes(text));
}

export async function click(target: string | RegExp | HTMLElement): Promise<void> {
  const element = typeof target === "string" || target instanceof RegExp ? button(target) : target;
  await act(async () => {
    element.click();
    await Promise.resolve();
  });
  await flush();
}

export async function key(
  target: Element,
  keyName: string,
  init: KeyboardEventInit = {},
): Promise<void> {
  await act(async () => {
    target.dispatchEvent(
      new KeyboardEvent("keydown", { key: keyName, bubbles: true, cancelable: true, ...init }),
    );
    await Promise.resolve();
  });
  await flush();
}

/** Types into a React-controlled input by setting the value the way React listens for. */
export async function type(input: HTMLElement, value: string): Promise<void> {
  if (!(input instanceof HTMLInputElement)) throw new Error("Not an input");
  const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
  await act(async () => {
    descriptor?.set?.call(input, value);
    input.dispatchEvent(new Event("input", { bubbles: true }));
    await Promise.resolve();
  });
  await flush();
}

/** The input labelled `label`. */
export function field(label: string): HTMLInputElement {
  const labelElement = all("label").find((element) => visibleText(element).includes(label));
  const id = labelElement?.getAttribute("for");
  const input = id ? document.getElementById(id) : labelElement?.querySelector("input");
  if (!(input instanceof HTMLInputElement)) throw new Error(`No field "${label}"`);
  return input;
}

export function text(): string {
  return visibleText(document.body);
}

export function dialog(): HTMLElement | null {
  const dialogs = all('[role="dialog"], [role="alertdialog"]');
  return dialogs[dialogs.length - 1] ?? null;
}

export function dialogTitle(): string {
  const current = dialog();
  const id = current?.getAttribute("aria-labelledby");
  return id ? visibleText(document.getElementById(id) ?? document.body) : "";
}
