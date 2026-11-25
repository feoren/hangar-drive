// @vitest-environment happy-dom

import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { App } from "./App";
import { createTranslator, I18nContext, type Language } from "./i18n";

Reflect.set(globalThis, "IS_REACT_ACT_ENVIRONMENT", true);

let host: HTMLElement;
let root: Root | null = null;

beforeEach(() => {
  host = document.createElement("div");
  document.body.append(host);
  root = createRoot(host);
});

afterEach(() => {
  act(() => {
    root?.unmount();
  });
  root = null;
  host.remove();
});

function show(language: Language) {
  act(() => {
    root?.render(
      <I18nContext.Provider value={createTranslator(language)}>
        <App />
      </I18nContext.Provider>,
    );
  });
}

describe("App", () => {
  it("shows the product name as the window's heading", () => {
    show("en");
    const heading = host.querySelector("h1");
    expect(heading?.textContent).toBe("Hangar Drive");
  });

  it("shows the empty state with the product name filled in", () => {
    show("en");
    const main = host.querySelector("main");
    expect(main?.querySelector("h2")?.textContent).toBe("Nothing synced yet");
    expect(main?.textContent).toContain(
      "Hangar Drive is in early development. Your synced folders will appear here later.",
    );
    expect(main?.textContent).not.toContain("{app}");
  });

  it("labels the empty state by its heading", () => {
    show("en");
    const main = host.querySelector("main");
    const labelId = main?.getAttribute("aria-labelledby");
    expect(labelId).toBeTruthy();
    expect(labelId ? host.querySelector(`#${labelId}`)?.tagName : undefined).toBe("H2");
  });

  it("speaks the language it is given", () => {
    show("de");
    expect(host.querySelector("h2")?.textContent).toBe("Noch nichts synchronisiert");
    expect(host.textContent).toContain("Deine synchronisierten Ordner erscheinen später hier.");
  });
});
