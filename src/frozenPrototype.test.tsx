// @vitest-environment happy-dom

// tauri.conf.json sets `app.security.freezePrototype`, so Tauri runs `Object.freeze(Object.prototype)`
// before the page's own scripts. Each test file runs in its own context, so freezing here leaves
// the other tests alone; the window must start and work as usual under it.

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import { cleanup, click, dialogTitle, openMenu, renderApp, text } from "./test/harness";

// After the test runner set itself up (its fake clock would trip over the frozen prototype,
// which the app never uses), as Tauri does before the page.
beforeAll(() => {
  Object.freeze(Object.prototype);
});

afterEach(() => {
  cleanup();
});

describe("the window with a frozen Object.prototype", () => {
  it("starts, opens views and dialogs", async () => {
    expect(Object.isFrozen(Object.prototype)).toBe(true);
    await renderApp("conflicts");
    await click("Ansehen");
    expect(dialogTitle()).toBe("Dateien in zwei Fassungen");
    await click("Schließen");
    await openMenu("Letzte Aktivitäten");
    expect(text()).toContain("Bericht.docx");
  });

  it("runs the first start", async () => {
    await renderApp("setup");
    expect(text().length).toBeGreaterThan(0);
  });
});
