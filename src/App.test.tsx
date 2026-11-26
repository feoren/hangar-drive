// @vitest-environment happy-dom

import { afterEach, describe, expect, it, vi } from "vitest";

import { MockBackend } from "./backend/mock/mockBackend";
import { TauriBackend } from "./backend/tauri/tauriBackend";
import {
  all,
  button,
  cleanup,
  click,
  dialogTitle,
  flush,
  key,
  renderApp,
  renderWith,
  text,
} from "./test/harness";

afterEach(() => {
  cleanup();
});

describe("App", () => {
  it("shows the setup on first start and the main window afterwards", async () => {
    await renderApp("setup");
    expect(text()).toContain("Willkommen bei Hangar Drive");
    cleanup();
    await renderApp("upToDate");
    expect(document.querySelector("h1")?.textContent).toBe("Alles aktuell");
  });

  it("speaks the language from the settings", async () => {
    const mock = new MockBackend();
    await mock.setLanguage("en");
    await renderWith(mock);
    expect(document.querySelector("h1")?.textContent).toBe("Up to date");
    expect(document.documentElement.lang).toBe("en");
  });

  it("changes the language at once when the person picks another one", async () => {
    const { mock } = await renderApp();
    await click("Einstellungen");
    const select = all("select")[0];
    if (!(select instanceof HTMLSelectElement)) throw new Error("no select");
    select.value = "fr";
    select.dispatchEvent(new Event("change", { bubbles: true }));
    await flush();
    expect(dialogTitle()).toBe(document.querySelector('[role="dialog"] h2')?.textContent);
    expect(mock.calls).toContain("setLanguage:fr");
    expect(document.documentElement.lang).toBe("fr");
  });

  it("keeps the tray in step with the window", async () => {
    const { mock } = await renderApp("paused");
    expect(mock.tray?.icon).toBe("paused");
    expect(mock.tray?.tooltip).toMatch(/^Hangar Drive: Angehalten bis /);
    await click("Fortsetzen");
    expect(mock.tray?.icon).toBe("upToDate");
  });

  it("runs the actions chosen in the tray menu", async () => {
    const { mock } = await renderApp("upToDate");
    mock.clickTray("pause:hour");
    await flush();
    expect(mock.calls).toContain("pause:hour");
    mock.clickTray("open-folder:f-photos");
    await flush();
    expect(mock.calls).toContain("openFolder:f-photos");
    mock.clickTray("quit");
    await flush();
    expect(mock.calls).toContain("quit");
  });

  it("brings the banner forward when a notification is clicked", async () => {
    const { mock } = await renderApp("many");
    // The mass deletion question opens by itself; close it first.
    await key(document.activeElement ?? document.body, "Escape");
    expect(document.querySelector(".banner-title")?.textContent).toBe("342 Dateien gelöscht");
    mock.clickNotification("w-conflicts");
    await flush();
    expect(document.querySelector(".banner-title")?.textContent).toBe(
      "2 Dateien gibt es in zwei Fassungen",
    );
    expect(document.activeElement?.classList.contains("banner")).toBe(true);
    expect(mock.calls).toContain("showWindow");
  });

  it("says so when the app on the Tauri side cannot do something yet", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const mock = new MockBackend();
    const snapshot = await mock.getSnapshot();
    const tauri = new TauriBackend(
      (command) => {
        if (command === "get_snapshot")
          return Promise.resolve(JSON.parse(JSON.stringify(snapshot)));
        if (command === "update_tray") return Promise.resolve(null);
        return Promise.reject(new Error(`command ${command} not found`));
      },
      () => Promise.resolve(() => undefined),
    );
    await renderWith(tauri);
    await click("Settings");
    expect(text()).toContain("This version of Hangar Drive cannot do that yet.");
    expect(button("Close")).toBeTruthy();
    warn.mockRestore();
  });
});
