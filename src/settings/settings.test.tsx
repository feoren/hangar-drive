// @vitest-environment happy-dom

import { afterEach, describe, expect, it } from "vitest";

import { all, cleanup, click, dialogTitle, field, renderApp, text } from "../test/harness";

afterEach(() => {
  cleanup();
});

describe("settings (UX 11)", () => {
  it("has only autostart and language, then account and about", async () => {
    await renderApp();
    await click("Einstellungen");
    expect(dialogTitle()).toBe("Einstellungen");
    expect(all('[role="dialog"] input[type="checkbox"], [role="dialog"] select')).toHaveLength(2);
    expect(text()).toContain("Server: drive.example.org");
    expect(text()).toContain("Versionen bleiben 30 Tage erhalten.");
    expect(text()).toContain("Version 0.1.0");
    expect(text()).toContain("Deine Dateien liegen auf diesem Computer unverschlüsselt.");
    expect(text()).toContain("Auf dem Server sind deine Dateien verschlüsselt.");
  });

  it("switches autostart", async () => {
    const { mock } = await renderApp();
    await click("Einstellungen");
    const toggle = field("Beim Anmelden starten");
    expect(toggle.checked).toBe(true);
    expect(toggle.getAttribute("role")).toBe("switch");
    await click(toggle);
    expect(mock.calls).toContain("setAutostart");
    expect(field("Beim Anmelden starten").checked).toBe(false);
  });

  it("lists every language by its own name, the system first", async () => {
    await renderApp();
    await click("Einstellungen");
    const options = all("select option").map((option) => option.textContent);
    expect(options[0]).toBe("Wie das System");
    expect(options).toContain("Ελληνικά");
    expect(options).toContain("简体中文");
    expect(options).toHaveLength(13);
  });

  it("shows the error report before saving it", async () => {
    const { mock } = await renderApp();
    await click("Einstellungen");
    await click("Fehlerbericht speichern");
    expect(text()).toContain("Das steht im Fehlerbericht");
    expect(document.querySelector(".report-preview")?.textContent).toContain("Hangar Drive 0.1.0");
    await click("Speichern");
    expect(mock.calls).toContain("saveErrorReport");
    expect(text()).toContain("Gespeichert: C:\\Users\\Alex\\Documents");
  });

  it("lists the keyboard shortcuts in the help", async () => {
    await renderApp();
    await click("Hilfe");
    expect(all("kbd").map((element) => element.textContent)).toEqual([
      "F1",
      "Strg+,",
      "Strg+Umschalt+D",
      "Esc",
      "Umschalt+F10",
    ]);
  });
});
