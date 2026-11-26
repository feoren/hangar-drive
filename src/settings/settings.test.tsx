// @vitest-environment happy-dom

import { afterEach, describe, expect, it, vi } from "vitest";

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

  // ADR 0002: internally X.Y.Z+B, shown as X.Y.Z-B, whether the build number comes with the version
  // (release build) or separately (development build).
  it.each([
    { version: "0.1.0+12", build: null },
    { version: "0.1.0", build: 12 },
    { version: "0.1.0+12", build: 12 },
  ])("shows $version with build $build as Version 0.1.0-12", async (about) => {
    const { mock } = await renderApp();
    vi.spyOn(mock, "getAbout").mockResolvedValue({ ...about, updates: true });
    await click("Einstellungen");
    const line = all('[role="dialog"] .info-line')
      .map((element) => element.textContent)
      .find((content) => content.startsWith("Version "));
    expect(line).toBe("Version 0.1.0-12");
  });
});

describe("reset this device", () => {
  it("asks once in place, then goes back to the welcome", async () => {
    const { mock } = await renderApp();
    await click("Einstellungen");
    expect(text()).toContain("Hilfe");
    await click("Dieses Gerät zurücksetzen");
    expect(text()).toContain("Dieses Gerät wirklich zurücksetzen?");
    expect(document.activeElement?.textContent).toBe("Abbrechen");
    await click("Abbrechen");
    expect(mock.calls).not.toContain("resetDevice");
    expect(document.activeElement?.textContent).toBe("Dieses Gerät zurücksetzen");
    await click("Dieses Gerät zurücksetzen");
    await click("Zurücksetzen");
    expect(mock.calls).toContain("resetDevice");
    expect(document.querySelector("h1")?.textContent).toBe("Willkommen bei Hangar Drive");
  });
});
