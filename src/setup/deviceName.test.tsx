// @vitest-environment happy-dom
// Rule N5 in the views: device names are trimmed before sending; a blank name is refused at the
// field, and the backend's own refusal is shown there too.

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BackendError } from "../backend/errors";
import { button, cleanup, click, field, flush, renderApp, text, type } from "../test/harness";

const FILLER = String.fromCharCode(0x3164);

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

async function wait(ms: number): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, ms));
  });
  await flush();
}

async function toConnectWithName() {
  const harness = await renderApp("setup");
  await click("Mit Einladungslink starten");
  await click("Einfügen");
  await wait(400);
  return harness;
}

describe("device name in the setup", () => {
  it("sends ' Laptop ' trimmed", async () => {
    const { mock } = await toConnectWithName();
    const begin = vi.spyOn(mock, "beginAccount");
    await type(field("Name dieses Geräts"), " Laptop ");
    await click("Weiter");
    expect(begin).toHaveBeenCalledWith(expect.any(String), "Laptop");
    expect(document.querySelector("h1")?.textContent).toBe("Dein Wiederherstellungscode");
  });

  it("refuses a name of only filler characters at the field", async () => {
    const { mock } = await toConnectWithName();
    await type(field("Name dieses Geräts"), FILLER);
    expect(text()).toContain("Der Name ist leer. Gib einen Namen mit sichtbaren Zeichen ein.");
    expect(field("Name dieses Geräts").getAttribute("aria-invalid")).toBe("true");
    expect(button("Weiter").getAttribute("aria-disabled")).toBe("true");
    await click("Weiter");
    expect(mock.calls).not.toContain("beginAccount");
  });

  it("shows the backend's refusal at the field until the name changes", async () => {
    const { mock } = await toConnectWithName();
    vi.spyOn(mock, "beginAccount").mockResolvedValue({ ok: false, error: "edgeWhitespace" });
    await click("Weiter");
    expect(text()).toContain("Der Name darf nicht mit einem Leerzeichen beginnen oder enden.");
    await type(field("Name dieses Geräts"), "Büro");
    expect(text()).not.toContain("Der Name darf nicht mit einem Leerzeichen");
  });
});

describe("device name in the recovery", () => {
  it("trims and refuses at the field", async () => {
    const { mock } = await renderApp("setup");
    await click("Kein Gerät mehr da? Wiederherstellungsblatt nutzen");
    await type(field("Serveradresse"), "drive.example.org");
    await type(field("Wiederherstellungscode"), "D7KQ M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY");
    await click("Weiter");
    const setName = vi.spyOn(mock, "setDeviceName");
    await type(field("Name dieses Geräts"), FILLER);
    expect(text()).toContain("Der Name ist leer.");
    await click("Weiter");
    expect(setName).not.toHaveBeenCalled();
    await type(field("Name dieses Geräts"), " Laptop ");
    await click("Weiter");
    expect(setName).toHaveBeenCalledWith("Laptop");
    expect(document.querySelector("h1")?.textContent).toBe("Alte Geräte entfernen");
  });
});

describe("renaming a device", () => {
  it("trims, refuses blank names and shows the backend's answer", async () => {
    const { mock } = await renderApp();
    await click("Geräte");
    await click("Aktionen für „Büro-PC“");
    await click("Umbenennen");
    await type(field("Name"), FILLER);
    expect(text()).toContain("Der Name ist leer.");
    const rename = vi.spyOn(mock, "renameDevice");
    rename.mockResolvedValueOnce({ ok: false, error: "blank" });
    await type(field("Name"), "Neu");
    await click("Speichern");
    expect(text()).toContain("Der Name ist leer.");
    await type(field("Name"), " Laptop ");
    await click("Speichern");
    expect(rename).toHaveBeenLastCalledWith("d-office", "Laptop");
    expect(button("Laptop, zuletzt")).toBeTruthy();
  });

  it("keeps an unexpected failure apart from the name rule", async () => {
    const { mock } = await renderApp();
    await click("Geräte");
    await click("Aktionen für „Büro-PC“");
    await click("Umbenennen");
    vi.spyOn(mock, "renameDevice").mockRejectedValue(
      new BackendError("unexpected", "rename_device"),
    );
    await click("Speichern");
    expect(text()).toContain("Etwas ist schiefgegangen.");
  });
});
