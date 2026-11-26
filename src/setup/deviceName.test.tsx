// @vitest-environment happy-dom
// Rule N5 in the views: device names are trimmed before sending; a blank name is refused at the
// field, and the backend's own refusal is shown there too.

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BackendError } from "../backend/errors";
import { MOCK_INPUTS } from "../backend/mock/mockBackend";
import { button, cleanup, click, field, flush, renderApp, text, type } from "../test/harness";
import { ARM_DELAY_MS } from "../ui/parts";

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
    await type(field("Link vom Blatt"), MOCK_INPUTS.recoverLink);
    await wait(400);
    await type(field("Wiederherstellungscode"), "D7KQ M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY");
    const recover = vi.spyOn(mock, "recoverAccount");
    await type(field("Name dieses Geräts"), FILLER);
    expect(text()).toContain("Der Name ist leer.");
    await click("Weiter");
    expect(recover).not.toHaveBeenCalled();
    await type(field("Name dieses Geräts"), " Laptop ");
    await click("Weiter");
    expect(recover).toHaveBeenCalledWith(
      MOCK_INPUTS.recoverLink,
      "D7KQM2XP9H4TRW8CZB3NF6JAQ1VEK5SY",
      "Laptop",
    );
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

describe("device name in the pairing", () => {
  async function toPairing() {
    const harness = await renderApp("setup", { timeScale: 0.04 });
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    return harness;
  }

  it("sends ' Laptop ' trimmed with the link", async () => {
    const { mock } = await toPairing();
    const start = vi.spyOn(mock, "startPairing");
    await type(field("Name dieses Geräts"), " Laptop ");
    await type(field("Kopplungslink"), MOCK_INPUTS.pair);
    await click("Koppeln");
    await wait(ARM_DELAY_MS + 50);
    await click("Verbinden");
    expect(start).toHaveBeenCalledWith({ kind: "link", link: MOCK_INPUTS.pair }, "Laptop");
    expect(text()).toContain("Bestätige jetzt auf deinem anderen Gerät.");
  });

  it("refuses a blank name at the field before anything is sent", async () => {
    const { mock } = await toPairing();
    await type(field("Kopplungslink"), MOCK_INPUTS.pair);
    await type(field("Name dieses Geräts"), FILLER);
    expect(text()).toContain("Der Name ist leer.");
    expect(button("Koppeln").getAttribute("aria-disabled")).toBe("true");
    await click("Koppeln");
    expect(mock.calls).not.toContain("inspectLink");
    expect(mock.calls).not.toContain("startPairing");
  });

  it("shows the backend's refusal at the field", async () => {
    const { mock } = await toPairing();
    vi.spyOn(mock, "startPairing").mockResolvedValue({ ok: false, error: "edgeWhitespace" });
    await type(field("Kopplungslink"), MOCK_INPUTS.pair);
    await click("Koppeln");
    await wait(ARM_DELAY_MS + 50);
    await click("Verbinden");
    expect(text()).toContain("Der Name darf nicht mit einem Leerzeichen beginnen oder enden.");
    expect(field("Name dieses Geräts").getAttribute("aria-invalid")).toBe("true");
  });
});
