// @vitest-environment happy-dom
// The usability pass (UX concept, "Usability pass"): where the focus lands after each step, the
// steps that were merged or skipped, and the error texts with a next step.

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { BackendError, type BackendErrorCode } from "./backend/errors";
import { MockBackend } from "./backend/mock/mockBackend";
import { createTranslator } from "./i18n";
import {
  all,
  button,
  cleanup,
  click,
  dialog,
  dialogTitle,
  field,
  flush,
  openMenu,
  renderApp,
  renderWith,
  text,
  type,
} from "./test/harness";
import { ARM_DELAY_MS } from "./ui/parts";
import { errorText } from "./ui/useAsync";

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

function focused(): HTMLElement | null {
  return document.activeElement instanceof HTMLElement ? document.activeElement : null;
}

/** Welcome, invite, Next: the recovery code step of a new account. */
async function reachRecoveryCode() {
  const harness = await renderApp("setup");
  await click("Mit Einladungslink starten");
  await click("Einfügen");
  await wait(400);
  button("Weiter").focus();
  await click("Weiter");
  return harness;
}

describe("new account: focus and steps", () => {
  it("puts the focus on the title of each new step, so reading starts there", async () => {
    await reachRecoveryCode();
    expect(focused()?.tagName).toBe("H1");
    expect(focused()?.textContent).toBe("Dein Wiederherstellungscode");
  });

  it("checks the typed group without a button and lands on the finish button", async () => {
    await reachRecoveryCode();
    const groups = all(".code-group").map((group) => group.textContent);
    await click("Ich habe ihn gesichert");
    const index = Number(/Tippe die (\d)\./.exec(text())?.[1]);
    const input = field(`Gruppe ${String(index)}`);
    expect(focused()).toBe(input);
    await type(input, (groups[index - 1] ?? "").slice(0, 3));
    expect(document.querySelector("h1")?.textContent).toBe("Kurz prüfen");
    await type(input, groups[index - 1] ?? "");
    expect(document.querySelector("h1")?.textContent).toBe("Wo sollen deine Dateien liegen?");
    expect(focused()?.textContent).toBe("Fertig");
  });

  it("keeps the focus on a button while its action runs and gives it back after", async () => {
    await reachRecoveryCode();
    const save = button("Als Datei speichern");
    save.focus();
    await click(save);
    expect(text()).toContain("Gespeichert:");
    expect(focused()).toBe(save);
  });
});

describe("recovery: nothing to remove", () => {
  it("passes the step of old devices by itself when the account has none", async () => {
    const mock = new MockBackend({ scenario: "setup" });
    await mock.setLanguage("de");
    mock.recoveryDevices = () => Promise.resolve([]);
    await renderWith(mock);
    await click("Kein Gerät mehr da? Wiederherstellungsblatt nutzen");
    await type(field("Link vom Blatt"), "hangar-drive://recover#AQ3f9a12c0sheet");
    await wait(400);
    await type(field("Wiederherstellungscode"), "D7KQ M2XP 9H4T 6RWB 3NCF 8VJA 5GYE 2SZD");
    await click("Weiter");
    expect(mock.calls).toContain("finishRecoveryCleanup:0");
    expect(document.querySelector("h1")?.textContent).toBe("Dein Wiederherstellungscode");
  });

  it("stops loading and offers Next again when passing the empty step fails", async () => {
    const mock = new MockBackend({ scenario: "setup" });
    await mock.setLanguage("de");
    mock.recoveryDevices = () => Promise.resolve([]);
    mock.finishRecoveryCleanup = () => Promise.reject(new BackendError("busy", "test"));
    await renderWith(mock);
    await click("Kein Gerät mehr da? Wiederherstellungsblatt nutzen");
    await type(field("Link vom Blatt"), "hangar-drive://recover#AQ3f9a12c0sheet");
    await wait(400);
    await type(field("Wiederherstellungscode"), "D7KQ M2XP 9H4T 6RWB 3NCF 8VJA 5GYE 2SZD");
    await click("Weiter");
    expect(document.querySelector("h1")?.textContent).toBe("Alte Geräte entfernen");
    expect(document.querySelector(".loading")).toBeNull();
    expect(document.querySelector(".feedback")).not.toBeNull();
    expect(button("Weiter").getAttribute("aria-disabled")).toBe("false");
  });
});

describe("add folder", () => {
  it("brings a deleted folder back onto this device in one click", async () => {
    const { mock } = await renderApp();
    await click("Ordner hinzufügen");
    // The size helps to decide whether a folder fits on this device.
    expect(dialog()?.textContent).toMatch(/Musik\s+18,3\sGB/);
    await click("Zurückholen");
    expect(mock.calls).toContain("restoreDeletedFolder");
    expect(mock.calls).toContain("addAccountFolder");
    expect(dialog()).toBeNull();
    expect(button("Altes Projekt, C:\\Users\\Alex\\Hangar Drive\\Altes Projekt")).toBeTruthy();
  });

  it("opens the picker at once when the other devices have nothing to offer", async () => {
    const { mock } = await renderApp();
    await click("Ordner hinzufügen");
    await click("Hierher holen");
    await click("Ordner hinzufügen");
    await click("Zurückholen");
    mock.calls.length = 0;
    mock.controls.pick = "cancel";
    await click("Ordner hinzufügen");
    expect(mock.calls).toContain("pickFolder");
    expect(dialog()).toBeNull();
    mock.controls.pick = "network";
    await click("Ordner hinzufügen");
    expect(dialogTitle()).toBe("Ordner hinzufügen");
    expect(dialog()?.textContent).toContain("Netzlaufwerke gehen nicht.");
    mock.controls.pick = "ok";
    await click(button(/^Ordner hinzufügen$/));
    expect(dialog()).toBeNull();
    expect(button("Projekte 2027")).toBeTruthy();
  });
});

describe("devices", () => {
  it("removes a device not seen for long right from its hint", async () => {
    const { mock } = await renderApp();
    await openMenu("Geräte");
    await click("Entfernen: Alter Laptop");
    expect(mock.calls.some((call) => call.startsWith("removeDevice"))).toBe(true);
    expect(text()).toContain("„Alter Laptop“ wurde entfernt.");
  });
});

describe("restore", () => {
  it("hands the focus to the next file when a restored one leaves the trash", async () => {
    await renderApp();
    await click(button("Aktionen für „Hangar Drive“"));
    await click("Papierkorb");
    const before = all(".dialog button").filter(
      (element) => element.textContent === "Wiederherstellen",
    );
    const first = before[0];
    const second = before[1];
    if (!first || !second) throw new Error("trash rows missing");
    first.focus();
    await click(first);
    await flush();
    expect(first.isConnected).toBe(false);
    expect(focused()).toBe(second);
  });

  it("offers the reset first after 'Undo a device', with the focus on it", async () => {
    await renderApp("removedHeads");
    await wait(ARM_DELAY_MS + 50);
    await click("Ansehen und rückgängig machen");
    const reset = button("Ganzen Ordner auf diesen Stand zurücksetzen");
    expect(reset.className).toContain("primary");
    expect(focused()).toBe(reset);
  });
});

describe("row menu", () => {
  it("moves a menu that would leave the window back inside it", async () => {
    await renderApp();
    vi.spyOn(HTMLElement.prototype, "getBoundingClientRect").mockImplementation(function (
      this: HTMLElement,
    ) {
      const menu = this.getAttribute("role") === "menu";
      const top = menu ? Number.parseFloat(this.style.top || "0") : 300;
      const height = menu ? 260 : 28;
      return new DOMRect(400, top, 200, height);
    });
    Object.defineProperty(window, "innerHeight", { value: 420, configurable: true });
    await click(button("Aktionen für „Hangar Drive“"));
    const menu = document.querySelector<HTMLElement>('[role="menu"]');
    const top = Number.parseFloat(menu?.style.top ?? "");
    expect(top + 260).toBeLessThanOrEqual(420 - 8);
    expect(menu?.style.maxHeight).toBe("404px");
  });
});

describe("error texts", () => {
  const codes: readonly BackendErrorCode[] = [
    "notImplemented",
    "busy",
    "locked",
    "badResponse",
    "updatesOff",
    "unexpected",
  ];

  it("say for every code of the bridge what happened and what to do now", () => {
    const t = createTranslator("de");
    for (const code of codes) {
      const sentence = errorText(new BackendError(code, "test"), t);
      // At least two sentences: what happened, then the next step.
      expect(sentence.split(". ").length, code).toBeGreaterThanOrEqual(2);
    }
    expect(errorText(new BackendError("locked", "test"), t)).toBe(
      "Eine Datei ist gerade in einem anderen Programm geöffnet. Schließ sie und versuch es noch mal.",
    );
    expect(errorText(new Error("boom"), t)).toContain("Versuch es noch mal.");
  });
});
