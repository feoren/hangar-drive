// @vitest-environment happy-dom

import { act } from "react";
import { afterEach, describe, expect, it } from "vitest";

import {
  all,
  button,
  cleanup,
  click,
  dialog,
  dialogTitle,
  field,
  flush,
  key,
  renderApp,
  text,
  type,
} from "../test/harness";
import { ARM_DELAY_MS } from "../ui/parts";

afterEach(() => {
  cleanup();
});

async function wait(ms: number): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, ms));
  });
  await flush();
}

async function openDevices(scenario: Parameters<typeof renderApp>[0] = "upToDate") {
  const harness = await renderApp(scenario, { timeScale: 0.001 });
  await click("Geräte");
  return harness;
}

describe("devices (UX 10)", () => {
  it("lists this device first, the others with last seen, a long absent one with a hint", async () => {
    await openDevices();
    expect(dialogTitle()).toBe("Deine Geräte");
    const rows = all(".device-row .row-main").map((row) => row.getAttribute("aria-label"));
    expect(rows[0]).toMatch(/^Arbeitslaptop, Dieses Gerät, seit /);
    expect(rows[1]).toMatch(/^Büro-PC, zuletzt vor 5 Min\./);
    expect(rows[2]).toContain("Lange nicht gesehen. Entferne es, wenn du es nicht mehr hast.");
    expect(text()).toContain("Wiederherstellungscode");
  });

  it("renames a device", async () => {
    const { mock } = await openDevices();
    await click("Aktionen für „Büro-PC“");
    await click("Umbenennen");
    await type(field("Name"), "");
    expect(text()).toContain("Der Name ist leer. Gib einen Namen mit sichtbaren Zeichen ein.");
    await type(field("Name"), "Büro");
    await click("Speichern");
    expect(mock.calls).toContain("renameDevice");
    expect(button("Büro, zuletzt")).toBeTruthy();
  });

  it("shows the safety number group by group", async () => {
    await openDevices();
    await click("Aktionen für „Büro-PC“");
    await click("Sicherheitsnummer anzeigen");
    expect(dialogTitle()).toBe("Sicherheitsnummer von „Büro-PC“");
    expect(all(".number-group")).toHaveLength(6);
  });

  it("removes a device after naming the one limit", async () => {
    const { mock } = await openDevices();
    await click("Aktionen für „Alter Laptop“");
    await click("Entfernen");
    expect(dialog()?.textContent).toContain(
      "kann auf einem anderen Gerät nichts aus der Ferne löschen",
    );
    expect(document.activeElement?.textContent).toBe("Abbrechen");
    await click(button(/^Entfernen$/));
    expect(mock.calls).toContain("removeDevice:d-old");
    expect(text()).toContain("„Alter Laptop“ wurde entfernt.");
  });

  it("disconnects this device, the only one only after a second question", async () => {
    const { mock } = await openDevices();
    await click("Aktionen für „Alter Laptop“");
    await click("Entfernen");
    await click(button(/^Entfernen$/));
    await click("Aktionen für „Büro-PC“");
    await click("Entfernen");
    await click(button(/^Entfernen$/));
    await click("Aktionen für „Arbeitslaptop“");
    await click("Dieses Gerät trennen");
    await click(button(/^Dieses Gerät trennen$/));
    expect(text()).toContain("Das ist dein einziges Gerät.");
    expect(mock.calls).not.toContain("disconnectThisDevice");
    await click("Trotzdem trennen");
    expect(mock.calls).toContain("disconnectThisDevice");
  });

  it("creates a new recovery code and checks one group", async () => {
    await openDevices();
    await click("Neu erzeugen");
    expect(text()).toContain("Der neue Code ersetzt den alten.");
    const groups = all(".code-group").map((group) => group.textContent);
    await click("Ich habe ihn gesichert");
    const index = Number(/Tippe die (\d)\./.exec(text())?.[1]);
    await type(field(`Gruppe ${String(index)}`), groups[index - 1] ?? "");
    await click("Bestätigen");
    expect(text()).toContain("Neuer Code gilt. Der alte funktioniert nicht mehr.");
  });
});

describe("adding a device (UX 5)", () => {
  it("shows a code and link valid until a fixed time", async () => {
    const { mock } = await openDevices();
    mock.controls.pairAnswer = "none";
    await click("Gerät hinzufügen");
    expect(dialogTitle()).toBe("Neues Gerät hinzufügen");
    expect(document.querySelector("svg.qr")?.getAttribute("aria-label")).toBe(
      "QR-Code mit dem Kopplungslink",
    );
    expect(text()).toMatch(/Gültig bis \d\d:\d\d, nur für ein Gerät\./);
    await click("Link kopieren");
    expect(text()).toContain(
      "Link kopiert. Er wird nach 1 Minute aus der Zwischenablage entfernt.",
    );
    await click("Kein Kopieren möglich? Code zum Abtippen zeigen");
    expect(text()).toContain("Serveradresse: drive.example.org");
  });

  it("adds a device that answered through the link, after one question", async () => {
    const { mock } = await openDevices();
    await click("Gerät hinzufügen");
    await wait(30);
    expect(dialogTitle()).toBe("„MacBook“ möchte dazukommen.");
    expect(document.activeElement?.textContent).toBe("Ablehnen");
    const add = button(/^Hinzufügen$/);
    await click(add);
    expect(mock.calls).not.toContain("answerPairRequest:accept");
    await wait(ARM_DELAY_MS + 50);
    await click(add);
    expect(mock.calls).toContain("answerPairRequest:accept");
    expect(text()).toContain("„MacBook“ ist jetzt dabei.");
  });

  it("makes the comparison part of the question on the typed path", async () => {
    const { mock } = await openDevices();
    mock.controls.pairAnswer = "typed";
    await click("Gerät hinzufügen");
    await wait(30);
    expect(text()).toContain("Stimmt sie mit dieser hier überein?");
    expect(all(".number-group")).toHaveLength(6);
    await click("Nein, abbrechen");
    expect(mock.calls).toContain("answerPairRequest:decline");
    expect(text()).toContain("Dann füge das Gerät nicht hinzu.");
  });

  it("declines with Escape", async () => {
    const { mock } = await openDevices();
    await click("Gerät hinzufügen");
    await wait(30);
    await key(dialog() ?? document.body, "Escape");
    expect(mock.calls).toContain("answerPairRequest:decline");
  });
});
