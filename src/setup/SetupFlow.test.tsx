// @vitest-environment happy-dom

import { act } from "react";
import { afterEach, describe, expect, it } from "vitest";

import { MOCK_INPUTS } from "../backend/mock/mockBackend";
import {
  all,
  button,
  cleanup,
  click,
  dialogTitle,
  field,
  flush,
  renderApp,
  text,
  type,
} from "../test/harness";

afterEach(() => {
  cleanup();
});

async function wait(ms: number): Promise<void> {
  await act(async () => {
    await new Promise((resolve) => setTimeout(resolve, ms));
  });
  await flush();
}

function heading(): string {
  return document.querySelector("h1")?.textContent ?? "";
}

describe("welcome", () => {
  it("offers three doors, the recovery one quiet", async () => {
    await renderApp("setup");
    expect(heading()).toBe("Willkommen bei Hangar Drive");
    expect(button("Mit Einladungslink starten").className).toContain("primary");
    expect(button("Ich nutze Hangar Drive schon auf einem anderen Gerät").className).toContain(
      "secondary",
    );
    expect(button("Kein Gerät mehr da? Wiederherstellungsblatt nutzen").className).toContain(
      "link-button",
    );
  });
});

describe("new account", () => {
  it("runs through the three steps into the main window", async () => {
    const { mock } = await renderApp("setup");
    await click("Mit Einladungslink starten");
    expect(text()).toContain("Schritt 1 von 3");
    expect(button("Weiter").getAttribute("aria-disabled")).toBe("true");

    await click("Einfügen");
    await wait(400);
    expect(text()).toContain("Verbunden mit drive.example.org");
    expect(field("Name dieses Geräts").value).toBe("Arbeitslaptop");
    await click("Weiter");

    expect(heading()).toBe("Dein Wiederherstellungscode");
    const groups = all(".code-group").map((group) => group.textContent);
    expect(groups).toHaveLength(8);
    expect(all(".code-group")[0]?.getAttribute("aria-label")).toMatch(/^Gruppe 1: D \w \w \w$/);
    await click("Kopieren");
    expect(text()).toContain("Kopiert. Er wird nach 1 Minute aus der Zwischenablage entfernt.");
    await click("Als Datei speichern");
    expect(text()).toContain("Gespeichert: C:\\Users\\Alex\\Documents");
    mock.controls.save = "inSync";
    await click("Als Datei speichern");
    expect(text()).toContain("Speichere den Code nicht in einem synchronisierten Ordner");
    await click("Drucken");
    expect(mock.calls).toContain("printRecoverySheet");

    await click("Ich habe ihn gesichert");
    const match = /Tippe die (\d)\. Gruppe/.exec(text());
    const index = Number(match?.[1]);
    expect(index).toBeGreaterThan(1);
    await type(field(`Gruppe ${String(index)}`), "zzzz");
    await click("Bestätigen");
    expect(text()).toContain("Das passt nicht.");
    await click("Code noch mal ansehen");
    expect(heading()).toBe("Dein Wiederherstellungscode");
    await click("Ich habe ihn gesichert");
    await type(field(`Gruppe ${String(index)}`), ` ${(groups[index - 1] ?? "").toLowerCase()} `);
    await click("Bestätigen");

    expect(heading()).toBe("Wo sollen deine Dateien liegen?");
    expect(text()).toContain("C:\\Users\\Alex\\Hangar Drive");
    await click("Fertig");
    expect(heading()).toBe("Alles bereit");
    expect(text()).toContain("Zieh das Symbol in die Taskleiste");
    await click("Ordner öffnen");
    expect(mock.calls).toContain("openFolder:default");
    expect(heading()).toBe("Alles aktuell");
  });

  it.each([
    ["kein Link", "Das ist kein Einladungslink."],
    ["https://drive.example.org/join#used", "Diese Einladung wurde schon benutzt."],
    ["https://drive.example.org/join#expired", "Diese Einladung ist abgelaufen."],
    ["https://drive.example.org/join#offline", "Der Server aus dem Link antwortet nicht."],
    ["http://drive.example.org/join#x", "Dieser Server ist nicht verschlüsselt erreichbar."],
  ])("explains a bad invite %s while typing", async (link, message) => {
    await renderApp("setup");
    await click("Mit Einladungslink starten");
    await type(field("Einladungslink"), link);
    await wait(400);
    expect(text()).toContain(message);
    expect(button("Weiter").getAttribute("aria-disabled")).toBe("true");
  });

  it("says when the clipboard is empty", async () => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = "";
    await click("Mit Einladungslink starten");
    await click("Einfügen");
    expect(text()).toContain("In der Zwischenablage ist gerade kein Text.");
  });

  it("goes back from step 2 to step 1", async () => {
    await renderApp("setup");
    await click("Mit Einladungslink starten");
    await click("Einfügen");
    await wait(400);
    await click("Weiter");
    await click("Zurück");
    expect(heading()).toBe("Mit deinem Server verbinden");
    expect(field("Einladungslink").value).toBe(MOCK_INPUTS.invite);
  });
});

describe("folder step", () => {
  async function reachFolderStep() {
    const harness = await renderApp("setup");
    await click("Mit Einladungslink starten");
    await click("Einfügen");
    await wait(400);
    await click("Weiter");
    const groups = all(".code-group").map((group) => group.textContent);
    await click("Ich habe ihn gesichert");
    const index = Number(/Tippe die (\d)\./.exec(text())?.[1]);
    await type(field(`Gruppe ${String(index)}`), groups[index - 1] ?? "");
    await click("Bestätigen");
    return harness;
  }

  it.each([
    ["network", "Netzlaufwerke gehen nicht."],
    ["root", "Ein ganzes Laufwerk geht nicht."],
    ["system", "Dieser Ordner gehört zum System."],
    ["nested", "Dieser Ordner liegt in „Hangar Drive“ oder enthält ihn."],
    ["noAccess", "Hangar Drive darf in diesen Ordner nicht schreiben."],
  ] as const)("refuses a %s folder with a reason", async (reason, message) => {
    const { mock } = await reachFolderStep();
    mock.controls.pick = reason;
    await click("Ändern");
    expect(text()).toContain(message);
  });

  it("says that existing files will be uploaded", async () => {
    const { mock } = await reachFolderStep();
    mock.controls.pick = "existing";
    await click("Ändern");
    expect(text()).toContain("Der Ordner enthält schon 214 Dateien, die hochgeladen werden.");
    await click("Fertig");
    expect(mock.calls).toContain("finishSetup");
  });
});

describe("additional device", () => {
  it("pairs with a link and chooses the folders", async () => {
    // A little simulated time, so the waiting screen is visible before the other device answers.
    const { mock } = await renderApp("setup", { timeScale: 0.04 });
    mock.controls.clipboard = MOCK_INPUTS.pair;
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    expect(text()).toContain("Schritt 1 von 2");
    await click("Einfügen");
    expect(text()).toContain("Bestätige jetzt auf deinem anderen Gerät.");
    expect(button("Zahlen anzeigen")).toBeTruthy();
    await wait(1100);
    expect(heading()).toBe("Welche Ordner sollen auf dieses Gerät?");
    expect(text()).toContain("Auf diesem Computer sind 120 GB frei.");
    const boxes = all('.choice-list input[type="checkbox"]');
    expect(boxes.every((box) => box instanceof HTMLInputElement && box.checked)).toBe(true);
    await click("Fertig");
    await wait(200);
    expect(mock.calls).toContain("joinFolders");
    expect(heading()).toBe("Alles aktuell");
  });

  it("shows the numbers at once on the typed path", async () => {
    await renderApp("setup", { timeScale: 0.04 });
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await click("Kein Kopieren möglich? Code abtippen");
    await type(field("Serveradresse"), "drive.example.org");
    await type(field("Kopplungscode"), "7kq2 mx9h trw8 czb3 nf6j aq1v e5");
    await click("Koppeln");
    expect(text()).toContain("Dort steht dieselbe Zahlenreihe:");
    expect(all(".number-group")).toHaveLength(6);
  });

  it.each([
    ["nope", "Das ist kein Kopplungslink."],
    ["hangar-drive://pair#expired", "Dieser Code ist abgelaufen oder wurde schon benutzt."],
    ["hangar-drive://pair#toomany", "Zu viele Versuche."],
    ["hangar-drive://pair#declined", "Das andere Gerät hat abgelehnt."],
    ["hangar-drive://pair#other", "Dieser Code gehört zu einem anderen Konto."],
  ])("explains a failed pairing with %s", async (link, message) => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = link;
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await click("Einfügen");
    await wait(50);
    expect(text()).toContain(message);
  });

  it("warns when the folders do not fit and asks before merging", async () => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = MOCK_INPUTS.pair;
    mock.controls.localFiles = 3;
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await click("Einfügen");
    await wait(1100);
    expect(text()).toContain("Auf diesem Computer sind 120 GB frei.");
    await click("Fertig");
    expect(dialogTitle()).toBe("In diesem Ordner liegen schon 3 Dateien");
    expect(document.activeElement?.textContent).toBe("Zusammenführen");
    await click("Zusammenführen");
    expect(dialogTitle()).toBe("In diesem Ordner liegen schon 3 Dateien");
    await click("Zusammenführen");
    await click("Zusammenführen");
    expect(mock.calls).toContain("joinFolders");
  });

  it("cannot finish without a folder", async () => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = MOCK_INPUTS.pair;
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await click("Einfügen");
    await wait(1100);
    for (const box of all('.choice-list input[type="checkbox"]')) await click(box);
    expect(text()).toContain("Wähle mindestens einen Ordner.");
    expect(button("Fertig").getAttribute("aria-disabled")).toBe("true");
  });
});

describe("recovery with the sheet", () => {
  it("runs through the five screens", async () => {
    const { mock } = await renderApp("setup");
    await click("Kein Gerät mehr da? Wiederherstellungsblatt nutzen");
    expect(text()).toContain("Schritt 1 von 5");
    await type(field("Serveradresse"), "drive.example.org");
    await type(field("Wiederherstellungscode"), "d7kq-m2xp-9h4t-rw8c-zb3n-f6ja-q1ve-k5sy");
    expect(text()).toContain("D7KQ M2XP 9H4T");
    await click("Weiter");
    expect(heading()).toBe("Wie soll dieses Gerät heißen?");
    await click("Weiter");
    expect(heading()).toBe("Alte Geräte entfernen");
    expect(all('.choice-list input[type="checkbox"]')).toHaveLength(3);
    await click(all('.choice-list input[type="checkbox"]')[0] ?? document.body);
    await click("Weiter");
    expect(mock.calls).toContain("finishRecoveryCleanup:2");
    expect(heading()).toBe("Dein Wiederherstellungscode");
    const groups = all(".code-group").map((group) => group.textContent);
    await click("Ich habe ihn gesichert");
    const index = Number(/Tippe die (\d)\./.exec(text())?.[1]);
    await type(field(`Gruppe ${String(index)}`), groups[index - 1] ?? "");
    await click("Bestätigen");
    expect(heading()).toBe("Welche Ordner sollen auf dieses Gerät?");
  });

  it.each([
    ["D7KQ", "Im Code ist ein Tippfehler."],
    ["H7KQ M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY", "Das ist ein Code für Hangar."],
    ["0000 M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY", "Dieser Code gehört zu keinem Konto"],
    ["1111 M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY", "Dieser Code wurde ersetzt."],
  ])("explains a bad code %s", async (code, message) => {
    await renderApp("setup");
    await click("Kein Gerät mehr da? Wiederherstellungsblatt nutzen");
    await type(field("Serveradresse"), "drive.example.org");
    await type(field("Wiederherstellungscode"), code);
    await click("Weiter");
    expect(text()).toContain(message);
  });
});
