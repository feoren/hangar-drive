// @vitest-environment happy-dom

import { act } from "react";
import { afterEach, describe, expect, it } from "vitest";

import { MOCK_INPUTS, MockBackend } from "../backend/mock/mockBackend";
import { TauriBackend } from "../backend/tauri/tauriBackend";
import {
  all,
  button,
  cleanup,
  click,
  field,
  flush,
  renderApp,
  renderWith,
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
    mock.controls.save = "inCloud";
    await click("Anderen Ort wählen");
    expect(text()).toContain("Dieser Ordner wird mit einer Cloud synchronisiert.");
    expect(text()).toContain("zum Beispiel in „Downloads“ oder auf einem USB-Stick.");
    mock.controls.save = "saved";
    await click("Anderen Ort wählen");
    expect(text()).toContain("Gespeichert: C:\\Users\\Alex\\Documents");
    expect(text()).not.toContain("Dieser Ordner wird mit einer Cloud synchronisiert.");
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

  // The shell only hands over a link or code of the app (security review L2); anything else
  // arrives as "", like an empty clipboard.
  it.each([
    ["empty", ""],
    ["other text", "Einkaufsliste: Milch, Brot"],
  ])("says calmly that there is no link on the clipboard: %s", async (_, clipboard) => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = clipboard;
    await click("Mit Einladungslink starten");
    await click("Einfügen");
    expect(text()).toContain("In der Zwischenablage ist kein Link von Hangar Drive.");
    expect(field("Einladungslink").value).toBe("");
    expect(all(".error-text").every((element) => element.textContent === "")).toBe(true);
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
  /** From the welcome screen through the server question (N2) up to the waiting screen. */
  async function pastServerQuestion(link: string = MOCK_INPUTS.pair, timeScale = 0.04) {
    const harness = await renderApp("setup", { timeScale });
    harness.mock.controls.clipboard = link;
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await click("Einfügen");
    expect(heading()).toBe("Mit diesem Server verbinden?");
    await wait(ARM_DELAY_MS + 50);
    await click("Verbinden");
    return harness;
  }

  it("asks before connecting: server in punycode, account, connect held back", async () => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = MOCK_INPUTS.pairIdn;
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await click("Einfügen");
    expect(heading()).toBe("Mit diesem Server verbinden?");
    expect(text()).toContain("xn--drve-6pa.example.org");
    expect(text()).toContain("3f9a 12c0 8b7e 44d1 a0b2 c3d4 e5f6 0718");
    expect(document.activeElement?.textContent).toBe("Zurück");
    expect(button("Verbinden").getAttribute("aria-disabled")).toBe("true");
    await click("Verbinden");
    expect(mock.calls).not.toContain("startPairing");
    await wait(ARM_DELAY_MS + 50);
    expect(button("Verbinden").getAttribute("aria-disabled")).toBe("false");
    await click("Verbinden");
    expect(mock.calls).toContain("startPairing");
  });

  it("goes back from the server question without sending anything", async () => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = MOCK_INPUTS.pair;
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await click("Einfügen");
    await click("Zurück");
    expect(heading()).toBe("Mit deinem anderen Gerät koppeln");
    expect(mock.calls).not.toContain("startPairing");
  });

  it("warns calmly when the pairing link pins a server", async () => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = MOCK_INPUTS.pairPinned;
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await click("Einfügen");
    expect(text()).toContain("Dieser Server hat kein öffentliches Zertifikat.");
    expect(document.querySelector(".notice")?.getAttribute("role")).toBe("note");
  });

  it("pairs with a link, shows the account's devices and chooses the folders", async () => {
    const { mock } = await pastServerQuestion();
    expect(text()).toContain("Bestätige jetzt auf deinem anderen Gerät.");
    expect(button("Zahlen anzeigen")).toBeTruthy();
    await wait(1100);
    expect(heading()).toBe("Das sind deine Geräte?");
    expect(text()).toContain("Büro-PC");
    await click("Ja, das sind meine");
    expect(heading()).toBe("Welche Ordner sollen auf dieses Gerät?");
    expect(text()).toContain("Auf diesem Computer sind 120 GB frei.");
    const boxes = all('.choice-list input[type="checkbox"]');
    expect(boxes.every((box) => box instanceof HTMLInputElement && box.checked)).toBe(true);
    await click("Fertig");
    await wait(200);
    expect(mock.calls).toContain("joinFolders");
    expect(heading()).toBe("Alles aktuell");
  });

  it("disconnects again when the devices are strangers", async () => {
    const { mock } = await pastServerQuestion(MOCK_INPUTS.pairStranger);
    await wait(1100);
    expect(heading()).toBe("Das sind deine Geräte?");
    expect(text()).toContain("DESKTOP-7Q2KF0M");
    await click("Nein, abbrechen");
    expect(mock.calls).toContain("disconnectThisDevice");
    expect(mock.calls).not.toContain("joinFolders");
    expect(heading()).toBe("Mit deinem anderen Gerät koppeln");
    expect(text()).toContain("Abgebrochen. Dieses Gerät ist wieder getrennt");
  });

  it("disconnects for real on the Tauri path when the devices are strangers", async () => {
    // The window on the real bridge: every command goes through `invoke` by its snake_case name
    // and comes back through the decoders, answered by the mock as the shell would.
    const mock = new MockBackend({ scenario: "setup", timeScale: 0.04 });
    await mock.setLanguage("de");
    mock.controls.clipboard = MOCK_INPUTS.pairStranger;
    const invoked: string[] = [];
    const json = (value: unknown): unknown => JSON.parse(JSON.stringify(value ?? null));
    const text = (value: unknown): string => (typeof value === "string" ? value : "");
    const routes: Record<string, (args: Record<string, unknown>) => Promise<unknown>> = {
      get_snapshot: () => mock.getSnapshot(),
      get_settings: () => mock.getSettings(),
      update_tray: () => Promise.resolve(null),
      read_clipboard_text: () => mock.readClipboardText(),
      inspect_link: (args) => mock.inspectLink(text(args.link)),
      default_device_name: () => mock.defaultDeviceName(),
      start_pairing: (args) => {
        const input = args.input;
        const link =
          typeof input === "object" && input !== null && "link" in input ? text(input.link) : "";
        return mock.startPairing({ kind: "link", link }, text(args.deviceName));
      },
      list_devices: () => mock.listDevices(),
      disconnect_this_device: () => mock.disconnectThisDevice(),
    };
    const tauri = new TauriBackend(
      async (command, args) => {
        invoked.push(command);
        const route = routes[command];
        if (!route) throw new Error(`command ${command} not found`);
        return json(await route(args ?? {}));
      },
      (_channel, handler) =>
        Promise.resolve(
          mock.subscribe((event) => {
            handler(json(event));
          }),
        ),
    );
    await renderWith(tauri);
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await click("Einfügen");
    expect(heading()).toBe("Mit diesem Server verbinden?");
    await wait(ARM_DELAY_MS + 50);
    await click("Verbinden");
    await wait(1100);
    expect(heading()).toBe("Das sind deine Geräte?");
    expect(invoked).not.toContain("disconnect_this_device");
    await click("Nein, abbrechen");
    expect(invoked).toContain("disconnect_this_device");
    expect(invoked).not.toContain("join_folders");
    expect(heading()).toBe("Mit deinem anderen Gerät koppeln");
    expect(document.body.textContent).toContain("Abgebrochen. Dieses Gerät ist wieder getrennt");
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

  it("explains a typed text that is not a pairing link", async () => {
    const { mock } = await renderApp("setup");
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await type(field("Kopplungslink"), "nope");
    await click("Koppeln");
    expect(text()).toContain("Das ist kein Kopplungslink.");
    expect(mock.calls).not.toContain("startPairing");
  });

  it.each([["hangar-drive://pair#damaged", "Der Link ist unvollständig."]])(
    "explains a link it cannot read: %s",
    async (link, message) => {
      const { mock } = await renderApp("setup");
      mock.controls.clipboard = link;
      await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
      await click("Einfügen");
      expect(text()).toContain(message);
      expect(mock.calls).not.toContain("startPairing");
    },
  );

  it.each([
    ["hangar-drive://pair#expired", "Dieser Code ist abgelaufen oder wurde schon benutzt."],
    ["hangar-drive://pair#toomany", "Zu viele Versuche."],
    ["hangar-drive://pair#declined", "Das andere Gerät hat abgelehnt."],
    ["hangar-drive://pair#other", "Dieser Code gehört zu einem anderen Konto."],
  ])("explains a failed pairing with %s", async (link, message) => {
    await pastServerQuestion(link);
    await wait(150);
    expect(text()).toContain(message);
  });

  it("names a link of another kind and switches to its flow", async () => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = MOCK_INPUTS.invite;
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await click("Einfügen");
    expect(text()).toContain("Das ist ein Einladungslink.");
    expect(button("Koppeln").getAttribute("aria-disabled")).toBe("true");
    expect(mock.calls).not.toContain("inspectLink");
    await click("Neues Konto einrichten");
    expect(heading()).toBe("Mit deinem Server verbinden");
    expect(field("Einladungslink").value).toBe(MOCK_INPUTS.invite);
    await wait(400);
    expect(text()).toContain("Verbunden mit drive.example.org");
  });

  // Security review H1: places that hold files are asked about natively by the shell; "Choose
  // another folder" there opens the picker for that folder, and "Done" tries again.
  it("warns when the folders do not fit and joins full places after the native question", async () => {
    const { mock } = await pastServerQuestion(MOCK_INPUTS.pair, 0);
    mock.controls.localFiles = 3;
    await wait(1100);
    await click("Ja, das sind meine");
    await wait(100);
    expect(text()).toContain("Auf diesem Computer sind 120 GB frei.");
    expect(text()).toContain("Hangar Drive\\Fotos");
    mock.controls.nativeConfirm = "no";
    mock.controls.pick = "cancel";
    await click("Fertig");
    expect(mock.calls).toContain("joinFolders");
    expect(mock.calls).toContain("pickFolder");
    expect(text()).toContain("Welche Ordner sollen auf dieses Gerät?");
    mock.controls.nativeConfirm = "yes";
    await click("Fertig");
    expect(text()).not.toContain("Welche Ordner sollen auf dieses Gerät?");
  });

  it("cannot finish without a folder", async () => {
    await pastServerQuestion();
    await wait(1100);
    await click("Ja, das sind meine");
    for (const box of all('.choice-list input[type="checkbox"]')) await click(box);
    expect(text()).toContain("Wähle mindestens einen Ordner.");
    expect(button("Fertig").getAttribute("aria-disabled")).toBe("true");
  });
});

describe("invite with a pin (N3)", () => {
  it("warns calmly that the server is trusted without a public certificate", async () => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = MOCK_INPUTS.invitePinned;
    await click("Mit Einladungslink starten");
    await click("Einfügen");
    await wait(400);
    expect(text()).toContain("Server mit eigenem Zertifikat");
    expect(text()).toContain("Nimm den Link nur an, wenn er direkt vom Betreiber");
    expect(button("Weiter").getAttribute("aria-disabled")).toBe("false");
  });

  it("shows no warning for a server with a public certificate", async () => {
    await renderApp("setup");
    await click("Mit Einladungslink starten");
    await click("Einfügen");
    await wait(400);
    expect(document.querySelector(".notice")).toBeNull();
  });

  it("reads the deep link form of an invite", async () => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = MOCK_INPUTS.inviteDeep;
    await click("Mit Einladungslink starten");
    await click("Einfügen");
    await wait(400);
    expect(text()).toContain("Verbunden mit drive.example.org");
  });

  it("does not send a pairing link to the server as an invite", async () => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = MOCK_INPUTS.pair;
    await click("Mit Einladungslink starten");
    await click("Einfügen");
    await wait(400);
    expect(text()).toContain("Das ist ein Kopplungslink von einem deiner Geräte.");
    expect(mock.calls).not.toContain("checkInvite");
    await click("Stattdessen koppeln");
    expect(heading()).toBe("Mit diesem Server verbinden?");
  });
});

describe("links from the OS", () => {
  it.each([
    ["deepLinkInvite", "Mit deinem Server verbinden"],
    ["deepLinkPair", "Mit diesem Server verbinden?"],
    ["deepLinkRecover", "Mit dem Wiederherstellungsblatt einrichten"],
  ] as const)("open the right door: %s", async (scenario, title) => {
    const { mock } = await renderApp(scenario);
    await wait(400);
    expect(heading()).toBe(title);
    expect(mock.calls).toContain("showWindow");
    expect(mock.calls).not.toContain("startPairing");
  });

  it("fills in an invite that arrives while the welcome screen is open", async () => {
    const { mock } = await renderApp("setup");
    act(() => {
      mock.openLink(MOCK_INPUTS.inviteDeep);
    });
    await wait(400);
    expect(heading()).toBe("Mit deinem Server verbinden");
    expect(text()).toContain("Verbunden mit drive.example.org");
  });
});

describe("recovery with the sheet", () => {
  const CODE = "d7kq-m2xp-9h4t-rw8c-zb3n-f6ja-q1ve-k5sy";

  async function enterSheet(link: string, code = CODE) {
    const harness = await renderApp("setup");
    await click("Kein Gerät mehr da? Wiederherstellungsblatt nutzen");
    await type(field("Link vom Blatt"), link);
    await wait(400);
    await type(field("Wiederherstellungscode"), code);
    return harness;
  }

  it("runs through the four screens with the link from the sheet", async () => {
    const { mock } = await enterSheet(MOCK_INPUTS.recoverLink);
    expect(text()).toContain("Schritt 1 von 4");
    expect(text()).toContain("Gefunden: drive.example.org");
    expect(text()).toContain("Konto 3f9a 12c0");
    expect(text()).toContain("D7KQ M2XP 9H4T");
    expect(field("Name dieses Geräts").value).toBe("Arbeitslaptop");
    await click("Weiter");
    expect(mock.calls).toContain("recoverAccount");
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

  // Follow-up check N-2: removing old devices asks natively with their names; after a "no"
  // the step stays and nothing went on.
  it("stays at the old devices after a no in the system's question", async () => {
    const { mock } = await enterSheet(MOCK_INPUTS.recoverLink);
    await click("Weiter");
    expect(heading()).toBe("Alte Geräte entfernen");
    mock.controls.nativeConfirm = "no";
    await click("Weiter");
    expect(mock.calls).toContain("finishRecoveryCleanup:3");
    expect(heading()).toBe("Alte Geräte entfernen");
  });

  it("takes a link that broke over lines", async () => {
    await enterSheet("hangar-drive://recover#AQ3f9a\n  12c0sheet");
    expect(text()).toContain("Gefunden: drive.example.org");
  });

  it.each([
    ["drive.example.org", "Das ist nicht der Link von deinem Blatt."],
    ["hangar-drive://recover#damaged", "Der Link ist unvollständig."],
    ["hangar-drive://recover#insecure", "Dieser Server ist nicht verschlüsselt erreichbar."],
  ])("explains a sheet link it cannot read: %s", async (link, message) => {
    await enterSheet(link);
    expect(text()).toContain(message);
    expect(button("Weiter").getAttribute("aria-disabled")).toBe("true");
  });

  it("names a pairing link and switches to pairing", async () => {
    await enterSheet(MOCK_INPUTS.pair);
    expect(text()).toContain("Das ist ein Kopplungslink");
    await click("Stattdessen koppeln");
    expect(heading()).toBe("Mit diesem Server verbinden?");
  });

  it.each([
    ["D7KQ", "Im Code ist ein Tippfehler."],
    ["H7KQ M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY", "Das ist ein Code für Hangar."],
    ["0000 M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY", "Dieser Code gehört zu keinem Konto"],
    ["1111 M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY", "Dieser Code wurde ersetzt."],
  ])("explains a bad code %s", async (code, message) => {
    await enterSheet(MOCK_INPUTS.recoverLink, code);
    await click("Weiter");
    expect(text()).toContain(message);
  });
});

describe("recovery sheet, version 2", () => {
  it("prints and saves the sheet with server, IDs, anchor and link, worded in German", async () => {
    const { mock } = await renderApp("setup");
    await click("Mit Einladungslink starten");
    await click("Einfügen");
    await wait(400);
    await click("Weiter");
    await click("Was noch auf dem Blatt steht");
    expect(text()).toContain("https://drive.example.org/");
    expect(text()).toContain(MOCK_INPUTS.recoverLink);
    await click("Drucken");
    const sheet = mock.sheet;
    expect(sheet?.title).toBe("Hangar Drive: Wiederherstellungsblatt");
    expect(sheet?.language).toBe("de-DE");
    expect(sheet?.qrLink).toBe(MOCK_INPUTS.recoverLink);
    const labels = sheet?.fields.map((entry) => entry.label) ?? [];
    expect(labels).toEqual([
      "Wiederherstellungscode",
      "Server",
      "Server-Kennung",
      "Konto-Kennung",
      "Prüfwert des Kontos",
      "Link zum Einfügen",
      "Erstellt am",
      "Gerät",
    ]);
    expect(sheet?.fields.at(-1)?.value).toBe("Arbeitslaptop");
    expect(sheet?.notes.join(" ")).not.toMatch(/D7KQ|[0-9A-Z]{4} [0-9A-Z]{4}/);
    await click("Als Datei speichern");
    expect(text()).toContain("Hangar Drive Wiederherstellungsblatt.txt");
  });
});
