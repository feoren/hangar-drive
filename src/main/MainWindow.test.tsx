// @vitest-environment happy-dom

import { afterEach, describe, expect, it, vi } from "vitest";

import { MockBackend } from "../backend/mock/mockBackend";
import type { ScenarioId } from "../backend/mock/scenarios";
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
  maybeButton,
  menuLabel,
  openMenu,
  renderApp,
  renderWith,
  text,
  type,
} from "../test/harness";
import { pinClock } from "../test/clock";

// Relative times ("vor 1 Std.", "Heute") come from fixtures placed relative to now.
pinClock();

afterEach(() => {
  cleanup();
});

function status(): string {
  return document.querySelector(".status")?.textContent ?? "";
}

/** Opens the details of the compact status in the header. */
async function openStatus(): Promise<void> {
  const item = document.querySelector<HTMLElement>(".status-button");
  if (!item) throw new Error("no status in the header");
  await click(item);
}

function banner(): HTMLElement | null {
  return document.querySelector(".banner");
}

async function closeDialog(): Promise<void> {
  const current = dialog();
  if (current) await key(current, "Escape");
}

describe("status", () => {
  it.each<[ScenarioId, string, string]>([
    ["upToDate", "Alles aktuell", "Zuletzt synchronisiert um"],
    ["syncing", "Alles aktuell", "Zuletzt synchronisiert um"],
    ["paused", "Angehalten bis", "Fortsetzen"],
    ["offline", "Offline. Änderungen werden später synchronisiert.", "Deine Dateien sind hier"],
    ["serverSilent", "Offline.", "Dein Server antwortet gerade nicht."],
    ["metered", "Alles andere ist aktuell", "Große Dateien warten auf ein Netz ohne Datenlimit"],
    ["budget", "Alles andere ist aktuell", "48 Dateien warten"],
    ["massDelete", "Braucht deine Hilfe", "Sieh dir den Hinweis unten an."],
  ])("%s says %s", async (scenario, title, line) => {
    await renderApp(scenario);
    await closeDialog();
    expect(document.querySelector("h1")?.textContent).toContain(title);
    await openStatus();
    expect(status()).toContain(title);
    expect(status()).toContain(line);
  });

  it("shows the state compactly in the header, the details as tooltip and description", async () => {
    await renderApp("upToDate");
    const item = document.querySelector<HTMLElement>(".topbar .status-button");
    expect(item?.textContent).toBe("Alles aktuell");
    expect(item?.getAttribute("aria-label")).toBe("Alles aktuell");
    expect(item?.getAttribute("title")).toMatch(/^Alles aktuell\nZuletzt synchronisiert um /);
    const description = document.getElementById(item?.getAttribute("aria-describedby") ?? "");
    expect(description?.textContent).toMatch(/^Zuletzt synchronisiert um /);
    expect(item?.querySelector("[data-icon]")?.getAttribute("data-icon")).toBe("upToDate");
    expect(item?.querySelector(".status-mark")?.classList.contains("tone-ok")).toBe(true);
    // Not in the content any more: the folders come first there.
    expect(document.querySelector("main .status-button")).toBeNull();
  });

  it("says offline in one word in the header, the sentence in its name", async () => {
    await renderApp("offline");
    const item = document.querySelector<HTMLElement>(".status-button");
    expect(item?.textContent).toBe("Offline");
    expect(item?.getAttribute("aria-label")).toBe(
      "Offline. Änderungen werden später synchronisiert.",
    );
  });

  it("closes the details with Escape and gives the focus back", async () => {
    await renderApp("paused");
    await openStatus();
    const panel = document.querySelector<HTMLElement>(".status-panel");
    expect(document.activeElement).toBe(panel);
    await key(panel ?? document.body, "Escape");
    expect(document.querySelector(".status-panel")).toBeNull();
    expect(document.activeElement).toBe(document.querySelector(".status-button"));
  });

  it("opens the main menu before the logo, closes it with Escape and opens a dialog from it", async () => {
    await renderApp();
    const menu = button("Menü");
    expect(menu.closest(".topbar-start")?.querySelector(".brand .brand-mark")).toBeTruthy();
    expect(menu.tabIndex).toBe(0);
    expect(menu.getAttribute("aria-haspopup")).toBe("menu");
    expect(menu.getAttribute("aria-expanded")).toBe("false");
    await click(menu);
    expect(menu.getAttribute("aria-expanded")).toBe("true");
    // A menu bar like Hangar's: three menus, each opening a submenu, none open by itself.
    const groups = all('.menu-root > li > [role="menuitem"]');
    expect(groups.map(menuLabel)).toEqual(["Datei", "Ansicht", "Hilfe"]);
    expect(groups.map((item) => item.getAttribute("aria-haspopup"))).toEqual([
      "menu",
      "menu",
      "menu",
    ]);
    expect(all(".menu-sub")).toHaveLength(0);
    expect(document.activeElement).toBe(groups[0]);
    await key(document.activeElement ?? document.body, "Escape");
    expect(all('[role="menu"]')).toHaveLength(0);
    expect(document.activeElement).toBe(menu);
    await openMenu("Einstellungen");
    expect(dialogTitle()).toBe("Einstellungen");
    // The bar holds only the menu, the logo with the name and the status.
    expect(all(".topbar button").map((element) => element.className)).toEqual([
      "icon-button menu-button",
      "quiet-button status-button",
    ]);
  });

  it("groups the entries into File, View and Help, with shortcuts and the current view", async () => {
    await renderApp();
    await click(button("Menü"));
    const entriesOf = async (group: string) => {
      const item = all('.menu-root > li > [role="menuitem"]').find(
        (element) => menuLabel(element) === group,
      );
      await click(item ?? document.body);
      return all('.menu-sub [role^="menuitem"]').map((element) => ({
        label: menuLabel(element),
        role: element.getAttribute("role"),
        checked: element.getAttribute("aria-checked"),
        keys: element.getAttribute("aria-keyshortcuts"),
      }));
    };
    expect(await entriesOf("Datei")).toEqual([
      { label: "Ordner hinzufügen", role: "menuitem", checked: null, keys: null },
      { label: "Geräte", role: "menuitem", checked: null, keys: "Control+Shift+D" },
      { label: "Einstellungen", role: "menuitem", checked: null, keys: "Control+," },
      { label: "Hangar Drive beenden", role: "menuitem", checked: null, keys: null },
    ]);
    expect(await entriesOf("Ansicht")).toEqual([
      { label: "Liste", role: "menuitemradio", checked: "true", keys: null },
      { label: "Kacheln", role: "menuitemradio", checked: "false", keys: null },
      { label: "Letzte Aktivitäten", role: "menuitem", checked: null, keys: null },
    ]);
    expect(await entriesOf("Hilfe")).toEqual([
      { label: "Hilfe", role: "menuitem", checked: null, keys: "F1" },
    ]);
    // The shortcut is shown next to the entry, in the UI language.
    expect(document.querySelector(".menu-sub .menu-hint")?.textContent).toBe("F1");
  });

  it("walks the menus with the arrow keys and opens a submenu only on Right arrow", async () => {
    const { mock } = await renderApp();
    const menu = button("Menü");
    menu.focus();
    await key(menu, "ArrowDown");
    const focused = () => menuLabel(document.activeElement ?? document.body);
    expect(focused()).toBe("Datei");
    await key(document.activeElement ?? document.body, "ArrowDown");
    expect(focused()).toBe("Ansicht");
    expect(all(".menu-sub")).toHaveLength(0);
    await key(document.activeElement ?? document.body, "ArrowRight");
    const view = all('.menu-root > li > [role="menuitem"]')[1];
    expect(view?.getAttribute("aria-expanded")).toBe("true");
    expect(focused()).toBe("Liste");
    // Left arrow closes only the submenu and puts the focus back on its entry.
    await key(document.activeElement ?? document.body, "ArrowLeft");
    expect(all(".menu-sub")).toHaveLength(0);
    expect(view?.getAttribute("aria-expanded")).toBe("false");
    expect(document.activeElement).toBe(view);
    // Enter opens it as well, and Escape in a submenu closes one level only.
    await key(document.activeElement ?? document.body, "Enter");
    expect(focused()).toBe("Liste");
    await key(document.activeElement ?? document.body, "Escape");
    expect(document.activeElement).toBe(view);
    expect(all(".menu-root")).toHaveLength(1);
    // Choosing "Kacheln" switches and stores the view, closes the menu and returns the focus.
    await key(document.activeElement ?? document.body, "ArrowRight");
    await key(document.activeElement ?? document.body, "ArrowDown");
    expect(focused()).toBe("Kacheln");
    await key(document.activeElement ?? document.body, "Enter");
    expect(all('[role="menu"]')).toHaveLength(0);
    expect(document.activeElement).toBe(menu);
    expect(mock.calls).toContain("setFolderView:grid");
    expect(document.querySelector(".folder-list.is-grid")).not.toBeNull();
    expect(button("Kacheln").getAttribute("aria-pressed")).toBe("true");
  });

  it("closes the whole menu with Tab and gives the focus back to its button", async () => {
    await renderApp();
    const menu = button("Menü");
    await click(menu);
    await key(document.activeElement ?? document.body, "ArrowRight");
    await key(document.activeElement ?? document.body, "Tab");
    expect(all('[role="menu"]')).toHaveLength(0);
    expect(document.activeElement).toBe(menu);
  });

  it("quits from the File menu", async () => {
    const { mock } = await renderApp();
    await openMenu("Hangar Drive beenden");
    expect(mock.calls).toContain("quit");
  });

  it("shows the version below the name with the beta badge, keeping its line before it loads", async () => {
    const { mock } = await renderApp();
    const version = document.querySelector(".topbar .brand-version");
    expect(document.querySelector(".topbar .brand-name")?.textContent).toBe("Hangar Drive");
    // The build number comes from the build (vite define), so it may or may not be there.
    expect(version?.textContent).toMatch(/^0\.1\.0(-\d+)?beta$/);
    expect(version?.querySelector(".beta-badge")?.textContent).toBe("beta");
    expect(mock.calls).toContain("getAbout");
    // Before the answer the line is there but empty, so the name does not move when it arrives.
    let release: () => void = () => undefined;
    const slow = new MockBackend({ scenario: "upToDate" });
    await slow.setLanguage("de");
    const original = slow.getAbout.bind(slow);
    slow.getAbout = async () => {
      await new Promise<void>((resolve) => {
        release = resolve;
      });
      return original();
    };
    await renderWith(slow);
    const waiting = document.querySelector(".topbar .brand-version");
    expect(waiting).not.toBeNull();
    expect(waiting?.textContent).toBe("");
    expect(waiting?.getAttribute("aria-hidden")).toBe("true");
    release();
    await flush();
    expect(document.querySelector(".topbar .brand-version")?.textContent).toMatch(
      /^0\.1\.0(-\d+)?beta$/,
    );
  });

  it("announces only changes of the state, not every file count", async () => {
    await renderApp("upToDate");
    const live = document.querySelector('main [role="status"]');
    expect(live?.textContent).toBe("Alles aktuell");
  });

  it("resumes, retries and lets waiting files go from the status", async () => {
    const paused = await renderApp("paused");
    await openStatus();
    await click("Fortsetzen");
    expect(paused.mock.calls).toContain("resume");
    expect(document.querySelector("h1")?.textContent).toBe("Alles aktuell");

    const silent = await renderApp("serverSilent");
    await openStatus();
    await click("Jetzt versuchen");
    expect(silent.mock.calls).toContain("retryConnection");

    const metered = await renderApp("metered");
    await openStatus();
    await click("Jetzt synchronisieren");
    expect(metered.mock.calls).toContain("syncNow");
  });

  it("shows a failed action next to the button", async () => {
    const { mock } = await renderApp("paused");
    mock.controls.failNext = "unexpected";
    await openStatus();
    await click("Fortsetzen");
    expect(status()).toContain("Etwas ist schiefgegangen. Deine Dateien sind nicht betroffen.");
  });
});

describe("banners", () => {
  it.each<[ScenarioId, string, string[]]>([
    ["suspect", "Auf „Büro-PC“ wurden sehr viele Dateien verändert", ["Was jetzt?", "Das war ich"]],
    ["massDelete", "342 Dateien gelöscht", ["Entscheiden"]],
    ["incomingDelete", "Büro-PC hat 342 Dateien in „Fotos“ gelöscht", ["Entscheiden"]],
    [
      "incomingDeleteUnknown",
      "Ein anderes Gerät hat 342 Dateien in „Fotos“ gelöscht",
      ["Entscheiden"],
    ],
    [
      "removed",
      "Dieses Gerät wurde von „Büro-PC“ entfernt.",
      ["Wieder koppeln", "Das war ich nicht"],
    ],
    [
      "refused",
      "Dein Server lässt dieses Gerät nicht mehr herein.",
      ["Wieder koppeln", "Fehlerbericht kopieren"],
    ],
    ["updateRequired", "Hangar Drive braucht ein Update", ["Jetzt aktualisieren"]],
    [
      "serverIdentity",
      "Dein Server weist sich anders aus als sonst.",
      ["Code von einem anderen Gerät scannen", "Mit dem Betreiber vergleichen"],
    ],
    [
      "serverIdentityAlone",
      "Dein Server weist sich anders aus als sonst.",
      ["Mit dem Betreiber vergleichen"],
    ],
    ["olderState", "„Hangar Drive“ ist angehalten", ["Fortsetzen …", "Jetzt noch mal prüfen"]],
    ["missingFolder", "„Fotos“ ist nicht mehr da", ["Ordner suchen", "Neu herunterladen"]],
    ["quotaFull", "Dein Speicher auf dem Server ist ganz voll", ["Fehlerbericht kopieren"]],
    ["quota", "Dein Speicher auf dem Server ist voll", []],
    ["serverDisk", "Dein Server hat keinen Platz mehr", ["Fehlerbericht kopieren"]],
    ["diskFull", "Auf diesem Computer ist der Speicher voll", ["Speicher anzeigen"]],
    ["serverLong", "Dein Server antwortet seit", ["Fehlerbericht kopieren", "Jetzt versuchen"]],
    ["conflicts", "2 Dateien gibt es in zwei Fassungen", ["Ansehen"]],
    ["names", "4 Dateien können auf diesem Gerät nicht gespeichert werden", ["Ansehen"]],
    [
      "noRecoveryCode",
      "Kein gültiger Wiederherstellungscode",
      ["Neuen Wiederherstellungscode erstellen"],
    ],
    ["foldersUnreadable", "Noch nicht erreichbar: Fotos und Musik", []],
    ["folderListUnreadable", "Ordnerliste neu begonnen", ["Ausblenden"]],
  ])("%s shows its banner", async (scenario, title, buttons) => {
    await renderApp(scenario);
    await closeDialog();
    const shown = banner();
    expect(shown?.textContent).toContain(title);
    const names = Array.from(
      shown?.querySelectorAll(".banner-actions button") ?? [],
      (b) => b.textContent,
    );
    expect(names).toEqual(buttons);
  });

  it("says the two-versions banner once, as its title only", async () => {
    await renderApp("conflicts");
    expect(banner()?.querySelector(".banner-body")).toBeNull();
    expect(banner()?.textContent).not.toContain("geändert");
  });

  it("uses red only for a suspected attack and alerts only for decisions", async () => {
    await renderApp("suspect");
    expect(banner()?.className).toContain("banner-danger");
    expect(banner()?.getAttribute("role")).toBe("alert");
    await renderApp("conflicts");
    expect(banner()?.className).toContain("banner-info");
    expect(banner()?.getAttribute("role")).toBe("status");
  });

  it("shows one banner and counts the others", async () => {
    await renderApp("many");
    await closeDialog();
    expect(all(".banner")).toHaveLength(1);
    expect(banner()?.textContent).toContain("342 Dateien gelöscht");
    await click("Noch 3 weitere Hinweise");
    expect(banner()?.textContent).toContain("„Fotos“ ist nicht mehr da");
    await click("Noch 3 weitere Hinweise");
    expect(banner()?.textContent).toContain("2 Dateien gibt es in zwei Fassungen");
  });

  it("opens the mass deletion question by itself, once", async () => {
    const { mock } = await renderApp("massDelete");
    expect(dialogTitle()).toBe("342 Dateien gelöscht");
    expect(document.activeElement?.textContent).toBe("Wiederherstellen");
    await key(dialog() ?? document.body, "Escape");
    expect(dialog()).toBeNull();
    expect(banner()?.textContent).toContain("342 Dateien gelöscht");
    await click("Entscheiden");
    await click("Liste ansehen");
    expect(text()).toContain("Urlaub/Urlaub 342.jpg");
    await click("Wiederherstellen");
    expect(mock.calls).toContain("resolveMassDelete:restore");
    expect(text()).toContain("342 Dateien sind wieder da.");
    await click("Schließen");
    expect(banner()).toBeNull();
  });

  it("deletes for good only through the danger button", async () => {
    const { mock } = await renderApp("massDelete");
    expect(button("Ja, löschen").className).toContain("danger");
    // The shell asks natively with the folder and the number (security review M4); "no" there
    // leaves the question open and shows no error.
    mock.controls.nativeConfirm = "no";
    await click("Ja, löschen");
    expect(mock.calls).toContain("resolveMassDelete:delete");
    expect(dialogTitle()).toBe("342 Dateien gelöscht");
    expect(text()).not.toContain("auf deinen anderen Geräten gelöscht.");
    mock.controls.nativeConfirm = "yes";
    await click("Ja, löschen");
    expect(mock.calls).toContain("resolveMassDelete:delete");
    expect(text()).toContain("342 Dateien sind jetzt auch auf deinen anderen Geräten gelöscht.");
  });

  // ADR 0001, amendment "incoming mass deletes": the same dialog in its incoming variant.
  it("asks about many deletes of another device, restore first", async () => {
    const { mock } = await renderApp("incomingDelete");
    expect(dialogTitle()).toBe("Büro-PC hat 342 Dateien in „Fotos“ gelöscht");
    expect(text()).toContain("Hier liegen sie noch. Sollen sie auch hier gelöscht werden?");
    // The day the device joined, from the verified log, so a look-alike name stands out (L5).
    expect(text()).toMatch(/Büro-PC ist seit .+ in deinem Konto\./);
    expect(text()).not.toContain("Im Papierkorb bleiben sie");
    const restore = button("Wiederherstellen");
    expect(document.activeElement).toBe(restore);
    expect(restore.className).toContain("primary");
    const hint = document.getElementById(restore.getAttribute("aria-describedby") ?? "");
    expect(hint?.textContent).toBe("Die Dateien kommen auf allen Geräten zurück.");
    expect(dialog()?.getAttribute("role")).toBe("alertdialog");
    await key(dialog() ?? document.body, "Escape");
    expect(dialog()).toBeNull();
    expect(mock.calls.some((call) => call.startsWith("resolveIncomingDelete"))).toBe(false);
    expect(banner()?.textContent).toContain("Hier liegen sie noch.");
    await click("Entscheiden");
    await click("Liste ansehen");
    expect(mock.calls).toContain("listIncomingDelete");
    expect(text()).toContain("Urlaub/Urlaub 342.jpg");
    await click("Wiederherstellen");
    expect(mock.calls).toContain("resolveIncomingDelete:restore");
    expect(text()).toContain("342 Dateien sind wieder da, auf allen Geräten.");
    await click("Schließen");
    expect(banner()).toBeNull();
  });

  it("names no device it does not know and deletes here only through the danger button", async () => {
    const { mock } = await renderApp("incomingDeleteUnknown");
    expect(dialogTitle()).toBe("Ein anderes Gerät hat 342 Dateien in „Fotos“ gelöscht");
    expect(text()).not.toContain("in deinem Konto");
    expect(button("Ja, hier löschen").className).toContain("danger");
    mock.controls.nativeConfirm = "no";
    await click("Ja, hier löschen");
    expect(mock.calls).toContain("resolveIncomingDelete:delete");
    expect(text()).not.toContain("jetzt auch hier gelöscht");
    mock.controls.nativeConfirm = "yes";
    await click("Ja, hier löschen");
    expect(text()).toContain("342 Dateien sind jetzt auch hier gelöscht.");
    expect(mock.calls.some((call) => call.startsWith("resolveMassDelete"))).toBe(false);
  });

  it("finds a missing folder, or says it is the wrong one", async () => {
    const { mock } = await renderApp("missingFolder");
    mock.controls.pick = "wrongFolder";
    await click("Ordner suchen");
    expect(banner()?.textContent).toContain("Das ist nicht der Ordner „Fotos“.");
    mock.controls.pick = "ok";
    await click("Ordner suchen");
    expect(banner()).toBeNull();
  });

  it("downloads a missing folder again", async () => {
    const { mock } = await renderApp("missingFolder");
    await click("Neu herunterladen");
    expect(mock.calls).toContain("redownloadFolder");
    expect(banner()).toBeNull();
  });

  it("hides the attack warning on this device only, and says so", async () => {
    const { mock } = await renderApp("suspect");
    await click("Das war ich");
    expect(mock.calls).toContain("dismissSuspect");
    expect(text()).toContain(
      "Ausgeblendet auf diesem Gerät. Auf deinen anderen Geräten siehst du den Hinweis noch.",
    );
  });

  it("checks an older state again", async () => {
    const { mock } = await renderApp("olderState");
    await click("Jetzt noch mal prüfen");
    expect(banner()?.textContent).toContain("Der Server zeigt noch den älteren Stand.");
    mock.controls.olderCheck = "resolved";
    await click("Jetzt noch mal prüfen");
    expect(banner()).toBeNull();
  });

  it("copies the error report for the operator", async () => {
    const { mock } = await renderApp("serverDisk");
    await click("Fehlerbericht kopieren");
    expect(mock.calls).toContain("copyErrorReport");
    expect(banner()?.textContent).toContain("Fehlerbericht kopiert.");
  });

  it("opens the storage settings and the update", async () => {
    const disk = await renderApp("diskFull");
    await click("Speicher anzeigen");
    expect(disk.mock.calls).toContain("openStorageSettings");
    const update = await renderApp("updateRequired");
    await click("Jetzt aktualisieren");
    expect(update.mock.calls).toContain("installUpdate");
    expect(banner()?.textContent).toContain("Version 0.2.0 ist installiert.");
    update.mock.controls.update = "upToDate";
    await click("Jetzt aktualisieren");
    expect(banner()?.textContent).toContain("Es gibt noch keine neuere Version.");
  });

  it("hides the update button while this build cannot update itself", async () => {
    const { mock } = await renderApp("updateOff");
    expect(mock.calls).toContain("getAbout");
    expect(maybeButton("Jetzt aktualisieren")).toBeUndefined();
    expect(banner()?.textContent).toContain(
      "Installiere die neue Version, dann geht es von selbst weiter.",
    );
  });

  it("hides the update button when the shell says updates are off, without an error", async () => {
    const { mock } = await renderApp("updateRequired");
    mock.controls.update = "off";
    await click("Jetzt aktualisieren");
    expect(mock.calls).toContain("installUpdate");
    expect(maybeButton("Jetzt aktualisieren")).toBeUndefined();
    expect(document.querySelector(".feedback-error")).toBeNull();
    expect(banner()?.textContent).toContain("Installiere die neue Version");
  });

  // Security review H2: a removal only the server reports is forgotten here after the native
  // question; "no" there keeps the account, and nothing is shown as an error.
  it("forgets the account after a reported removal only when the person confirms", async () => {
    const { mock } = await renderApp("removalReported");
    expect(banner()?.textContent).toContain(
      "Dein Server meldet, dass dieses Gerät aus deinem Konto entfernt wurde.",
    );
    mock.controls.nativeConfirm = "no";
    await click("Bestätigen");
    expect(mock.calls).toContain("confirmDeviceRemoved");
    expect(banner()?.textContent).toContain("Dein Server meldet");
    expect(document.querySelector(".feedback-error")).toBeNull();
    mock.controls.nativeConfirm = "yes";
    await click("Bestätigen");
    expect(text()).toContain("Willkommen bei Hangar Drive");
  });

  // Security review M3: a version of a folder beyond the limits leads to the earlier versions.
  it("leads from an oversized server version to the earlier versions", async () => {
    await renderApp("treeLimit");
    expect(banner()?.textContent).toContain("Ein zu großer Stand von „Hangar Drive“");
    expect(text()).toContain("Angehalten: zu großer Stand auf dem Server");
    await click("Frühere Versionen");
    expect(dialogTitle()).toBe("Frühere Versionen von „Hangar Drive“");
  });

  // Security review "recovery" L1: an account without a valid recovery code says so until a new
  // code is confirmed; the banner cannot be hidden, and it leads through the code's steps.
  it("leads from 'no valid recovery code' to a new code, and the banner goes", async () => {
    const { mock } = await renderApp("noRecoveryCode");
    const shown = banner();
    expect(shown?.className).toContain("banner-attention");
    expect(shown?.getAttribute("role")).toBe("alert");
    expect(shown?.textContent).toContain(
      "Erstelle einen neuen. Ohne ihn kommst du nicht mehr an deine Dateien, wenn du alle Geräte verlierst.",
    );
    await click("Neuen Wiederherstellungscode erstellen");
    expect(mock.calls).toContain("renewRecoveryCode");
    expect(dialog()?.textContent).toContain(
      "Dein Konto hatte keinen gültigen Code. Dieser hier gilt, sobald du ihn bestätigt hast.",
    );
    const groups = all(".code-group").map((group) => group.textContent);
    await click("Ich habe ihn gesichert");
    const index = Number(/Tippe die (\d)\./.exec(text())?.[1]);
    await type(field(`Gruppe ${String(index)}`), groups[index - 1] ?? "");
    expect(mock.calls).toContain("confirmRecoveryGroup");
    expect(dialog()).toBeNull();
    expect(banner()).toBeNull();
  });

  // Follow-up review LOW 2: folders whose key could not be read after the recovery are named
  // calmly and come back by themselves; nothing to hide while a folder is named.
  it("names the folders not readable after a recovery, calmly", async () => {
    await renderApp("foldersUnreadable");
    const shown = banner();
    expect(shown?.className).toContain("banner-info");
    expect(shown?.getAttribute("role")).toBe("status");
    expect(shown?.textContent).toContain(
      "Diese Ordner ließen sich nach der Wiederherstellung noch nicht öffnen. Sobald dein Server oder ein anderes Gerät sie liefert, sind sie von selbst wieder da.",
    );
    expect(shown?.textContent).not.toContain("Ordnerliste");
  });

  it("hides the started-over folder list on request", async () => {
    const { mock } = await renderApp("folderListUnreadable");
    expect(banner()?.textContent).toContain(
      "Die Liste deiner Ordner ließ sich nach der Wiederherstellung nicht lesen und wurde leer neu begonnen.",
    );
    await click("Ausblenden");
    expect(mock.calls).toContain("dismissSuspect");
    expect(banner()).toBeNull();
  });

  it("keeps 'no valid recovery code' when the new code is cancelled", async () => {
    await renderApp("noRecoveryCode");
    await click("Neuen Wiederherstellungscode erstellen");
    await click("Abbrechen");
    expect(dialog()).toBeNull();
    expect(banner()?.textContent).toContain("Kein gültiger Wiederherstellungscode");
  });

  it("names no device when the server only said this device was removed", async () => {
    await renderApp("removedUnknown");
    expect(banner()?.textContent).toContain(
      "Dieses Gerät wurde aus deinem Konto entfernt. Deine Dateien bleiben hier",
    );
    expect(banner()?.textContent).not.toContain("„“");
    expect(button("Wieder koppeln")).toBeTruthy();
  });

  it("explains 'that was not me' after a removal", async () => {
    await renderApp("removed");
    await click("Das war ich nicht");
    expect(dialog()?.textContent).toContain(
      "Richte Hangar Drive mit deinem Wiederherstellungsblatt neu ein",
    );
  });
});

describe("folders", () => {
  it("shows name, path and status in one accessible name", async () => {
    await renderApp("syncing");
    expect(button("Fotos, D:\\Fotos, 117 Dateien werden hochgeladen")).toBeTruthy();
  });

  it("shows the size of each folder on this disk, also in the accessible name", async () => {
    await renderApp();
    // Intl puts a no-break space between number and unit.
    const sizes = all(".folder-row .row-size").map((size) => size.textContent.replace(/\s/g, " "));
    expect(sizes).toEqual(["2,4 GB", "86,3 GB"]);
    expect(button(/^Fotos, D:\\Fotos, Aktuell, 86,3\sGB$/)).toBeTruthy();
  });

  it.each<[ScenarioId, string, string[]]>([
    ["upToDate", "done", ["is-ok", "is-ok"]],
    ["syncing", "syncing", ["is-active", "is-active"]],
    ["offline", "offline", ["is-quiet", "is-quiet"]],
    ["paused", "paused", ["is-quiet", "is-quiet"]],
    ["missingFolder", "needs you", ["is-ok", "is-stopped"]],
  ])("marks the folders of %s as %s", async (scenario, _what, tones) => {
    await renderApp(scenario);
    await closeDialog();
    const rows = all(".folder-row").map((row) =>
      ["is-ok", "is-active", "is-stopped", "is-quiet"].find((tone) => row.classList.contains(tone)),
    );
    expect(rows).toEqual(tones);
  });

  it("switches between list and grid and keeps the choice in the settings", async () => {
    const { mock } = await renderApp();
    const list = button("Liste");
    const grid = button("Kacheln");
    expect(list.closest('[role="group"]')?.getAttribute("aria-label")).toBe("Ansicht");
    expect(list.getAttribute("aria-pressed")).toBe("true");
    expect(document.querySelector(".folder-list.is-grid")).toBeNull();
    await click(grid);
    expect(mock.calls).toContain("setFolderView:grid");
    expect(grid.getAttribute("aria-pressed")).toBe("true");
    expect(list.getAttribute("aria-pressed")).toBe("false");
    // The cards keep everything: name, status, size, the menu and the dashed "add" card.
    const cards = all(".folder-list.is-grid .folder-row");
    expect(cards).toHaveLength(2);
    expect(cards[1]?.querySelector(".row-size")?.textContent.replace(/\s/g, " ")).toBe("86,3 GB");
    expect(button("Fotos, D:\\Fotos, Aktuell").getAttribute("title")).toBe("D:\\Fotos");
    expect(button("Aktionen für „Fotos“")).toBeTruthy();
    expect(document.querySelector(".is-grid .add-row")).not.toBeNull();
    // Read again on the next start.
    await renderWith(mock);
    expect(document.querySelector(".folder-list.is-grid")).not.toBeNull();
  });

  it("shows no size for a folder that was not scanned yet", async () => {
    const { mock } = await renderApp();
    mock.controls.pick = "ok";
    await click("Ordner hinzufügen");
    await click("Anderen Ordner wählen …");
    const added = button("Projekte 2027").closest(".folder-row");
    expect(added?.querySelector(".row-size")).toBeNull();
    expect(button("Projekte 2027").getAttribute("aria-label")).not.toMatch(/\d B$/);
  });

  it("opens a folder with Enter and offers the row menu", async () => {
    const { mock } = await renderApp();
    const row = button("Hangar Drive, C:\\Users\\Alex\\Hangar Drive, Aktuell");
    await click(row);
    expect(mock.calls).toContain("openFolder:f-main");
    await key(row, "F10", { shiftKey: true });
    const items = all('[role="menuitem"]').map((item) => item.textContent);
    expect(items).toEqual([
      "Im Explorer öffnen",
      "Frühere Versionen",
      "Papierkorb",
      "Pausieren",
      "Ordnernummer anzeigen",
      "Auf diesem Gerät nicht mehr synchronisieren",
      "Auf allen Geräten löschen",
    ]);
    expect(document.activeElement?.textContent).toBe("Im Explorer öffnen");
    await key(document.activeElement ?? document.body, "ArrowDown");
    expect(document.activeElement?.textContent).toBe("Frühere Versionen");
    await key(document.activeElement ?? document.body, "Escape");
    expect(all('[role="menu"]')).toHaveLength(0);
    expect(document.activeElement).toBe(row);
  });

  it("moves through the list with the arrow keys as one tab stop", async () => {
    await renderApp();
    const rows = all(".folder-list [data-roving]");
    expect(rows.map((row) => row.tabIndex)).toEqual([0, -1, -1]);
    rows[0]?.focus();
    await key(rows[0] ?? document.body, "ArrowDown");
    expect(document.activeElement).toBe(rows[1]);
    await key(rows[1] ?? document.body, "End");
    expect(document.activeElement?.textContent).toContain("Ordner hinzufügen");
  });

  it("pauses one folder from its menu", async () => {
    const { mock } = await renderApp();
    await click("Aktionen für „Fotos“");
    await click("Pausieren");
    expect(mock.calls).toContain("pauseFolder");
    expect(button("Fotos, D:\\Fotos, Angehalten")).toBeTruthy();
  });

  it("stops syncing a folder after saying the files stay", async () => {
    const { mock } = await renderApp();
    await click("Aktionen für „Fotos“");
    await click("Auf diesem Gerät nicht mehr synchronisieren");
    expect(dialog()?.textContent).toContain(
      "Die Dateien bleiben in diesem Ordner und auf deinem Server.",
    );
    expect(document.activeElement?.textContent).toBe("Abbrechen");
    await click("Nicht mehr synchronisieren");
    expect(mock.calls).toContain("stopFolder");
    expect(maybeButton("Fotos, D:\\Fotos")).toBeUndefined();
  });

  // The shell asks natively (security review L2); the window does not ask a second time.
  it("deletes a folder everywhere after the native question, with the retention window named", async () => {
    const { mock } = await renderApp();
    await click("Aktionen für „Fotos“");
    await click("Auf allen Geräten löschen");
    expect(dialog()).toBeNull();
    expect(mock.calls).toContain("deleteFolderEverywhere");
    expect(maybeButton("Fotos, D:\\Fotos")).toBeUndefined();
    expect(text()).toContain(
      "„Fotos“ ist gelöscht. Der Ordner verschwindet von allen deinen Geräten. 30 Tage lang kannst du ihn unter Ordner hinzufügen zurückholen.",
    );
  });

  it("keeps the folder quietly when the native question is answered with no", async () => {
    const { mock } = await renderApp();
    mock.controls.nativeConfirm = "no";
    await click("Aktionen für „Fotos“");
    await click("Auf allen Geräten löschen");
    expect(mock.calls).toContain("deleteFolderEverywhere");
    expect(button("Fotos, D:\\Fotos")).toBeTruthy();
    expect(text()).not.toContain("ist gelöscht");
    expect(document.querySelector(".feedback-error")).toBeNull();
  });

  it("shows the folder number, or why it cannot", async () => {
    const { mock } = await renderApp();
    await click("Aktionen für „Fotos“");
    await click("Ordnernummer anzeigen");
    expect(all(".number-group")).toHaveLength(6);
    expect(all(".number-group")[0]?.getAttribute("aria-label")).toMatch(
      /^Gruppe 1: \d \d \d \d \d$/,
    );
    await click("Schließen");
    mock.controls.folderNumber = "offline";
    await click("Aktionen für „Fotos“");
    await click("Ordnernummer anzeigen");
    expect(dialog()?.textContent).toContain("Gerade keine Verbindung zum Server.");
  });

  it("shows the quiet lines of a folder: no news, and what is never synced", async () => {
    await renderApp("freeze");
    expect(text()).toContain("Seit 14 Tagen nichts Neues von deinen anderen Geräten.");
    await click("3 Einträge werden nicht synchronisiert");
    expect(dialog()?.textContent).toContain("Verknüpfungen und Links werden nicht synchronisiert.");
    expect(dialog()?.textContent).toContain("desktop.ini");
  });

  it("invites to add the first folder", async () => {
    await renderApp("empty");
    expect(text()).toContain("Noch kein Ordner");
    expect(document.querySelector(".segmented")).toBeNull();
    await click(button(/^Ordner hinzufügen$/));
    expect(dialogTitle()).toBe("Ordner hinzufügen");
  });
});

describe("add folder", () => {
  it("brings a folder of the other devices here", async () => {
    const { mock } = await renderApp();
    await click("Ordner hinzufügen");
    expect(dialog()?.textContent).toContain("Auf deinen anderen Geräten gibt es noch:");
    await click("Hierher holen");
    expect(mock.calls.join(",")).toContain("addAccountFolder");
    expect(dialog()).toBeNull();
    // Proposed below the app's folder, never in the home folder itself (H1, N8).
    expect(button("Musik, C:\\Users\\Alex\\Hangar Drive\\Musik")).toBeTruthy();
  });

  // Security review H1: a place that holds files is asked about natively by the shell, with the
  // place, the number of files and the server; "Choose another folder" there opens the picker.
  it("joins a folder that is not empty only after the native question", async () => {
    const { mock } = await renderApp();
    mock.controls.localFiles = 1;
    mock.controls.nativeConfirm = "no";
    mock.controls.pick = "cancel";
    await click("Ordner hinzufügen");
    await click("Hierher holen");
    expect(mock.calls).toContain("addAccountFolder");
    expect(mock.calls).toContain("pickFolder");
    expect(dialog()?.textContent).toContain("Auf deinen anderen Geräten gibt es noch:");
    expect(text()).not.toContain("86 Dateien werden heruntergeladen");
    mock.controls.nativeConfirm = "yes";
    await click("Hierher holen");
    expect(dialog()).toBeNull();
    expect(button("Musik, C:\\Users\\Alex\\Hangar Drive\\Musik")).toBeTruthy();
  });

  it("adds any folder and explains a refused one", async () => {
    const { mock } = await renderApp();
    mock.controls.pick = "network";
    await click("Ordner hinzufügen");
    await click("Anderen Ordner wählen …");
    expect(dialog()?.textContent).toContain("Netzlaufwerke gehen nicht.");
    mock.controls.pick = "ok";
    await click("Anderen Ordner wählen …");
    expect(mock.calls).toContain("addFolder");
    expect(button("Projekte 2027")).toBeTruthy();
  });

  it("brings back a deleted folder", async () => {
    const { mock } = await renderApp();
    await click("Ordner hinzufügen");
    expect(dialog()?.textContent).toContain("Altes Projekt noch 12 Tage");
    await click("Zurückholen");
    expect(mock.calls).toContain("restoreDeletedFolder");
  });
});

describe("activity", () => {
  it("lives in the main menu, not in the window, and says when nothing happened yet", async () => {
    await renderApp("empty");
    expect(text()).not.toContain("Letzte Aktivitäten");
    await openMenu("Letzte Aktivitäten");
    expect(dialogTitle()).toBe("Letzte Aktivitäten");
    expect(dialog()?.textContent).toContain("Hier erscheint, was sich in deinen Ordnern ändert.");
    await click("Schließen");
    expect(dialog()).toBeNull();
  });

  it("lists what happened with folder, action and time", async () => {
    await renderApp();
    await openMenu("Letzte Aktivitäten");
    expect(button("Bericht.docx, Hangar Drive, geändert, vor 2 Min.")).toBeTruthy();
    expect(button("Urlaub 014.jpg, Fotos, von Büro-PC, vor 1 Std.")).toBeTruthy();
    expect(button("Fotos: 120 neue Dateien")).toBeTruthy();
  });

  it("says yesterday for an hour old entry shortly after midnight", async () => {
    vi.setSystemTime(new Date(2026, 10, 27, 0, 7));
    await renderApp();
    await openMenu("Letzte Aktivitäten");
    expect(button("Bericht.docx, Hangar Drive, geändert, vor 2 Min.")).toBeTruthy();
    expect(button("Urlaub 014.jpg, Fotos, von Büro-PC, gestern")).toBeTruthy();
  });

  it("shows a file in Explorer and opens its versions", async () => {
    const { mock } = await renderApp();
    await openMenu("Letzte Aktivitäten");
    await click(button("Bericht.docx, Hangar Drive"));
    expect(mock.calls).toContain("openFolder:f-main:Projekte/Bericht.docx");
    await click("Aktionen für „Bericht.docx“");
    await click(
      all('[role="menuitem"]').find((item) => item.textContent === "Frühere Versionen") ??
        document.body,
    );
    await flush();
    expect(dialogTitle()).toBe("Frühere Versionen von „Hangar Drive“");
    expect(text()).toContain("Nur Versionen von „Bericht.docx“");
  });

  it("brings back files another device deleted", async () => {
    const { mock } = await renderApp();
    await openMenu("Letzte Aktivitäten");
    const restore = all(".activity-row .row-note button")[0];
    await click(restore ?? document.body);
    expect(mock.calls).toContain("restoreRemoteDeleted");
    expect(text()).toContain("14 Dateien sind wieder da.");
  });
});

describe("quiet lines", () => {
  it("shows the storage line only above 80 % and the server notices", async () => {
    await renderApp("upToDate");
    expect(text()).not.toContain("auf deinem Server belegt");
    await renderApp("storage");
    expect(text()).toContain("86,4 GB von 100 GB auf deinem Server belegt");
    expect(text()).toContain("Alte Versionen belegen auf deinem Server gerade viel Platz.");
    expect(text()).toContain("„Büro-PC“ hat heute sehr viel hochgeladen.");
    expect(text()).toContain("nur noch 14 Tage auf");
    expect(text()).toContain("Dein Speicher auf dem Server ist fast voll.");
    expect(text()).toContain("Deine Geräte haben heute sehr viel hochgeladen.");
    expect(text()).toContain("Auf deinem Server wird der Platz knapp.");
  });
});

describe("keyboard", () => {
  it("opens help, settings and devices with their shortcuts", async () => {
    await renderApp();
    await key(document.body, "F1");
    expect(dialogTitle()).toBe("Hilfe");
    expect(dialog()?.textContent).toContain("Strg+Umschalt+D");
    await key(dialog() ?? document.body, "Escape");
    await key(document.body, ",", { ctrlKey: true });
    expect(dialogTitle()).toBe("Einstellungen");
    await key(dialog() ?? document.body, "Escape");
    await key(document.body, "D", { ctrlKey: true, shiftKey: true });
    expect(dialogTitle()).toBe("Deine Geräte");
  });

  it("ignores Ctrl plus a letter", async () => {
    await renderApp();
    await key(document.body, "d", { ctrlKey: true });
    expect(dialog()).toBeNull();
  });

  it("returns focus to the opener when a dialog closes", async () => {
    await renderApp();
    await openMenu("Einstellungen");
    expect(dialog()).not.toBeNull();
    await key(dialog() ?? document.body, "Escape");
    expect(document.activeElement).toBe(button("Menü"));
  });

  it("keeps Tab inside a dialog", async () => {
    await renderApp();
    await openMenu("Hilfe");
    const close = button("Schließen");
    close.focus();
    await key(close, "Tab");
    expect(dialog()?.contains(document.activeElement)).toBe(true);
  });

  it("puts the header buttons last in the tab order", async () => {
    await renderApp();
    const order = all("button, [tabindex='0']").filter((element) => element.tabIndex >= 0);
    const menu = order.findIndex((element) => element.getAttribute("aria-label") === "Menü");
    const content = order.filter((element) => element.closest("main") !== null);
    const lastContent = order.indexOf(content[content.length - 1] ?? document.body);
    // The folder list and the view switch are in the content, the header follows all of it.
    expect(content.some((element) => element.closest(".folder-list") !== null)).toBe(true);
    expect(content.some((element) => element.closest(".segmented") !== null)).toBe(true);
    expect(lastContent).toBeGreaterThanOrEqual(0);
    expect(menu).toBeGreaterThan(lastContent);
    expect(order[menu + 1]?.classList.contains("status-button")).toBe(true);
  });
});
