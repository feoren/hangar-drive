// @vitest-environment happy-dom

import { afterEach, describe, expect, it } from "vitest";

import type { MockControls } from "../backend/mock/mockBackend";
import {
  all,
  button,
  cleanup,
  click,
  dialogTitle,
  field,
  key,
  renderApp,
  text,
  type,
} from "../test/harness";
import { withParents } from "./RestoreDialog";

afterEach(() => {
  cleanup();
});

async function openVersions() {
  const harness = await renderApp();
  await click("Aktionen für „Hangar Drive“");
  await click("Frühere Versionen");
  return harness;
}

function selectedOption(): string {
  return document.querySelector('[role="option"][aria-selected="true"]')?.textContent ?? "";
}

describe("timeline (UX 9.1)", () => {
  it("lists versions by day with who and what, newest selected", async () => {
    await openVersions();
    expect(dialogTitle()).toBe("Frühere Versionen von „Hangar Drive“");
    const days = all(".timeline-day-head").map((head) => head.textContent);
    expect(days[0]).toBe("Heute");
    expect(selectedOption()).toContain("Arbeitslaptop");
    expect(selectedOption()).toContain("3 Dateien geändert");
    expect(text()).toContain("23 ältere Versionen sind nicht mehr verfügbar");
    expect(text()).toContain("Versionen bleiben 30 Tage erhalten. Das legt dein Server fest.");
  });

  it("marks the version a re-anchor wrote", async () => {
    await openVersions();
    expect(text()).toContain("Hier hat dein Server einen älteren Stand zurückgespielt.");
  });

  it("moves with the arrow keys and updates the right side at once", async () => {
    await openVersions();
    const list = document.querySelector('[role="listbox"]');
    if (!(list instanceof HTMLElement)) throw new Error("no listbox");
    expect(list.getAttribute("aria-activedescendant")).toBeTruthy();
    await key(list, "ArrowDown");
    expect(selectedOption()).toContain("Büro-PC");
    expect(selectedOption()).toContain("12 Dateien neu");
    await key(list, "End");
    expect(selectedOption()).toContain("40 Dateien neu");
    await key(list, "Home");
    expect(selectedOption()).toContain("3 Dateien geändert");
  });

  it("shows the differences to now, only differences by default", async () => {
    await openVersions();
    expect(text()).toContain("Gegenüber jetzt: 1 Datei anders, 1 Datei fehlt jetzt");
    expect(text()).not.toContain("Vertrag.pdf");
    await click(field("Nur Unterschiede"));
    expect(text()).toContain("Vertrag.pdf");
  });

  it("filters to the versions of one file and back", async () => {
    await openVersions();
    await click("Aktionen für „Bericht.docx“");
    await click("Alle Versionen dieser Datei");
    expect(text()).toContain("Nur Versionen von „Bericht.docx“");
    await click("Alle Versionen zeigen");
    expect(text()).not.toContain("Nur Versionen von");
  });

  it("finds the state before a device's changes", async () => {
    const { mock } = await openVersions();
    await click("Stand vor Änderungen von …");
    expect(text()).toContain("Entferne dieses Gerät zuerst");
    await click("Stand suchen");
    expect(mock.calls.some((call) => call.startsWith("findBeforeDevice:f-main:d-office"))).toBe(
      true,
    );
    expect(text()).toContain("Vor den Änderungen von „Büro-PC“");
  });
});

describe("restoring (UX 9.1, 9.2)", () => {
  it.each<[MockControls["restore"], string]>([
    ["done", "Wiederhergestellt. Die vorherige Fassung ist unter Frühere Versionen."],
    ["renamed", "Wiederhergestellt als „Bericht (wiederhergestellt"],
    ["waitBudget", "Wartet: Heute wurde schon sehr viel hochgeladen."],
    ["noSpace", "Dafür ist auf deinem Server kein Platz."],
    ["expired", "Diese Version ist nicht mehr verfügbar. Es wurde nichts verändert."],
    ["failed", "Das Wiederherstellen hat nicht geklappt."],
  ])("restores one file: %s", async (outcome, message) => {
    const { mock } = await openVersions();
    mock.controls.restore = outcome;
    await click(
      all(".tree-row button").find((b) => b.textContent === "Wiederherstellen") ?? document.body,
    );
    expect(text()).toContain(message);
  });

  it("undoes a restore and cancels a waiting one", async () => {
    const { mock } = await openVersions();
    await click(
      all(".tree-row button").find((b) => b.textContent === "Wiederherstellen") ?? document.body,
    );
    await click("Rückgängig");
    expect(mock.calls).toContain("undo");
    expect(text()).toContain("Rückgängig gemacht.");
    mock.controls.restore = "waitBudget";
    await click(
      all(".tree-row button").find((b) => b.textContent === "Wiederherstellen") ?? document.body,
    );
    await click(all(".tree-row .feedback button")[0] ?? document.body);
    expect(mock.calls.some((call) => call.startsWith("cancelRestore:"))).toBe(true);
  });

  it("saves an old version as a copy next to the current one", async () => {
    const { mock } = await openVersions();
    await click("Aktionen für „Bericht.docx“");
    await click("Als Kopie speichern");
    expect(mock.calls).toContain("restoreFile:copy:Projekte/Bericht.docx");
    expect(text()).toContain("Wiederhergestellt als „Bericht (wiederhergestellt");
  });

  it("resets the whole folder after one question", async () => {
    const { mock } = await openVersions();
    await click("Ganzen Ordner auf diesen Stand zurücksetzen");
    expect(dialogTitle()).toBe("Auf diesen Stand zurücksetzen?");
    expect(text()).toContain("Der jetzige Stand bleibt als Version erhalten");
    await click(button(/^Zurücksetzen$/));
    expect(mock.calls.some((call) => call.startsWith("resetFolder:f-main:t1"))).toBe(true);
    expect(text()).toMatch(/„Hangar Drive“ ist auf dem Stand von heute, \d\d:\d\d\./);
  });
});

describe("trash (UX 9.3)", () => {
  async function openTrash() {
    const harness = await renderApp();
    await click("Aktionen für „Hangar Drive“");
    await click("Papierkorb");
    return harness;
  }

  it("lists deleted files with place, time and device, and no button that pretends to delete", async () => {
    await openTrash();
    expect(dialogTitle()).toBe("Papierkorb von „Hangar Drive“");
    expect(text()).toContain("Notizen.txt");
    expect(text()).toContain("Projekte\\Entwürfe\\");
    expect(text()).toContain("Endgültig löschen kann nur der Betreiber.");
    expect(all("button").some((b) => /leeren|löschen/i.test(b.textContent))).toBe(false);
  });

  it("searches by name as one types", async () => {
    await openTrash();
    await type(field("Suchen"), "alt");
    expect(all(".trash-row")).toHaveLength(1);
    await type(field("Suchen"), "zzz");
    expect(text()).toContain("Nichts gefunden für „zzz“.");
  });

  it("restores one file or several selected with Shift", async () => {
    const { mock } = await openTrash();
    await click(all(".trash-row button")[0] ?? document.body);
    expect(text()).toContain("1 Datei wiederhergestellt");
    const boxes = all(".trash-check");
    await click(boxes[0] ?? document.body);
    boxes[2]?.dispatchEvent(new MouseEvent("click", { bubbles: true, shiftKey: true }));
    await click(button("Dateien wiederherstellen"));
    expect(mock.calls).toContain("restoreTrash:3");
  });

  it("switches tabs with the arrow keys", async () => {
    await openTrash();
    const tab = document.querySelector('[role="tab"][aria-selected="true"]');
    if (!(tab instanceof HTMLElement)) throw new Error("no tab");
    await key(tab, "ArrowLeft");
    expect(document.querySelector('[role="tab"][aria-selected="true"]')?.textContent).toBe(
      "Versionen",
    );
  });
});

describe("withParents", () => {
  it("keeps differing files and the folders on their way", () => {
    const nodes = withParents([
      { path: "A", name: "A", depth: 0, kind: "dir", diff: "same" },
      { path: "A/x", name: "x", depth: 1, kind: "file", diff: "same" },
      { path: "B", name: "B", depth: 0, kind: "dir", diff: "same" },
      { path: "B/y", name: "y", depth: 1, kind: "file", diff: "different" },
    ]);
    expect(nodes.map((node) => node.path)).toEqual(["B", "B/y"]);
  });
});
