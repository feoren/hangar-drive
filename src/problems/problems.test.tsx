// @vitest-environment happy-dom

import { act } from "react";
import { afterEach, describe, expect, it } from "vitest";

import { MOCK_INPUTS } from "../backend/mock/mockBackend";
import {
  all,
  button,
  cleanup,
  click,
  dialog,
  dialogTitle,
  field,
  flush,
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

describe("two versions (UX 7.1)", () => {
  it("lists each file with both versions, device and time", async () => {
    await renderApp("conflicts");
    await click("Ansehen");
    expect(dialogTitle()).toBe("Dateien in zwei Fassungen");
    expect(text()).toContain("Bericht (Konflikt Arbeitslaptop 2026-11-26).docx");
    expect(text()).toContain("Fassung von Büro-PC, vor 40 Min.");
    expect(text()).toContain("Zwei Dateien unterscheiden sich nur in Groß- und Kleinschreibung.");
  });

  it("keeps one version with undo, and both without a question", async () => {
    const { mock } = await renderApp("conflicts");
    await click("Ansehen");
    await click(all(".version-row button")[0] ?? document.body);
    expect(mock.calls).toContain("keepConflictVersion:c1-a");
    expect(text()).toContain(
      "Erledigt. Die andere Fassung findest du 30 Tage lang unter Frühere Versionen.",
    );
    await click("Rückgängig");
    expect(text()).toContain("Rückgängig gemacht.");
    expect(all(".group-card")).toHaveLength(2);
    await click("Beide behalten");
    await click("Beide behalten");
    expect(text()).toContain("Alles aufgeräumt.");
  });

  it("opens both versions", async () => {
    const { mock } = await renderApp("conflicts");
    await click("Ansehen");
    await click("Beide öffnen");
    expect(mock.calls).toContain("openConflict:c1");
  });
});

describe("names Windows refuses (UX 7.2)", () => {
  it("says why in words and where the file came from", async () => {
    await renderApp("names");
    await click("Ansehen");
    expect(text()).toContain("Der Name enthält „:“. Das erlaubt Windows nicht.");
    expect(text()).toContain("„CON“ ist unter Windows ein reservierter Name.");
    expect(text()).toContain("Der Name endet mit einem Punkt oder Leerzeichen.");
    expect(text()).toContain("Von MacBook");
  });

  it("renames with a suggestion that is checked while typing", async () => {
    const { mock } = await renderApp("names");
    await click("Ansehen");
    await click(
      all(".group-card button").find((b) => b.textContent === "Umbenennen") ?? document.body,
    );
    const input = field("Neuer Name");
    expect(input.value).toBe("Budget Q1.xlsx");
    await type(input, "Budget|Q1.xlsx");
    expect(text()).toContain("Auch dieser Name geht unter Windows nicht.");
    await type(input, "");
    expect(text()).toContain("Gib einen Namen ein.");
    await type(input, "Bericht.docx");
    await click(all(".rename-form button")[0] ?? document.body);
    expect(text()).toContain("Eine Datei mit diesem Namen gibt es dort schon.");
    await type(input, "Budget Q1.xlsx");
    await click(all(".rename-form button")[0] ?? document.body);
    expect(mock.calls).toContain("renameNameIssue");
    expect(text()).toContain("Umbenannt in „Budget Q1.xlsx“.");
  });

  it("only ignores entries this device cannot create", async () => {
    const { mock } = await renderApp("names");
    await click("Ansehen");
    const card = all(".group-card").find((element) =>
      element.textContent.includes("Verknüpfung oder Systemdatei"),
    );
    expect(Array.from(card?.querySelectorAll("button") ?? [], (b) => b.textContent)).toEqual([
      "Ignorieren",
    ]);
    await click(card?.querySelector("button") ?? document.body);
    expect(mock.calls).toContain("ignoreNameIssue");
  });
});

describe("server identity (UX 8.3)", () => {
  it("takes the code of another device of this account", async () => {
    const { mock } = await renderApp("serverIdentity");
    await click("Code von einem anderen Gerät scannen");
    // Pasting checks the link at once; typing waits for "Connect".
    await type(field("Kopplungslink"), "hangar-drive://pair#other");
    await click("Verbinden");
    expect(text()).toContain("Dieser Code gehört zu einem anderen Konto.");
    mock.controls.clipboard = MOCK_INPUTS.pair;
    await click("Einfügen");
    expect(text()).toContain("Verbunden. Alles läuft wieder.");
    expect(mock.calls.filter((call) => call === "fixServerWithOffer")).toHaveLength(2);
  });

  it("compares the server number with the operator, the confirm button held back", async () => {
    const { mock } = await renderApp("serverIdentityAlone");
    await click("Mit dem Betreiber vergleichen");
    expect(dialogTitle()).toBe("Servernummer vergleichen");
    expect(dialog()?.querySelector("code")?.textContent).toBe(
      "hangar-drive-server server-key-number",
    );
    expect(all(".number-group")).toHaveLength(6);
    const yes = button("Ja, gleiche Zahlen, verbinden");
    expect(yes.getAttribute("aria-disabled")).toBe("true");
    await click(yes);
    expect(mock.calls).not.toContain("confirmServerNumber");
    await wait(ARM_DELAY_MS + 50);
    expect(yes.getAttribute("aria-disabled")).toBe("false");
    await click(yes);
    expect(mock.calls).toContain("confirmServerNumber");
    expect(text()).toContain("Verbunden. Alles läuft wieder.");
  });

  it("trusts nothing when the native question is answered with no", async () => {
    const { mock } = await renderApp("serverIdentityAlone");
    mock.controls.nativeConfirm = "no";
    await click("Mit dem Betreiber vergleichen");
    await wait(ARM_DELAY_MS + 50);
    await click("Ja, gleiche Zahlen, verbinden");
    expect(mock.calls).toContain("confirmServerNumber");
    expect(text()).toContain("Dann verbinde nicht.");
    expect(text()).not.toContain("Verbunden. Alles läuft wieder.");
  });

  it("says what to do when the numbers differ", async () => {
    await renderApp("serverIdentityAlone");
    await click("Mit dem Betreiber vergleichen");
    await click("Nein, nicht verbinden");
    expect(text()).toContain(
      "Dann verbinde nicht. Sag dem Betreiber, dass die Zahlen nicht passen.",
    );
  });
});

describe("older state (UX 8.6)", () => {
  it("compares, confirms honestly and continues", async () => {
    const { mock } = await renderApp("olderState");
    await click("Fortsetzen …");
    expect(dialogTitle()).toBe("Erst mit einem anderen Gerät vergleichen");
    await wait(ARM_DELAY_MS + 50);
    // The shell asks natively with the folder and what is lost (security review M4); the
    // window asks nothing more after the comparison, and "no" there keeps the screen.
    mock.controls.nativeConfirm = "no";
    await click("Ja, gleiche Zahlen");
    expect(mock.calls).toContain("reanchor:compared");
    expect(dialogTitle()).toBe("Erst mit einem anderen Gerät vergleichen");
    mock.controls.nativeConfirm = "yes";
    await click("Ja, gleiche Zahlen");
    expect(dialogTitle()).toBe("„Hangar Drive“ läuft wieder.");
    expect(text()).toContain("bestätige es dort genauso");
  });

  it("continues without comparing only after saying what that costs", async () => {
    const { mock } = await renderApp("olderState");
    await click("Fortsetzen …");
    await click("Kein anderes Gerät da?");
    expect(dialogTitle()).toBe("Ohne Vergleich fortsetzen?");
    expect(text()).toContain("Mach das nur, wenn der Betreiber es dir bestätigt hat.");
    await wait(ARM_DELAY_MS + 50);
    await click("Ohne Vergleich fortsetzen");
    expect(mock.calls).toContain("reanchor:blind");
  });

  it("stops when the numbers differ", async () => {
    const { mock } = await renderApp("olderState");
    await click("Fortsetzen …");
    await click("Nein, sie sind anders");
    expect(dialogTitle()).toBe("Dann setze nicht fort");
    await click("Fehlerbericht kopieren");
    expect(mock.calls).toContain("copyErrorReport");
    expect(mock.calls).not.toContain("reanchor:compared");
  });
});

describe("suspected ransomware (UX 9.4)", () => {
  it("guides in three steps: remove the device, check it, bring back the state", async () => {
    const { mock } = await renderApp("suspect");
    await click("Was jetzt?");
    expect(all(".steps .step").map((step) => step.querySelector("p")?.textContent)).toEqual([
      "Trenne „Büro-PC“ vom Netz oder entferne es hier.",
      "Prüfe das Gerät mit deinem Virenschutz.",
      "Hol den Stand von davor zurück.",
    ]);
    // The shell asks natively with the device's name (security review M4).
    mock.controls.nativeConfirm = "no";
    await click("Entfernen");
    expect(mock.calls).toContain("removeDevice:d-office");
    expect(text()).not.toContain("wurde entfernt");
    mock.controls.nativeConfirm = "yes";
    await click("Entfernen");
    expect(text()).toContain("„Büro-PC“ wurde entfernt.");
    await click("Stand vor den Änderungen ansehen");
    expect(dialogTitle()).toBe("Frühere Versionen von „Hangar Drive“");
    expect(text()).toContain("Vor den Änderungen von „Büro-PC“");
    expect(document.querySelector('[role="option"][aria-selected="true"]')?.textContent).toContain(
      "Büro-PC",
    );
  });
});
