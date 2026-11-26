// @vitest-environment happy-dom
// Changes of a removed device (UX 8.9), the focus after an automatically opened question, links
// the OS hands to a set-up device, and the small fixes of the last acceptance review.

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MOCK_INPUTS } from "../backend/mock/mockBackend";
import {
  all,
  button,
  cleanup,
  click,
  dialog,
  dialogTitle,
  flush,
  key,
  renderApp,
  text,
} from "../test/harness";
import { ARM_DELAY_MS } from "../ui/parts";

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

function banner(): HTMLElement | null {
  return document.querySelector(".banner");
}

describe("changes from a removed device (UX 8.9)", () => {
  it("asks by itself in one sentence, the safe way first", async () => {
    await renderApp("removedHeads");
    expect(dialogTitle()).toBe("Änderungen von einem entfernten Gerät");
    expect(dialog()?.getAttribute("role")).toBe("alertdialog");
    expect(text()).toContain(
      "In „Fotos“ sind Änderungen von „Alter Laptop“ angekommen, obwohl das Gerät nicht mehr zu deinem Konto gehört.",
    );
    expect(document.activeElement?.textContent).toBe("Ansehen und rückgängig machen");
    expect(button("Ansehen und rückgängig machen").className).toContain("primary");
    expect(button("Übernehmen").className).toContain("secondary");
  });

  it("holds back both buttons for a second", async () => {
    const { mock } = await renderApp("removedHeads");
    expect(button("Ansehen und rückgängig machen").getAttribute("aria-disabled")).toBe("true");
    expect(button("Übernehmen").getAttribute("aria-disabled")).toBe("true");
    await click("Übernehmen");
    await click("Ansehen und rückgängig machen");
    expect(mock.calls.some((call) => call.startsWith("acceptRemovedHeads"))).toBe(false);
    await wait(ARM_DELAY_MS + 50);
    expect(button("Übernehmen").getAttribute("aria-disabled")).toBe("false");
  });

  it("reviews and undoes: earlier versions open at the state before the device", async () => {
    const { mock } = await renderApp("removedHeads");
    await wait(ARM_DELAY_MS + 50);
    await click("Ansehen und rückgängig machen");
    expect(mock.calls).toContain("acceptRemovedHeads:f-photos");
    expect(dialogTitle()).toBe("Frühere Versionen von „Fotos“");
    expect(text()).toContain("Vor den Änderungen von „Alter Laptop“");
    expect(document.querySelector('[role="option"][aria-selected="true"]')?.id).toMatch(/t3$/);
  });

  it("accepts, says the folder syncs again and still offers to undo", async () => {
    const { mock } = await renderApp("removedHeads");
    await wait(ARM_DELAY_MS + 50);
    await click("Übernehmen");
    expect(mock.calls).toContain("acceptRemovedHeads:f-photos");
    expect(text()).toContain("Übernommen. „Fotos“ wird wieder synchronisiert.");
    expect(document.activeElement?.textContent).toBe("Schließen");
    await click("Doch rückgängig machen");
    expect(dialogTitle()).toBe("Frühere Versionen von „Fotos“");
  });

  // Security review M4: taking the changes in asks natively; "no" there leaves the folder
  // stopped and the question open.
  it("takes nothing in when the native question is answered with no", async () => {
    const { mock } = await renderApp("removedHeads");
    mock.controls.nativeConfirm = "no";
    await wait(ARM_DELAY_MS + 50);
    await click("Übernehmen");
    expect(mock.calls).toContain("acceptRemovedHeads:f-photos");
    expect(dialogTitle()).toBe("Änderungen von einem entfernten Gerät");
    expect(text()).not.toContain("Übernommen.");
    await click("Ansehen und rückgängig machen");
    expect(dialogTitle()).toBe("Änderungen von einem entfernten Gerät");
  });

  it("names the devices by number when it does not know every name", async () => {
    await renderApp("removedHeadsMany");
    expect(text()).toContain(
      "In „Fotos“ sind Änderungen von 2 Geräten angekommen, die nicht mehr zu deinem Konto gehören.",
    );
  });

  it("leaves the folder stopped on Escape and puts the focus on the banner", async () => {
    await renderApp("removedHeads");
    await key(dialog() ?? document.body, "Escape");
    expect(dialog()).toBeNull();
    expect(banner()?.textContent).toContain("Änderungen von einem entfernten Gerät");
    expect(document.activeElement).toBe(banner());
    expect(text()).toContain("Angehalten: Änderungen eines entfernten Geräts");
    await click("Entscheiden");
    expect(dialogTitle()).toBe("Änderungen von einem entfernten Gerät");
  });

  it("brings the question back when the backend reports the changes again", async () => {
    const { mock } = await renderApp("removedHeads");
    await key(dialog() ?? document.body, "Escape");
    act(() => {
      mock.setScenario("removedHeads");
    });
    await flush();
    expect(dialogTitle()).toBe("Änderungen von einem entfernten Gerät");
  });
});

describe("focus after the automatic mass deletion question (UX 8.1)", () => {
  it("goes to the banner after Escape", async () => {
    await renderApp("massDelete");
    expect(dialogTitle()).toBe("342 Dateien gelöscht");
    await key(dialog() ?? document.body, "Escape");
    expect(document.activeElement).toBe(banner());
  });

  it("returns to the opener when the person opened it", async () => {
    await renderApp("massDelete");
    await key(dialog() ?? document.body, "Escape");
    const opener = button("Entscheiden");
    opener.focus();
    await click(opener);
    await key(dialog() ?? document.body, "Escape");
    expect(document.activeElement).toBe(button("Entscheiden"));
  });
});

describe("links on a device that is set up", () => {
  it("says the link is not needed here", async () => {
    const { mock } = await renderApp("deepLinkDone");
    await flush();
    expect(dialogTitle()).toBe("Dieses Gerät ist schon eingerichtet");
    expect(mock.calls).not.toContain("checkInvite");
  });

  it("fills a pairing link into the server fix when the server identifies itself differently", async () => {
    const { mock } = await renderApp("serverIdentity");
    act(() => {
      mock.openLink(MOCK_INPUTS.pair);
    });
    await flush();
    expect(dialogTitle()).toBe("Code von einem anderen Gerät scannen");
    expect(
      all("input").some(
        (input) => input instanceof HTMLInputElement && input.value === MOCK_INPUTS.pair,
      ),
    ).toBe(true);
    expect(mock.calls).not.toContain("fixServerWithOffer");
  });
});

describe("two versions: size in a sentence of its own", () => {
  it("joins version and size through the dictionary", async () => {
    await renderApp("conflicts");
    await click("Ansehen");
    const line = document.querySelector(".version-sub")?.textContent ?? "";
    expect(line).toMatch(/^Fassung von Büro-PC, vor 40 Min\., \d/);
  });
});

describe("earlier versions: loading the devices for 'state before'", () => {
  it("shows that it loads and that it searches", async () => {
    const { mock } = await renderApp();
    await click("Aktionen für „Hangar Drive“");
    await click("Frühere Versionen");
    let finish: (() => void) | null = null;
    const list = mock.listDevices.bind(mock);
    vi.spyOn(mock, "listDevices").mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          finish = () => {
            void list().then(resolve);
          };
        }),
    );
    await click("Stand vor Änderungen von …");
    expect(document.querySelector(".before-device .loading")?.textContent).toBe("Wird geladen …");
    act(() => {
      finish?.();
    });
    await flush();
    expect(document.querySelector(".before-device .loading")).toBeNull();
    let found: ((entry: string | null) => void) | null = null;
    vi.spyOn(mock, "findBeforeDevice").mockImplementationOnce(
      () =>
        new Promise((resolve) => {
          found = resolve;
        }),
    );
    await click("Stand suchen");
    const search = document.querySelector<HTMLElement>(".before-device button[type=submit]");
    expect(search?.textContent).toBe("Wird gesucht …");
    expect(search?.getAttribute("aria-busy")).toBe("true");
    act(() => {
      found?.("t4");
    });
    await flush();
    expect(text()).toContain("Vor den Änderungen von „Büro-PC“");
  });
});
