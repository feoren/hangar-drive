// @vitest-environment happy-dom
// Every link field removes white space while the person types or pastes, because the backend's
// parsers refuse it: a link typed from paper in groups of four still arrives whole.

import { act } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { MOCK_INPUTS } from "../backend/mock/mockBackend";
import { cleanup, click, field, flush, renderApp, text, type } from "../test/harness";

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

/** "hangar-drive://pair#Z4mK8q" as a person types it from a sheet: groups of four. */
function inGroupsOfFour(link: string, separator = " "): string {
  return (link.match(/.{1,4}/g) ?? []).join(separator);
}

describe("link fields", () => {
  it("sends a pairing link typed in groups of four without the spaces", async () => {
    const { mock } = await renderApp("setup");
    const inspect = vi.spyOn(mock, "inspectLink");
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    await type(field("Kopplungslink"), inGroupsOfFour(MOCK_INPUTS.pair));
    expect(field("Kopplungslink").value).toBe(MOCK_INPUTS.pair);
    await click("Koppeln");
    expect(inspect).toHaveBeenCalledWith(MOCK_INPUTS.pair);
    expect(text()).toContain("Mit diesem Server verbinden?");
  });

  it("joins an invite pasted over several lines", async () => {
    const { mock } = await renderApp("setup");
    mock.controls.clipboard = inGroupsOfFour(MOCK_INPUTS.invite, "\n");
    const check = vi.spyOn(mock, "checkInvite");
    await click("Mit Einladungslink starten");
    await click("Einfügen");
    expect(field("Einladungslink").value).toBe(MOCK_INPUTS.invite);
    await wait(400);
    expect(check).toHaveBeenCalledWith(MOCK_INPUTS.invite);
    expect(text()).toContain("Verbunden mit drive.example.org");
  });

  it("sends the recovery sheet's link typed in groups of four without the spaces", async () => {
    const { mock } = await renderApp("setup");
    const inspect = vi.spyOn(mock, "inspectLink");
    await click("Kein Gerät mehr da? Wiederherstellungsblatt nutzen");
    await type(field("Link vom Blatt"), inGroupsOfFour(MOCK_INPUTS.recoverLink));
    await wait(400);
    expect(inspect).toHaveBeenLastCalledWith(MOCK_INPUTS.recoverLink);
    expect(text()).not.toContain("Der Link ist unvollständig.");
  });

  it("keeps the caret after the same character when a space is removed", async () => {
    await renderApp("setup");
    await click("Ich nutze Hangar Drive schon auf einem anderen Gerät");
    const input = field("Kopplungslink");
    await type(input, "abcd");
    const descriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value");
    await act(async () => {
      descriptor?.set?.call(input, "ab cd");
      input.setSelectionRange(3, 3);
      input.dispatchEvent(new Event("input", { bubbles: true }));
      await Promise.resolve();
    });
    await flush();
    expect(input.value).toBe("abcd");
    expect(input.selectionStart).toBe(2);
  });
});
