// @vitest-environment happy-dom

// Security review LOW 3: file and path names from other devices are shown with their bidi
// controls replaced by U+FFFD, in every view that lists them, so a name cannot reorder its own
// letters (an override that makes `...exe` read like `...txt`).

import { afterEach, describe, expect, it, vi } from "vitest";

import { MockBackend } from "./backend/mock/mockBackend";
import { displayName, isolateName } from "./i18n";
import { all, cleanup, click, dialog, openMenu, renderApp, renderWith } from "./test/harness";
import { pinClock } from "./test/clock";

pinClock();

afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const OVERRIDE = String.fromCharCode(0x202e);
const REPLACEMENT = String.fromCharCode(0xfffd);
/** A harmless marker name with a right-to-left override inside. */
const SPOOF = `Marker${OVERRIDE}txt.docx`;
const SHOWN = `Marker${REPLACEMENT}txt.docx`;

/** No override anywhere on the page, text or attributes, and the marker shown replaced. */
function expectClean(scope: Element | null = document.body): void {
  const html = scope?.outerHTML ?? "";
  expect(html).not.toContain(OVERRIDE);
  expect(html).toContain(SHOWN);
}

describe("displayName", () => {
  it("replaces every bidi control and adds no isolate", () => {
    const controls = [0x061c, 0x200e, 0x200f, 0x202a, 0x202e, 0x2066, 0x2069]
      .map((c) => String.fromCharCode(c))
      .join("");
    expect(displayName(`a${controls}b`)).toBe(`a${REPLACEMENT.repeat(7)}b`);
    expect(displayName("Bericht.docx")).toBe("Bericht.docx");
    expect(displayName("\u05D0.txt")).toBe("\u05D0.txt");
    // The sentence form still isolates, with the same replacement inside.
    expect(isolateName(SPOOF)).toBe(`\u2068${SHOWN}\u2069`);
  });
});

describe("names from other devices in the views", () => {
  it("conflicts", async () => {
    const { mock } = await renderApp("conflicts");
    const original = mock.listConflicts.bind(mock);
    vi.spyOn(mock, "listConflicts").mockImplementation(async () =>
      (await original()).map((group) => ({
        ...group,
        path: `Projekte/${SPOOF}`,
        versions: group.versions.map((version) => ({ ...version, name: SPOOF })),
      })),
    );
    await click("Ansehen");
    expectClean(dialog());
  });

  it("names that do not work on Windows", async () => {
    const { mock } = await renderApp("names");
    const original = mock.listNameIssues.bind(mock);
    vi.spyOn(mock, "listNameIssues").mockImplementation(async () =>
      (await original()).map((issue) => ({ ...issue, name: SPOOF, dir: SPOOF })),
    );
    await click("Ansehen");
    expectClean(dialog());
  });

  it("the list of many deletions, each line isolated", async () => {
    const { mock } = await renderApp("massDelete");
    vi.spyOn(mock, "listMassDelete").mockResolvedValue([`Urlaub/${SPOOF}`]);
    await click("Liste ansehen");
    const line = all(".scroll-list li")[0];
    expect(line?.className).toBe("bidi-name");
    expectClean(line ?? null);
  });

  it("entries that are never synced", async () => {
    const { mock } = await renderApp("freeze");
    vi.spyOn(mock, "listNotSynced").mockResolvedValue([{ path: SPOOF, reason: "link" }]);
    await click("3 Einträge werden nicht synchronisiert");
    expectClean(dialog());
  });

  it("the tree of an earlier version", async () => {
    const { mock } = await renderApp();
    const original = mock.getTreeAt.bind(mock);
    vi.spyOn(mock, "getTreeAt").mockImplementation(async (folderId, entryId) => {
      const tree = await original(folderId, entryId);
      return { ...tree, nodes: tree.nodes.map((node) => ({ ...node, name: SPOOF })) };
    });
    await click("Aktionen für „Hangar Drive“");
    await click("Frühere Versionen");
    expectClean(dialog());
  });

  it("the trash", async () => {
    const { mock } = await renderApp();
    const original = mock.getTrash.bind(mock);
    vi.spyOn(mock, "getTrash").mockImplementation(async (folderId) =>
      (await original(folderId)).map((item) => ({ ...item, name: SPOOF, dir: SPOOF })),
    );
    await click("Aktionen für „Hangar Drive“");
    await click("Papierkorb");
    expectClean(dialog());
  });

  it("recent activity, its tooltip and its accessible name", async () => {
    const mock = new MockBackend({ scenario: "upToDate" });
    await mock.setLanguage("de");
    const original = mock.getSnapshot.bind(mock);
    vi.spyOn(mock, "getSnapshot").mockImplementation(async () => {
      const snapshot = await original();
      return {
        ...snapshot,
        activity: snapshot.activity.map((entry) =>
          entry.kind === "file" ? { ...entry, name: SPOOF } : entry,
        ),
      };
    });
    await renderWith(mock);
    await openMenu("Letzte Aktivitäten");
    const row = all(".activity-row")[0];
    expectClean(row ?? null);
    expect(row?.querySelector(".activity-name")?.getAttribute("title")).toBe(SHOWN);
  });

  it("a folder's path in the folder list", async () => {
    const mock = new MockBackend({ scenario: "upToDate" });
    await mock.setLanguage("de");
    const original = mock.getSnapshot.bind(mock);
    vi.spyOn(mock, "getSnapshot").mockImplementation(async () => {
      const snapshot = await original();
      return {
        ...snapshot,
        folders: snapshot.folders.map((folder) => ({ ...folder, path: `C:\\${SPOOF}` })),
      };
    });
    await renderWith(mock);
    expectClean(all(".folder-list, .list")[0] ?? null);
  });
});
