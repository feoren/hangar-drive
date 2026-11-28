import { describe, expect, it } from "vitest";

import type { Folder, FolderStatus } from "../backend/types";
import { createTranslator, type Language } from "../i18n";
import { folderContentText, folderTone, sameRowProps } from "./FolderList";

function folder(status: FolderStatus): Folder {
  return {
    id: "f",
    name: "Docs",
    path: "C:\\Docs",
    status,
    freezeDays: null,
    notSyncedCount: 0,
    bytes: null,
    fileCount: null,
  };
}

describe("folder tone", () => {
  it("is green only for a folder that is done while the server answers", () => {
    expect(folderTone(folder({ kind: "upToDate" }), true)).toBe("is-ok");
    expect(folderTone(folder({ kind: "upToDate" }), false)).toBe("is-quiet");
  });

  it("is red for every state that needs the person, online or not", () => {
    for (const reason of [
      "missing",
      "olderState",
      "removedHeads",
      "treeLimit",
      "tooLarge",
    ] as const) {
      for (const online of [true, false]) {
        expect(folderTone(folder({ kind: "stopped", reason }), online)).toBe("is-stopped");
      }
    }
  });

  it("stays neutral while syncing or paused", () => {
    expect(folderTone(folder({ kind: "uploading", count: 3 }), true)).toBe("is-active");
    expect(folderTone(folder({ kind: "downloading", count: 3 }), true)).toBe("is-active");
    expect(folderTone(folder({ kind: "paused" }), true)).toBe("is-quiet");
  });
});

describe("folder content line", () => {
  // Intl puts a no-break space before some units, depending on the language; compared as space.
  const content = (language: Language, fileCount: number | null, bytes: number | null) =>
    folderContentText(
      { ...folder({ kind: "upToDate" }), fileCount, bytes },
      language,
      createTranslator(language),
    )?.replace(/\u00a0/g, " ") ?? null;

  it("names the files and the size, with localized numbers", () => {
    expect(content("de", 1234, 6_200_000_000)).toBe("1.234 Dateien · 6,2 GB");
    expect(content("en", 1234, 6_200_000_000)).toBe("1,234 files · 6.2 GB");
    expect(content("de", 1, 2_000)).toBe("1 Datei · 2 kB");
  });

  it("leaves out what is not known yet, and shows nothing when nothing is", () => {
    expect(content("de", null, 6_200_000_000)).toBe("6,2 GB");
    expect(content("de", 12, null)).toBe("12 Dateien");
    expect(content("de", null, null)).toBeNull();
    // An empty folder that was scanned says so.
    expect(content("de", 0, 0)).toBe("0 Dateien · 0 Byte");
  });

  it("uses the plural forms of each language", () => {
    const files = (language: Language, count: number) => content(language, count, null);
    expect([1, 2, 5, 22, 1001].map((n) => files("pl", n))).toEqual([
      "1 plik",
      "2 pliki",
      "5 plików",
      "22 pliki",
      "1001 plików",
    ]);
    expect([1, 3, 11, 21].map((n) => files("ru", n))).toEqual([
      "1 файл",
      "3 файла",
      "11 файлов",
      "21 файл",
    ]);
    expect(files("fr", 1)).toBe("1 fichier");
    expect(files("fr", 2)).toBe("2 fichiers");
    expect(files("fr", 1_000_000)).toBe("1 000 000 de fichiers");
    expect(files("ja", 3)).toBe("3 個のファイル");
    expect(files("zh", 3)).toBe("3 个文件");
  });
});

describe("folder row memo", () => {
  const open = () => undefined;
  const onDeleted = () => undefined;
  const onItemFocus = () => undefined;
  const props = (status: FolderStatus) => ({
    folder: folder(status),
    online: true,
    open,
    onDeleted,
    index: 0,
    tabIndex: 0 as const,
    onItemFocus,
  });

  // Every snapshot brings new folder objects; a row draws again only when its folder changed.
  it("treats a new folder object with the same content as the same row", () => {
    expect(sameRowProps(props({ kind: "upToDate" }), props({ kind: "upToDate" }))).toBe(true);
    expect(
      sameRowProps(props({ kind: "uploading", count: 3 }), props({ kind: "uploading", count: 2 })),
    ).toBe(false);
    expect(
      sameRowProps(props({ kind: "upToDate" }), { ...props({ kind: "upToDate" }), online: false }),
    ).toBe(false);
    expect(
      sameRowProps(props({ kind: "upToDate" }), { ...props({ kind: "upToDate" }), tabIndex: -1 }),
    ).toBe(false);
  });
});
