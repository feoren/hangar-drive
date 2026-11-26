import { describe, expect, it } from "vitest";

import type { Folder, FolderStatus } from "../backend/types";
import { folderTone } from "./FolderList";

function folder(status: FolderStatus): Folder {
  return {
    id: "f",
    name: "Docs",
    path: "C:\\Docs",
    status,
    freezeDays: null,
    notSyncedCount: 0,
    bytes: null,
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
