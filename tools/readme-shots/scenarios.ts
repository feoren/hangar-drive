// The mock backend's scenarios for the README screenshots: run.mjs serves this module in place of
// src/backend/mock/scenarios.ts. It keeps every export of the real module and replaces the state
// a scenario starts with by the state of the README scene that run.mjs stored (`readmeShots.scene`),
// in English and with made-up names only. The real mock backend then runs unchanged on it.

import type { Millis, Warning } from "../../src/backend/types";
import * as real from "../../src/backend/mock/scenarios";
import * as fx from "./fixtures";

export * from "../../src/backend/mock/scenarios";

/** The README scene run.mjs chose before the app started. */
export function readmeScene(): string {
  try {
    const value: unknown = JSON.parse(localStorage.getItem("readmeShots.scene") ?? "null");
    return typeof value === "string" ? value : "overview";
  } catch {
    return "overview";
  }
}

/** The English base state: four folders, the account's other folder and one deleted folder. */
export function baseState(now: Millis): real.MockState {
  const state = real.baseState(now);
  state.sync.lastFile = { name: "Report.docx", at: now - 2 * fx.MINUTE };
  state.remoteFolders = [{ id: "f-archive", name: "Archive", size: 18_300_000_000 }];
  state.deletedFolders = [{ id: "f-old", name: "Old project", daysLeft: 12 }];
  state.storage = { used: 128_100_000_000, quota: 500_000_000_000 };
  return state;
}

const massDelete: Warning = {
  kind: "massDelete",
  id: "w-delete",
  folderId: "f-photos",
  folderName: "Photos",
  count: 342,
  sample: ["Holiday 001.jpg", "Holiday 002.jpg", "Holiday 003.jpg"],
};

/** The state of the README scene; `id` is ignored, the scene decides. */
export function scenarioState(_id: real.ScenarioId, now: Millis): real.MockState {
  const state = baseState(now);
  const status = (folderId: string, next: real.MockState["folders"][number]["status"]) => {
    state.folders = state.folders.map((folder) =>
      folder.id === folderId ? { ...folder, status: next } : folder,
    );
  };
  switch (readmeScene()) {
    case "overview":
      state.sync.pendingFiles = 120;
      state.sync.bytesLeft = 840_000_000;
      status("f-photos", { kind: "uploading", count: 117 });
      status("f-projects", { kind: "downloading", count: 3 });
      break;
    case "invite":
      state.setup = "needed";
      state.folders = [];
      state.activity = [];
      state.account = null;
      state.storage = null;
      state.sync.lastSync = null;
      state.sync.lastFile = null;
      break;
    case "conflicts":
      // One file, so the whole question fits the window.
      state.conflicts = state.conflicts.slice(0, 1);
      state.warnings = [{ kind: "conflicts", id: "w-conflicts", count: 1 }];
      break;
    case "mass-delete":
      state.warnings = [massDelete];
      break;
    default:
      break;
  }
  return state;
}
