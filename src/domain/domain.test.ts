import { describe, expect, it } from "vitest";

import { scenarioState } from "../backend/mock/scenarios";
import type { Snapshot, Warning } from "../backend/types";
import { looksLikeRecoveryCode, normalizeCode, spellOut, splitGroups } from "./codes";
import {
  anyAttention,
  needsAttention,
  SERVER_SILENT_PROBLEM_MS,
  shownWarnings,
  tone,
} from "./warnings";
import { suggestWindowsName, windowsNameProblem } from "./windowsNames";

const NOW = new Date(2026, 10, 26, 14, 0).getTime();

function snapshot(warnings: Warning[], patch: Partial<Snapshot["sync"]> = {}): Snapshot {
  const state = scenarioState("upToDate", NOW);
  return {
    setup: "done",
    sync: { ...state.sync, ...patch },
    folders: state.folders,
    activity: [],
    warnings,
    notices: [],
    storage: null,
    account: state.account,
    remoteFolders: [],
    deletedFolders: [],
    env: { camera: false },
  };
}

describe("codes", () => {
  it("forgives what people mix up when they copy from paper", () => {
    expect(normalizeCode(" d7kq-m2xp ")).toBe("D7KQM2XP");
    expect(normalizeCode("oIlL")).toBe("0111");
  });

  it("splits a pasted code into groups of four", () => {
    expect(splitGroups("D7KQ M2XP-9H4T")).toEqual(["D7KQ", "M2XP", "9H4T"]);
  });

  it("spells groups out for screen readers", () => {
    expect(spellOut("9H4T")).toBe("9 H 4 T");
  });

  it("recognizes a full recovery code", () => {
    expect(looksLikeRecoveryCode("D7KQ M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY")).toBe(true);
    expect(looksLikeRecoveryCode("D7KQ M2XP")).toBe(false);
    expect(looksLikeRecoveryCode("U".repeat(32))).toBe(false);
  });
});

describe("Windows names", () => {
  it("names the forbidden character", () => {
    expect(windowsNameProblem("Budget: Q1.xlsx")).toEqual({ kind: "char", char: ":" });
    expect(windowsNameProblem("a?b")).toEqual({ kind: "char", char: "?" });
  });

  it("finds reserved names even with an extension", () => {
    expect(windowsNameProblem("CON.txt")).toEqual({ kind: "reserved", name: "CON" });
    expect(windowsNameProblem("lpt1")).toEqual({ kind: "reserved", name: "lpt1" });
    expect(windowsNameProblem("CONSOLE.txt")).toBeNull();
  });

  it("finds trailing dots and spaces and control characters", () => {
    expect(windowsNameProblem("Notizen.")).toEqual({ kind: "trailing" });
    expect(windowsNameProblem("Notizen ")).toEqual({ kind: "trailing" });
    expect(windowsNameProblem(`a${String.fromCharCode(7)}b`)).toEqual({ kind: "control" });
  });

  it("finds names Explorer takes for a shell junction", () => {
    const name = "Bilder.{0AFACED1-E828-11D1-9187-B532F1E9575D}";
    expect(windowsNameProblem(name)).toEqual({ kind: "reserved", name });
    expect(windowsNameProblem("a.{0afaced1-e828-11d1-9187-b532f1e9575d}")).not.toBeNull();
    expect(windowsNameProblem("a.{0AFACED1-E828-11D1-9187-B532F1E9575D}.txt")).toBeNull();
    expect(windowsNameProblem("notes {draft}")).toBeNull();
    expect(suggestWindowsName(name)).toBe("Bilder {0AFACED1-E828-11D1-9187-B532F1E9575D}");
    expect(windowsNameProblem(suggestWindowsName(name))).toBeNull();
  });

  it("accepts ordinary names", () => {
    expect(windowsNameProblem("Bericht (final).docx")).toBeNull();
  });

  it("suggests a close name Windows accepts", () => {
    expect(suggestWindowsName("Budget: Q1.xlsx")).toBe("Budget Q1.xlsx");
    expect(suggestWindowsName("CON.txt")).toBe("CON_.txt");
    expect(suggestWindowsName("NUL")).toBe("NUL_");
    expect(suggestWindowsName("Notizen.")).toBe("Notizen");
    expect(suggestWindowsName("???")).toBe("_");
    for (const name of ["Budget: Q1.xlsx", "CON.txt", "a|b<c>", "x. "]) {
      expect(windowsNameProblem(suggestWindowsName(name)), name).toBeNull();
    }
  });
});

describe("warnings", () => {
  const conflicts: Warning = { kind: "conflicts", id: "c", count: 2 };
  const missing: Warning = { kind: "missingFolder", id: "m", folderId: "f", folderName: "Fotos" };
  const suspect: Warning = {
    kind: "suspect",
    id: "s",
    deviceId: "d",
    deviceName: "PC",
    folderId: "f",
    folderName: "Fotos",
    entryId: "t",
    days: 30,
    until: NOW + 90 * 86_400_000,
    lapsed: false,
  };

  it("orders by urgency, a suspected attack first", () => {
    const list = shownWarnings(snapshot([conflicts, missing, suspect]), NOW);
    expect(list.map((warning) => warning.kind)).toEqual(["suspect", "missingFolder", "conflicts"]);
  });

  it("keeps conflicts and names calm", () => {
    expect(needsAttention(conflicts)).toBe(false);
    expect(needsAttention(missing)).toBe(true);
    expect(anyAttention(snapshot([conflicts]), NOW)).toBe(false);
    expect(anyAttention(snapshot([missing]), NOW)).toBe(true);
  });

  it("makes only the suspected attack red", () => {
    expect(tone(suspect)).toBe("danger");
    expect(tone(missing)).toBe("attention");
    expect(tone(conflicts)).toBe("info");
  });

  // A missing recovery code needs the person (tray "needs you"); a pending recovery finishes by
  // itself and stays calm.
  it("ranks the recovery warnings: no code needs you, a pending recovery is calm", () => {
    const noCode: Warning = { kind: "noRecoveryCode", id: "noRecoveryCode" };
    const pending: Warning = { kind: "recoveryPending", id: "recoveryPending" };
    expect(needsAttention(noCode)).toBe(true);
    expect(tone(noCode)).toBe("attention");
    expect(needsAttention(pending)).toBe(false);
    expect(tone(pending)).toBe("info");
    const list = shownWarnings(snapshot([conflicts, pending, noCode, missing]), NOW);
    expect(list.map((warning) => warning.kind)).toEqual([
      "missingFolder",
      "noRecoveryCode",
      "recoveryPending",
      "conflicts",
    ]);
  });

  it("keeps folders unreadable after a recovery calm, and drops an empty one", () => {
    const folders: Warning = {
      kind: "foldersUnreadable",
      id: "foldersUnreadable",
      folders: ["Docs"],
      folderList: false,
    };
    expect(needsAttention(folders)).toBe(false);
    expect(tone(folders)).toBe("info");
    expect(anyAttention(snapshot([folders]), NOW)).toBe(false);
    expect(shownWarnings(snapshot([conflicts, folders]), NOW).map((w) => w.kind)).toEqual([
      "foldersUnreadable",
      "conflicts",
    ]);
    const listOnly: Warning = { ...folders, folders: [], folderList: true };
    expect(shownWarnings(snapshot([listOnly]), NOW)).toHaveLength(1);
    const nothing: Warning = { ...folders, folders: [], folderList: false };
    expect(shownWarnings(snapshot([nothing]), NOW)).toEqual([]);
  });

  it("drops banners whose count fell to zero", () => {
    expect(shownWarnings(snapshot([{ kind: "names", id: "n", count: 0 }]), NOW)).toEqual([]);
  });

  it("promotes a server silent for a day to a problem", () => {
    const short = snapshot([], { connection: { kind: "serverSilent", since: NOW - 5 * 60_000 } });
    const long = snapshot([], {
      connection: { kind: "serverSilent", since: NOW - SERVER_SILENT_PROBLEM_MS },
    });
    expect(shownWarnings(short, NOW)).toEqual([]);
    expect(shownWarnings(long, NOW).map((warning) => warning.kind)).toEqual(["serverLong"]);
    expect(anyAttention(long, NOW)).toBe(true);
  });
});
