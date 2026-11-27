import { describe, expect, it } from "vitest";

import { scenarioState, type ScenarioId } from "../backend/mock/scenarios";
import type { Snapshot } from "../backend/types";
import { createTranslator } from "../i18n";
import {
  actionId,
  parseActionId,
  pauseUntil,
  stateText,
  SYNC_ENTER_MS,
  SYNC_LEAVE_MS,
  SyncHysteresis,
  tooltip,
  trayMenu,
  trayModel,
  trayState,
  type TrayAction,
  type TrayMenuItem,
} from "./trayModel";

const NOW = new Date(2026, 10, 26, 14, 0).getTime();
const de = createTranslator("de");
const en = createTranslator("en");

function snap(id: ScenarioId): Snapshot {
  const s = scenarioState(id, NOW);
  return {
    setup: s.setup,
    sync: s.sync,
    folders: s.folders,
    activity: s.activity,
    warnings: s.warnings,
    notices: s.notices,
    storage: s.storage,
    account: s.account,
    remoteFolders: s.remoteFolders,
    deletedFolders: s.deletedFolders,
    env: { camera: false },
  };
}

function labels(menu: readonly TrayMenuItem[]): string[] {
  return menu.map((item) => {
    if (item.type === "separator") return "---";
    if (item.type === "action" && item.isDefault) return `*${item.label}`;
    return item.label;
  });
}

function subLabels(menu: readonly TrayMenuItem[], label: string): string[] {
  const sub = menu.find((item) => item.type === "submenu" && item.label === label);
  if (sub?.type !== "submenu") return [];
  return sub.items.map((item) => (item.type === "action" ? `${item.id}=${item.label}` : ""));
}

describe("tray state", () => {
  it("shows one state for the whole app, the most urgent", () => {
    expect(trayState(snap("setup"), NOW, false).kind).toBe("setup");
    expect(trayState(snap("massDelete"), NOW, false).kind).toBe("attention");
    expect(trayState(snap("incomingDelete"), NOW, false).kind).toBe("attention");
    expect(trayState(snap("paused"), NOW, false).kind).toBe("paused");
    expect(trayState(snap("offline"), NOW, false)).toEqual({
      kind: "offline",
      reason: "noNetwork",
    });
    expect(trayState(snap("serverSilent"), NOW, false)).toEqual({
      kind: "offline",
      reason: "server",
    });
    expect(trayState(snap("serverLong"), NOW, false).kind).toBe("attention");
    expect(trayState(snap("syncing"), NOW, true)).toEqual({ kind: "syncing", count: 120 });
    expect(trayState(snap("upToDate"), NOW, false)).toEqual({ kind: "upToDate", waiting: false });
  });

  it("puts problems above a pause and a pause above offline", () => {
    const offline = { kind: "noNetwork" } as const;
    const both: Snapshot = {
      ...snap("massDelete"),
      sync: { ...snap("paused").sync, connection: offline },
    };
    expect(trayState(both, NOW, false).kind).toBe("attention");
    const pausedOffline: Snapshot = {
      ...snap("paused"),
      sync: { ...snap("paused").sync, connection: offline },
    };
    expect(trayState(pausedOffline, NOW, false).kind).toBe("paused");
  });

  it("shows syncing only when the hysteresis says so", () => {
    expect(trayState(snap("syncing"), NOW, false).kind).toBe("upToDate");
  });

  it("keeps conflicts and names out of 'needs you'", () => {
    expect(trayState(snap("conflicts"), NOW, false).kind).toBe("upToDate");
    expect(trayState(snap("names"), NOW, false).kind).toBe("upToDate");
  });

  it("does not count waiting files as work", () => {
    const metered = trayState(snap("metered"), NOW, false);
    expect(metered).toEqual({ kind: "upToDate", waiting: true });
    expect(stateText(metered, de, "de", NOW)).toBe("Alles andere ist aktuell");
    expect(trayState(snap("budget"), NOW, false)).toEqual({ kind: "upToDate", waiting: true });
  });

  it("names the state in words", () => {
    expect(stateText({ kind: "syncing", count: 1 }, de, "de", NOW)).toBe(
      "1 Datei wird synchronisiert",
    );
    expect(stateText({ kind: "paused", until: null }, de, "de", NOW)).toBe("Angehalten");
    expect(stateText({ kind: "paused", until: NOW + 3_600_000 }, de, "de", NOW)).toBe(
      "Angehalten bis 15:00",
    );
    expect(stateText({ kind: "attention" }, en, "en", NOW)).toBe("Needs your help");
    expect(stateText({ kind: "offline", reason: "server" }, de, "de", NOW)).toBe(
      "Offline. Änderungen werden später synchronisiert.",
    );
  });

  it("puts the state and the waiting reason into the tooltip", () => {
    const s = snap("budget");
    expect(tooltip(s, trayState(s, NOW, false), de, "de", NOW)).toBe(
      "Hangar Drive: Alles andere ist aktuell\n48 Dateien warten, weil heute schon sehr viel hochgeladen wurde. Die Dateien gehen spätestens morgen raus.",
    );
  });
});

describe("hysteresis", () => {
  it("shows syncing only after 2 s of work and leaves it after 3 s without", () => {
    const h = new SyncHysteresis();
    expect(h.update(true, 0)).toBe(false);
    expect(h.pending(0)).toBe(SYNC_ENTER_MS);
    expect(h.update(true, SYNC_ENTER_MS - 1)).toBe(false);
    expect(h.update(true, SYNC_ENTER_MS)).toBe(true);
    expect(h.pending(SYNC_ENTER_MS)).toBeNull();
    expect(h.update(false, 5000)).toBe(true);
    expect(h.update(false, 5000 + SYNC_LEAVE_MS - 1)).toBe(true);
    expect(h.update(false, 5000 + SYNC_LEAVE_MS)).toBe(false);
  });

  it("ignores short bursts of work", () => {
    const h = new SyncHysteresis();
    h.update(true, 0);
    expect(h.update(false, 1000)).toBe(false);
    expect(h.update(true, 1500)).toBe(false);
    expect(h.update(true, 3000)).toBe(false);
    expect(h.update(true, 3500)).toBe(true);
  });
});

describe("tray menu", () => {
  it("has status, last file, open folder, open app, pause and quit", () => {
    const s = { ...snap("upToDate"), folders: snap("upToDate").folders.slice(0, 1) };
    expect(labels(trayMenu(s, trayState(s, NOW, false), de, "de", NOW))).toEqual([
      "Alles aktuell",
      "Zuletzt: Bericht.docx, vor 2 Min.",
      "---",
      "*Ordner öffnen",
      "Hangar Drive öffnen",
      "---",
      "Pausieren",
      "---",
      "Beenden",
    ]);
  });

  it("makes 'Show problem' the only default item when something needs the person", () => {
    const s = snap("missingFolder");
    const menu = labels(trayMenu(s, trayState(s, NOW, false), de, "de", NOW));
    expect(menu[3]).toBe("*Problem ansehen");
    expect(menu.filter((label) => label.startsWith("*"))).toHaveLength(1);
  });

  it("offers several folders as a submenu", () => {
    const s = snap("upToDate");
    expect(
      subLabels(trayMenu(s, trayState(s, NOW, false), de, "de", NOW), "Ordner öffnen"),
    ).toEqual(["open-folder:f-main=Hangar Drive", "open-folder:f-photos=Fotos"]);
  });

  it("offers three pause durations, and resume while paused", () => {
    const s = snap("upToDate");
    expect(subLabels(trayMenu(s, trayState(s, NOW, false), de, "de", NOW), "Pausieren")).toEqual([
      "pause:hour=Für 1 Stunde",
      "pause:tomorrow=Bis morgen",
      "pause:manual=Bis ich fortsetze",
    ]);
    const paused = snap("paused");
    expect(labels(trayMenu(paused, trayState(paused, NOW, false), de, "de", NOW))).toContain(
      "Fortsetzen",
    );
  });

  it("offers only opening the window during setup", () => {
    const s = snap("setup");
    expect(labels(trayMenu(s, trayState(s, NOW, false), de, "de", NOW))).toEqual([
      "Einrichtung noch nicht fertig",
      "---",
      "*Hangar Drive öffnen",
      "---",
      "Beenden",
    ]);
  });

  it("picks the icon of the state", () => {
    const s = snap("offline");
    expect(trayModel(s, trayState(s, NOW, false), de, "de", NOW).icon).toBe("offline");
  });

  it("turns every action into an id and back", () => {
    const actions: TrayAction[] = [
      { kind: "showProblem" },
      { kind: "openFolder", folderId: "f:1" },
      { kind: "openApp" },
      { kind: "pause", duration: "hour" },
      { kind: "pause", duration: "tomorrow" },
      { kind: "pause", duration: "manual" },
      { kind: "resume" },
      { kind: "quit" },
    ];
    for (const action of actions) expect(parseActionId(actionId(action))).toEqual(action);
    expect(parseActionId("open-folder:")).toBeNull();
    expect(parseActionId("pause:year")).toBeNull();
    expect(parseActionId("nonsense")).toBeNull();
  });
});

describe("pause durations", () => {
  it("ends in an hour, tomorrow at 06:00, or never", () => {
    expect(pauseUntil("hour", NOW)).toBe(NOW + 3_600_000);
    expect(pauseUntil("tomorrow", NOW)).toBe(new Date(2026, 10, 27, 6, 0).getTime());
    expect(pauseUntil("tomorrow", new Date(2026, 10, 26, 2, 0).getTime())).toBe(
      new Date(2026, 10, 27, 6, 0).getTime(),
    );
    expect(pauseUntil("manual", NOW)).toBeNull();
  });
});
