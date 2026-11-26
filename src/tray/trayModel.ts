// The tray state model (UX 6.1) and the tray menu (UX 6.2) as pure logic. The window computes
// both and hands them to the backend (`Backend.updateTray`), which draws the native icon and menu
// and reports clicks back as `trayAction` events. The status sentence at the top of the main
// window is the same text, so tray and window never disagree.

import type { Folder, Millis, PauseDuration, Snapshot } from "../backend/types";
import { anyAttention } from "../domain/warnings";
import { formatFutureTime, formatRelative } from "../format";
import type { Language, Translate } from "../i18n";

export type TrayState =
  | { readonly kind: "setup" }
  | { readonly kind: "attention" }
  | { readonly kind: "paused"; readonly until: Millis | null }
  | { readonly kind: "offline"; readonly reason: "noNetwork" | "server" }
  | { readonly kind: "syncing"; readonly count: number }
  /** `waiting`: files wait for an unmetered network or the upload budget. */
  | { readonly kind: "upToDate"; readonly waiting: boolean };

/** One icon per state, each with its own shape (icons.ts). */
export type TrayIcon = TrayState["kind"];

/** Work must last this long before the icon shows arrows, and be gone this long before it stops. */
export const SYNC_ENTER_MS = 2000;
export const SYNC_LEAVE_MS = 3000;

/**
 * Hysteresis for the syncing state (2 s in, 3 s out), so the icon does not blink while small files
 * change. Feed it the raw "is there work" value; it answers what to show.
 */
export class SyncHysteresis {
  private shown = false;
  private changedAt: Millis | null = null;

  update(hasWork: boolean, now: Millis): boolean {
    if (hasWork === this.shown) {
      this.changedAt = null;
      return this.shown;
    }
    this.changedAt ??= now;
    if (now - this.changedAt >= (hasWork ? SYNC_ENTER_MS : SYNC_LEAVE_MS)) {
      this.shown = hasWork;
      this.changedAt = null;
    }
    return this.shown;
  }

  /** Milliseconds until the shown value flips if the raw value stays; null when stable. */
  pending(now: Millis): number | null {
    if (this.changedAt === null) return null;
    const wait = this.shown ? SYNC_LEAVE_MS : SYNC_ENTER_MS;
    return Math.max(0, this.changedAt + wait - now);
  }
}

/**
 * The one state for the whole app, the most urgent across all folders. `syncingShown` is the
 * output of the hysteresis for `pendingFiles > 0`.
 */
export function trayState(snapshot: Snapshot, now: Millis, syncingShown: boolean): TrayState {
  if (snapshot.setup === "needed") return { kind: "setup" };
  if (anyAttention(snapshot, now)) return { kind: "attention" };
  const { sync } = snapshot;
  if (sync.pause) return { kind: "paused", until: sync.pause.until };
  if (sync.connection.kind === "noNetwork") return { kind: "offline", reason: "noNetwork" };
  if (sync.connection.kind === "serverSilent") return { kind: "offline", reason: "server" };
  if (syncingShown && sync.pendingFiles > 0) return { kind: "syncing", count: sync.pendingFiles };
  return { kind: "upToDate", waiting: sync.waitingMetered + sync.waitingBudget > 0 };
}

/** The state sentence: tray tooltip and the heading of the main window. */
export function stateText(state: TrayState, t: Translate, language: Language, now: Millis): string {
  switch (state.kind) {
    case "setup":
      return t("tray.state.setup");
    case "attention":
      return t("tray.state.attention");
    case "paused":
      return state.until === null
        ? t("tray.state.pausedOpen")
        : t("tray.state.paused", { time: formatFutureTime(language, state.until, now) });
    case "offline":
      return t("tray.state.offline");
    case "syncing":
      return t("tray.state.syncing", { count: state.count });
    case "upToDate":
      return state.waiting ? t("tray.state.restUpToDate") : t("tray.state.upToDate");
  }
}

/** Muted lines that say why files wait (UX 6.1, 8.4). */
export function waitingLines(snapshot: Snapshot, t: Translate): string[] {
  const lines: string[] = [];
  if (snapshot.sync.waitingMetered > 0) lines.push(t("tray.metered"));
  if (snapshot.sync.waitingBudget > 0) {
    lines.push(t("budget.line", { count: snapshot.sync.waitingBudget }));
  }
  return lines;
}

export function tooltip(
  snapshot: Snapshot,
  state: TrayState,
  t: Translate,
  language: Language,
  now: Millis,
): string {
  const head = t("tray.tooltip", { app: t("app.name"), state: stateText(state, t, language, now) });
  return [head, ...(state.kind === "setup" ? [] : waitingLines(snapshot, t))].join("\n");
}

// ---------------------------------------------------------------------------------------------
// Menu

export type TrayAction =
  | { readonly kind: "showProblem" }
  | { readonly kind: "openFolder"; readonly folderId: string }
  | { readonly kind: "openApp" }
  | { readonly kind: "pause"; readonly duration: PauseDuration }
  | { readonly kind: "resume" }
  | { readonly kind: "quit" };

export type TrayMenuItem =
  /** Not clickable; `muted` for the "last file" line. */
  | { readonly type: "label"; readonly label: string; readonly muted: boolean }
  | { readonly type: "separator" }
  | {
      readonly type: "action";
      /** Stable id the native menu reports back (`actionId`). */
      readonly id: string;
      readonly label: string;
      /** Bold default item, run by a double click on the icon. */
      readonly isDefault: boolean;
    }
  | { readonly type: "submenu"; readonly label: string; readonly items: readonly TrayMenuItem[] };

export interface TrayModel {
  readonly icon: TrayIcon;
  readonly tooltip: string;
  readonly menu: readonly TrayMenuItem[];
}

export function actionId(action: TrayAction): string {
  switch (action.kind) {
    case "openFolder":
      return `open-folder:${action.folderId}`;
    case "pause":
      return `pause:${action.duration}`;
    default:
      return action.kind;
  }
}

/** The action behind an id from the native menu; null for an unknown id. */
export function parseActionId(id: string): TrayAction | null {
  if (id === "showProblem" || id === "openApp" || id === "resume" || id === "quit") {
    return { kind: id };
  }
  if (id.startsWith("open-folder:")) {
    const folderId = id.slice("open-folder:".length);
    return folderId ? { kind: "openFolder", folderId } : null;
  }
  const duration = PAUSE_IDS[id];
  return duration ? { kind: "pause", duration } : null;
}

const PAUSE_IDS: Readonly<Record<string, PauseDuration>> = {
  "pause:hour": "hour",
  "pause:tomorrow": "tomorrow",
  "pause:manual": "manual",
};

function item(action: TrayAction, label: string, isDefault = false): TrayMenuItem {
  return { type: "action", id: actionId(action), label, isDefault };
}

function openFolderItems(
  folders: readonly Folder[],
  t: Translate,
  isDefault: boolean,
): TrayMenuItem {
  const [only] = folders;
  if (folders.length === 1 && only) {
    return item({ kind: "openFolder", folderId: only.id }, t("tray.openFolder"), isDefault);
  }
  return {
    type: "submenu",
    label: t("tray.openFolder"),
    items: folders.map((folder) => item({ kind: "openFolder", folderId: folder.id }, folder.name)),
  };
}

export function trayMenu(
  snapshot: Snapshot,
  state: TrayState,
  t: Translate,
  language: Language,
  now: Millis,
): TrayMenuItem[] {
  const status: TrayMenuItem = {
    type: "label",
    label: stateText(state, t, language, now),
    muted: false,
  };
  const quit = item({ kind: "quit" }, t("tray.quit"));
  const app = t("app.name");
  if (state.kind === "setup") {
    return [
      status,
      { type: "separator" },
      item({ kind: "openApp" }, t("tray.openApp", { app }), true),
      { type: "separator" },
      quit,
    ];
  }

  const menu: TrayMenuItem[] = [status];
  const last = snapshot.sync.lastFile;
  if (last) {
    menu.push({
      type: "label",
      label: t("tray.last", { name: last.name, time: formatRelative(language, last.at, now) }),
      muted: true,
    });
  }
  menu.push({ type: "separator" });
  const problem = state.kind === "attention";
  if (problem) menu.push(item({ kind: "showProblem" }, t("tray.showProblem"), true));
  if (snapshot.folders.length > 0) menu.push(openFolderItems(snapshot.folders, t, !problem));
  menu.push(
    item(
      { kind: "openApp" },
      t("tray.openApp", { app }),
      !problem && snapshot.folders.length === 0,
    ),
  );
  menu.push({ type: "separator" });
  if (snapshot.sync.pause) {
    menu.push(item({ kind: "resume" }, t("tray.resume")));
  } else {
    menu.push({
      type: "submenu",
      label: t("tray.pause"),
      items: [
        item({ kind: "pause", duration: "hour" }, t("tray.pause.hour")),
        item({ kind: "pause", duration: "tomorrow" }, t("tray.pause.tomorrow")),
        item({ kind: "pause", duration: "manual" }, t("tray.pause.manual")),
      ],
    });
  }
  menu.push({ type: "separator" }, quit);
  return menu;
}

export function trayModel(
  snapshot: Snapshot,
  state: TrayState,
  t: Translate,
  language: Language,
  now: Millis,
): TrayModel {
  return {
    icon: state.kind,
    tooltip: tooltip(snapshot, state, t, language, now),
    menu: trayMenu(snapshot, state, t, language, now),
  };
}

/** When a pause ends: in one hour, tomorrow at 06:00 local time, or never (UX 6.2). */
export function pauseUntil(duration: PauseDuration, now: Millis): Millis | null {
  if (duration === "manual") return null;
  if (duration === "hour") return now + 60 * 60 * 1000;
  const date = new Date(now);
  date.setDate(date.getDate() + 1);
  date.setHours(6, 0, 0, 0);
  return date.getTime();
}
