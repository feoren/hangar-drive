// Which problems the window shows, in which order, and which of them raise the tray to "needs
// you". Pure functions, so the tray model and the banner area agree and both have tests.

import type { Millis, Snapshot, Warning } from "../backend/types";

/** A server that stays silent this long is promoted from offline to a problem (UX 8.3). */
export const SERVER_SILENT_PROBLEM_MS = 24 * 60 * 60 * 1000;

/** The backend's warnings plus the ones the window derives itself. */
export type ShownWarning =
  Warning | { readonly kind: "serverLong"; readonly id: string; readonly since: Millis };

export type ShownWarningKind = ShownWarning["kind"];

/** Most urgent first. Data at risk, then blocked sync, then storage, then the quiet ones. */
const PRIORITY: readonly ShownWarningKind[] = [
  "suspect",
  "massDelete",
  "removedHeads",
  "removed",
  "refused",
  "updateRequired",
  "serverIdentity",
  "olderState",
  "missingFolder",
  "quotaFull",
  "quota",
  "serverDisk",
  "diskFull",
  "serverLong",
  "conflicts",
  "names",
];

/** Informational banners: nothing is lost, the tray stays calm (UX 7.1, 7.2). */
const QUIET: ReadonlySet<ShownWarningKind> = new Set(["conflicts", "names"]);

export function rank(kind: ShownWarningKind): number {
  return PRIORITY.indexOf(kind);
}

export function needsAttention(warning: ShownWarning): boolean {
  return !QUIET.has(warning.kind);
}

/** Banner tone: red only for a suspected attack, the one red banner of the app (UX 9.4). */
export function tone(warning: ShownWarning): "danger" | "attention" | "info" {
  if (warning.kind === "suspect") return "danger";
  return needsAttention(warning) ? "attention" : "info";
}

/** Warnings to show, most urgent first; equal kinds keep the backend's order. */
export function shownWarnings(snapshot: Snapshot, now: Millis): ShownWarning[] {
  const list: ShownWarning[] = snapshot.warnings.filter(
    (warning) => !("count" in warning) || warning.count > 0,
  );
  const connection = snapshot.sync.connection;
  if (connection.kind === "serverSilent" && now - connection.since >= SERVER_SILENT_PROBLEM_MS) {
    list.push({ kind: "serverLong", id: "server-long", since: connection.since });
  }
  return list
    .map((warning, index) => ({ warning, index }))
    .sort((a, b) => rank(a.warning.kind) - rank(b.warning.kind) || a.index - b.index)
    .map(({ warning }) => warning);
}

export function anyAttention(snapshot: Snapshot, now: Millis): boolean {
  return shownWarnings(snapshot, now).some(needsAttention);
}
