// Texts of the restore views that depend on dates and outcomes, as pure functions with tests.

import type { RestoreOutcome, TimelineEntry } from "../backend/types";
import { calendarDaysBetween, formatDate, formatDayHeading, formatTime } from "../format";
import type { Language, Translate } from "../i18n";

/** "heute, 11:20", "gestern, 18:02" or "23. Nov., 09:12". */
export function whenText(language: Language, t: Translate, at: number, now: number): string {
  const time = formatTime(language, at);
  const days = calendarDaysBetween(at, now);
  if (days === 0) return t("restore.whenToday", { time });
  if (days === 1) return t("restore.whenYesterday", { time });
  return t("restore.whenDate", { date: formatDate(language, at, now), time });
}

/** Day heading of the timeline. */
export function dayHeading(language: Language, t: Translate, at: number, now: number): string {
  const days = calendarDaysBetween(at, now);
  if (days === 0) return t("restore.today");
  if (days === 1) return t("restore.yesterday");
  return formatDayHeading(language, at, now);
}

/** "3 Dateien geändert, 1 Datei neu", only the parts that are not zero. */
export function entrySummary(entry: TimelineEntry, t: Translate): string {
  const parts: string[] = [];
  if (entry.changed > 0) parts.push(t("restore.entry.changed", { count: entry.changed }));
  if (entry.added > 0) parts.push(t("restore.entry.added", { count: entry.added }));
  if (entry.deleted > 0) parts.push(t("restore.entry.deleted", { count: entry.deleted }));
  return parts.join(", ");
}

/** "Gegenüber jetzt: 3 Dateien anders, 1 Datei fehlt jetzt" from one plural key per number. */
export function diffText(changed: number, missing: number, t: Translate): string {
  const changedText = changed > 0 ? t("restore.diff.changed", { count: changed }) : null;
  const missingText = missing > 0 ? t("restore.diff.missing", { count: missing }) : null;
  if (changedText && missingText)
    return t("restore.diff", { changed: changedText, missing: missingText });
  const part = changedText ?? missingText;
  return part ? t("restore.diffSingle", { part }) : t("restore.diffNone");
}

/** Groups entries by calendar day, newest first, keeping their order. */
export function groupByDay(entries: readonly TimelineEntry[], now: number): TimelineEntry[][] {
  const groups: TimelineEntry[][] = [];
  let lastDay: number | null = null;
  for (const entry of entries) {
    const day = calendarDaysBetween(entry.at, now);
    const current = groups[groups.length - 1];
    if (day === lastDay && current) current.push(entry);
    else groups.push([entry]);
    lastDay = day;
  }
  return groups;
}

export interface OutcomeView {
  readonly tone: "ok" | "error" | "info";
  readonly text: string;
  readonly undoToken: string | null;
  /** Set while the restore waits for the daily budget; the line offers "Cancel". */
  readonly jobId: string | null;
}

/** The feedback line next to the button that started a restore (UX 9.1, 9.2). */
export function outcomeView(
  outcome: RestoreOutcome,
  t: Translate,
  doneText: (count: number) => string,
): OutcomeView {
  switch (outcome.kind) {
    case "done":
      return {
        tone: "ok",
        text: outcome.renamedTo
          ? t("restore.file.doneRenamed", { name: outcome.renamedTo })
          : doneText(outcome.count),
        undoToken: outcome.undoToken,
        jobId: null,
      };
    case "waitBudget":
      return { tone: "info", text: t("restore.waitBudget"), undoToken: null, jobId: outcome.jobId };
    case "noSpace":
      return { tone: "error", text: t("restore.noSpace"), undoToken: null, jobId: null };
    case "expired":
      return { tone: "error", text: t("restore.expired"), undoToken: null, jobId: null };
    case "failed":
      return { tone: "error", text: t("error.restore.failed"), undoToken: null, jobId: null };
  }
}
