import { describe, expect, it } from "vitest";

import type { TimelineEntry } from "../backend/types";
import { createTranslator } from "../i18n";
import {
  dayHeading,
  diffText,
  entrySummary,
  groupByDay,
  outcomeView,
  whenText,
} from "./restoreText";

const NOW = new Date(2026, 10, 26, 14, 0).getTime();
const de = createTranslator("de");

function entry(id: string, at: number, patch: Partial<TimelineEntry> = {}): TimelineEntry {
  return {
    id,
    at,
    device: "Laptop",
    changed: 0,
    added: 0,
    deleted: 0,
    reanchored: false,
    ...patch,
  };
}

describe("restore texts", () => {
  it("names the moment of a version", () => {
    expect(whenText("de", de, new Date(2026, 10, 26, 11, 20).getTime(), NOW)).toBe("heute, 11:20");
    expect(whenText("de", de, new Date(2026, 10, 25, 18, 2).getTime(), NOW)).toBe("gestern, 18:02");
    expect(whenText("de", de, new Date(2026, 10, 23, 9, 5).getTime(), NOW)).toBe("23. Nov., 09:05");
  });

  it("heads each day", () => {
    expect(dayHeading("de", de, NOW, NOW)).toBe("Heute");
    expect(dayHeading("de", de, NOW - 86_400_000, NOW)).toBe("Gestern");
    expect(dayHeading("de", de, new Date(2026, 10, 23).getTime(), NOW)).toBe(
      "Montag, 23. November",
    );
  });

  it("summarizes only what is not zero", () => {
    expect(entrySummary(entry("a", NOW, { changed: 3 }), de)).toBe("3 Dateien geändert");
    expect(entrySummary(entry("a", NOW, { changed: 1, added: 12 }), de)).toBe(
      "1 Datei geändert, 12 Dateien neu",
    );
  });

  it("builds the difference from one plural text per number", () => {
    expect(diffText(3, 1, de)).toBe("Gegenüber jetzt: 3 Dateien anders, 1 Datei fehlt jetzt");
    expect(diffText(0, 2, de)).toBe("Gegenüber jetzt: 2 Dateien fehlen jetzt");
    expect(diffText(1, 0, de)).toBe("Gegenüber jetzt: 1 Datei anders");
    expect(diffText(0, 0, de)).toBe("Gegenüber jetzt: keine Unterschiede");
  });

  it("groups entries by calendar day in order", () => {
    const groups = groupByDay(
      [entry("a", NOW - 1000), entry("b", NOW - 2000), entry("c", NOW - 86_400_000)],
      NOW,
    );
    expect(groups.map((group) => group.map((item) => item.id))).toEqual([["a", "b"], ["c"]]);
  });

  it("puts every restore outcome into words", () => {
    const done = (count: number) => `done ${String(count)}`;
    expect(
      outcomeView({ kind: "done", count: 2, renamedTo: null, undoToken: "u" }, de, done),
    ).toEqual({ tone: "ok", text: "done 2", undoToken: "u", jobId: null });
    expect(
      outcomeView({ kind: "done", count: 1, renamedTo: "a (x).txt", undoToken: null }, de, done)
        .text,
    ).toBe("Wiederhergestellt als „a (x).txt“, weil der Name schon vergeben war.");
    expect(outcomeView({ kind: "waitBudget", jobId: "j" }, de, done)).toMatchObject({
      tone: "info",
      jobId: "j",
    });
    expect(outcomeView({ kind: "noSpace" }, de, done).text).toContain("kein Platz");
    expect(outcomeView({ kind: "expired" }, de, done).text).toContain("nicht mehr verfügbar");
    expect(outcomeView({ kind: "failed" }, de, done).text).toContain("nicht geklappt");
  });
});
