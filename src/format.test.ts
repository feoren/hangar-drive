import { describe, expect, it } from "vitest";

import {
  calendarDaysBetween,
  formatDate,
  formatFutureTime,
  formatRelative,
  formatSince,
  formatSize,
  formatTime,
} from "./format";

/** Intl puts narrow and normal no-break spaces between number and unit. */
function plain(text: string): string {
  return text.replace(new RegExp("[\u00a0\u202f]", "g"), " ");
}

const NOW = new Date(2026, 10, 26, 14, 31).getTime();
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

describe("format", () => {
  it("counts calendar days, not 24 hour blocks", () => {
    const lateYesterday = new Date(2026, 10, 25, 23, 50).getTime();
    expect(calendarDaysBetween(lateYesterday, NOW)).toBe(1);
    expect(calendarDaysBetween(NOW - 2 * HOUR, NOW)).toBe(0);
  });

  // The formatters are kept per language and options: a cached one never answers for another.
  it("keeps one formatter per language and options", () => {
    expect(plain(formatSize("de", 6_200_000_000))).toBe("6,2 GB");
    expect(plain(formatSize("en", 6_200_000_000))).toBe("6.2 GB");
    expect(plain(formatSize("de", 6_200_000_000))).toBe("6,2 GB");
    expect(plain(formatSize("de", 620_000_000_000))).toBe("620 GB");
    expect(plain(formatRelative("en", NOW - DAY, NOW))).toBe("yesterday");
    expect(plain(formatSince("de", NOW - DAY, NOW))).toBe("gestern");
  });

  it("formats times and dates for the language", () => {
    expect(plain(formatTime("de", NOW))).toBe("14:31");
    expect(plain(formatDate("de", NOW, NOW))).toBe("26. Nov.");
    expect(formatDate("de", new Date(2025, 0, 2).getTime(), NOW)).toContain("2025");
  });

  it("says how long ago, never less than a minute", () => {
    expect(plain(formatRelative("de", NOW - 10_000, NOW))).toBe("vor 1 Min.");
    expect(plain(formatRelative("de", NOW - 2 * MINUTE, NOW))).toBe("vor 2 Min.");
    expect(plain(formatRelative("de", NOW - 3 * HOUR, NOW))).toBe("vor 3 Std.");
    expect(plain(formatRelative("de", NOW - DAY, NOW))).toBe("gestern");
    expect(plain(formatRelative("en", NOW - DAY, NOW))).toBe("yesterday");
    expect(plain(formatRelative("de", NOW - 20 * DAY, NOW))).toBe("6. Nov.");
    expect(plain(formatRelative("de", NOW - 104 * DAY, NOW))).toBe("vor 3 Monaten");
  });

  it("names a future time with the weekday only when it is not today", () => {
    expect(plain(formatFutureTime("de", NOW + HOUR, NOW))).toBe("15:31");
    expect(plain(formatFutureTime("de", new Date(2026, 10, 27, 6, 0).getTime(), NOW))).toMatch(
      /^Fr\.?, 06:00$/,
    );
  });

  it("formats 'since' as a time, yesterday or a date", () => {
    expect(plain(formatSince("de", NOW - HOUR, NOW))).toBe("13:31");
    expect(plain(formatSince("de", NOW - DAY, NOW))).toBe("gestern");
  });

  describe("across midnight, month and year boundaries", () => {
    const justAfterMidnight = new Date(2026, 10, 27, 0, 7).getTime();

    it("keeps minutes under an hour even when the event was before midnight", () => {
      expect(plain(formatRelative("de", justAfterMidnight - 20 * MINUTE, justAfterMidnight))).toBe(
        "vor 20 Min.",
      );
      expect(plain(formatRelative("de", justAfterMidnight - 7 * MINUTE, justAfterMidnight))).toBe(
        "vor 7 Min.",
      );
      const midnight = new Date(2026, 10, 27, 0, 0).getTime();
      expect(plain(formatRelative("de", midnight - 1, midnight))).toBe("vor 1 Min.");
    });

    it("says yesterday, not hours, once an hour old event lies on the previous day", () => {
      expect(plain(formatRelative("de", justAfterMidnight - 62 * MINUTE, justAfterMidnight))).toBe(
        "gestern",
      );
      expect(plain(formatRelative("en", justAfterMidnight - 62 * MINUTE, justAfterMidnight))).toBe(
        "yesterday",
      );
      expect(plain(formatRelative("de", justAfterMidnight - 3 * HOUR, justAfterMidnight))).toBe(
        "gestern",
      );
    });

    it("counts hours up to the end of the same day", () => {
      const lateEvening = new Date(2026, 10, 26, 23, 59).getTime();
      const earlyMorning = new Date(2026, 10, 26, 0, 30).getTime();
      expect(plain(formatRelative("de", earlyMorning, lateEvening))).toBe("vor 23 Std.");
      expect(plain(formatRelative("de", lateEvening - HOUR, lateEvening))).toBe("vor 1 Std.");
    });

    it("says yesterday across a month and a year boundary", () => {
      const firstOfDecember = new Date(2026, 11, 1, 0, 7).getTime();
      expect(
        plain(formatRelative("de", new Date(2026, 10, 30, 22, 0).getTime(), firstOfDecember)),
      ).toBe("gestern");
      const newYear = new Date(2027, 0, 1, 0, 7).getTime();
      expect(plain(formatRelative("de", new Date(2026, 11, 31, 22, 0).getTime(), newYear))).toBe(
        "gestern",
      );
      expect(plain(formatRelative("de", new Date(2026, 11, 29, 12, 0).getTime(), newYear))).toBe(
        "vor 3 Tagen",
      );
      expect(plain(formatRelative("de", new Date(2026, 11, 10, 12, 0).getTime(), newYear))).toBe(
        "10. Dez. 2026",
      );
    });

    it("shows a time since today, but yesterday for a moment just before midnight", () => {
      expect(plain(formatSince("de", justAfterMidnight - 5 * MINUTE, justAfterMidnight))).toBe(
        "00:02",
      );
      expect(plain(formatSince("de", justAfterMidnight - 20 * MINUTE, justAfterMidnight))).toBe(
        "gestern",
      );
    });

    it("adds the weekday to a future time that falls after midnight", () => {
      const beforeMidnight = new Date(2026, 10, 26, 23, 50).getTime();
      expect(plain(formatFutureTime("de", beforeMidnight + 5 * MINUTE, beforeMidnight))).toBe(
        "23:55",
      );
      expect(plain(formatFutureTime("de", beforeMidnight + 20 * MINUTE, beforeMidnight))).toMatch(
        /^Fr\.?, 00:10$/,
      );
    });
  });

  it("formats sizes with decimal units", () => {
    expect(plain(formatSize("de", 12_400_000_000))).toBe("12,4 GB");
    expect(plain(formatSize("en", 48_200))).toBe("48.2 kB");
    expect(plain(formatSize("de", 512))).toBe("512 Byte");
    expect(plain(formatSize("en", 120_000_000_000))).toBe("120 GB");
  });
});
