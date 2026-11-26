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

  it("formats sizes with decimal units", () => {
    expect(plain(formatSize("de", 12_400_000_000))).toBe("12,4 GB");
    expect(plain(formatSize("en", 48_200))).toBe("48.2 kB");
    expect(plain(formatSize("de", 512))).toBe("512 Byte");
    expect(plain(formatSize("en", 120_000_000_000))).toBe("120 GB");
  });
});
