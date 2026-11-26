// Locale-aware formatting of times, dates and sizes. Everything goes through `Intl` with the UI
// language, so no format string lives in the dictionaries.

import { LOCALES, type Language } from "./i18n";

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

function startOfDay(ms: number): number {
  const date = new Date(ms);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
}

/** Whole calendar days between two moments in local time (0 = same day, 1 = yesterday). */
export function calendarDaysBetween(earlier: number, later: number): number {
  return Math.round((startOfDay(later) - startOfDay(earlier)) / DAY);
}

/** "14:31" */
export function formatTime(language: Language, ms: number): string {
  return new Intl.DateTimeFormat(LOCALES[language], { hour: "2-digit", minute: "2-digit" }).format(
    ms,
  );
}

/** "26. Nov." or "26 Nov", with the year only when it is not the current one. */
export function formatDate(language: Language, ms: number, now: number = Date.now()): string {
  const sameYear = new Date(ms).getFullYear() === new Date(now).getFullYear();
  return new Intl.DateTimeFormat(LOCALES[language], {
    day: "numeric",
    month: "short",
    ...(sameYear ? {} : { year: "numeric" }),
  }).format(ms);
}

/** "26. November 2026", for the recovery sheet and the long date of a day heading. */
export function formatLongDate(language: Language, ms: number): string {
  return new Intl.DateTimeFormat(LOCALES[language], { dateStyle: "long" }).format(ms);
}

/** A day heading in the timeline: the weekday and date ("Montag, 23. November"). */
export function formatDayHeading(language: Language, ms: number, now: number = Date.now()): string {
  const sameYear = new Date(ms).getFullYear() === new Date(now).getFullYear();
  return new Intl.DateTimeFormat(LOCALES[language], {
    weekday: "long",
    day: "numeric",
    month: "long",
    ...(sameYear ? {} : { year: "numeric" }),
  }).format(ms);
}

/**
 * Relative time for lists: "gerade eben" is avoided on purpose (it reads like a status), so the
 * smallest step is one minute. "vor 2 Min.", "vor 1 Std.", "gestern", then the date.
 */
export function formatRelative(language: Language, ms: number, now: number = Date.now()): string {
  const format = new Intl.RelativeTimeFormat(LOCALES[language], {
    numeric: "auto",
    style: "short",
  });
  const diff = now - ms;
  if (diff < HOUR) return format.format(-Math.max(1, Math.round(diff / MINUTE)), "minute");
  const days = calendarDaysBetween(ms, now);
  if (days === 0) return format.format(-Math.round(diff / HOUR), "hour");
  if (days === 1) return format.format(-1, "day");
  if (days < 7) return format.format(-days, "day");
  if (days < 60) return formatDate(language, ms, now);
  return format.format(-Math.round(days / 30), "month");
}

/** A time in the future: "14:42" today, otherwise with the weekday ("Fr., 06:00"). */
export function formatFutureTime(language: Language, ms: number, now: number = Date.now()): string {
  if (calendarDaysBetween(now, ms) === 0) return formatTime(language, ms);
  return new Intl.DateTimeFormat(LOCALES[language], {
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
  }).format(ms);
}

/** A moment in the past for "seit {since}": the time today, "gestern" or the date. */
export function formatSince(language: Language, ms: number, now: number = Date.now()): string {
  const days = calendarDaysBetween(ms, now);
  if (days === 0) return formatTime(language, ms);
  if (days === 1) {
    return new Intl.RelativeTimeFormat(LOCALES[language], { numeric: "auto" }).format(-1, "day");
  }
  return formatDate(language, ms, now);
}

const UNITS = ["byte", "kilobyte", "megabyte", "gigabyte", "terabyte"] as const;

/** "12,4 GB" with decimal units, the way Windows Explorer and macOS Finder count. */
export function formatSize(language: Language, bytes: number): string {
  let value = Math.max(0, bytes);
  let unit = 0;
  while (value >= 1000 && unit < UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  return new Intl.NumberFormat(LOCALES[language], {
    style: "unit",
    unit: UNITS[unit] ?? "byte",
    unitDisplay: "short",
    maximumFractionDigits: unit === 0 || value >= 100 ? 0 : 1,
  }).format(value);
}
