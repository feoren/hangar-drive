// The network traffic line of the main window (src/main/TrafficBar.tsx), after the system bar of
// the sister app: the last minute of upload and download rates as sparklines and the current
// rate next to them. Pure: the history, its shape as SVG paths and the formatting are testable
// without a DOM; trafficStore.ts keeps the readings.

import type { TrafficHistory, TrafficSample } from "../backend/types";
import { LOCALES, type Language } from "../i18n";

/**
 * Readings a sparkline keeps: the last minute, plus the one that scrolls out at its left edge.
 * The shell sends the quiet readings after a busy minute that this length needs to turn quiet
 * (`QUIET_READINGS_OWED` in src-tauri/src/traffic.rs).
 */
export const HISTORY_LENGTH = 61;
/**
 * Below this rate in bytes per second a direction is quiet: the event stream's keep-alive and
 * the feed poll never show a line (`QUIET_RATE` in crates/hangar-drive-sync/src/traffic.rs).
 */
export const QUIET_RATE = 1000;
/**
 * The least top of the sparklines' scale in bytes per second, so a trickle stays a low line
 * instead of filling the graph.
 */
export const SCALE_FLOOR = 100_000;

/** Width of a sparkline in its own units: one unit per reading, so a reading scrolls by one. */
export const SPARK_WIDTH = HISTORY_LENGTH - 1;
/** Height of a sparkline in its own units; 0 sits at the bottom. */
export const SPARK_HEIGHT = 16;

/** One direction's rates, oldest first, at most HISTORY_LENGTH. */
export type History = readonly number[];

export interface TrafficState {
  readonly up: History;
  readonly down: History;
  /** The tick of the newest reading; 0 before any. */
  readonly tick: number;
  readonly sent: number;
  readonly received: number;
}

export const EMPTY_TRAFFIC: TrafficState = { up: [], down: [], tick: 0, sent: 0, received: 0 };

/** The history with `value` appended, the oldest falling out beyond HISTORY_LENGTH. */
export function pushRate(history: History, value: number): History {
  const next = [...history, Math.max(0, value)];
  return next.length > HISTORY_LENGTH ? next.slice(next.length - HISTORY_LENGTH) : next;
}

/**
 * The state after a reading, or null when readings were missed in between (the window was
 * hidden, or the backend stayed silent through a quiet minute): the history must then come from
 * the backend, a gap filled with guesses would draw traffic that never was, or hide some.
 */
export function advance(state: TrafficState, sample: TrafficSample): TrafficState | null {
  if (state.tick === 0 || sample.tick !== state.tick + 1) return null;
  return {
    up: pushRate(state.up, sample.up),
    down: pushRate(state.down, sample.down),
    tick: sample.tick,
    sent: sample.sent,
    received: sample.received,
  };
}

/** The state of a history the backend sent. */
export function fromHistory(history: TrafficHistory): TrafficState {
  const tail = (values: readonly number[]) =>
    values.slice(Math.max(0, values.length - HISTORY_LENGTH)).map((value) => Math.max(0, value));
  return {
    up: tail(history.up),
    down: tail(history.down),
    tick: history.tick,
    sent: history.sent,
    received: history.received,
  };
}

/** The newest rate of a direction, 0 without readings. */
export function currentRate(history: History): number {
  return history[history.length - 1] ?? 0;
}

/** Whether the last minute stayed below QUIET_RATE both ways; the line is hidden then. */
export function isQuiet(state: TrafficState): boolean {
  return [...state.up, ...state.down].every((value) => value < QUIET_RATE);
}

/** The top of the scale both sparklines share, so their heights compare. */
export function scaleTop(state: TrafficState): number {
  return Math.max(SCALE_FLOOR, ...state.up, ...state.down);
}

/**
 * The sparkline's line and the area below it as SVG paths: the newest reading at the right
 * edge, one unit per reading to the left, `top` at the upper edge. `null` with fewer than two
 * readings.
 */
export function sparkPaths(history: History, top: number): { line: string; area: string } | null {
  if (history.length < 2 || top <= 0) return null;
  const first = SPARK_WIDTH - (history.length - 1);
  const points = history.map((value, index) => {
    const y = SPARK_HEIGHT - (Math.min(top, Math.max(0, value)) / top) * SPARK_HEIGHT;
    return `${String(first + index)} ${String(Math.round(y * 100) / 100)}`;
  });
  const line = `M${points.join(" L")}`;
  const area = `${line} L${String(SPARK_WIDTH)} ${String(SPARK_HEIGHT)} L${String(first)} ${String(SPARK_HEIGHT)} Z`;
  return { line, area };
}

const RATE_UNITS = [
  "byte-per-second",
  "kilobyte-per-second",
  "megabyte-per-second",
  "gigabyte-per-second",
] as const;

/** One formatter per language, unit and precision: the line formats twice a second. */
const rateFormats = new Map<string, Intl.NumberFormat>();

function rateFormat(language: Language, unit: string, digits: number): Intl.NumberFormat {
  const key = `${language}|${unit}|${String(digits)}`;
  let format = rateFormats.get(key);
  if (!format) {
    format = new Intl.NumberFormat(LOCALES[language], {
      style: "unit",
      unit,
      unitDisplay: "short",
      maximumFractionDigits: digits,
    });
    rateFormats.set(key, format);
  }
  return format;
}

/** "5,2 MB/s" with decimal units, like the sizes (format.ts `formatSize`). */
export function formatRate(language: Language, bytesPerSecond: number): string {
  let value = Math.max(0, bytesPerSecond);
  let unit = 0;
  while (value >= 1000 && unit < RATE_UNITS.length - 1) {
    value /= 1000;
    unit += 1;
  }
  const digits = unit === 0 || value >= 100 ? 0 : 1;
  return rateFormat(language, RATE_UNITS[unit] ?? "byte-per-second", digits).format(value);
}
