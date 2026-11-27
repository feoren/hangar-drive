// A pinned wall clock for tests that show relative times ("vor 1 Std.", "Heute", "gestern").
// The mock fixtures place entries at "now minus a few hours"; with the real clock those cross
// midnight shortly after 00:00 local time and the texts change from "today" to "yesterday".

import { afterEach, beforeEach, vi } from "vitest";

/** Thursday 26 November 2026, 14:00 local time: far from midnight and from month and year ends. */
export const FIXED_NOW = new Date(2026, 10, 26, 14, 0, 0, 0);

/**
 * Pins `Date` to `at` for every test of the calling file and restores the real clock afterwards.
 *
 * Uses `vi.setSystemTime` without `vi.useFakeTimers`: that fakes only `Date`, so `setTimeout`,
 * `setInterval` and promises stay real and `vi.isFakeTimers()` stays false, which keeps
 * `flush()` in the harness on real zero-delay timers. A test may still switch to fake timers;
 * they start from the pinned time. The clock does not advance on its own while pinned.
 */
export function pinClock(at: Date = FIXED_NOW): void {
  beforeEach(() => {
    vi.setSystemTime(at);
  });
  afterEach(() => {
    vi.useRealTimers();
  });
}
