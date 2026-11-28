import { describe, expect, it, vi } from "vitest";

import { MockBackend } from "../backend/mock/mockBackend";
import type { TrafficSample } from "../backend/types";
import {
  advance,
  currentRate,
  EMPTY_TRAFFIC,
  formatRate,
  fromHistory,
  HISTORY_LENGTH,
  isQuiet,
  pushRate,
  QUIET_RATE,
  SCALE_FLOOR,
  scaleTop,
  SPARK_HEIGHT,
  SPARK_WIDTH,
  sparkPaths,
} from "./traffic";
import { createTrafficStore } from "./trafficStore";

function sample(tick: number, up: number, down = 0): TrafficSample {
  return { tick, up, down, sent: tick * 10, received: tick * 5 };
}

describe("traffic rates", () => {
  it("formats rates with decimal units in the UI language", () => {
    expect(formatRate("de", 5_200_000)).toBe("5,2 MB/s");
    expect(formatRate("en", 5_200_000)).toBe("5.2 MB/s");
    expect(formatRate("de", 0)).toBe("0 Byte/s");
    expect(formatRate("de", 999)).toBe("999 Byte/s");
    expect(formatRate("de", 1_500)).toBe("1,5 kB/s");
    expect(formatRate("de", 250_000)).toBe("250 kB/s");
    expect(formatRate("en", 2_000_000_000)).toBe("2 GB/s");
    expect(formatRate("de", -5)).toBe("0 Byte/s");
    // Every language formats, and repeated calls give the same text from the cached formatter.
    for (const language of ["el", "es", "fr", "it", "ja", "pl", "pt", "ru", "tr", "zh"] as const) {
      const first = formatRate(language, 3_400_000);
      expect(first).toMatch(/3[.,]4/);
      expect(formatRate(language, 3_400_000)).toBe(first);
    }
  });

  it("keeps one minute plus the reading that scrolls out", () => {
    let history: readonly number[] = [];
    for (let i = 0; i < 100; i += 1) history = pushRate(history, i);
    expect(history).toHaveLength(HISTORY_LENGTH);
    expect(history[0]).toBe(100 - HISTORY_LENGTH);
    expect(currentRate(history)).toBe(99);
    expect(currentRate([])).toBe(0);
    expect(pushRate([], -3)).toEqual([0]);
  });

  it("advances only on the next tick and asks for the history after a gap", () => {
    expect(advance(EMPTY_TRAFFIC, sample(1, 5))).toBeNull();
    const start = fromHistory({ tick: 4, up: [1, 2], down: [3, 4], sent: 40, received: 20 });
    const next = advance(start, sample(5, 9, 8));
    expect(next).toEqual({ up: [1, 2, 9], down: [3, 4, 8], tick: 5, sent: 50, received: 25 });
    expect(advance(start, sample(7, 1))).toBeNull();
    expect(advance(start, sample(4, 1))).toBeNull();
  });

  it("takes at most the last minute of a history", () => {
    const long = Array.from({ length: 80 }, (_, i) => i);
    const state = fromHistory({ tick: 80, up: long, down: long, sent: 1, received: 2 });
    expect(state.up).toHaveLength(HISTORY_LENGTH);
    expect(currentRate(state.up)).toBe(79);
  });

  it("is quiet while both directions stay below the keep-alive level", () => {
    const keepAlive = fromHistory({
      tick: 3,
      up: [0, 20, 0],
      down: [QUIET_RATE - 1, 0, 0],
      sent: 0,
      received: 0,
    });
    expect(isQuiet(EMPTY_TRAFFIC)).toBe(true);
    expect(isQuiet(keepAlive)).toBe(true);
    expect(isQuiet({ ...keepAlive, down: [QUIET_RATE] })).toBe(false);
  });

  it("scales both sparklines to the larger rate, never below the floor", () => {
    expect(scaleTop(EMPTY_TRAFFIC)).toBe(SCALE_FLOOR);
    expect(scaleTop({ ...EMPTY_TRAFFIC, up: [5_000_000], down: [7_000_000] })).toBe(7_000_000);
  });

  it("draws the newest reading at the right edge and the top at the upper edge", () => {
    expect(sparkPaths([5], 10)).toBeNull();
    const paths = sparkPaths([0, 5, 10, 20], 10);
    const first = SPARK_WIDTH - 3;
    expect(paths?.line).toBe(
      `M${String(first)} ${String(SPARK_HEIGHT)} L${String(first + 1)} 8 L${String(first + 2)} 0 L${String(SPARK_WIDTH)} 0`,
    );
    expect(paths?.area).toBe(
      `${paths?.line ?? ""} L${String(SPARK_WIDTH)} ${String(SPARK_HEIGHT)} L${String(first)} ${String(SPARK_HEIGHT)} Z`,
    );
  });
});

describe("the traffic store", () => {
  it("starts from the backend's history, appends readings and fetches again after a gap", async () => {
    const mock = new MockBackend();
    mock.pushTraffic(2_000_000, 0);
    const store = createTrafficStore(mock);
    const seen = vi.fn();
    const stop = store.subscribe(seen);
    await Promise.resolve();
    expect(store.get()).toMatchObject({ tick: 1, up: [2_000_000], down: [0] });

    mock.pushTraffic(3_000_000, 1_000);
    expect(store.get()).toMatchObject({ tick: 2, up: [2_000_000, 3_000_000], down: [0, 1_000] });
    expect(store.get().sent).toBe(5_000_000);

    // Readings the window missed (it was hidden): the next one brings the whole minute again.
    stop();
    mock.pushTraffic(1, 1);
    mock.pushTraffic(4_000_000, 0);
    const again = store.subscribe(seen);
    await Promise.resolve();
    expect(store.get()).toMatchObject({ tick: 4, up: [2_000_000, 3_000_000, 1, 4_000_000] });
    expect(seen).toHaveBeenCalled();
    again();
    expect(store.get()).toBe(EMPTY_TRAFFIC);
  });
});
