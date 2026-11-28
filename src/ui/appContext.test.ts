import { describe, expect, it } from "vitest";

import { sameTrayState } from "./appContext";

describe("tray state identity", () => {
  // The context keeps one object per state, so consumers skip snapshots that change nothing.
  it("compares tray states by what they say", () => {
    expect(
      sameTrayState({ kind: "upToDate", waiting: false }, { kind: "upToDate", waiting: false }),
    ).toBe(true);
    expect(sameTrayState({ kind: "syncing", count: 3 }, { kind: "syncing", count: 3 })).toBe(true);
    expect(sameTrayState({ kind: "syncing", count: 3 }, { kind: "syncing", count: 2 })).toBe(false);
    expect(sameTrayState({ kind: "paused", until: null }, { kind: "paused", until: 5 })).toBe(
      false,
    );
    expect(sameTrayState({ kind: "setup" }, { kind: "attention" })).toBe(false);
    expect(sameTrayState({ kind: "upToDate", waiting: false }, { kind: "setup" })).toBe(false);
  });
});
