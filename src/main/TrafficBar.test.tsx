// @vitest-environment happy-dom

import { act } from "react";
import { afterEach, describe, expect, it } from "vitest";

import type { MockBackend } from "../backend/mock/mockBackend";
import { cleanup, flush, renderApp } from "../test/harness";
import { SPARK_WIDTH } from "./traffic";

afterEach(() => {
  cleanup();
});

/** Readings of the shell's sampler, one second each, with the window settling after each. */
async function readings(mock: MockBackend, ...rates: readonly (readonly [number, number])[]) {
  for (const [up, down] of rates) {
    await act(async () => {
      mock.pushTraffic(up, down);
      await Promise.resolve();
    });
    await flush(2);
  }
}

function bar(): HTMLElement | null {
  return document.querySelector<HTMLElement>(".traffic");
}

describe("the traffic line", () => {
  it("stays hidden on an idle connection", async () => {
    const { mock } = await renderApp("upToDate");
    expect(bar()).toBeNull();
    await readings(mock, [0, 20], [0, 0]);
    expect(bar()).toBeNull();
  });

  it("shows upload and download with their rates, sparklines and the session's totals", async () => {
    const { mock } = await renderApp("upToDate");
    await readings(mock, [1_000_000, 0], [5_200_000, 300_000]);
    const line = bar();
    if (!line) throw new Error("no traffic line");
    expect(line.getAttribute("role")).toBe("group");
    expect(line.getAttribute("aria-label")).toBe("Netzwerkverkehr");
    expect(line.title).toBe(
      "Hochladen: 5,2 MB/s\nHerunterladen: 300 kB/s\nSeit dem Start: 6,2 MB hochgeladen, 300 kB heruntergeladen",
    );
    const read = Array.from(line.querySelectorAll(".sr-only"), (element) => element.textContent);
    expect(read).toEqual([
      "Hochladen: 5,2 MB/s",
      "Herunterladen: 300 kB/s",
      "Seit dem Start: 6,2 MB hochgeladen, 300 kB heruntergeladen",
    ]);
    // The arrows tell the directions apart, not only the colors; both are hidden from screen
    // readers, which hear the words.
    const arrows = Array.from(line.querySelectorAll(".traffic-arrow"));
    expect(arrows.map((arrow) => arrow.textContent)).toEqual(["↑", "↓"]);
    expect(arrows.every((arrow) => arrow.getAttribute("aria-hidden") === "true")).toBe(true);
    expect(Array.from(line.querySelectorAll(".traffic-rate"), (r) => r.textContent)).toEqual([
      "5,2 MB/s",
      "300 kB/s",
    ]);
    // Both sparklines share one scale: the upload's newest point touches the top, the download's
    // stays low; the newest reading sits at the right edge.
    const lines = Array.from(line.querySelectorAll(".traffic-line"), (path) =>
      path.getAttribute("d"),
    );
    expect(lines[0]?.endsWith(`L${String(SPARK_WIDTH)} 0`)).toBe(true);
    expect(lines[1]?.endsWith(`L${String(SPARK_WIDTH)} 15.08`)).toBe(true);
    expect(line.querySelectorAll("svg[aria-hidden='true']")).toHaveLength(2);
  });

  it("moves on with every reading and hides after a quiet minute", async () => {
    const { mock } = await renderApp("upToDate");
    await readings(mock, [0, 2_000_000], [0, 2_000_000]);
    expect(bar()).not.toBeNull();
    // Consecutive readings append without asking the backend again.
    await act(async () => {
      for (let i = 0; i < 60; i += 1) mock.pushTraffic(0, 0);
      await Promise.resolve();
    });
    await flush();
    expect(bar()?.querySelector(".traffic-down .traffic-rate")?.textContent).toBe("0 Byte/s");
    await readings(mock, [0, 0]);
    expect(bar()).toBeNull();
  });
});
