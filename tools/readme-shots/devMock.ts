// The mock backend for the README screenshots: run.mjs serves this module in place of
// src/backend/mock/devMock.ts. No latency and no simulated progress, so every run shows the same
// numbers; the overview gets a fixed minute of network traffic for the header.

import { MockBackend } from "../../src/backend/mock/mockBackend";
import { readmeScene } from "./scenarios";

/** A steady upload of a few MB/s with a short download in the middle, one reading a second. */
function trafficMinute(backend: MockBackend): void {
  for (let second = 0; second < 60; second += 1) {
    const up =
      3_200_000 + Math.round(1_400_000 * Math.sin(second / 5) ** 2) + (second % 7) * 90_000;
    const down = second > 30 ? 900_000 + (second % 5) * 160_000 : 0;
    backend.pushTraffic(up, down);
  }
}

export function createDevMock(_search: string): MockBackend {
  const backend = new MockBackend({
    scenario: "upToDate",
    latency: 0,
    timeScale: 0,
    animate: false,
  });
  if (readmeScene() === "overview") trafficMinute(backend);
  // The scene shows the pairing link and code; no new device answers it meanwhile.
  backend.controls.pairAnswer = "none";
  return backend;
}
