// The mock as the dev server uses it: a short delay on every call so loading states are visible,
// simulated progress, and the scenario from the address (`?scenario=conflicts`).

import { MockBackend } from "./mockBackend";
import { isScenarioId } from "./scenarios";

export function createDevMock(search: string): MockBackend {
  const scenario = new URLSearchParams(search).get("scenario");
  return new MockBackend({
    scenario: isScenarioId(scenario) ? scenario : "upToDate",
    latency: 180,
    timeScale: 1,
    animate: true,
  });
}
