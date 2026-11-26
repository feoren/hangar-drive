import { describe, expect, it } from "vitest";

import { BackendError } from "../errors";
import type { BackendEvent } from "../types";
import { MOCK_INPUTS, MockBackend } from "./mockBackend";
import { SCENARIOS, scenarioState } from "./scenarios";

describe("mock scenarios", () => {
  it("each produce a different state", () => {
    const now = Date.now();
    const states = SCENARIOS.map((scenario) => JSON.stringify(scenarioState(scenario.id, now)));
    expect(new Set(states).size).toBe(SCENARIOS.length);
  });

  it("cover every warning kind of the interface", () => {
    const kinds = new Set(
      SCENARIOS.flatMap((scenario) =>
        scenarioState(scenario.id, Date.now()).warnings.map((w) => w.kind),
      ),
    );
    expect([...kinds].sort()).toEqual(
      [
        "conflicts",
        "diskFull",
        "massDelete",
        "missingFolder",
        "names",
        "olderState",
        "quota",
        "quotaFull",
        "refused",
        "removed",
        "serverDisk",
        "serverIdentity",
        "suspect",
        "updateRequired",
      ].sort(),
    );
  });

  it("switch and announce the new state", async () => {
    const mock = new MockBackend();
    const events: BackendEvent[] = [];
    mock.subscribe((event) => events.push(event));
    mock.setScenario("setup");
    expect(events.at(-1)).toMatchObject({ type: "snapshot", snapshot: { setup: "needed" } });
    expect((await mock.getSnapshot()).setup).toBe("needed");
  });
});

describe("mock magic inputs", () => {
  const mock = new MockBackend();

  it("check invite links", async () => {
    expect(await mock.checkInvite(MOCK_INPUTS.invite)).toEqual({
      ok: true,
      value: { host: "drive.example.org" },
    });
    expect(await mock.checkInvite("hello")).toEqual({ ok: false, error: "notALink" });
    expect(await mock.checkInvite("https://a.org/join#used")).toEqual({ ok: false, error: "used" });
    expect(await mock.checkInvite("https://a.org/join#expired")).toEqual({
      ok: false,
      error: "expired",
    });
    expect(await mock.checkInvite("https://a.org/join#offline")).toEqual({
      ok: false,
      error: "unreachable",
    });
    expect(await mock.checkInvite("http://a.org/join#x")).toEqual({ ok: false, error: "insecure" });
    expect(await mock.checkInvite("http://localhost:8080/join#x")).toMatchObject({ ok: true });
  });

  it("check pairing input", async () => {
    expect(await mock.startPairing({ kind: "link", link: "nope" })).toEqual({
      ok: false,
      error: "notALink",
    });
    expect(await mock.startPairing({ kind: "link", link: "hangar-drive://pair#toomany" })).toEqual({
      ok: false,
      error: "tooMany",
    });
    expect(
      await mock.startPairing({ kind: "typed", server: "drive.example.org", code: "abc" }),
    ).toEqual({
      ok: false,
      error: "typo",
    });
    expect(
      await mock.startPairing({
        kind: "typed",
        server: "drive.example.org",
        code: "7KQ2 MX9H TRW8 CZB3 NF6J AQ1V E5",
      }),
    ).toMatchObject({ ok: true, value: { path: "typed" } });
  });

  it("check recovery codes", async () => {
    const code = "D7KQ M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY";
    expect(await mock.recoverAccount("drive.example.org", code)).toEqual({ ok: true, value: null });
    expect(await mock.recoverAccount("drive.example.org", "D7KQ")).toEqual({
      ok: false,
      error: "typo",
    });
    expect(await mock.recoverAccount("drive.example.org", `H${code.slice(1)}`)).toEqual({
      ok: false,
      error: "otherApp",
    });
    expect(await mock.recoverAccount("drive.example.org", `0000${code.slice(4)}`)).toEqual({
      ok: false,
      error: "unknown",
    });
    expect(await mock.recoverAccount("drive.example.org", `1111${code.slice(4)}`)).toEqual({
      ok: false,
      error: "used",
    });
  });
});

describe("mock controls", () => {
  it("decide the outcome of the next folder pick and restore", async () => {
    const mock = new MockBackend();
    mock.controls.pick = "network";
    expect(await mock.pickFolder({ kind: "new" })).toEqual({
      kind: "refused",
      reason: "network",
      folder: null,
    });
    mock.controls.pick = "nested";
    expect(await mock.pickFolder({ kind: "new" })).toMatchObject({
      reason: "nested",
      folder: "Hangar Drive",
    });
    mock.controls.restore = "waitBudget";
    expect(await mock.resetFolder("f-main", "t1")).toMatchObject({ kind: "waitBudget" });
  });

  it("fail the next call on request", async () => {
    const mock = new MockBackend();
    mock.controls.failNext = "notImplemented";
    await expect(mock.getSettings()).rejects.toBeInstanceOf(BackendError);
    await expect(mock.getSettings()).resolves.toMatchObject({ autostart: true });
  });

  it("create a recovery code that starts with D and checks one group", async () => {
    const mock = new MockBackend({ random: () => 0.5 });
    const result = await mock.beginAccount(MOCK_INPUTS.invite, "Laptop");
    if (!result.ok) throw new Error("expected a code");
    expect(result.value.groups).toHaveLength(8);
    expect(result.value.groups[0]?.startsWith("D")).toBe(true);
    expect(result.value.checkGroup).toBeGreaterThan(1);
    const group = result.value.groups[result.value.checkGroup - 1] ?? "";
    expect(await mock.confirmRecoveryGroup("WRONG")).toBe(false);
    expect(await mock.confirmRecoveryGroup(group.toLowerCase())).toBe(true);
  });

  it("finish the setup into a state with one folder", async () => {
    const mock = new MockBackend({ scenario: "setup" });
    await mock.finishSetup("C:\\Users\\Alex\\Hangar Drive");
    const snapshot = await mock.getSnapshot();
    expect(snapshot.setup).toBe("done");
    expect(snapshot.folders.map((folder) => folder.name)).toEqual(["Hangar Drive"]);
  });
});
