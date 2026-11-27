import { describe, expect, it } from "vitest";

import { BackendError } from "../errors";
import type { BackendEvent, PairInput } from "../types";
import { MOCK_INPUTS, MockBackend, readableClipboard } from "./mockBackend";
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
        "foldersUnreadable",
        "incomingDelete",
        "massDelete",
        "missingFolder",
        "names",
        "noRecoveryCode",
        "olderState",
        "quota",
        "quotaFull",
        "recoveryPending",
        "refused",
        "removalReported",
        "removed",
        "removedHeads",
        "serverDisk",
        "serverIdentity",
        "suspect",
        "treeLimit",
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
      value: { host: "drive.example.org", pinned: false },
    });
    expect(await mock.checkInvite(MOCK_INPUTS.invitePinned)).toEqual({
      ok: true,
      value: { host: "drive.example.org", pinned: true },
    });
    expect(await mock.checkInvite(MOCK_INPUTS.inviteDeep)).toEqual({
      ok: true,
      value: { host: "drive.example.org", pinned: false },
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
    const pair = (input: PairInput, name = "Laptop") => mock.startPairing(input, name);
    expect(await pair({ kind: "link", link: "nope" })).toEqual({
      ok: false,
      error: "notALink",
    });
    expect(await pair({ kind: "link", link: "hangar-drive://pair#toomany" })).toEqual({
      ok: false,
      error: "tooMany",
    });
    expect(await pair({ kind: "typed", server: "drive.example.org", code: "abc" })).toEqual({
      ok: false,
      error: "typo",
    });
    expect(
      await pair({
        kind: "typed",
        server: "drive.example.org",
        code: "7KQ2 MX9H TRW8 CZB3 NF6J AQ1V E5",
      }),
    ).toMatchObject({ ok: true, value: { path: "typed" } });
    const link: PairInput = { kind: "link", link: MOCK_INPUTS.pair };
    expect(await pair(link, " Laptop")).toEqual({ ok: false, error: "edgeWhitespace" });
    expect(await pair(link, "")).toEqual({ ok: false, error: "blank" });
    expect(await pair(link)).toMatchObject({ ok: true, value: { path: "link" } });
  });

  it("refuses links with white space, as the engine's parsers do", async () => {
    const spaced = (link: string) => `${link.slice(0, 8)} ${link.slice(8)}`;
    expect(await mock.checkInvite(spaced(MOCK_INPUTS.invite))).toEqual({
      ok: false,
      error: "notALink",
    });
    expect(await mock.inspectLink(`${MOCK_INPUTS.pair}\n`)).toEqual({
      ok: false,
      error: "notALink",
    });
    expect(await mock.startPairing({ kind: "link", link: spaced(MOCK_INPUTS.pair) }, "L")).toEqual({
      ok: false,
      error: "notALink",
    });
    expect(await mock.inspectLink(MOCK_INPUTS.pair)).toMatchObject({ ok: true });
  });

  it("check recovery codes", async () => {
    const code = "D7KQ M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY";
    const sheet = MOCK_INPUTS.recoverLink;
    const recover = (link: string, typed: string, name = "Laptop") =>
      mock.recoverAccount(link, typed, name);
    expect(await recover(sheet, code)).toEqual({ ok: true, value: null });
    expect(await recover(sheet, "D7KQ")).toEqual({ ok: false, error: "typo" });
    expect(await recover(sheet, `H${code.slice(1)}`)).toEqual({ ok: false, error: "otherApp" });
    expect(await recover(sheet, `0000${code.slice(4)}`)).toEqual({ ok: false, error: "unknown" });
    expect(await recover(sheet, `1111${code.slice(4)}`)).toEqual({ ok: false, error: "used" });
    expect(await recover("drive.example.org", code)).toEqual({ ok: false, error: "unknown" });
    expect(await recover("hangar-drive://recover#foreign", code)).toEqual({
      ok: false,
      error: "wrongSheet",
    });
    expect(await recover("hangar-drive://recover#offline", code)).toEqual({
      ok: false,
      error: "unreachable",
    });
    expect(await recover(sheet, code, " Laptop")).toEqual({ ok: false, error: "edgeWhitespace" });
  });

  // As the engine: nameless devices before the join, the account only after the last step,
  // which can also end the recovery.
  it("join a recovered device only in its last step", async () => {
    const fresh = new MockBackend({ scenario: "setup" });
    const code = "D7KQ M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY";
    expect(await fresh.recoverAccount(MOCK_INPUTS.recoverLink, code, "Neu")).toMatchObject({
      ok: true,
    });
    const devices = await fresh.recoveryDevices();
    expect(devices.length).toBeGreaterThan(0);
    expect(devices.every((device) => device.name === "" && device.added > 0)).toBe(true);
    expect((await fresh.getSnapshot()).setup).toBe("needed");
    const done = await fresh.finishRecoveryCleanup([]);
    expect(done.ok && done.value !== null).toBe(true);
    expect((await fresh.getSnapshot()).setup).toBe("done");

    const ended = new MockBackend({ scenario: "setup" });
    await ended.recoverAccount(MOCK_INPUTS.recoverLink, `2222${code.slice(4)}`, "Neu");
    expect(await ended.finishRecoveryCleanup([])).toEqual({ ok: false, error: "used" });
    expect((await ended.getSnapshot()).setup).toBe("needed");
    // Nothing waits any more: the engine refuses, and the recovery starts again.
    await expect(ended.finishRecoveryCleanup([])).rejects.toMatchObject({ code: "unexpected" });

    const offline = new MockBackend({ scenario: "setup" });
    await offline.recoverAccount(MOCK_INPUTS.recoverLink, `3333${code.slice(4)}`, "Neu");
    expect(await offline.finishRecoveryCleanup([])).toEqual({ ok: false, error: "unreachable" });
    expect((await offline.finishRecoveryCleanup([])).ok).toBe(true);

    const changed = new MockBackend({ scenario: "setup" });
    await changed.recoverAccount(MOCK_INPUTS.recoverLink, `4444${code.slice(4)}`, "Neu");
    const before = (await changed.recoveryDevices()).length;
    expect(await changed.finishRecoveryCleanup([])).toEqual({ ok: false, error: "listChanged" });
    expect(await changed.recoveryDevices()).toHaveLength(before + 1);
    expect((await changed.finishRecoveryCleanup([])).ok).toBe(true);
  });

  it("read links offline", async () => {
    expect(await mock.inspectLink(MOCK_INPUTS.pair)).toEqual({
      ok: true,
      value: {
        kind: "pair",
        host: "drive.example.org",
        account: "3f9a12c08b7e44d1a0b2c3d4e5f60718",
        pinned: false,
      },
    });
    expect(await mock.inspectLink(MOCK_INPUTS.pairIdn)).toMatchObject({
      ok: true,
      value: { host: "xn--drve-6pa.example.org" },
    });
    expect(await mock.inspectLink(MOCK_INPUTS.pairPinned)).toMatchObject({
      value: { pinned: true },
    });
    expect(await mock.inspectLink(MOCK_INPUTS.recoverLink)).toMatchObject({
      value: { kind: "recover" },
    });
    expect(await mock.inspectLink("hangar-drive://pair#damaged")).toEqual({
      ok: false,
      error: "damaged",
    });
    expect(await mock.inspectLink("hello")).toEqual({ ok: false, error: "notALink" });
  });

  it("hold a start link until the window listens", async () => {
    const early = new MockBackend({ scenario: "deepLinkPair" });
    const events: BackendEvent[] = [];
    early.subscribe((event) => events.push(event));
    await Promise.resolve();
    expect(events).toEqual([{ type: "openLink", link: MOCK_INPUTS.pair }]);
  });

  it("take in changes of a removed device and name the state before them", async () => {
    const heads = new MockBackend({ scenario: "removedHeads" });
    expect(await heads.acceptRemovedHeads("f-photos")).toEqual({
      kind: "accepted",
      count: 1,
      beforeEntryId: "t3",
    });
    const snapshot = await heads.getSnapshot();
    expect(snapshot.warnings).toEqual([]);
    expect(snapshot.folders.find((folder) => folder.id === "f-photos")?.status).toEqual({
      kind: "upToDate",
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
    expect(await mock.confirmRecoveryGroup("WRONG")).toBe("wrong");
    expect(await mock.confirmRecoveryGroup(group.toLowerCase())).toBe("confirmed");
  });

  it("finish the setup into a state with one folder", async () => {
    const mock = new MockBackend({ scenario: "setup" });
    const place = await mock.defaultFolderPlace();
    await mock.finishSetup(place.token);
    const snapshot = await mock.getSnapshot();
    expect(snapshot.setup).toBe("done");
    expect(snapshot.folders.map((folder) => folder.name)).toEqual(["Hangar Drive"]);
  });
});

describe("places by token (security review L2)", () => {
  it("names every place with a token and takes nothing else", async () => {
    const mock = new MockBackend();
    const picked = await mock.pickFolder({ kind: "new" });
    if (picked.kind !== "picked") throw new Error("expected a place");
    expect(picked.token).not.toBe("");
    await expect(mock.countLocalFiles(picked.path)).rejects.toBeInstanceOf(BackendError);
    await expect(mock.addFolder("C:\\Users\\Alex\\Projekte 2027")).rejects.toBeInstanceOf(
      BackendError,
    );
    await mock.addFolder(picked.token);
    expect((await mock.getSnapshot()).folders.map((folder) => folder.path)).toContain(picked.path);
    // A token names one place once.
    await expect(mock.addFolder(picked.token)).rejects.toBeInstanceOf(BackendError);
  });

  it("proposes account folders with a token each and joins by token", async () => {
    const mock = new MockBackend({ scenario: "setup" });
    const { folders } = await mock.listAccountFolders();
    expect(folders.every((folder) => folder.proposedToken !== "")).toBe(true);
    const first = folders[0];
    if (!first) throw new Error("expected a folder");
    await mock.joinFolders([{ folderId: first.id, token: first.proposedToken }]);
    expect((await mock.getSnapshot()).folders.map((folder) => folder.path)).toEqual([
      first.proposedPath,
    ]);
  });

  it("gives an empty token for a found folder, which has moved already", async () => {
    const mock = new MockBackend({ scenario: "missingFolder" });
    const result = await mock.findMissingFolder("f-photos");
    expect(result).toMatchObject({ kind: "picked", token: "" });
  });
});

describe("native confirmations, updates and the clipboard", () => {
  it("keep the folder and decline the device on a native no", async () => {
    const mock = new MockBackend();
    mock.controls.nativeConfirm = "no";
    expect(await mock.deleteFolderEverywhere("f-photos")).toBe("kept");
    expect((await mock.getSnapshot()).folders.map((folder) => folder.id)).toContain("f-photos");
    const offer = await mock.createPairingOffer();
    expect(await mock.answerPairRequest(offer.id, true)).toBe("declined");
    mock.controls.nativeConfirm = "yes";
    expect(await mock.deleteFolderEverywhere("f-photos")).toBe("deleted");
  });

  it("report whether updates are on and refuse to update while they are off", async () => {
    const mock = new MockBackend();
    expect((await mock.getAbout()).updates).toBe(true);
    expect(await mock.installUpdate()).toEqual({ kind: "installed", version: "0.2.0" });
    const off = new MockBackend({ scenario: "updateOff" });
    expect((await off.getAbout()).updates).toBe(false);
    await expect(off.installUpdate()).rejects.toMatchObject({ code: "updatesOff" });
  });

  it("let only links and codes of the app through, like the shell", () => {
    expect(readableClipboard(MOCK_INPUTS.invite)).toBe(MOCK_INPUTS.invite);
    expect(readableClipboard(` ${MOCK_INPUTS.pair}\n`)).toBe(MOCK_INPUTS.pair);
    expect(readableClipboard("D7KQ M2XP 9H4T RW8C ZB3N F6JA Q1VE K5SY")).not.toBe("");
    expect(readableClipboard("Einkaufsliste: Milch, Brot")).toBe("");
    expect(readableClipboard("nope")).toBe("");
    expect(readableClipboard("")).toBe("");
  });

  it("reset this device into the setup", async () => {
    const mock = new MockBackend();
    await mock.resetDevice();
    expect((await mock.getSnapshot()).setup).toBe("needed");
  });
});
