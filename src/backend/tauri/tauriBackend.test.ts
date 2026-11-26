import { describe, expect, it, vi } from "vitest";

import { MockBackend } from "../mock/mockBackend";
import { BackendError } from "../errors";
import type { BackendEvent } from "../types";
import { backendChoice, insideTauri } from "../index";
import {
  codeOf,
  commandName,
  EVENT_CHANNEL,
  isMissingCommand,
  TauriBackend,
  type Invoke,
  type Listen,
} from "./tauriBackend";

function backendWith(answers: Record<string, unknown>, listen?: Listen) {
  const calls: { command: string; args: Record<string, unknown> | undefined }[] = [];
  const invoke: Invoke = (command, args) => {
    calls.push({ command, args });
    if (!(command in answers)) return Promise.reject(new Error(`command ${command} not found`));
    return Promise.resolve(answers[command]);
  };
  const noListen: Listen = () => Promise.resolve(() => undefined);
  return { backend: new TauriBackend(invoke, listen ?? noListen), calls };
}

describe("tauri backend", () => {
  it("names commands in snake_case", () => {
    expect(commandName("getSnapshot")).toBe("get_snapshot");
    expect(commandName("confirmRecoveryGroup")).toBe("confirm_recovery_group");
  });

  it("recognizes a command that does not exist yet", () => {
    expect(isMissingCommand("command get_snapshot not found", "get_snapshot")).toBe(true);
    expect(isMissingCommand(new Error("Command get_snapshot not found"), "get_snapshot")).toBe(
      true,
    );
    expect(isMissingCommand("disk full", "get_snapshot")).toBe(false);
  });

  it("reports a missing command as notImplemented, naming the command once", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const { backend } = backendWith({});
    const first = await backend.getSettings().catch((error: unknown) => error);
    expect(first).toBeInstanceOf(BackendError);
    expect(first).toMatchObject({ code: "notImplemented", command: "get_settings" });
    await backend.getSettings().catch(() => undefined);
    expect(warn).toHaveBeenCalledTimes(1);
    warn.mockRestore();
  });

  it("checks answers and refuses a wrong shape", async () => {
    const { backend } = backendWith({ get_settings: { autostart: "yes", language: "de" } });
    await expect(backend.getSettings()).rejects.toMatchObject({ code: "badResponse" });
    const good = backendWith({ get_settings: { autostart: true, language: "system" } });
    await expect(good.backend.getSettings()).resolves.toEqual({
      autostart: true,
      language: "system",
      folderView: "list",
    });
    const grid = backendWith({
      get_settings: { autostart: true, language: "system", folderView: "grid" },
    });
    await expect(grid.backend.getSettings()).resolves.toMatchObject({ folderView: "grid" });
    const wrong = backendWith({
      get_settings: { autostart: true, language: "system", folderView: "tiles" },
    });
    await expect(wrong.backend.getSettings()).rejects.toMatchObject({ code: "badResponse" });
  });

  it("decodes a full snapshot from the mock unchanged", async () => {
    const snapshot = await new MockBackend({ scenario: "many" }).getSnapshot();
    const { backend } = backendWith({ get_snapshot: JSON.parse(JSON.stringify(snapshot)) });
    await expect(backend.getSnapshot()).resolves.toEqual(snapshot);
    // The engine's states of the overall security review (H2, M2, M3) decode too, so a snapshot
    // with one of them does not break the window.
    for (const scenario of ["removalReported", "treeLimit"] as const) {
      const state = await new MockBackend({ scenario }).getSnapshot();
      const bridge = backendWith({ get_snapshot: JSON.parse(JSON.stringify(state)) });
      await expect(bridge.backend.getSnapshot()).resolves.toEqual(state);
    }
  });

  it("decodes a folder's size, null before the first scan, and refuses a wrong one", async () => {
    const snapshot = await new MockBackend({ scenario: "upToDate" }).getSnapshot();
    const unscanned = {
      ...snapshot,
      folders: snapshot.folders.map((folder, index) =>
        index === 1 ? { ...folder, bytes: null } : folder,
      ),
    };
    const decoded = await backendWith({ get_snapshot: unscanned }).backend.getSnapshot();
    expect(decoded.folders.map((folder) => folder.bytes)).toEqual([2_412_000_000, null]);
    const wrong = {
      ...snapshot,
      folders: snapshot.folders.map((folder) => ({ ...folder, bytes: "2,4 GB" })),
    };
    await expect(backendWith({ get_snapshot: wrong }).backend.getSnapshot()).rejects.toMatchObject({
      code: "badResponse",
    });
  });

  it("decodes results with their error codes", async () => {
    const { backend, calls } = backendWith({ check_invite: { ok: false, error: "used" } });
    await expect(backend.checkInvite("https://x/join#y")).resolves.toEqual({
      ok: false,
      error: "used",
    });
    expect(calls[0]).toEqual({ command: "check_invite", args: { link: "https://x/join#y" } });
    const bad = backendWith({ check_invite: { ok: false, error: "weird" } });
    await expect(bad.backend.checkInvite("x")).rejects.toMatchObject({ code: "badResponse" });
  });

  it("passes the backend's busy code through", async () => {
    const invoke: Invoke = () => Promise.reject(new Error("x"));
    const busy: Invoke = () => Promise.reject(Object.assign(new Error("busy"), { code: "busy" }));
    await expect(new TauriBackend(invoke).resume()).rejects.toMatchObject({ code: "unexpected" });
    await expect(new TauriBackend(busy).resume()).rejects.toMatchObject({ code: "busy" });
  });

  it("delivers checked events and drops unreadable ones", async () => {
    const box: { handler: ((payload: unknown) => void) | null } = { handler: null };
    const listen: Listen = (channel, next) => {
      expect(channel).toBe(EVENT_CHANNEL);
      box.handler = next;
      return Promise.resolve(() => undefined);
    };
    const warn = vi.spyOn(console, "warn").mockImplementation(() => undefined);
    const { backend } = backendWith({}, listen);
    const events: BackendEvent[] = [];
    const stop = backend.subscribe((event) => events.push(event));
    await Promise.resolve();
    const deliver = (payload: unknown) => {
      if (!box.handler) throw new Error("not listening");
      box.handler(payload);
    };
    deliver({ type: "trayAction", actionId: "quit" });
    deliver({ type: "nonsense" });
    expect(events).toEqual([{ type: "trayAction", actionId: "quit" }]);
    expect(warn).toHaveBeenCalled();
    stop();
    warn.mockRestore();
  });
});

describe("the sync engine's shapes", () => {
  it("decodes the removed-device warning and stop reason from the mock unchanged", async () => {
    const snapshot = await new MockBackend({ scenario: "removedHeads" }).getSnapshot();
    const { backend } = backendWith({ get_snapshot: JSON.parse(JSON.stringify(snapshot)) });
    await expect(backend.getSnapshot()).resolves.toEqual(snapshot);
  });

  it("decodes the recovery code with its sheet and sends the sheet document", async () => {
    const mock = new MockBackend();
    const code = await mock.beginAccount("https://drive.example.org/join#k7Qm2xR9", "Laptop");
    const value = code.ok ? code.value : null;
    const { backend, calls } = backendWith({
      begin_account: { ok: true, value },
      print_recovery_sheet: null,
      recover_account: { ok: false, error: "edgeWhitespace" },
    });
    await expect(backend.beginAccount("x", "Laptop")).resolves.toEqual({ ok: true, value });
    const bad = backendWith({ begin_account: { ok: true, value: { ...value, sheet: null } } });
    await expect(bad.backend.beginAccount("x", "y")).rejects.toMatchObject({ code: "badResponse" });
    const document = {
      language: "de-DE",
      title: "t",
      fields: [{ label: "a", value: "b" }],
      notes: [],
      qrLink: "hangar-drive://recover#x",
      fileName: "f.txt",
    };
    await backend.printRecoverySheet(document);
    expect(calls.at(-1)).toEqual({ command: "print_recovery_sheet", args: { document } });
    await expect(backend.recoverAccount("hangar-drive://recover#x", "C", " N")).resolves.toEqual({
      ok: false,
      error: "edgeWhitespace",
    });
    expect(calls.at(-1)?.args).toEqual({
      sheet: "hangar-drive://recover#x",
      code: "C",
      deviceName: " N",
    });
  });

  it("decodes invite checks, read links and taken-in heads", async () => {
    const { backend, calls } = backendWith({
      check_invite: { ok: true, value: { host: "xn--drve-6pa.example.org", pinned: true } },
      inspect_link: {
        ok: true,
        value: { kind: "pair", host: "h", account: "3f9a", pinned: false },
      },
      accept_removed_heads: { kind: "accepted", count: 2, beforeEntryId: null },
    });
    await expect(backend.checkInvite("l")).resolves.toEqual({
      ok: true,
      value: { host: "xn--drve-6pa.example.org", pinned: true },
    });
    await expect(backend.inspectLink("l")).resolves.toMatchObject({ value: { kind: "pair" } });
    await expect(backend.acceptRemovedHeads("f")).resolves.toEqual({
      kind: "accepted",
      count: 2,
      beforeEntryId: null,
    });
    expect(calls.at(-1)).toEqual({ command: "accept_removed_heads", args: { folderId: "f" } });
  });

  it("delivers the removedHeads and openLink events", async () => {
    const box: { handler: ((payload: unknown) => void) | null } = { handler: null };
    const listen: Listen = (_channel, next) => {
      box.handler = next;
      return Promise.resolve(() => undefined);
    };
    const { backend } = backendWith({}, listen);
    const events: BackendEvent[] = [];
    backend.subscribe((event) => events.push(event));
    await Promise.resolve();
    const heads = {
      type: "removedHeads",
      folderId: "f",
      heads: [{ commit: "c", deviceId: "d", deviceName: "", sequence: 4 }],
    };
    box.handler?.(heads);
    box.handler?.({ type: "openLink", link: "hangar-drive://pair#x" });
    expect(events).toEqual([heads, { type: "openLink", link: "hangar-drive://pair#x" }]);
  });
});

describe("pairing", () => {
  it("sends the new device's name with the input and decodes its refusal", async () => {
    const { backend, calls } = backendWith({
      start_pairing: { ok: false, error: "blank" },
    });
    const input = { kind: "link", link: "hangar-drive://pair#x" } as const;
    await expect(backend.startPairing(input, "Laptop")).resolves.toEqual({
      ok: false,
      error: "blank",
    });
    expect(calls.at(-1)).toEqual({
      command: "start_pairing",
      args: { input, deviceName: "Laptop" },
    });
  });

  it("decodes an offer with its QR code as an SVG document", async () => {
    const offer = await new MockBackend().createPairingOffer();
    expect(offer.qrSvg).toMatch(/^<\?xml[^>]*\?><svg /);
    const { backend } = backendWith({ create_pairing_offer: JSON.parse(JSON.stringify(offer)) });
    await expect(backend.createPairingOffer()).resolves.toEqual(offer);
    const bad = backendWith({ create_pairing_offer: { ...offer, qrSvg: undefined } });
    await expect(bad.backend.createPairingOffer()).rejects.toMatchObject({ code: "badResponse" });
  });
});

describe("backend choice", () => {
  it("uses Tauri only inside the app when the build says auto", () => {
    expect(backendChoice()).toBe("auto");
    expect(insideTauri({})).toBe(false);
    expect(insideTauri({ __TAURI_INTERNALS__: {} })).toBe(true);
  });
});

const SHEET = {
  language: "de-DE",
  title: "t",
  fields: [{ label: "a", value: "b" }],
  notes: [],
  qrLink: "hangar-drive://recover#x",
  fileName: "f.txt",
};

describe("tauri backend after the security review (L2, M2)", () => {
  const place = { path: "C:\\Users\\Alex\\Docs", name: "Docs", token: "t0k" };

  it("reads places with their token and sends only tokens back", async () => {
    const { backend, calls } = backendWith({
      pick_folder: { kind: "picked", ...place },
      default_folder_place: place,
      count_local_files: 3,
      finish_setup: null,
      add_folder: null,
      add_account_folder: "declined",
      join_folders: ["f"],
      list_account_folders: {
        folders: [
          { id: "f", name: "Docs", size: 1, proposedPath: place.path, proposedToken: "p1" },
        ],
        free: 9,
      },
    });
    await expect(backend.pickFolder({ kind: "new" })).resolves.toEqual({
      kind: "picked",
      ...place,
    });
    await expect(backend.defaultFolderPlace()).resolves.toEqual(place);
    await expect(backend.listAccountFolders()).resolves.toMatchObject({
      folders: [{ proposedToken: "p1" }],
    });
    await backend.countLocalFiles("t0k");
    await backend.finishSetup("t0k");
    await backend.addFolder("t0k");
    await expect(backend.addAccountFolder("f", "t0k")).resolves.toBe("declined");
    await expect(backend.joinFolders([{ folderId: "f", token: "p1" }])).resolves.toEqual(["f"]);
    expect(calls.slice(3).map((call) => [call.command, call.args])).toEqual([
      ["count_local_files", { token: "t0k" }],
      ["finish_setup", { token: "t0k" }],
      ["add_folder", { token: "t0k" }],
      ["add_account_folder", { folderId: "f", token: "t0k" }],
      ["join_folders", { choices: [{ folderId: "f", token: "p1" }] }],
    ]);
    const old = backendWith({ default_folder_place: { path: "C:\\x", name: "x" } });
    await expect(old.backend.defaultFolderPlace()).rejects.toMatchObject({ code: "badResponse" });
  });

  it("reads a refused place in a cloud folder", async () => {
    const { backend } = backendWith({ save_recovery_file: { kind: "inCloudFolder" } });
    await expect(backend.saveRecoveryFile(SHEET)).resolves.toEqual({ kind: "inCloudFolder" });
  });

  it("reads the update outcome and turns 'updates are off' into its own code", async () => {
    const { backend } = backendWith({
      install_update: { kind: "installed", version: "0.2.0" },
      get_about: { version: "0.1.0", build: 3 },
    });
    await expect(backend.installUpdate()).resolves.toEqual({ kind: "installed", version: "0.2.0" });
    // A shell without the proposed `updates` field reads as "on".
    await expect(backend.getAbout()).resolves.toEqual({
      version: "0.1.0",
      build: 3,
      updates: true,
    });
    const off = new TauriBackend(
      () =>
        // The shell rejects with its `CommandError` object, not an Error (error.rs).
        // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
        Promise.reject({
          code: "unexpected",
          kind: "unexpected",
          message:
            "updates are off: tauri.conf.json carries no updater public key (plugins.updater.pubkey) and endpoint",
        }),
      () => Promise.resolve(() => undefined),
    );
    await expect(off.installUpdate()).rejects.toMatchObject({ code: "updatesOff" });
    expect(codeOf({ code: "busy" })).toBe("busy");
    expect(codeOf({ code: "unexpected", message: "disk full" })).toBe("unexpected");
  });

  it("reads how the native question ended from the shell's answer", async () => {
    const kept = backendWith({ delete_folder_everywhere: "kept" });
    await expect(kept.backend.deleteFolderEverywhere("f-photos")).resolves.toBe("kept");
    const gone = backendWith({ delete_folder_everywhere: "deleted" });
    await expect(gone.backend.deleteFolderEverywhere("f-photos")).resolves.toBe("deleted");
    expect(gone.calls).toEqual([
      { command: "delete_folder_everywhere", args: { folderId: "f-photos" } },
    ]);
    const added = backendWith({ answer_pair_request: "added" });
    await expect(added.backend.answerPairRequest("o", true)).resolves.toBe("added");
    expect(added.calls).toEqual([
      { command: "answer_pair_request", args: { offerId: "o", accept: true } },
    ]);
    const declined = backendWith({ answer_pair_request: "declined" });
    await expect(declined.backend.answerPairRequest("o", false)).resolves.toBe("declined");
    // An answer without the outcome is a broken shell, not a silent "kept".
    const silent = backendWith({ delete_folder_everywhere: null });
    await expect(silent.backend.deleteFolderEverywhere("f-photos")).rejects.toMatchObject({
      code: "badResponse",
    });
  });

  it("resets this device", async () => {
    const { backend, calls } = backendWith({ reset_device: "confirmed" });
    await expect(backend.resetDevice()).resolves.toBe("confirmed");
    expect(calls).toEqual([{ command: "reset_device", args: {} }]);
  });

  // Security review M4: the answers of the native questions, "declined" included, decode; an
  // answer of the old shape does not pass silently.
  it("decodes the answers of the native questions", async () => {
    const { backend } = backendWith({
      remove_device: "declined",
      disconnect_this_device: "confirmed",
      reanchor: "declined",
      set_autostart: "declined",
      confirm_recovery_group: "declined",
      resolve_mass_delete: { kind: "declined" },
      accept_removed_heads: { kind: "declined" },
      install_update: { kind: "declined" },
    });
    await expect(backend.removeDevice("d")).resolves.toBe("declined");
    await expect(backend.disconnectThisDevice()).resolves.toBe("confirmed");
    await expect(backend.reanchor("f", true)).resolves.toBe("declined");
    await expect(backend.setAutostart(false)).resolves.toBe("declined");
    await expect(backend.confirmRecoveryGroup("ABCD")).resolves.toBe("declined");
    await expect(backend.resolveMassDelete("w", "delete")).resolves.toEqual({ kind: "declined" });
    await expect(backend.acceptRemovedHeads("f")).resolves.toEqual({ kind: "declined" });
    await expect(backend.installUpdate()).resolves.toEqual({ kind: "declined" });
    const old = backendWith({ confirm_recovery_group: true, remove_device: null });
    await expect(old.backend.confirmRecoveryGroup("ABCD")).rejects.toMatchObject({
      code: "badResponse",
    });
    await expect(old.backend.removeDevice("d")).rejects.toMatchObject({ code: "badResponse" });
  });
});
