import { describe, expect, it, vi } from "vitest";

import { MockBackend } from "../mock/mockBackend";
import { BackendError } from "../errors";
import type { BackendEvent } from "../types";
import { backendChoice, insideTauri } from "../index";
import {
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
    });
  });

  it("decodes a full snapshot from the mock unchanged", async () => {
    const snapshot = await new MockBackend({ scenario: "many" }).getSnapshot();
    const { backend } = backendWith({ get_snapshot: JSON.parse(JSON.stringify(snapshot)) });
    await expect(backend.getSnapshot()).resolves.toEqual(snapshot);
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

describe("backend choice", () => {
  it("uses Tauri only inside the app when the build says auto", () => {
    expect(backendChoice()).toBe("auto");
    expect(insideTauri({})).toBe(false);
    expect(insideTauri({ __TAURI_INTERNALS__: {} })).toBe(true);
  });
});
