// The bridge to the Rust backend. Every method calls one Tauri command of the same name in
// snake_case (`getSnapshot` -> `get_snapshot`) with camelCase arguments, and checks the answer
// with a decoder. Events arrive on one channel, `hangar-drive://event`, as `BackendEvent` JSON.
//
// The Rust side is still being built. A command it does not have yet rejects with a
// BackendError "notImplemented" that names the command, so the window shows "this version cannot
// do that yet" instead of breaking, and the console says which command is missing.

import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";

import type { Language } from "../../i18n";
import type { TrayModel } from "../../tray/trayModel";
import { BackendError } from "../errors";
import type {
  Backend,
  BackendEvent,
  DeviceId,
  FolderChoice,
  FolderId,
  Millis,
  PairInput,
  PauseDuration,
  PickPurpose,
  Unsubscribe,
} from "../types";
import type { Decoder } from "./decode";
import * as d from "./decoders";

export const EVENT_CHANNEL = "hangar-drive://event";

export type Invoke = (command: string, args?: Record<string, unknown>) => Promise<unknown>;
export type Listen = (channel: string, handler: (payload: unknown) => void) => Promise<() => void>;

/** `getSnapshot` -> `get_snapshot`. */
export function commandName(method: string): string {
  return method.replace(/[A-Z]/g, (char) => `_${char.toLowerCase()}`);
}

/** Tauri rejects an unknown command with a message that names it ("command x not found"). */
export function isMissingCommand(error: unknown, command: string): boolean {
  const text = typeof error === "string" ? error : error instanceof Error ? error.message : "";
  return /not found|unknown command|not allowed/i.test(text) && text.includes(command);
}

const defaultInvoke: Invoke = (command, args) => invoke(command, args);
const defaultListen: Listen = (channel, handler) =>
  listen(channel, (event) => {
    handler(event.payload);
  });

export class TauriBackend implements Backend {
  readonly kind = "tauri";
  private readonly invokeFn: Invoke;
  private readonly listenFn: Listen;
  private readonly reported = new Set<string>();

  constructor(invokeFn: Invoke = defaultInvoke, listenFn: Listen = defaultListen) {
    this.invokeFn = invokeFn;
    this.listenFn = listenFn;
  }

  private async call<T>(
    method: string,
    args: Record<string, unknown>,
    decoder: Decoder<T>,
  ): Promise<T> {
    const command = commandName(method);
    let raw: unknown;
    try {
      raw = await this.invokeFn(command, args);
    } catch (error) {
      if (isMissingCommand(error, command)) {
        if (!this.reported.has(command)) {
          this.reported.add(command);
          console.warn(`Hangar Drive: backend command "${command}" is not implemented yet.`);
        }
        throw new BackendError("notImplemented", command);
      }
      throw new BackendError(codeOf(error), command, String(error));
    }
    try {
      return decoder(raw, command);
    } catch (error) {
      throw new BackendError("badResponse", command, String(error));
    }
  }

  private run(method: string, args: Record<string, unknown> = {}): Promise<null> {
    return this.call(method, args, d.nothing);
  }

  getSnapshot() {
    return this.call("getSnapshot", {}, d.snapshot);
  }

  subscribe(listener: (event: BackendEvent) => void): Unsubscribe {
    let stop: (() => void) | null = null;
    let stopped = false;
    this.listenFn(EVENT_CHANNEL, (payload) => {
      try {
        listener(d.event(payload, "event"));
      } catch (error) {
        console.warn("Hangar Drive: unreadable backend event", error);
      }
    }).then(
      (unlisten) => {
        if (stopped) unlisten();
        else stop = unlisten;
      },
      (error: unknown) => {
        console.warn("Hangar Drive: cannot listen to backend events", error);
      },
    );
    return () => {
      stopped = true;
      stop?.();
    };
  }

  readClipboardText() {
    return this.call("readClipboardText", {}, d.str);
  }

  checkInvite(link: string) {
    return this.call(
      "checkInvite",
      { link },
      d.result(d.host, "notALink", "used", "expired", "unreachable", "insecure"),
    );
  }
  defaultDeviceName() {
    return this.call("defaultDeviceName", {}, d.str);
  }
  beginAccount(link: string, deviceName: string) {
    return this.call(
      "beginAccount",
      { link, deviceName },
      d.result(
        d.recoveryCode,
        "notALink",
        "used",
        "expired",
        "unreachable",
        "insecure",
        "blank",
        "edgeWhitespace",
      ),
    );
  }
  async printRecoverySheet() {
    await this.run("printRecoverySheet");
  }
  saveRecoveryFile() {
    return this.call("saveRecoveryFile", {}, d.saveResult);
  }
  async copyRecoveryCode() {
    await this.run("copyRecoveryCode");
  }
  confirmRecoveryGroup(group: string) {
    return this.call("confirmRecoveryGroup", { group }, d.bool);
  }
  defaultFolderPlace() {
    return this.call("defaultFolderPlace", {}, d.folderPlace);
  }
  pickFolder(purpose: PickPurpose) {
    return this.call("pickFolder", { purpose }, d.pickResult);
  }
  countLocalFiles(path: string) {
    return this.call("countLocalFiles", { path }, d.num);
  }
  async finishSetup(path: string) {
    await this.run("finishSetup", { path });
  }
  scanWithCamera() {
    return this.call("scanWithCamera", {}, d.nullableStr);
  }
  startPairing(input: PairInput) {
    return this.call("startPairing", { input }, d.result(d.pairWaiting, ...PAIR_ERRORS));
  }
  async cancelPairing() {
    await this.run("cancelPairing");
  }
  listAccountFolders() {
    return this.call("listAccountFolders", {}, d.accountFolders);
  }
  async joinFolders(choices: readonly FolderChoice[]) {
    await this.run("joinFolders", { choices });
  }
  recoverAccount(server: string, code: string) {
    return this.call(
      "recoverAccount",
      { server, code },
      d.result(d.nothing, "typo", "unknown", "used", "otherApp", "unreachable", "insecure"),
    );
  }
  setDeviceName(name: string) {
    return this.call("setDeviceName", { name }, d.result(d.nothing, "blank", "edgeWhitespace"));
  }
  recoveryDevices() {
    return this.call("recoveryDevices", {}, d.array(d.device));
  }
  finishRecoveryCleanup(remove: readonly DeviceId[]) {
    return this.call("finishRecoveryCleanup", { remove }, d.recoveryCode);
  }

  async openFolder(folderId: FolderId | null, path?: string) {
    await this.run("openFolder", { folderId, path: path ?? null });
  }
  async pause(duration: PauseDuration) {
    await this.run("pause", { duration });
  }
  async resume() {
    await this.run("resume");
  }
  async syncNow() {
    await this.run("syncNow");
  }
  async retryConnection() {
    await this.run("retryConnection");
  }
  async pauseFolder(folderId: FolderId) {
    await this.run("pauseFolder", { folderId });
  }
  async resumeFolder(folderId: FolderId) {
    await this.run("resumeFolder", { folderId });
  }
  async addFolder(path: string) {
    await this.run("addFolder", { path });
  }
  async addAccountFolder(folderId: FolderId, path: string) {
    await this.run("addAccountFolder", { folderId, path });
  }
  async stopFolder(folderId: FolderId) {
    await this.run("stopFolder", { folderId });
  }
  async deleteFolderEverywhere(folderId: FolderId) {
    await this.run("deleteFolderEverywhere", { folderId });
  }
  async restoreDeletedFolder(folderId: FolderId) {
    await this.run("restoreDeletedFolder", { folderId });
  }
  listNotSynced(folderId: FolderId) {
    return this.call("listNotSynced", { folderId }, d.notSynced);
  }
  getFolderNumber(folderId: FolderId) {
    return this.call("getFolderNumber", { folderId }, d.folderNumber);
  }
  restoreRemoteDeleted(activityId: string) {
    return this.call("restoreRemoteDeleted", { activityId }, d.num);
  }

  listMassDelete(warningId: string) {
    return this.call("listMassDelete", { warningId }, d.array(d.str));
  }
  resolveMassDelete(warningId: string, decision: "restore" | "delete") {
    return this.call("resolveMassDelete", { warningId, decision }, d.num);
  }
  findMissingFolder(folderId: FolderId) {
    return this.call("findMissingFolder", { folderId }, d.pickResult);
  }
  async redownloadFolder(folderId: FolderId) {
    await this.run("redownloadFolder", { folderId });
  }
  getServerNumber() {
    return this.call("getServerNumber", {}, d.serverNumber);
  }
  async confirmServerNumber() {
    await this.run("confirmServerNumber");
  }
  fixServerWithOffer(link: string) {
    return this.call(
      "fixServerWithOffer",
      { link },
      d.result(d.nothing, "notALink", "otherAccount", "expired"),
    );
  }
  checkOlderState(folderId: FolderId) {
    return this.call("checkOlderState", { folderId }, d.olderCheck);
  }
  async reanchor(folderId: FolderId, compared: boolean) {
    await this.run("reanchor", { folderId, compared });
  }
  async dismissSuspect(warningId: string) {
    await this.run("dismissSuspect", { warningId });
  }
  async openStorageSettings() {
    await this.run("openStorageSettings");
  }
  async installUpdate() {
    await this.run("installUpdate");
  }
  async copyErrorReport() {
    await this.run("copyErrorReport");
  }
  previewErrorReport() {
    return this.call("previewErrorReport", {}, d.str);
  }
  saveErrorReport() {
    return this.call("saveErrorReport", {}, d.saveResult);
  }

  listConflicts() {
    return this.call("listConflicts", {}, d.conflictGroups);
  }
  async openConflict(groupId: string) {
    await this.run("openConflict", { groupId });
  }
  keepConflictVersion(groupId: string, versionId: string) {
    return this.call("keepConflictVersion", { groupId, versionId }, d.undoToken);
  }
  async keepBothConflict(groupId: string) {
    await this.run("keepBothConflict", { groupId });
  }
  async undo(token: string) {
    await this.run("undo", { token });
  }
  listNameIssues() {
    return this.call("listNameIssues", {}, d.nameIssues);
  }
  renameNameIssue(issueId: string, name: string) {
    return this.call(
      "renameNameIssue",
      { issueId, name },
      d.result(d.nothing, "invalid", "exists"),
    );
  }
  async ignoreNameIssue(issueId: string) {
    await this.run("ignoreNameIssue", { issueId });
  }

  getTimeline(folderId: FolderId, path?: string) {
    return this.call("getTimeline", { folderId, path: path ?? null }, d.timeline);
  }
  getTreeAt(folderId: FolderId, entryId: string) {
    return this.call("getTreeAt", { folderId, entryId }, d.versionTree);
  }
  restoreFile(folderId: FolderId, entryId: string, path: string, mode: "replace" | "copy") {
    return this.call("restoreFile", { folderId, entryId, path, mode }, d.restoreOutcome);
  }
  resetFolder(folderId: FolderId, entryId: string) {
    return this.call("resetFolder", { folderId, entryId }, d.restoreOutcome);
  }
  async cancelRestore(jobId: string) {
    await this.run("cancelRestore", { jobId });
  }
  findBeforeDevice(folderId: FolderId, deviceId: DeviceId, from: Millis) {
    return this.call("findBeforeDevice", { folderId, deviceId, from }, d.nullableStr);
  }
  getTrash(folderId: FolderId) {
    return this.call("getTrash", { folderId }, d.trash);
  }
  restoreTrash(folderId: FolderId, itemIds: readonly string[]) {
    return this.call("restoreTrash", { folderId, itemIds }, d.restoreOutcome);
  }

  listDevices() {
    return this.call("listDevices", {}, d.deviceList);
  }
  renameDevice(deviceId: DeviceId, name: string) {
    return this.call(
      "renameDevice",
      { deviceId, name },
      d.result(d.nothing, "blank", "edgeWhitespace"),
    );
  }
  getSafetyNumber(deviceId: DeviceId) {
    return this.call("getSafetyNumber", { deviceId }, d.numberRows);
  }
  async removeDevice(deviceId: DeviceId) {
    await this.run("removeDevice", { deviceId });
  }
  async disconnectThisDevice() {
    await this.run("disconnectThisDevice");
  }
  createPairingOffer() {
    return this.call("createPairingOffer", {}, d.pairingOffer);
  }
  async copyPairingLink(offerId: string) {
    await this.run("copyPairingLink", { offerId });
  }
  async answerPairRequest(offerId: string, accept: boolean) {
    await this.run("answerPairRequest", { offerId, accept });
  }
  renewRecoveryCode() {
    return this.call("renewRecoveryCode", {}, d.recoveryCode);
  }

  getSettings() {
    return this.call("getSettings", {}, d.settings);
  }
  async setAutostart(on: boolean) {
    await this.run("setAutostart", { on });
  }
  async setLanguage(language: Language | "system") {
    await this.run("setLanguage", { language });
  }
  getAbout() {
    return this.call("getAbout", {}, d.about);
  }

  async updateTray(model: TrayModel) {
    await this.run("updateTray", { model });
  }
  async showWindow() {
    await this.run("showWindow");
  }
  async quit() {
    await this.run("quit");
  }
}

const PAIR_ERRORS = [
  "notALink",
  "expired",
  "typo",
  "declined",
  "tooMany",
  "otherAccount",
  "unreachable",
  "insecure",
] as const;

/** The Rust side may reject with `{ code: "busy" | "locked" }`; anything else is unexpected. */
function codeOf(error: unknown): "busy" | "locked" | "unexpected" {
  if (typeof error === "object" && error !== null && "code" in error) {
    if (error.code === "busy" || error.code === "locked") return error.code;
  }
  return "unexpected";
}
