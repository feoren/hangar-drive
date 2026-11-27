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
  DeleteOutcome,
  DeviceId,
  FolderChoice,
  FolderId,
  FolderView,
  Millis,
  PairAnswer,
  PairInput,
  PauseDuration,
  PickPurpose,
  RecoverySheetDocument,
  ServerConfirm,
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
      d.result(d.inviteCheck, "notALink", "used", "expired", "unreachable", "insecure"),
    );
  }
  inspectLink(link: string) {
    return this.call(
      "inspectLink",
      { link },
      d.result(d.inspectedLink, "notALink", "damaged", "insecure"),
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
  async printRecoverySheet(document: RecoverySheetDocument) {
    await this.run("printRecoverySheet", { document });
  }
  saveRecoveryFile(document: RecoverySheetDocument) {
    return this.call("saveRecoveryFile", { document }, d.saveResult);
  }
  async copyRecoveryCode() {
    await this.run("copyRecoveryCode");
  }
  confirmRecoveryGroup(group: string) {
    return this.call("confirmRecoveryGroup", { group }, d.recoveryCheck);
  }
  defaultFolderPlace() {
    return this.call("defaultFolderPlace", {}, d.folderPlace);
  }
  pickFolder(purpose: PickPurpose) {
    return this.call("pickFolder", { purpose }, d.pickResult);
  }
  countLocalFiles(token: string) {
    return this.call("countLocalFiles", { token }, d.num);
  }
  async finishSetup(token: string) {
    await this.run("finishSetup", { token });
  }
  scanWithCamera() {
    return this.call("scanWithCamera", {}, d.nullableStr);
  }
  startPairing(input: PairInput, deviceName: string) {
    return this.call(
      "startPairing",
      { input, deviceName },
      d.result(d.pairWaiting, ...PAIR_ERRORS, "blank", "edgeWhitespace"),
    );
  }
  async cancelPairing() {
    await this.run("cancelPairing");
  }
  listAccountFolders() {
    return this.call("listAccountFolders", {}, d.accountFolders);
  }
  joinFolders(choices: readonly FolderChoice[]) {
    return this.call("joinFolders", { choices }, d.array(d.str));
  }
  recoverAccount(sheet: string, code: string, deviceName: string) {
    return this.call(
      "recoverAccount",
      { sheet, code, deviceName },
      d.result(
        d.nothing,
        "typo",
        "unknown",
        "used",
        "otherApp",
        "wrongSheet",
        "unreachable",
        "insecure",
        "blank",
        "edgeWhitespace",
      ),
    );
  }
  setDeviceName(name: string) {
    return this.call(
      "setDeviceName",
      { name },
      d.result(d.nothing, "blank", "edgeWhitespace", "looksLike"),
    );
  }
  recoveryDevices() {
    return this.call("recoveryDevices", {}, d.array(d.device));
  }
  finishRecoveryCleanup(remove: readonly DeviceId[]) {
    return this.call(
      "finishRecoveryCleanup",
      { remove },
      d.result(d.nullableRecoveryCode, "listChanged", "unreachable", "used", "unknown", "insecure"),
    );
  }
  resetDevice() {
    return this.call("resetDevice", {}, d.resetOutcome);
  }

  resetDeviceDiscardingRecovery() {
    return this.call("resetDeviceDiscardingRecovery", {}, d.confirmation);
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
  async addFolder(token: string) {
    await this.run("addFolder", { token });
  }
  addAccountFolder(folderId: FolderId, token: string) {
    return this.call("addAccountFolder", { folderId, token }, d.joinOutcome);
  }
  async stopFolder(folderId: FolderId) {
    await this.run("stopFolder", { folderId });
  }
  /** The shell asks once more in a native dialog and answers how it ended. */
  deleteFolderEverywhere(folderId: FolderId): Promise<DeleteOutcome> {
    return this.call("deleteFolderEverywhere", { folderId }, d.deleteOutcome);
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
    return this.call("resolveMassDelete", { warningId, decision }, d.massDeleteOutcome);
  }
  listIncomingDelete(warningId: string) {
    return this.call("listIncomingDelete", { warningId }, d.array(d.str));
  }
  resolveIncomingDelete(warningId: string, decision: "restore" | "delete") {
    return this.call("resolveIncomingDelete", { warningId, decision }, d.massDeleteOutcome);
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
  /** Confirming asks once more in a native dialog with the number; the shell answers how. */
  confirmServerNumber(): Promise<ServerConfirm> {
    return this.call("confirmServerNumber", {}, d.serverConfirm);
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
  reanchor(folderId: FolderId, compared: boolean) {
    return this.call("reanchor", { folderId, compared }, d.confirmation);
  }
  async dismissSuspect(warningId: string) {
    await this.run("dismissSuspect", { warningId });
  }
  acceptRemovedHeads(folderId: FolderId) {
    return this.call("acceptRemovedHeads", { folderId }, d.headsAnswer);
  }
  async openStorageSettings() {
    await this.run("openStorageSettings");
  }
  confirmDeviceRemoved() {
    return this.call("confirmDeviceRemoved", {}, d.confirmation);
  }
  installUpdate() {
    return this.call("installUpdate", {}, d.updateOutcome);
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
    return this.call("resetFolder", { folderId, entryId }, d.nullableRestoreOutcome);
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
      d.result(d.nothing, "blank", "edgeWhitespace", "looksLike"),
    );
  }
  getSafetyNumber(deviceId: DeviceId) {
    return this.call("getSafetyNumber", { deviceId }, d.numberRows);
  }
  removeDevice(deviceId: DeviceId) {
    return this.call("removeDevice", { deviceId }, d.confirmation);
  }
  disconnectThisDevice() {
    return this.call("disconnectThisDevice", {}, d.confirmation);
  }
  createPairingOffer() {
    return this.call("createPairingOffer", {}, d.pairingOffer);
  }
  async copyPairingLink(offerId: string) {
    await this.run("copyPairingLink", { offerId });
  }
  /** Accepting asks once more in a native dialog; the shell answers how it ended. */
  answerPairRequest(offerId: string, accept: boolean): Promise<PairAnswer> {
    return this.call("answerPairRequest", { offerId, accept }, d.pairAnswer);
  }
  renewRecoveryCode() {
    return this.call("renewRecoveryCode", {}, d.recoveryCode);
  }

  getSettings() {
    return this.call("getSettings", {}, d.settings);
  }
  setAutostart(on: boolean) {
    return this.call("setAutostart", { on }, d.confirmation);
  }
  async setLanguage(language: Language | "system") {
    await this.run("setLanguage", { language });
  }

  async setFolderView(view: FolderView) {
    await this.run("setFolderView", { view });
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

/** The start of the message `install_update` rejects with while updates are off (updater.rs). */
const UPDATES_OFF = "updates are off";

/**
 * The Rust side rejects with `{ code, kind, message }`: `code` "busy" or "locked" is kept, the
 * "updates are off" refusal becomes "updatesOff", anything else is unexpected.
 */
export function codeOf(error: unknown): "busy" | "locked" | "updatesOff" | "unexpected" {
  if (typeof error === "object" && error !== null) {
    if ("code" in error && (error.code === "busy" || error.code === "locked")) return error.code;
    if (
      "message" in error &&
      typeof error.message === "string" &&
      error.message.startsWith(UPDATES_OFF)
    ) {
      return "updatesOff";
    }
  }
  return "unexpected";
}
