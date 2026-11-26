// The contract between the window and the Rust backend. The window only renders and calls these
// methods; every file, network and system access happens behind them. Two implementations exist:
// the mock (mock/mockBackend.ts) for the dev server and tests, and the Tauri bridge
// (tauri/tauriBackend.ts) that calls the real commands.
//
// Conventions:
// - Times are milliseconds since the epoch (UTC), sizes are bytes.
// - Expected outcomes that the person has to see (a used invite, a typo in a code, a restore that
//   waits) are part of the return type. Only unexpected failures reject, with a BackendError.
// - Nothing here carries keys, tokens or secrets except the recovery code and the pairing link,
//   which the person has to see to write down or pass on.

import type { Language } from "../i18n";
import type { TrayModel } from "../tray/trayModel";

export type Millis = number;
export type Bytes = number;
export type FolderId = string;
export type DeviceId = string;

/** A result the window shows in words; `error` is one of a closed list of codes. */
export type Result<T, E extends string> =
  { readonly ok: true; readonly value: T } | { readonly ok: false; readonly error: E };

/** Six groups of five digits (safety number, folder number, server number). */
export interface NumberRows {
  readonly groups: readonly string[];
}

/** A QR code as a square of modules, row by row, "1" dark and "0" light. */
export interface QrMatrix {
  readonly size: number;
  readonly modules: string;
}

// ---------------------------------------------------------------------------------------------
// Snapshot: everything the main window and the tray show, pushed whenever it changes.

export type Connection =
  | { readonly kind: "online" }
  /** The OS reports no network. */
  | { readonly kind: "noNetwork" }
  /** The server has not answered for at least two minutes. */
  | { readonly kind: "serverSilent"; readonly since: Millis };

export interface SyncSummary {
  readonly connection: Connection;
  /** Set while the person paused syncing; `until` null means "until I resume". */
  readonly pause: { readonly until: Millis | null } | null;
  /** Files with real work left (waiting files below are not counted). */
  readonly pendingFiles: number;
  readonly bytesLeft: Bytes;
  readonly lastSync: Millis | null;
  readonly lastFile: { readonly name: string; readonly at: Millis } | null;
  /** Large files held back by a metered network. */
  readonly waitingMetered: number;
  /** Files held back by the server's daily upload budget. */
  readonly waitingBudget: number;
}

export type FolderStatus =
  | { readonly kind: "upToDate" }
  | { readonly kind: "uploading"; readonly count: number }
  | { readonly kind: "downloading"; readonly count: number }
  | { readonly kind: "paused" }
  | { readonly kind: "stopped"; readonly reason: "missing" | "olderState" };

export interface Folder {
  readonly id: FolderId;
  readonly name: string;
  readonly path: string;
  readonly status: FolderStatus;
  /** Days without news from the other devices (section 8.7), null below the threshold. */
  readonly freezeDays: number | null;
  /** Entries that are never synced (links, system files), shown as a quiet line. */
  readonly notSyncedCount: number;
}

export type FileAction =
  "changed" | "added" | "deleted" | "renamed" | "fromDevice" | "restored" | "twoVersions";

export type ActivityEntry =
  | {
      readonly kind: "file";
      readonly id: string;
      readonly folderId: FolderId;
      readonly folderName: string;
      readonly name: string;
      readonly path: string;
      readonly action: FileAction;
      /** The other device for "fromDevice". */
      readonly device: string | null;
      readonly at: Millis;
    }
  | {
      readonly kind: "group";
      readonly id: string;
      readonly folderId: FolderId;
      readonly folderName: string;
      readonly count: number;
      readonly at: Millis;
    }
  | {
      readonly kind: "remoteDeleted";
      readonly id: string;
      readonly folderId: FolderId;
      readonly folderName: string;
      readonly count: number;
      readonly device: string;
      readonly at: Millis;
    }
  | {
      readonly kind: "cameBack";
      readonly id: string;
      readonly folderId: FolderId;
      readonly folderName: string;
      readonly name: string;
      readonly path: string;
      readonly device: string;
      readonly at: Millis;
    };

/** Everything the window shows as a banner. Order of urgency: domain/warnings.ts. */
export type Warning =
  | {
      readonly kind: "massDelete";
      readonly id: string;
      readonly folderId: FolderId;
      readonly folderName: string;
      readonly count: number;
      /** The first few names, for the sentence "a, b, c and 339 more". */
      readonly sample: readonly string[];
    }
  | {
      readonly kind: "missingFolder";
      readonly id: string;
      readonly folderId: FolderId;
      readonly folderName: string;
    }
  | { readonly kind: "serverIdentity"; readonly id: string; readonly hasOtherDevice: boolean }
  | { readonly kind: "quota"; readonly id: string }
  | { readonly kind: "quotaFull"; readonly id: string }
  | { readonly kind: "serverDisk"; readonly id: string }
  | { readonly kind: "diskFull"; readonly id: string; readonly needed: Bytes }
  | {
      readonly kind: "olderState";
      readonly id: string;
      readonly folderId: FolderId;
      readonly folderName: string;
    }
  | { readonly kind: "removed"; readonly id: string; readonly by: string }
  | { readonly kind: "updateRequired"; readonly id: string }
  | { readonly kind: "refused"; readonly id: string }
  | {
      readonly kind: "suspect";
      readonly id: string;
      readonly deviceId: DeviceId;
      readonly deviceName: string;
      readonly folderId: FolderId;
      readonly folderName: string;
      /** The timeline entry before the first commit of that device in the burst. */
      readonly entryId: string;
      /** Retention days the server guarantees at least. */
      readonly days: number;
    }
  | { readonly kind: "conflicts"; readonly id: string; readonly count: number }
  | { readonly kind: "names"; readonly id: string; readonly count: number };

export type WarningKind = Warning["kind"];

/** Quiet notices from the server's change feed: a closed list, the text is the app's own. */
export type ServerNotice =
  | { readonly kind: "retained" }
  | { readonly kind: "budgetDevice"; readonly device: string }
  | { readonly kind: "minCount"; readonly days: number };

export interface Account {
  readonly host: string;
  readonly retentionDays: number;
  readonly hasOtherDevices: boolean;
}

export interface Storage {
  readonly used: Bytes;
  readonly quota: Bytes;
}

/** A folder of the account that is not on this device yet. */
export interface RemoteFolder {
  readonly id: FolderId;
  readonly name: string;
  readonly size: Bytes;
}

/** A folder deleted on all devices that can still be brought back. */
export interface DeletedFolder {
  readonly id: FolderId;
  readonly name: string;
  readonly daysLeft: number;
}

export interface Environment {
  readonly camera: boolean;
}

export interface Snapshot {
  readonly setup: "needed" | "done";
  readonly sync: SyncSummary;
  readonly folders: readonly Folder[];
  /** Newest first, at most 50. */
  readonly activity: readonly ActivityEntry[];
  readonly warnings: readonly Warning[];
  readonly notices: readonly ServerNotice[];
  /** Null when the server does not report a quota. */
  readonly storage: Storage | null;
  readonly account: Account | null;
  readonly remoteFolders: readonly RemoteFolder[];
  readonly deletedFolders: readonly DeletedFolder[];
  readonly env: Environment;
}

// ---------------------------------------------------------------------------------------------
// Setup

export type InviteError = "notALink" | "used" | "expired" | "unreachable" | "insecure";

/**
 * Why a device name was refused (rule N5): empty or only filler characters after trimming, or
 * whitespace at the edges. The window trims before sending; the backend checks again.
 */
export type NameError = "blank" | "edgeWhitespace";

export interface RecoveryCode {
  /** Eight groups of four characters. */
  readonly groups: readonly string[];
  /** One-based group the person types back; never 1. */
  readonly checkGroup: number;
}

export type SaveResult =
  | { readonly kind: "saved"; readonly path: string }
  | { readonly kind: "cancelled" }
  /** The chosen place lies in a synced folder (recovery file only). */
  | { readonly kind: "inSyncFolder" };

export type FolderRefusal = "network" | "root" | "system" | "nested" | "noAccess" | "wrongFolder";

export type PickResult =
  | { readonly kind: "picked"; readonly path: string; readonly name: string }
  | { readonly kind: "cancelled" }
  | {
      readonly kind: "refused";
      readonly reason: FolderRefusal;
      /** The synced folder it collides with, for "nested". */
      readonly folder: string | null;
    };

export type PickPurpose =
  | { readonly kind: "new" }
  /** A place for an account folder that comes to this device. */
  | { readonly kind: "account"; readonly folderId: FolderId }
  /** The new place of a missing folder; the marker must match. */
  | { readonly kind: "find"; readonly folderId: FolderId };

export interface FolderPlace {
  readonly path: string;
  readonly name: string;
}

export type PairError =
  | "notALink"
  | "expired"
  | "typo"
  | "declined"
  | "tooMany"
  | "otherAccount"
  | "unreachable"
  | "insecure";

export type PairInput =
  | { readonly kind: "link"; readonly link: string }
  | { readonly kind: "typed"; readonly server: string; readonly code: string };

export interface PairWaiting {
  readonly path: "link" | "typed";
  readonly safety: NumberRows;
}

export interface AccountFolder {
  readonly id: FolderId;
  readonly name: string;
  readonly size: Bytes;
  readonly proposedPath: string;
}

export interface FolderChoice {
  readonly folderId: FolderId;
  readonly path: string;
}

export type RecoverError = "typo" | "unknown" | "used" | "otherApp" | "unreachable" | "insecure";

// ---------------------------------------------------------------------------------------------
// Conflicts and names

export interface ConflictVersion {
  readonly id: string;
  readonly name: string;
  readonly device: string;
  readonly modified: Millis;
  readonly size: Bytes;
  /** The version that kept the name. */
  readonly original: boolean;
}

export interface ConflictGroup {
  readonly id: string;
  readonly folderId: FolderId;
  readonly folderName: string;
  readonly path: string;
  readonly kind: "content" | "caseOnly";
  readonly versions: readonly ConflictVersion[];
}

export type NameReason =
  | { readonly kind: "char"; readonly char: string }
  | { readonly kind: "reserved"; readonly name: string }
  | { readonly kind: "trailing" }
  | { readonly kind: "control" }
  | { readonly kind: "cannotCreate" };

export interface NameIssue {
  readonly id: string;
  readonly folderId: FolderId;
  readonly folderName: string;
  /** Path of the parent inside the folder, empty at the root. */
  readonly dir: string;
  readonly name: string;
  readonly reason: NameReason;
  readonly device: string;
}

export type RenameError = "invalid" | "exists";

export interface NotSyncedEntry {
  readonly path: string;
  readonly reason: "link" | "system";
}

// ---------------------------------------------------------------------------------------------
// Restore

export interface TimelineEntry {
  readonly id: string;
  /** Time of the last commit of the session. */
  readonly at: Millis;
  readonly device: string;
  readonly changed: number;
  readonly added: number;
  readonly deleted: number;
  /** Written by a re-anchor (section 8.6); shows the marker line. */
  readonly reanchored: boolean;
}

export interface Timeline {
  readonly entries: readonly TimelineEntry[];
  readonly expiredCount: number;
  readonly retentionDays: number;
}

export type FileDiff = "same" | "different" | "missing" | "newer";

export interface TreeNode {
  /** Path inside the folder, "/" separated. */
  readonly path: string;
  readonly name: string;
  readonly depth: number;
  readonly kind: "file" | "dir";
  readonly diff: FileDiff;
}

export interface VersionTree {
  readonly nodes: readonly TreeNode[];
  readonly changed: number;
  readonly missing: number;
}

export type RestoreOutcome =
  | {
      readonly kind: "done";
      readonly count: number;
      /** Set when the name was taken and the file came back under another name. */
      readonly renamedTo: string | null;
      readonly undoToken: string | null;
    }
  | { readonly kind: "waitBudget"; readonly jobId: string }
  | { readonly kind: "noSpace" }
  | { readonly kind: "expired" }
  | { readonly kind: "failed" };

export interface TrashItem {
  readonly id: string;
  readonly name: string;
  /** Last parent path inside the folder, empty at the root. */
  readonly dir: string;
  readonly deletedAt: Millis;
  readonly device: string;
}

// ---------------------------------------------------------------------------------------------
// Devices

export interface Device {
  readonly id: DeviceId;
  readonly name: string;
  readonly kind: "laptop" | "desktop";
  readonly isThis: boolean;
  readonly lastSeen: Millis | null;
  readonly added: Millis;
}

export interface DeviceList {
  readonly devices: readonly Device[];
  readonly recoveryCreated: Millis;
}

export interface PairingOffer {
  readonly id: string;
  readonly link: string;
  /** The code to type, 26 characters, already grouped for reading. */
  readonly code: readonly string[];
  readonly host: string;
  readonly qr: QrMatrix;
  readonly expiresAt: Millis;
}

export interface PairRequest {
  readonly offerId: string;
  readonly deviceName: string;
  readonly path: "link" | "typed";
  readonly safety: NumberRows;
}

// ---------------------------------------------------------------------------------------------
// Settings

export interface Settings {
  readonly autostart: boolean;
  readonly language: Language | "system";
}

export interface About {
  readonly version: string;
  readonly build: number | null;
}

export type PauseDuration = "hour" | "tomorrow" | "manual";

// ---------------------------------------------------------------------------------------------
// Events

export type BackendEvent =
  | { readonly type: "snapshot"; readonly snapshot: Snapshot }
  /** A new device answered an offer of this device and waits for the person's decision. */
  | { readonly type: "pairRequest"; readonly request: PairRequest }
  /** The new device gave up or the offer expired while the question was open. */
  | { readonly type: "pairRequestGone"; readonly offerId: string }
  /** The outcome of a pairing started on this (new) device. */
  | {
      readonly type: "pairResult";
      readonly result:
        { readonly kind: "joined" } | { readonly kind: "failed"; readonly error: PairError };
    }
  /** A notification was clicked: show the window with this banner. */
  | { readonly type: "focusWarning"; readonly warningId: string }
  /** An item of the native tray menu was chosen; the id comes from `TrayMenuItem.id`. */
  | { readonly type: "trayAction"; readonly actionId: string };

export type Unsubscribe = () => void;

// ---------------------------------------------------------------------------------------------
// The interface

export interface Backend {
  /** "mock" or "tauri", for the dev tools only. */
  readonly kind: "mock" | "tauri";

  getSnapshot(): Promise<Snapshot>;
  subscribe(listener: (event: BackendEvent) => void): Unsubscribe;

  /** Reads text from the clipboard, only when the person clicked "Paste" (UX 4.2 step 1). */
  readClipboardText(): Promise<string>;

  // Setup, new account (UX 4.2)
  checkInvite(link: string): Promise<Result<{ readonly host: string }, InviteError>>;
  defaultDeviceName(): Promise<string>;
  /** Checks the invite again and creates the device identity locally; redeems nothing yet. */
  beginAccount(
    link: string,
    deviceName: string,
  ): Promise<Result<RecoveryCode, InviteError | NameError>>;
  printRecoverySheet(): Promise<void>;
  saveRecoveryFile(): Promise<SaveResult>;
  /** Copies the code; the backend clears the clipboard after one minute. */
  copyRecoveryCode(): Promise<void>;
  /**
   * Checks the typed group (already normalized). On success the account comes into being (4.2.1),
   * or the renewed code replaces the old one (10.3).
   */
  confirmRecoveryGroup(group: string): Promise<boolean>;
  defaultFolderPlace(): Promise<FolderPlace>;
  pickFolder(purpose: PickPurpose): Promise<PickResult>;
  /** Number of local files at a place, ignoring the built-in ignore list (6.5). */
  countLocalFiles(path: string): Promise<number>;
  finishSetup(path: string): Promise<void>;

  // Setup, additional device (4.3) and recovery (4.4)
  scanWithCamera(): Promise<string | null>;
  startPairing(input: PairInput): Promise<Result<PairWaiting, PairError>>;
  cancelPairing(): Promise<void>;
  listAccountFolders(): Promise<{
    readonly folders: readonly AccountFolder[];
    readonly free: Bytes;
  }>;
  joinFolders(choices: readonly FolderChoice[]): Promise<void>;
  recoverAccount(server: string, code: string): Promise<Result<null, RecoverError>>;
  setDeviceName(name: string): Promise<Result<null, NameError>>;
  recoveryDevices(): Promise<readonly Device[]>;
  /** Removes the chosen old devices and the used recovery device, returns the new code. */
  finishRecoveryCleanup(remove: readonly DeviceId[]): Promise<RecoveryCode>;

  // Everyday (6)
  openFolder(folderId: FolderId | null, path?: string): Promise<void>;
  pause(duration: PauseDuration): Promise<void>;
  resume(): Promise<void>;
  /** Lets the files waiting for an unmetered network go once. */
  syncNow(): Promise<void>;
  retryConnection(): Promise<void>;
  pauseFolder(folderId: FolderId): Promise<void>;
  resumeFolder(folderId: FolderId): Promise<void>;
  addFolder(path: string): Promise<void>;
  addAccountFolder(folderId: FolderId, path: string): Promise<void>;
  stopFolder(folderId: FolderId): Promise<void>;
  deleteFolderEverywhere(folderId: FolderId): Promise<void>;
  restoreDeletedFolder(folderId: FolderId): Promise<void>;
  listNotSynced(folderId: FolderId): Promise<readonly NotSyncedEntry[]>;
  /** Checks with the server first; "offline" without a connection (8.6). */
  getFolderNumber(
    folderId: FolderId,
  ): Promise<
    { readonly kind: "number"; readonly number: NumberRows } | { readonly kind: "offline" }
  >;
  restoreRemoteDeleted(activityId: string): Promise<number>;

  // Problems (8)
  listMassDelete(warningId: string): Promise<readonly string[]>;
  resolveMassDelete(warningId: string, decision: "restore" | "delete"): Promise<number>;
  findMissingFolder(folderId: FolderId): Promise<PickResult>;
  redownloadFolder(folderId: FolderId): Promise<void>;
  getServerNumber(): Promise<{ readonly number: NumberRows; readonly command: string }>;
  confirmServerNumber(): Promise<void>;
  fixServerWithOffer(link: string): Promise<Result<null, "notALink" | "otherAccount" | "expired">>;
  checkOlderState(folderId: FolderId): Promise<"stillOlder" | "resolved">;
  reanchor(folderId: FolderId, compared: boolean): Promise<void>;
  dismissSuspect(warningId: string): Promise<void>;
  openStorageSettings(): Promise<void>;
  installUpdate(): Promise<void>;
  copyErrorReport(): Promise<void>;
  previewErrorReport(): Promise<string>;
  saveErrorReport(): Promise<SaveResult>;

  // Conflicts and names (7)
  listConflicts(): Promise<readonly ConflictGroup[]>;
  openConflict(groupId: string): Promise<void>;
  keepConflictVersion(groupId: string, versionId: string): Promise<{ readonly undoToken: string }>;
  keepBothConflict(groupId: string): Promise<void>;
  undo(token: string): Promise<void>;
  listNameIssues(): Promise<readonly NameIssue[]>;
  renameNameIssue(issueId: string, name: string): Promise<Result<null, RenameError>>;
  ignoreNameIssue(issueId: string): Promise<void>;

  // Restore (9)
  getTimeline(folderId: FolderId, path?: string): Promise<Timeline>;
  getTreeAt(folderId: FolderId, entryId: string): Promise<VersionTree>;
  restoreFile(
    folderId: FolderId,
    entryId: string,
    path: string,
    mode: "replace" | "copy",
  ): Promise<RestoreOutcome>;
  resetFolder(folderId: FolderId, entryId: string): Promise<RestoreOutcome>;
  cancelRestore(jobId: string): Promise<void>;
  /** The entry for "state before changes from ..." (9.4), null when there is none. */
  findBeforeDevice(folderId: FolderId, deviceId: DeviceId, from: Millis): Promise<string | null>;
  getTrash(folderId: FolderId): Promise<readonly TrashItem[]>;
  restoreTrash(folderId: FolderId, itemIds: readonly string[]): Promise<RestoreOutcome>;

  // Devices (10)
  listDevices(): Promise<DeviceList>;
  renameDevice(deviceId: DeviceId, name: string): Promise<Result<null, NameError>>;
  getSafetyNumber(deviceId: DeviceId): Promise<NumberRows>;
  removeDevice(deviceId: DeviceId): Promise<void>;
  disconnectThisDevice(): Promise<void>;
  createPairingOffer(): Promise<PairingOffer>;
  copyPairingLink(offerId: string): Promise<void>;
  answerPairRequest(offerId: string, accept: boolean): Promise<void>;
  /** Starts a new recovery code; the old one stays valid until the group check succeeds. */
  renewRecoveryCode(): Promise<RecoveryCode>;

  // Settings (11)
  getSettings(): Promise<Settings>;
  setAutostart(on: boolean): Promise<void>;
  setLanguage(language: Language | "system"): Promise<void>;
  getAbout(): Promise<About>;

  // Tray (6.1, 6.2): the window computes icon, tooltip and menu, the backend draws them.
  updateTray(model: TrayModel): Promise<void>;
  /** Brings the window to the front (tray "open", a notification click). */
  showWindow(): Promise<void>;
  quit(): Promise<void>;
}
