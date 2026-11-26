// The contract between the window and the Rust backend. The window only renders and calls these
// methods; every file, network and system access happens behind them. Two implementations exist:
// the mock (mock/mockBackend.ts) for the dev server and tests, and the Tauri bridge
// (tauri/tauriBackend.ts) that calls the real commands.
//
// Conventions:
// - Times are milliseconds since the epoch (UTC), sizes are bytes.
// - Expected outcomes that the person has to see (a used invite, a typo in a code, a restore that
//   waits) are part of the return type. Only unexpected failures reject, with a BackendError.
// - Nothing here carries keys or secrets except the recovery code and the pairing link, which the
//   person has to see to write down or pass on.
// - The window never sends a path of its own choosing (security review L2). A place on disk is
//   one the backend proposed or the person picked in a native dialog, and the backend names it
//   with an opaque `token`; later commands take the token, the path is only shown.
// - Hosts are always the ASCII form the client connects to: an internationalized name arrives in
//   punycode (`xn--...`), so letters that look alike cannot hide another server (N2).

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
  | { readonly kind: "stopped"; readonly reason: StopReason };

/**
 * Why a folder stopped: its folder is missing, the server shows an older state (UX 8.6),
 * changes of a removed device wait for the person's decision (UX 8.9, security review H1), or
 * the server's newest version of the folder is too deep or too large to be one (security review
 * M3), which a restore replaces.
 */
/** `tooLarge`: the folder on this disk is beyond the limits of a folder; nothing is published. */
export type StopReason = "missing" | "olderState" | "removedHeads" | "treeLimit" | "tooLarge";

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
  /**
   * Changes of a device that was removed from the account arrived without the removal's
   * confirmation. The folder stays stopped until the person takes them in
   * (`acceptRemovedHeads`) and then usually undoes them (UX 8.9).
   */
  | {
      readonly kind: "removedHeads";
      readonly id: string;
      readonly folderId: FolderId;
      readonly folderName: string;
      /** The removed devices' names as far as this device still knows them; "" when unknown. */
      readonly devices: readonly string[];
      /** How many saved states (commits) of them wait; for the error report, never shown. */
      readonly count: number;
    }
  /**
   * This device was removed from the account. `by` names the device that removed it, "" when
   * that is unknown (the server only answered `deviceRemoved` at sign-in).
   */
  | { readonly kind: "removed"; readonly id: string; readonly by: string }
  /**
   * The server answered this device's sign-in with "removed", which this device cannot check
   * (security review H2). Sync stops; the account is forgotten here only once the person
   * confirms (`confirmDeviceRemoved`) or the server has said so for a day. `since` is when the
   * server said it first.
   */
  | { readonly kind: "removalReported"; readonly id: string; readonly since: Millis }
  /**
   * The server's newest version of a folder is too deep or too large to be a folder (security
   * review M3): it was not taken in, and the folder waits for a restore of an earlier version.
   */
  | {
      readonly kind: "treeLimit";
      readonly id: string;
      readonly folderId: FolderId;
      readonly folderName: string;
    }
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
  | { readonly kind: "minCount"; readonly days: number }
  /**
   * The server's change list was behind this device (an older backup of the server): the device
   * read the whole account again (security review M2). Nothing is lost.
   */
  | { readonly kind: "olderAccountState" };

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

/** What `checkInvite` learnt from a valid invite. */
export interface InviteCheck {
  /** The server's host, ASCII (punycode for an internationalized name). */
  readonly host: string;
  /**
   * The link carries a pin: the server has no certificate from a public authority, and this
   * device will trust the key the link names (N3). The window warns calmly before going on.
   */
  readonly pinned: boolean;
}

/** The kinds of link the app reads (UX 4.2 to 4.4); `domain/links.ts` tells them apart. */
export type LinkKind = "invite" | "pair" | "recover";

/** Why a link could not be read offline: not a link of the app, damaged, or not encrypted. */
export type LinkError = "notALink" | "damaged" | "insecure";

/**
 * What a link says before anything is sent (`inspectLink`): read offline, nothing leaves the
 * device. The window shows host and account and asks before it connects (N2).
 */
export type InspectedLink =
  | { readonly kind: "invite"; readonly host: string; readonly pinned: boolean }
  | {
      readonly kind: "pair" | "recover";
      readonly host: string;
      /** The account ID in lowercase hex (32 characters), as the recovery sheet prints it. */
      readonly account: string;
      readonly pinned: boolean;
    };

/**
 * Why a device name was refused (rule N5): empty or only filler characters after trimming, or
 * whitespace at the edges. The window trims before sending; the backend checks again.
 */
export type NameError = "blank" | "edgeWhitespace";

/**
 * Why naming or renaming a device was refused: the name rule, or `looksLike`, a name that looks
 * the same as another device's of the account and was not confirmed in the native question.
 */
export type DeviceNameError = NameError | "looksLike";

export interface RecoveryCode {
  /** Eight groups of four characters. */
  readonly groups: readonly string[];
  /** One-based group the person types back; never 1. */
  readonly checkGroup: number;
  /** What the recovery sheet prints next to the code (version 2 of the sheet). */
  readonly sheet: RecoverySheet;
}

/**
 * The public part of the recovery sheet, printed in the clear and carried by its link. None of it
 * is secret; the code is never part of it.
 */
export interface RecoverySheet {
  /** The server address as the client connects to it (`https://drive.example.org/`). */
  readonly serverUrl: string;
  /** The server ID, lowercase hex. */
  readonly serverId: string;
  /** The account ID, lowercase hex. */
  readonly accountId: string;
  /** The genesis anchor: the hash of the account log's first entry, lowercase hex. */
  readonly genesisAnchor: string;
  /** The server's pin for a server without a public certificate, null otherwise. */
  readonly pin: string | null;
  /** `hangar-drive://recover#...`, which the person pastes or scans during a recovery. */
  readonly link: string;
}

/**
 * The recovery sheet as the person reads it, in the window's language: the window writes the
 * words, the backend lays them out for printing (with a QR code of `qrLink`) or writes them as
 * a text file. The code is one of the fields; nothing else secret is in it.
 */
export interface RecoverySheetDocument {
  /** BCP 47 tag of the texts, for the printed page. */
  readonly language: string;
  readonly title: string;
  /** Label and value, in print order: code, server, IDs, anchor, pin, link, date, device. */
  readonly fields: readonly { readonly label: string; readonly value: string }[];
  /** The plain sentences under the fields (UX 4.2 step 2). */
  readonly notes: readonly string[];
  /** The sheet's link, for the QR code; never the code. */
  readonly qrLink: string;
  /** The proposed file name for "Save as file", without a folder. */
  readonly fileName: string;
}

export type SaveResult =
  | { readonly kind: "saved"; readonly path: string }
  | { readonly kind: "cancelled" }
  /** The chosen place lies in a synced folder (recovery file only). */
  | { readonly kind: "inSyncFolder" }
  /**
   * The chosen place lies in another sync client's or a cloud folder (OneDrive, Dropbox, Google
   * Drive, iCloud Drive; security review M2); recovery file only.
   */
  | { readonly kind: "inCloudFolder" };

export type FolderRefusal = "network" | "root" | "system" | "nested" | "noAccess" | "wrongFolder";

export type PickResult =
  | ({ readonly kind: "picked" } & FolderPlace)
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

/**
 * A place on disk the backend handed out. `token` names it in `countLocalFiles`, `finishSetup`,
 * `addFolder`, `addAccountFolder` and `joinFolders`; `path` and `name` are only shown. The token
 * from `findMissingFolder` is empty: the folder has moved already, there is nothing to name.
 */
export interface FolderPlace {
  readonly path: string;
  readonly name: string;
  readonly token: string;
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
  /** Where the folder would go, for display; `proposedToken` names that place. */
  readonly proposedPath: string;
  readonly proposedToken: string;
}

/** An account folder and the token of its place (`proposedToken` or a picked place). */
export interface FolderChoice {
  readonly folderId: FolderId;
  readonly token: string;
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
  /** The account ID in lowercase hex, so the new device's question can be compared (N2). */
  readonly account: string;
  readonly qr: QrMatrix;
  /**
   * The same code as a complete SVG document (black on white, with its quiet zone). The window
   * shows it only as an image (`<img>` with a `data:` URL), never as markup, so nothing the
   * backend sends becomes part of the page.
   */
  readonly qrSvg: string;
  readonly expiresAt: Millis;
}

export interface PairRequest {
  readonly offerId: string;
  readonly deviceName: string;
  readonly path: "link" | "typed";
  readonly safety: NumberRows;
  /** A device of the account whose name looks the same, or null. */
  readonly similarTo: string | null;
}

/** One saved state of a removed device that stopped a folder (`removedHeads` event). */
export interface RemovedHead {
  /** The commit; its timeline entry ID once taken in. */
  readonly commit: string;
  readonly deviceId: DeviceId;
  /** "" when this device no longer knows the name. */
  readonly deviceName: string;
  /** The folder sequence. */
  readonly sequence: number;
}

/** What `acceptRemovedHeads` did. */
export interface AcceptedHeads {
  /** Saved states the barrier now covers. */
  readonly count: number;
  /**
   * The timeline entry right before the first of them, for "Undo a device" (UX 9.4); null when
   * the folder has no earlier version.
   */
  readonly beforeEntryId: string | null;
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
  /**
   * Whether in-app updates are set up (an updater key and endpoint in this build). While false,
   * the window hides "Update now"; `installUpdate` would reject with "updatesOff".
   */
  readonly updates: boolean;
}

/** What `installUpdate` did. */
export type UpdateOutcome =
  | { readonly kind: "upToDate" }
  /** The signed update is installed; on Windows the installer ends the app. */
  | { readonly kind: "installed"; readonly version: string }
  /** An update was found, and the person said no in the native dialog. */
  | { readonly kind: "declined" };

/**
 * The answer of the native confirmation behind `deleteFolderEverywhere`, an accepted
 * `answerPairRequest` and `confirmServerNumber` (security review L2). "No" there is not an
 * error: the folder stays, the device is declined, or the server key is not trusted.
 */
export type DeleteOutcome = "deleted" | "kept";
export type PairAnswer = "added" | "declined";
export type ServerConfirm = Confirmation;

/**
 * The answer of the native confirmation behind removing a device, resetting or disconnecting
 * this device, re-anchoring a folder and turning autostart off (security review M4). The window
 * asks nothing before these; "declined" means the person said no there, which is not an error.
 */
export type Confirmation = "confirmed" | "declined";

/**
 * How the group check ended: "wrong" for a group that does not match, "declined" when the
 * person said no to taking a renewed code in the native dialog (the old code stays valid).
 */
export type RecoveryCheck = "confirmed" | "wrong" | "declined";

/** How `resolveMassDelete` ended; "declined" when "delete" was declined natively. */
export type MassDeleteOutcome =
  { readonly kind: "resolved"; readonly count: number } | { readonly kind: "declined" };

/** How `acceptRemovedHeads` ended; "declined" leaves the folder stopped. */
export type HeadsAnswer =
  ({ readonly kind: "accepted" } & AcceptedHeads) | { readonly kind: "declined" };

/**
 * How joining an account folder at a place ended. A place that already holds files asks
 * natively with the place, the number of files and the server (security review H1, UX 6.5);
 * "declined" means "choose another folder" there, and nothing was joined.
 */
export type JoinOutcome = "joined" | "declined";

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
  | { readonly type: "trayAction"; readonly actionId: string }
  /**
   * Changes of a removed device stopped a folder (UX 8.9). The matching `removedHeads` warning
   * comes with the snapshot; this event asks the window to put the question in front.
   */
  | {
      readonly type: "removedHeads";
      readonly folderId: FolderId;
      readonly heads: readonly RemovedHead[];
    }
  /**
   * The OS handed the app a `hangar-drive://` link (join, pair, recover), at start or while it
   * runs. The text is passed on as it came; the window never acts on it without the person.
   */
  | { readonly type: "openLink"; readonly link: string };

export type Unsubscribe = () => void;

// ---------------------------------------------------------------------------------------------
// The interface

export interface Backend {
  /** "mock" or "tauri", for the dev tools only. */
  readonly kind: "mock" | "tauri";

  getSnapshot(): Promise<Snapshot>;
  subscribe(listener: (event: BackendEvent) => void): Unsubscribe;

  /**
   * Reads text from the clipboard, only when the person clicked "Paste" (UX 4.2 step 1). Only a
   * link or code of the app comes back; anything else, like an empty clipboard, is "".
   */
  readClipboardText(): Promise<string>;

  // Setup, new account (UX 4.2)
  checkInvite(link: string): Promise<Result<InviteCheck, InviteError>>;
  /** Reads a link offline, without contacting anyone, so the window can ask first (N2). */
  inspectLink(link: string): Promise<Result<InspectedLink, LinkError>>;
  defaultDeviceName(): Promise<string>;
  /** Checks the invite again and creates the device identity locally; redeems nothing yet. */
  beginAccount(
    link: string,
    deviceName: string,
  ): Promise<Result<RecoveryCode, InviteError | NameError>>;
  /** Prints the sheet of the current code as the window worded it. */
  printRecoverySheet(document: RecoverySheetDocument): Promise<void>;
  /** Writes the same sheet as a text file; refuses a place inside a synced folder. */
  saveRecoveryFile(document: RecoverySheetDocument): Promise<SaveResult>;
  /** Copies the code; the backend clears the clipboard after one minute. */
  copyRecoveryCode(): Promise<void>;
  /**
   * Checks the typed group (already normalized). On success the account comes into being (4.2.1),
   * or the renewed code replaces the old one (10.3).
   */
  confirmRecoveryGroup(group: string): Promise<RecoveryCheck>;
  defaultFolderPlace(): Promise<FolderPlace>;
  pickFolder(purpose: PickPurpose): Promise<PickResult>;
  /** Number of local files at a place (its token), ignoring the built-in ignore list (6.5). */
  countLocalFiles(token: string): Promise<number>;
  finishSetup(token: string): Promise<void>;

  // Setup, additional device (4.3) and recovery (4.4)
  scanWithCamera(): Promise<string | null>;
  /**
   * Answers an offer of another device. `deviceName` is the name of this new device (trimmed),
   * which the other device shows in its question; refused by rule N5 like every device name.
   */
  startPairing(
    input: PairInput,
    deviceName: string,
  ): Promise<Result<PairWaiting, PairError | NameError>>;
  cancelPairing(): Promise<void>;
  listAccountFolders(): Promise<{
    readonly folders: readonly AccountFolder[];
    readonly free: Bytes;
  }>;
  /** Joins the chosen folders; answers the IDs of those declined natively (see `JoinOutcome`). */
  joinFolders(choices: readonly FolderChoice[]): Promise<readonly FolderId[]>;
  /**
   * Recovery with the sheet (UX 4.4): `sheet` is the sheet's link `hangar-drive://recover#...`
   * (pasted or scanned, white space removed), `code` the typed code (normalized), `deviceName`
   * the name of this new device (trimmed).
   */
  recoverAccount(
    sheet: string,
    code: string,
    deviceName: string,
  ): Promise<Result<null, RecoverError | NameError>>;
  /** No longer called by the window (the name goes with `recoverAccount`); kept for the shell. */
  setDeviceName(name: string): Promise<Result<null, DeviceNameError>>;
  recoveryDevices(): Promise<readonly Device[]>;
  /**
   * Removes the chosen old devices and the used recovery device, returns the new code. Removing
   * devices asks natively first with their names; null when the person said no there (nothing
   * was removed). The window asks nothing before it.
   */
  finishRecoveryCleanup(remove: readonly DeviceId[]): Promise<RecoveryCode | null>;
  /**
   * Forgets the account on this device: secrets, stored account and the folders' sync state; the
   * files stay. The next snapshot says `setup: "needed"`, so the window shows the welcome again.
   */
  resetDevice(): Promise<Confirmation>;

  // Everyday (6)
  openFolder(folderId: FolderId | null, path?: string): Promise<void>;
  pause(duration: PauseDuration): Promise<void>;
  resume(): Promise<void>;
  /** Lets the files waiting for an unmetered network go once. */
  syncNow(): Promise<void>;
  retryConnection(): Promise<void>;
  pauseFolder(folderId: FolderId): Promise<void>;
  resumeFolder(folderId: FolderId): Promise<void>;
  addFolder(token: string): Promise<void>;
  addAccountFolder(folderId: FolderId, token: string): Promise<JoinOutcome>;
  stopFolder(folderId: FolderId): Promise<void>;
  /** Asks once more in a native dialog that names the folder; "no" there keeps it. */
  deleteFolderEverywhere(folderId: FolderId): Promise<DeleteOutcome>;
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
  /** "delete" asks once more natively with the folder and the number of files. */
  resolveMassDelete(warningId: string, decision: "restore" | "delete"): Promise<MassDeleteOutcome>;
  findMissingFolder(folderId: FolderId): Promise<PickResult>;
  redownloadFolder(folderId: FolderId): Promise<void>;
  getServerNumber(): Promise<{ readonly number: NumberRows; readonly command: string }>;
  /** Asks once more in a native dialog with the server number; "no" there trusts nothing. */
  confirmServerNumber(): Promise<ServerConfirm>;
  fixServerWithOffer(link: string): Promise<Result<null, "notALink" | "otherAccount" | "expired">>;
  checkOlderState(folderId: FolderId): Promise<"stillOlder" | "resolved">;
  /** Asks natively with the folder and what is lost; the window asks nothing more before it. */
  reanchor(folderId: FolderId, compared: boolean): Promise<Confirmation>;
  dismissSuspect(warningId: string): Promise<void>;
  /**
   * Takes in the changes of a removed device that stopped a folder (UX 8.9): the barrier after
   * them is written and the folder syncs again. The window then offers to undo them.
   */
  acceptRemovedHeads(folderId: FolderId): Promise<HeadsAnswer>;
  openStorageSettings(): Promise<void>;
  /**
   * Forgets the account here after the server reported this device as removed
   * (`removalReported`); the shell asks natively first. "declined" changes nothing.
   */
  confirmDeviceRemoved(): Promise<Confirmation>;
  /** Rejects with "updatesOff" while this build has no updater key (see `About.updates`). */
  installUpdate(): Promise<UpdateOutcome>;
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
  /**
   * Asks natively every time, with the folder and the number of files that disappear on every
   * device; null when the person said no there. The window asks nothing before it.
   */
  resetFolder(folderId: FolderId, entryId: string): Promise<RestoreOutcome | null>;
  cancelRestore(jobId: string): Promise<void>;
  /** The entry for "state before changes from ..." (9.4), null when there is none. */
  findBeforeDevice(folderId: FolderId, deviceId: DeviceId, from: Millis): Promise<string | null>;
  getTrash(folderId: FolderId): Promise<readonly TrashItem[]>;
  restoreTrash(folderId: FolderId, itemIds: readonly string[]): Promise<RestoreOutcome>;

  // Devices (10)
  listDevices(): Promise<DeviceList>;
  /** A name that looks like another device's is taken only after a native question. */
  renameDevice(deviceId: DeviceId, name: string): Promise<Result<null, DeviceNameError>>;
  getSafetyNumber(deviceId: DeviceId): Promise<NumberRows>;
  /** Asks natively with the device's name; the window asks nothing before it. */
  removeDevice(deviceId: DeviceId): Promise<Confirmation>;
  /** Asks natively, with the warning for the account's last device. */
  disconnectThisDevice(): Promise<Confirmation>;
  createPairingOffer(): Promise<PairingOffer>;
  copyPairingLink(offerId: string): Promise<void>;
  /**
   * Accepting asks once more in a native dialog with the device's name and safety number; "no"
   * there declines the request.
   */
  answerPairRequest(offerId: string, accept: boolean): Promise<PairAnswer>;
  /** Starts a new recovery code; the old one stays valid until the group check succeeds. */
  renewRecoveryCode(): Promise<RecoveryCode>;

  // Settings (11)
  getSettings(): Promise<Settings>;
  /** Turning it off asks natively first. */
  setAutostart(on: boolean): Promise<Confirmation>;
  setLanguage(language: Language | "system"): Promise<void>;
  getAbout(): Promise<About>;

  // Tray (6.1, 6.2): the window computes icon, tooltip and menu, the backend draws them.
  updateTray(model: TrayModel): Promise<void>;
  /** Brings the window to the front (tray "open", a notification click). */
  showWindow(): Promise<void>;
  quit(): Promise<void>;
}
