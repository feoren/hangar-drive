// Every state of the UX concept as a named scenario of the mock backend, so each one can be
// opened in the dev server (`?scenario=...` or the mock panel) and in tests.

import type {
  Account,
  ConflictGroup,
  DeletedFolder,
  Device,
  Folder,
  Millis,
  NameIssue,
  RemoteFolder,
  RemovedHead,
  ServerNotice,
  Settings,
  Storage,
  SyncSummary,
  Warning,
  ActivityEntry,
} from "../types";
import * as fx from "./fixtures";

type Mutable<T> = { -readonly [K in keyof T]: T[K] };

export interface MockState {
  setup: "needed" | "done";
  sync: Mutable<SyncSummary>;
  folders: Folder[];
  activity: ActivityEntry[];
  warnings: Warning[];
  notices: ServerNotice[];
  storage: Storage | null;
  account: Account | null;
  remoteFolders: RemoteFolder[];
  deletedFolders: DeletedFolder[];
  camera: boolean;
  devices: Device[];
  recoveryCreated: Millis;
  conflicts: ConflictGroup[];
  nameIssues: NameIssue[];
  settings: Settings;
  /** A link the OS hands over at start (`openLink`), held until the window listens. */
  startLink: string | null;
  /** Saved states of removed devices that stopped a folder, sent as the `removedHeads` event. */
  removedHeads: { readonly folderId: string; readonly heads: readonly RemovedHead[] } | null;
  /** Whether this build can update itself (`About.updates`); false without an updater key. */
  updates: boolean;
}

/** Links the deep link scenarios start with. */
export const START_LINKS = {
  invite: "hangar-drive://join#k7Qm2xR9@https://drive.example.org/",
  pair: "hangar-drive://pair#Z4mK8q",
  recover: "hangar-drive://recover#AQ3f9a12c0sheet",
} as const;

export const SCENARIOS = [
  { id: "upToDate", label: "Up to date" },
  { id: "setup", label: "First start (setup)" },
  { id: "empty", label: "No folder yet" },
  { id: "syncing", label: "Syncing 120 files" },
  { id: "paused", label: "Paused until tomorrow" },
  { id: "offline", label: "Offline (no network)" },
  { id: "serverSilent", label: "Server silent (5 min)" },
  { id: "serverLong", label: "Server silent for a day" },
  { id: "metered", label: "Metered network" },
  { id: "budget", label: "Upload budget reached" },
  { id: "storage", label: "Storage above 80 % and notices" },
  { id: "conflicts", label: "Two versions" },
  { id: "names", label: "Names Windows refuses" },
  { id: "freeze", label: "No news from other devices" },
  { id: "massDelete", label: "342 files deleted" },
  { id: "missingFolder", label: "Folder missing" },
  { id: "serverIdentity", label: "Server identity changed" },
  { id: "serverIdentityAlone", label: "Server identity, no other device" },
  { id: "quota", label: "Server quota full" },
  { id: "quotaFull", label: "Quota and headroom full" },
  { id: "serverDisk", label: "Server disk full" },
  { id: "diskFull", label: "Disk full here" },
  { id: "olderState", label: "Server shows older state" },
  { id: "removed", label: "This device was removed" },
  { id: "removedUnknown", label: "Removed, by an unknown device" },
  { id: "removalReported", label: "Server reports a removal" },
  { id: "treeLimit", label: "Server version too large" },
  { id: "updateRequired", label: "Update required" },
  { id: "updateOff", label: "Update required, updates off" },
  { id: "refused", label: "Server refuses this device" },
  { id: "suspect", label: "Suspected ransomware" },
  { id: "suspectElsewhere", label: "Suspected ransomware, folder not here" },
  { id: "removedHeads", label: "Changes from a removed device" },
  { id: "removedHeadsMany", label: "Changes from two removed devices" },
  { id: "deepLinkInvite", label: "Setup opened by an invite link" },
  { id: "deepLinkPair", label: "Setup opened by a pairing link" },
  { id: "deepLinkRecover", label: "Setup opened by a recovery link" },
  { id: "deepLinkDone", label: "Link opened on a set-up device" },
  { id: "many", label: "Several problems at once" },
] as const;

export type ScenarioId = (typeof SCENARIOS)[number]["id"];

export function isScenarioId(value: string | null): value is ScenarioId {
  return SCENARIOS.some((scenario) => scenario.id === value);
}

function baseSync(now: Millis): Mutable<SyncSummary> {
  return {
    connection: { kind: "online" },
    pause: null,
    pendingFiles: 0,
    bytesLeft: 0,
    lastSync: now - 2 * fx.MINUTE,
    lastFile: { name: "Bericht.docx", at: now - 2 * fx.MINUTE },
    waitingMetered: 0,
    waitingBudget: 0,
  };
}

export function baseState(now: Millis): MockState {
  return {
    setup: "done",
    sync: baseSync(now),
    folders: fx.folders(),
    activity: fx.activity(now),
    warnings: [],
    notices: [],
    storage: { used: 41_200_000_000, quota: 100_000_000_000 },
    account: { host: fx.HOST, retentionDays: 30, hasOtherDevices: true },
    remoteFolders: [{ id: "f-music", name: "Musik", size: 18_300_000_000 }],
    deletedFolders: [{ id: "f-old", name: "Altes Projekt", daysLeft: 12 }],
    camera: false,
    devices: fx.devices(now),
    recoveryCreated: now - 30 * fx.DAY,
    conflicts: fx.conflicts(now),
    nameIssues: fx.nameIssues(),
    settings: { autostart: true, language: "system" },
    startLink: null,
    removedHeads: null,
    updates: true,
  };
}

function setupState(state: MockState): void {
  state.setup = "needed";
  state.folders = [];
  state.activity = [];
  state.account = null;
  state.storage = null;
  state.sync.lastSync = null;
  state.sync.lastFile = null;
}

/** Changes of removed devices stopped "Fotos"; the removed devices are gone from the list. */
function removedHeadsState(state: MockState, devices: readonly string[]): void {
  state.devices = state.devices.filter((device) => device.name !== fx.REMOVED_DEVICE);
  state.warnings = [
    {
      kind: "removedHeads",
      id: "w-heads",
      folderId: "f-photos",
      folderName: "Fotos",
      devices,
      count: devices.length + 1,
    },
  ];
  setFolderStatus(state, "f-photos", { kind: "stopped", reason: "removedHeads" });
  state.removedHeads = {
    folderId: "f-photos",
    heads: devices.map((name, index) => ({
      commit: index === 0 ? "t2" : "t4",
      deviceId: `d-removed-${String(index)}`,
      deviceName: name,
      sequence: 40 - index,
    })),
  };
}

const warn = {
  massDelete: (): Warning => ({
    kind: "massDelete",
    id: "w-delete",
    folderId: "f-photos",
    folderName: "Fotos",
    count: 342,
    sample: ["Urlaub 001.jpg", "Urlaub 002.jpg", "Urlaub 003.jpg"],
  }),
  missing: (): Warning => ({
    kind: "missingFolder",
    id: "w-missing",
    folderId: "f-photos",
    folderName: "Fotos",
  }),
  older: (): Warning => ({
    kind: "olderState",
    id: "w-older",
    folderId: "f-main",
    folderName: "Hangar Drive",
  }),
  suspect: (now: Millis): Extract<Warning, { kind: "suspect" }> => ({
    kind: "suspect",
    id: "w-suspect",
    deviceId: "d-office",
    deviceName: fx.OTHER_DEVICE,
    folderId: "f-main",
    folderName: "Hangar Drive",
    entryId: "t4",
    days: 30,
    until: now + 90 * fx.DAY,
    lapsed: false,
  }),
};

function setFolderStatus(state: MockState, folderId: string, status: Folder["status"]): void {
  state.folders = state.folders.map((folder) =>
    folder.id === folderId ? { ...folder, status } : folder,
  );
}

/** The state of a scenario. Conflicts and name issues exist in the data of every scenario, but
 *  their banners appear only in the scenarios that are about them. */
export function scenarioState(id: ScenarioId, now: Millis): MockState {
  const state = baseState(now);
  const conflictsBanner: Warning = {
    kind: "conflicts",
    id: "w-conflicts",
    count: state.conflicts.length,
  };
  const namesBanner: Warning = { kind: "names", id: "w-names", count: state.nameIssues.length };
  switch (id) {
    case "upToDate":
      break;
    case "setup":
      setupState(state);
      break;
    case "empty":
      state.folders = [];
      state.activity = [];
      state.sync.lastFile = null;
      break;
    case "syncing":
      state.sync.pendingFiles = 120;
      state.sync.bytesLeft = 840_000_000;
      setFolderStatus(state, "f-photos", { kind: "uploading", count: 117 });
      setFolderStatus(state, "f-main", { kind: "downloading", count: 3 });
      break;
    case "paused": {
      const tomorrow = new Date(now);
      tomorrow.setDate(tomorrow.getDate() + 1);
      tomorrow.setHours(6, 0, 0, 0);
      state.sync.pause = { until: tomorrow.getTime() };
      state.folders = state.folders.map((folder) => ({ ...folder, status: { kind: "paused" } }));
      break;
    }
    case "offline":
      state.sync.connection = { kind: "noNetwork" };
      break;
    case "serverSilent":
      state.sync.connection = { kind: "serverSilent", since: now - 5 * fx.MINUTE };
      break;
    case "serverLong":
      state.sync.connection = { kind: "serverSilent", since: now - 26 * fx.HOUR };
      break;
    case "metered":
      state.sync.waitingMetered = 3;
      break;
    case "budget":
      state.sync.waitingBudget = 48;
      break;
    case "storage":
      state.storage = { used: 86_400_000_000, quota: 100_000_000_000 };
      state.notices = [
        { kind: "quota" },
        { kind: "retained" },
        { kind: "budgetDevice", device: fx.OTHER_DEVICE },
        { kind: "budgetAccount" },
        { kind: "serverDisk" },
        { kind: "minCount", days: 14 },
      ];
      break;
    case "conflicts":
      state.warnings = [conflictsBanner];
      break;
    case "names":
      state.warnings = [namesBanner];
      break;
    case "freeze":
      state.folders = state.folders.map((folder, index) =>
        index === 0 ? { ...folder, freezeDays: 14, notSyncedCount: 3 } : folder,
      );
      break;
    case "massDelete":
      state.warnings = [warn.massDelete()];
      break;
    case "missingFolder":
      state.warnings = [warn.missing()];
      setFolderStatus(state, "f-photos", { kind: "stopped", reason: "missing" });
      break;
    case "serverIdentity":
      state.warnings = [{ kind: "serverIdentity", id: "w-identity", hasOtherDevice: true }];
      break;
    case "serverIdentityAlone":
      state.warnings = [{ kind: "serverIdentity", id: "w-identity", hasOtherDevice: false }];
      state.account = { host: fx.HOST, retentionDays: 30, hasOtherDevices: false };
      break;
    case "quota":
      state.warnings = [{ kind: "quota", id: "w-quota" }];
      state.storage = { used: 100_000_000_000, quota: 100_000_000_000 };
      break;
    case "quotaFull":
      state.warnings = [{ kind: "quotaFull", id: "w-quota-full" }];
      state.storage = { used: 100_000_000_000, quota: 100_000_000_000 };
      break;
    case "serverDisk":
      state.warnings = [{ kind: "serverDisk", id: "w-server-disk" }];
      break;
    case "diskFull":
      state.warnings = [{ kind: "diskFull", id: "w-disk", needed: 2_400_000_000 }];
      break;
    case "olderState":
      state.warnings = [warn.older()];
      setFolderStatus(state, "f-main", { kind: "stopped", reason: "olderState" });
      break;
    case "removed":
      state.warnings = [{ kind: "removed", id: "w-removed", by: fx.OTHER_DEVICE }];
      break;
    case "removedUnknown":
      // The server answered `deviceRemoved` at sign-in; who removed it is not known.
      state.warnings = [{ kind: "removed", id: "w-removed", by: "" }];
      break;
    case "removalReported":
      // The server answered this device's sign-in with "removed" (security review H2).
      state.warnings = [{ kind: "removalReported", id: "w-removal", since: now - 2 * fx.HOUR }];
      break;
    case "treeLimit":
      // The server's newest version of a folder is too large to be one (security review M3).
      state.warnings = [
        { kind: "treeLimit", id: "w-tree", folderId: "f-main", folderName: "Hangar Drive" },
      ];
      setFolderStatus(state, "f-main", { kind: "stopped", reason: "treeLimit" });
      state.notices = [{ kind: "olderAccountState" }];
      break;
    case "updateRequired":
      state.warnings = [{ kind: "updateRequired", id: "w-update" }];
      break;
    case "updateOff":
      state.warnings = [{ kind: "updateRequired", id: "w-update" }];
      state.updates = false;
      break;
    case "refused":
      state.warnings = [{ kind: "refused", id: "w-refused" }];
      break;
    case "suspect":
      state.warnings = [warn.suspect(now)];
      break;
    case "suspectElsewhere":
      // A folder not synced here, its pin lapsed under the pin cap: the device is unknown.
      state.warnings = [
        {
          ...warn.suspect(now),
          deviceId: "",
          deviceName: "",
          folderId: "f-elsewhere",
          folderName: "Fotos",
          lapsed: true,
        },
      ];
      break;
    case "removedHeads":
      removedHeadsState(state, [fx.REMOVED_DEVICE]);
      break;
    case "removedHeadsMany":
      removedHeadsState(state, [fx.REMOVED_DEVICE, ""]);
      break;
    case "deepLinkInvite":
      setupState(state);
      state.startLink = START_LINKS.invite;
      break;
    case "deepLinkPair":
      setupState(state);
      state.startLink = START_LINKS.pair;
      break;
    case "deepLinkRecover":
      setupState(state);
      state.startLink = START_LINKS.recover;
      break;
    case "deepLinkDone":
      state.startLink = START_LINKS.invite;
      break;
    case "many":
      state.warnings = [conflictsBanner, warn.missing(), warn.massDelete(), namesBanner];
      setFolderStatus(state, "f-photos", { kind: "stopped", reason: "missing" });
      break;
  }
  return state;
}
