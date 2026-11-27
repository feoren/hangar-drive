// Decoders for every answer of the Rust side, one per type of ../types.ts. The `satisfies`
// checks at the end of each decoder make the compiler compare it with the interface, so the two
// cannot drift apart.

import type {
  About,
  AccountFolder,
  ActivityEntry,
  AcceptedHeads,
  BackendEvent,
  Confirmation,
  ResetOutcome,
  ConflictGroup,
  DeleteOutcome,
  Device,
  DeviceList,
  FolderPlace,
  HeadsAnswer,
  InspectedLink,
  InviteCheck,
  JoinOutcome,
  MassDeleteOutcome,
  NameIssue,
  NotSyncedEntry,
  NumberRows,
  PairAnswer,
  ServerConfirm,
  PairingOffer,
  PairWaiting,
  PickResult,
  RecoveryCheck,
  RecoveryCode,
  RecoverySheet,
  RestoreOutcome,
  SaveResult,
  Settings,
  Snapshot,
  Timeline,
  TrashItem,
  UpdateOutcome,
  VersionTree,
} from "../types";
import { isLanguage, type Language } from "../../i18n";
import {
  array,
  bool,
  DecodeError,
  knownArray,
  literal,
  nothing,
  nullable,
  num,
  object,
  orDefault,
  str,
  union,
  type Decoder,
} from "./decode";

export const numberRows = object({ groups: array(str) }) satisfies Decoder<NumberRows>;

const connection = union("kind", {
  online: {},
  noNetwork: {},
  serverSilent: { since: num },
});

const folderStatus = union("kind", {
  upToDate: {},
  uploading: { count: num },
  downloading: { count: num },
  paused: {},
  stopped: { reason: literal("missing", "olderState", "removedHeads", "treeLimit", "tooLarge") },
});

const fileAction = literal(
  "changed",
  "added",
  "deleted",
  "renamed",
  "fromDevice",
  "restored",
  "twoVersions",
);

const activityEntry = union("kind", {
  file: {
    id: str,
    folderId: str,
    folderName: str,
    name: str,
    path: str,
    action: fileAction,
    device: nullable(str),
    at: num,
  },
  group: { id: str, folderId: str, folderName: str, count: num, at: num },
  remoteDeleted: { id: str, folderId: str, folderName: str, count: num, device: str, at: num },
  cameBack: { id: str, folderId: str, folderName: str, name: str, path: str, device: str, at: num },
}) satisfies Decoder<ActivityEntry>;

const warningVariants = {
  massDelete: { id: str, folderId: str, folderName: str, count: num, sample: array(str) },
  incomingDelete: {
    id: str,
    folderId: str,
    folderName: str,
    device: nullable(str),
    deviceAdded: nullable(num),
    count: num,
    sample: array(str),
  },
  missingFolder: { id: str, folderId: str, folderName: str },
  serverIdentity: { id: str, hasOtherDevice: bool },
  quota: { id: str },
  quotaFull: { id: str },
  serverDisk: { id: str },
  diskFull: { id: str, needed: num },
  olderState: { id: str, folderId: str, folderName: str },
  removedHeads: { id: str, folderId: str, folderName: str, devices: array(str), count: num },
  removed: { id: str, by: str },
  removalReported: { id: str, since: num },
  treeLimit: { id: str, folderId: str, folderName: str },
  updateRequired: { id: str },
  refused: { id: str },
  noRecoveryCode: { id: str },
  recoveryPending: { id: str },
  foldersUnreadable: { id: str, folders: array(str), folderList: bool },
  suspect: {
    id: str,
    deviceId: str,
    deviceName: str,
    folderId: str,
    folderName: str,
    entryId: str,
    days: num,
    until: num,
    lapsed: bool,
  },
  conflicts: { id: str, count: num },
  names: { id: str, count: num },
};

/**
 * Banners and notices of a newer engine than this window knows are left out instead of failing
 * the whole snapshot (an empty window). A known kind with a wrong shape still fails.
 */
const warnings = knownArray("kind", Object.keys(warningVariants), union("kind", warningVariants));

const noticeVariants = {
  quota: {},
  retained: {},
  budgetDevice: { device: str },
  budgetAccount: {},
  serverDisk: {},
  minCount: { days: num },
  olderAccountState: {},
};

const notices = knownArray("kind", Object.keys(noticeVariants), union("kind", noticeVariants));

export const snapshot = object({
  setup: literal("needed", "done"),
  sync: object({
    connection,
    pause: nullable(object({ until: nullable(num) })),
    pendingFiles: num,
    bytesLeft: num,
    lastSync: nullable(num),
    lastFile: nullable(object({ name: str, at: num })),
    waitingMetered: num,
    waitingBudget: num,
  }),
  folders: array(
    object({
      id: str,
      name: str,
      path: str,
      status: folderStatus,
      freezeDays: nullable(num),
      notSyncedCount: num,
      bytes: nullable(num),
    }),
  ),
  activity: array(activityEntry),
  warnings,
  notices,
  storage: nullable(object({ used: num, quota: num })),
  account: nullable(object({ host: str, retentionDays: num, hasOtherDevices: bool })),
  remoteFolders: array(object({ id: str, name: str, size: num })),
  deletedFolders: array(object({ id: str, name: str, daysLeft: num })),
  env: object({ camera: bool }),
}) satisfies Decoder<Snapshot>;

/** `Result<T, E>` as the Rust side sends it: `{ ok: true, value }` or `{ ok: false, error }`. */
export function result<T, E extends string>(
  value: Decoder<T>,
  ...errors: readonly E[]
): Decoder<{ ok: true; value: T } | { ok: false; error: E }> {
  const error = literal(...errors);
  return (input, path) => {
    const tagged = object({ ok: bool })(input, path);
    const record = object({ value: (v) => v, error: (v) => v })(input, path);
    return tagged.ok
      ? { ok: true, value: value(record.value, `${path}.value`) }
      : { ok: false, error: error(record.error, `${path}.error`) };
  };
}

export const inviteCheck = object({ host: str, pinned: bool }) satisfies Decoder<InviteCheck>;

export const inspectedLink = union("kind", {
  invite: { host: str, pinned: bool },
  pair: { host: str, account: str, pinned: bool },
  recover: { host: str, account: str, pinned: bool },
}) satisfies Decoder<InspectedLink>;

const recoverySheet = object({
  serverUrl: str,
  serverId: str,
  accountId: str,
  genesisAnchor: str,
  pin: nullable(str),
  link: str,
}) satisfies Decoder<RecoverySheet>;

export const recoveryCode = object({
  groups: array(str),
  checkGroup: num,
  sheet: recoverySheet,
}) satisfies Decoder<RecoveryCode>;

export const saveResult = union("kind", {
  saved: { path: str },
  cancelled: {},
  inSyncFolder: {},
  inCloudFolder: {},
}) satisfies Decoder<SaveResult>;

export const folderPlace = object({
  path: str,
  name: str,
  token: str,
}) satisfies Decoder<FolderPlace>;

export const pickResult = union("kind", {
  picked: { path: str, name: str, token: str },
  cancelled: {},
  refused: {
    reason: literal("network", "root", "system", "nested", "noAccess", "wrongFolder"),
    folder: nullable(str),
  },
}) satisfies Decoder<PickResult>;

export const pairWaiting = object({
  path: literal("link", "typed"),
  safety: numberRows,
}) satisfies Decoder<PairWaiting>;

export const accountFolders = object({
  folders: array(
    object({
      id: str,
      name: str,
      size: num,
      proposedPath: str,
      proposedToken: str,
    }) satisfies Decoder<AccountFolder>,
  ),
  free: num,
});

export const device = object({
  id: str,
  name: str,
  kind: literal("laptop", "desktop"),
  isThis: bool,
  lastSeen: nullable(num),
  added: num,
}) satisfies Decoder<Device>;

export const deviceList = object({
  devices: array(device),
  recoveryCreated: num,
}) satisfies Decoder<DeviceList>;

export const notSynced = array(
  object({ path: str, reason: literal("link", "system") }) satisfies Decoder<NotSyncedEntry>,
);

export const folderNumber = union("kind", {
  number: { number: numberRows },
  offline: {},
});

export const serverNumber = object({ number: numberRows, command: str });

export const conflictGroups = array(
  object({
    id: str,
    folderId: str,
    folderName: str,
    path: str,
    kind: literal("content", "caseOnly"),
    versions: array(
      object({ id: str, name: str, device: str, modified: num, size: num, original: bool }),
    ),
  }) satisfies Decoder<ConflictGroup>,
);

const nameReason = union("kind", {
  char: { char: str },
  reserved: { name: str },
  trailing: {},
  control: {},
  cannotCreate: {},
});

export const nameIssues = array(
  object({
    id: str,
    folderId: str,
    folderName: str,
    dir: str,
    name: str,
    reason: nameReason,
    device: str,
  }) satisfies Decoder<NameIssue>,
);

export const timeline = object({
  entries: array(
    object({
      id: str,
      at: num,
      device: str,
      changed: num,
      added: num,
      deleted: num,
      reanchored: bool,
    }),
  ),
  expiredCount: num,
  retentionDays: num,
}) satisfies Decoder<Timeline>;

export const versionTree = object({
  nodes: array(
    object({
      path: str,
      name: str,
      depth: num,
      kind: literal("file", "dir"),
      diff: literal("same", "different", "missing", "newer"),
    }),
  ),
  changed: num,
  missing: num,
}) satisfies Decoder<VersionTree>;

export const restoreOutcome = union("kind", {
  done: { count: num, renamedTo: nullable(str), undoToken: nullable(str) },
  waitBudget: { jobId: str },
  noSpace: {},
  expired: {},
  failed: {},
}) satisfies Decoder<RestoreOutcome>;

export const nullableRestoreOutcome = nullable(restoreOutcome);

export const nullableRecoveryCode = nullable(recoveryCode);

export const trash = array(
  object({
    id: str,
    name: str,
    dir: str,
    deletedAt: num,
    device: str,
  }) satisfies Decoder<TrashItem>,
);

export const pairingOffer = object({
  id: str,
  link: str,
  code: array(str),
  host: str,
  account: str,
  qr: object({ size: num, modules: str }),
  qrSvg: str,
  expiresAt: num,
}) satisfies Decoder<PairingOffer>;

const language: Decoder<Language | "system"> = (value, path) => {
  if (value === "system" || isLanguage(value)) return value;
  throw new DecodeError(path, "language");
};

/** `folderView` came later: a shell without it reads as the list. */
export const settings = object({
  autostart: bool,
  language,
  folderView: orDefault(literal("list", "grid"), "list"),
}) satisfies Decoder<Settings>;

/**
 * `updates` is the proposed field of `get_about`. A shell without it reads as "on": the button
 * stays, and the "updates are off" refusal hides it after the first try.
 */
export const about = object({
  version: str,
  build: nullable(num),
  updates: orDefault(bool, true),
}) satisfies Decoder<About>;

export const updateOutcome = union("kind", {
  upToDate: {},
  installed: { version: str },
  declined: {},
}) satisfies Decoder<UpdateOutcome>;

/**
 * How the native question of the three commands ended (commands.rs `DeleteOutcome`,
 * `PairAnswer`, `ServerConfirm`).
 */
export const deleteOutcome: Decoder<DeleteOutcome> = literal("deleted", "kept");
export const pairAnswer: Decoder<PairAnswer> = literal("added", "declined");
export const serverConfirm: Decoder<ServerConfirm> = literal("confirmed", "declined");

/** The native questions of the overall security review (commands.rs `Confirmation` and kin). */
export const confirmation: Decoder<Confirmation> = literal("confirmed", "declined");

export const resetOutcome: Decoder<ResetOutcome> = literal(
  "confirmed",
  "declined",
  "recoveryPending",
);
export const recoveryCheck: Decoder<RecoveryCheck> = literal("confirmed", "wrong", "declined");
export const joinOutcome: Decoder<JoinOutcome> = literal("joined", "declined");
export const massDeleteOutcome = union("kind", {
  resolved: { count: num },
  declined: {},
}) satisfies Decoder<MassDeleteOutcome>;

export const undoToken = object({ undoToken: str });

export const pairError = literal(
  "notALink",
  "expired",
  "typo",
  "declined",
  "tooMany",
  "otherAccount",
  "unreachable",
  "insecure",
);

export const event = union("type", {
  snapshot: { snapshot },
  pairRequest: {
    request: object({
      offerId: str,
      deviceName: str,
      path: literal("link", "typed"),
      safety: numberRows,
      similarTo: nullable(str),
    }),
  },
  pairRequestGone: { offerId: str },
  pairResult: {
    result: union("kind", { joined: {}, failed: { error: pairError } }),
  },
  focusWarning: { warningId: str },
  trayAction: { actionId: str },
  removedHeads: {
    folderId: str,
    heads: array(object({ commit: str, deviceId: str, deviceName: str, sequence: num })),
  },
  openLink: { link: str },
}) satisfies Decoder<BackendEvent>;

export const acceptedHeads = object({
  count: num,
  beforeEntryId: nullable(str),
}) satisfies Decoder<AcceptedHeads>;

export const headsAnswer = union("kind", {
  accepted: { count: num, beforeEntryId: nullable(str) },
  declined: {},
}) satisfies Decoder<HeadsAnswer>;

export const nullableStr = nullable(str);

export const olderCheck = literal("stillOlder", "resolved");

export { array, bool, nothing, num, str };
