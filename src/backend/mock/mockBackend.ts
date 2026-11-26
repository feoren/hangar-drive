// In-memory backend for the dev server and the tests. It plays every state of the UX concept:
// the scenarios (scenarios.ts) set the overall state, `controls` decide the outcome of the next
// action (a refused folder, a restore that waits, a pairing that fails), and a few magic inputs
// produce the error texts of the setup flows (listed in MOCK_INPUTS).

import { normalizeCode } from "../../domain/codes";
import { linkKind } from "../../domain/links";
import { strictNameProblem } from "../../domain/names";
import { windowsNameProblem } from "../../domain/windowsNames";
import type { Language } from "../../i18n";
import { pauseUntil, type TrayModel } from "../../tray/trayModel";
import { BackendError, type BackendErrorCode } from "../errors";
import type {
  About,
  AcceptedHeads,
  AccountFolder,
  ActivityEntry,
  Backend,
  BackendEvent,
  ConflictGroup,
  DeleteOutcome,
  Device,
  DeviceId,
  DeviceList,
  FolderChoice,
  FolderId,
  FolderPlace,
  FolderRefusal,
  InspectedLink,
  InviteCheck,
  InviteError,
  LinkError,
  Millis,
  NameError,
  NameIssue,
  NotSyncedEntry,
  NumberRows,
  PairAnswer,
  ServerConfirm,
  PairError,
  PairInput,
  PairWaiting,
  PairingOffer,
  PauseDuration,
  PickPurpose,
  PickResult,
  RecoverError,
  RecoveryCode,
  RecoverySheetDocument,
  RenameError,
  RestoreOutcome,
  Result,
  SaveResult,
  Settings,
  Snapshot,
  Timeline,
  TrashItem,
  Unsubscribe,
  UpdateOutcome,
  VersionTree,
} from "../types";
import * as fx from "./fixtures";
import {
  baseState,
  scenarioState,
  START_LINKS,
  type MockState,
  type ScenarioId,
} from "./scenarios";

/** Inputs that make the setup flows fail, for trying every error text by hand. */
export const MOCK_INPUTS = {
  invite: "https://drive.example.org/join#k7Qm2xR9",
  /** Token, server ID and pin: a server without a public certificate (N3). */
  invitePinned: "https://drive.example.org/join#k7Qm2xR9.9c41d07e.Zp3Q",
  inviteDeep: START_LINKS.invite,
  inviteErrors: "…#used, …#expired, …#offline, http://…, anything without #",
  pair: START_LINKS.pair,
  pairPinned: "hangar-drive://pair#pin",
  /** A host with a letter outside ASCII, shown in punycode. */
  pairIdn: "hangar-drive://pair#idn",
  /** Joins an account with devices the person does not know. */
  pairStranger: "hangar-drive://pair#stranger",
  pairErrors: "…#expired, …#declined, …#toomany, …#other, …#offline, …#damaged",
  recoverLink: START_LINKS.recover,
  recoverLinkErrors: "…#damaged, …#offline, …#insecure",
  recovery: "any 32 characters; starting with H: other app, 0000…: unknown, 1111…: used",
} as const;

/** The host of the "idn" pairing link before the window sees it in punycode. */
const IDN_HOST = "drïve.example.org";

export interface MockControls {
  /** Outcome of the next folder picker. */
  pick: "ok" | "existing" | Exclude<FolderRefusal, "wrongFolder"> | "wrongFolder" | "cancel";
  /** Outcome of the next restore. */
  restore: "done" | "renamed" | "waitBudget" | "noSpace" | "expired" | "failed";
  save: "saved" | "inSync" | "inCloud" | "cancel";
  /**
   * The person's answer to the native confirmation of the shell (security review L2), asked
   * before a folder is deleted everywhere, before a device is added and before a new server key
   * is trusted.
   */
  nativeConfirm: "yes" | "no";
  /** What "Update now" finds; "off" is a build without an updater key (`About.updates`). */
  update: "upToDate" | "installed" | "off";
  /** How a new device answers the next pairing offer of this device. */
  pairAnswer: "link" | "typed" | "none";
  folderNumber: "number" | "offline";
  olderCheck: "stillOlder" | "resolved";
  clipboard: string;
  /** Files already at a place an account folder comes to (merge question, UX 6.5). */
  localFiles: number;
  /** The next call of any method fails with this code. */
  failNext: BackendErrorCode | null;
}

export interface MockOptions {
  scenario?: ScenarioId;
  /** Delay of every call in ms, so loading states are visible in the dev server. */
  latency?: number;
  /** Factor for the simulated waits (pairing, sync progress); 0 runs them at once. */
  timeScale?: number;
  /** Simulate sync progress over time. */
  animate?: boolean;
  now?: () => Millis;
  random?: () => number;
}

const DEFAULT_CONTROLS: MockControls = {
  pick: "ok",
  restore: "done",
  save: "saved",
  nativeConfirm: "yes",
  update: "installed",
  pairAnswer: "link",
  folderNumber: "number",
  olderCheck: "stillOlder",
  clipboard: MOCK_INPUTS.invite,
  localFiles: 0,
  failNext: null,
};

export class MockBackend implements Backend {
  readonly kind = "mock";
  readonly controls: MockControls = { ...DEFAULT_CONTROLS };
  /** Calls in order, for tests. */
  readonly calls: string[] = [];
  /** The last tray model the window sent. */
  tray: TrayModel | null = null;
  /** The last recovery sheet the window printed or saved. */
  sheet: RecoverySheetDocument | null = null;

  private state: MockState;
  private scenario: ScenarioId;
  private readonly listeners = new Set<(event: BackendEvent) => void>();
  private readonly latency: number;
  private readonly timeScale: number;
  private readonly animate: boolean;
  private readonly now: () => Millis;
  private readonly random: () => number;
  private timers = new Set<ReturnType<typeof setTimeout>>();
  private ticker: ReturnType<typeof setInterval> | null = null;
  private recovery: RecoveryCode | null = null;
  private offer: PairingOffer | null = null;
  private undoTokens = new Map<string, () => void>();
  /** Places handed out with a token, as the shell keeps them (security review L2). */
  private places = new Map<string, { path: string; name: string }>();
  private hiddenTrash = new Set<string>();
  private counter = 0;
  /** Events sent before the window listened, delivered when it subscribes (like the shell). */
  private held: BackendEvent[] = [];

  constructor(options: MockOptions = {}) {
    this.latency = options.latency ?? 0;
    this.timeScale = options.timeScale ?? 0;
    this.animate = options.animate ?? false;
    this.now = options.now ?? Date.now;
    this.random = options.random ?? Math.random;
    this.scenario = options.scenario ?? "upToDate";
    this.state = scenarioState(this.scenario, this.now());
    this.startTicker();
    this.announceScenario();
  }

  // -------------------------------------------------------------------------------------------
  // Mock controls

  get currentScenario(): ScenarioId {
    return this.scenario;
  }

  setScenario(id: ScenarioId): void {
    this.scenario = id;
    this.state = scenarioState(id, this.now());
    this.recovery = null;
    this.offer = null;
    this.places.clear();
    this.emitSnapshot();
    this.announceScenario();
  }

  /** The events a scenario starts with: a link the OS handed over, a folder that stopped. */
  private announceScenario(): void {
    const { startLink, removedHeads } = this.state;
    if (startLink) this.emit({ type: "openLink", link: startLink });
    if (removedHeads) this.emit({ type: "removedHeads", ...removedHeads });
  }

  /** Simulates the OS handing over a `hangar-drive://` link. */
  openLink(link: string): void {
    this.emit({ type: "openLink", link });
  }

  setCamera(on: boolean): void {
    this.state.camera = on;
    this.emitSnapshot();
  }

  /** Simulates the click on an OS notification. */
  clickNotification(warningId: string): void {
    this.emit({ type: "focusWarning", warningId });
  }

  /** Simulates a click in the native tray menu. */
  clickTray(actionId: string): void {
    this.emit({ type: "trayAction", actionId });
  }

  /** Simulates a new device that answers the open pairing offer. */
  answerOffer(path: "link" | "typed"): void {
    if (!this.offer) return;
    this.emit({
      type: "pairRequest",
      request: { offerId: this.offer.id, deviceName: "MacBook", path, safety: fx.numberRows(7) },
    });
  }

  dispose(): void {
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
    if (this.ticker) clearInterval(this.ticker);
    this.ticker = null;
    this.listeners.clear();
  }

  // -------------------------------------------------------------------------------------------
  // Plumbing

  private async call(name: string): Promise<void> {
    this.calls.push(name);
    if (this.latency > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.latency));
    } else {
      await Promise.resolve();
    }
    const fail = this.controls.failNext;
    if (fail) {
      this.controls.failNext = null;
      throw new BackendError(fail, name);
    }
  }

  private later(ms: number, run: () => void): void {
    const timer = setTimeout(() => {
      this.timers.delete(timer);
      run();
    }, ms * this.timeScale);
    this.timers.add(timer);
  }

  private emit(event: BackendEvent): void {
    if (this.listeners.size === 0) {
      if (event.type === "openLink" || event.type === "removedHeads") this.held.push(event);
      return;
    }
    for (const listener of this.listeners) listener(event);
  }

  private snapshot(): Snapshot {
    const s = this.state;
    return {
      setup: s.setup,
      sync: { ...s.sync },
      folders: [...s.folders],
      activity: [...s.activity],
      warnings: [...s.warnings],
      notices: [...s.notices],
      storage: s.storage,
      account: s.account,
      remoteFolders: [...s.remoteFolders],
      deletedFolders: [...s.deletedFolders],
      env: { camera: s.camera },
    };
  }

  private emitSnapshot(): void {
    this.emit({ type: "snapshot", snapshot: this.snapshot() });
  }

  private startTicker(): void {
    if (!this.animate) return;
    this.ticker = setInterval(() => {
      const sync = this.state.sync;
      if (sync.pendingFiles === 0 || sync.pause || sync.connection.kind !== "online") return;
      const step = Math.min(sync.pendingFiles, 7);
      sync.pendingFiles -= step;
      sync.bytesLeft = Math.max(0, sync.bytesLeft - step * 7_000_000);
      this.state.folders = this.state.folders.map((folder) => {
        const status = folder.status;
        if (status.kind !== "uploading" && status.kind !== "downloading") return folder;
        const count = Math.max(0, status.count - step);
        return { ...folder, status: count === 0 ? { kind: "upToDate" } : { ...status, count } };
      });
      if (sync.pendingFiles === 0) {
        sync.lastSync = this.now();
        sync.lastFile = { name: "Urlaub 120.jpg", at: this.now() };
      }
      this.emitSnapshot();
    }, 1000);
  }

  private id(prefix: string): string {
    this.counter += 1;
    return `${prefix}-${String(this.counter)}`;
  }

  private removeWarning(id: string): void {
    this.state.warnings = this.state.warnings.filter((warning) => warning.id !== id);
  }

  private setStatus(folderId: FolderId, status: MockState["folders"][number]["status"]): void {
    this.state.folders = this.state.folders.map((folder) =>
      folder.id === folderId ? { ...folder, status } : folder,
    );
  }

  private folderName(folderId: FolderId): string {
    return this.state.folders.find((folder) => folder.id === folderId)?.name ?? folderId;
  }

  /** Hands out a place under a fresh token. */
  private place(path: string, name: string): FolderPlace {
    const token = this.id("place");
    this.places.set(token, { path, name });
    return { path, name, token };
  }

  /** The place a token names; an unknown token is refused like the shell does. */
  private placeOf(token: string, command: string): { path: string; name: string } {
    const found = this.places.get(token);
    if (!found) throw new BackendError("unexpected", command, "unknown place token");
    return found;
  }

  private undoable(revert: () => void): string {
    const token = this.id("undo");
    this.undoTokens.set(token, revert);
    return token;
  }

  private syncConflictBanner(): void {
    const count = this.state.conflicts.length;
    const others = this.state.warnings.filter((warning) => warning.kind !== "conflicts");
    const had = this.state.warnings.some((warning) => warning.kind === "conflicts");
    this.state.warnings =
      had && count > 0 ? [...others, { kind: "conflicts", id: "w-conflicts", count }] : others;
  }

  private syncNamesBanner(): void {
    const count = this.state.nameIssues.length;
    const others = this.state.warnings.filter((warning) => warning.kind !== "names");
    const had = this.state.warnings.some((warning) => warning.kind === "names");
    this.state.warnings =
      had && count > 0 ? [...others, { kind: "names", id: "w-names", count }] : others;
  }

  // -------------------------------------------------------------------------------------------
  // Backend

  async getSnapshot(): Promise<Snapshot> {
    await this.call("getSnapshot");
    return this.snapshot();
  }

  subscribe(listener: (event: BackendEvent) => void): Unsubscribe {
    this.listeners.add(listener);
    const held = this.held;
    this.held = [];
    if (held.length > 0) {
      void Promise.resolve().then(() => {
        for (const event of held) listener(event);
      });
    }
    return () => {
      this.listeners.delete(listener);
    };
  }

  async readClipboardText(): Promise<string> {
    await this.call("readClipboardText");
    return readableClipboard(this.controls.clipboard);
  }

  async checkInvite(link: string): Promise<Result<InviteCheck, InviteError>> {
    await this.call("checkInvite");
    return parseInvite(link);
  }

  async inspectLink(link: string): Promise<Result<InspectedLink, LinkError>> {
    await this.call("inspectLink");
    // Like the engine's parsers: a link with white space is not a link (the window cleans it).
    if (hasSpace(link)) return { ok: false, error: "notALink" };
    const kind = linkKind(link);
    if (kind === null) return { ok: false, error: "notALink" };
    if (kind === "invite") {
      const invite = parseInvite(link);
      if (invite.ok) return { ok: true, value: { kind, ...invite.value } };
      return { ok: false, error: invite.error === "insecure" ? "insecure" : "damaged" };
    }
    const fragment = (link.split("#")[1] ?? "").toLowerCase();
    if (fragment === "damaged") return { ok: false, error: "damaged" };
    if (fragment === "insecure") return { ok: false, error: "insecure" };
    return {
      ok: true,
      value: {
        kind,
        host: fragment === "idn" ? new URL(`https://${IDN_HOST}/`).hostname : fx.HOST,
        account: fragment === "stranger" ? fx.STRANGER_ACCOUNT : fx.ACCOUNT,
        pinned: fragment === "pin",
      },
    };
  }

  async defaultDeviceName(): Promise<string> {
    await this.call("defaultDeviceName");
    return fx.THIS_DEVICE;
  }

  async beginAccount(
    link: string,
    deviceName: string,
  ): Promise<Result<RecoveryCode, InviteError | NameError>> {
    await this.call("beginAccount");
    const invite = parseInvite(link);
    if (!invite.ok) return invite;
    const nameError = strictNameProblem(deviceName);
    if (nameError) return { ok: false, error: nameError };
    this.recovery = this.newRecoveryCode();
    return { ok: true, value: this.recovery };
  }

  private newRecoveryCode(): RecoveryCode {
    return {
      groups: fx.recoveryCode(this.random),
      checkGroup: 2 + Math.floor(this.random() * 7),
      sheet: {
        serverUrl: `https://${fx.HOST}/`,
        serverId: fx.SERVER_ID,
        accountId: fx.ACCOUNT,
        genesisAnchor: fx.GENESIS,
        pin: null,
        link: START_LINKS.recover,
      },
    };
  }

  async printRecoverySheet(document: RecoverySheetDocument): Promise<void> {
    await this.call("printRecoverySheet");
    this.sheet = document;
  }

  async saveRecoveryFile(document: RecoverySheetDocument): Promise<SaveResult> {
    await this.call("saveRecoveryFile");
    this.sheet = document;
    return this.saveResult(`${fx.HOME}\\Documents\\${document.fileName}`);
  }

  private saveResult(path: string): SaveResult {
    switch (this.controls.save) {
      case "saved":
        return { kind: "saved", path };
      case "inSync":
        return { kind: "inSyncFolder" };
      case "inCloud":
        return { kind: "inCloudFolder" };
      case "cancel":
        return { kind: "cancelled" };
    }
  }

  async copyRecoveryCode(): Promise<void> {
    await this.call("copyRecoveryCode");
  }

  async confirmRecoveryGroup(group: string): Promise<boolean> {
    await this.call("confirmRecoveryGroup");
    const code = this.recovery;
    if (!code) return false;
    const expected = code.groups[code.checkGroup - 1];
    if (normalizeCode(group) !== expected) return false;
    this.state.recoveryCreated = this.now();
    return true;
  }

  async defaultFolderPlace(): Promise<FolderPlace> {
    await this.call("defaultFolderPlace");
    return this.place(`${fx.HOME}\\Hangar Drive`, "Hangar Drive");
  }

  async pickFolder(purpose: PickPurpose): Promise<PickResult> {
    await this.call("pickFolder");
    return this.pick(purpose);
  }

  private pick(purpose: PickPurpose): PickResult {
    const choice = this.controls.pick;
    switch (choice) {
      case "cancel":
        return { kind: "cancelled" };
      case "ok":
        return purpose.kind === "new"
          ? { kind: "picked", ...this.place(`${fx.HOME}\\Projekte 2027`, "Projekte 2027") }
          : { kind: "picked", ...this.place(`${fx.HOME}\\Neu`, "Neu") };
      case "existing":
        return { kind: "picked", ...this.place(`${fx.HOME}\\Bilder`, "Bilder") };
      default:
        return {
          kind: "refused",
          reason: choice,
          folder: choice === "nested" ? "Hangar Drive" : null,
        };
    }
  }

  async countLocalFiles(token: string): Promise<number> {
    await this.call("countLocalFiles");
    const { path } = this.placeOf(token, "countLocalFiles");
    if (this.timeScale > 0)
      await new Promise((resolve) => setTimeout(resolve, 900 * this.timeScale));
    if (path.endsWith("\\Bilder")) return 214;
    return this.controls.localFiles;
  }

  async finishSetup(token: string): Promise<void> {
    await this.call("finishSetup");
    const { path, name } = this.placeOf(token, "finishSetup");
    this.places.delete(token);
    const fresh = baseState(this.now());
    this.state = {
      ...fresh,
      folders: [
        {
          id: "f-main",
          name,
          path,
          status: { kind: "upToDate" },
          freezeDays: null,
          notSyncedCount: 0,
        },
      ],
      activity: [],
      remoteFolders: [],
      deletedFolders: [],
      conflicts: [],
      nameIssues: [],
      storage: { used: 0, quota: 100_000_000_000 },
      account: { host: fx.HOST, retentionDays: 30, hasOtherDevices: false },
      devices: [fx.devices(this.now())[0]].filter(
        (device): device is Device => device !== undefined,
      ),
    };
    this.state.sync.lastFile = null;
    this.emitSnapshot();
  }

  async scanWithCamera(): Promise<string | null> {
    await this.call("scanWithCamera");
    return this.state.camera ? MOCK_INPUTS.pair : null;
  }

  async startPairing(
    input: PairInput,
    deviceName: string,
  ): Promise<Result<PairWaiting, PairError | NameError>> {
    await this.call("startPairing");
    const parsed =
      input.kind === "link" ? parsePairLink(input.link) : parseTyped(input.server, input.code);
    if (!parsed.ok) return parsed;
    const nameError = strictNameProblem(deviceName);
    if (nameError) return { ok: false, error: nameError };
    const outcome = parsed.value;
    // The account this device joins decides which devices it sees right after (N2).
    const stranger = input.kind === "link" && input.link.toLowerCase().endsWith("#stranger");
    this.state.devices = stranger ? fx.strangerDevices(this.now()) : fx.devices(this.now());
    this.later(2500, () => {
      this.emit({
        type: "pairResult",
        result: outcome === "ok" ? { kind: "joined" } : { kind: "failed", error: outcome },
      });
    });
    return { ok: true, value: { path: input.kind, safety: fx.numberRows(7) } };
  }

  async cancelPairing(): Promise<void> {
    await this.call("cancelPairing");
    for (const timer of this.timers) clearTimeout(timer);
    this.timers.clear();
  }

  async listAccountFolders(): Promise<{ folders: AccountFolder[]; free: number }> {
    await this.call("listAccountFolders");
    const proposal = (id: string, name: string, size: number): AccountFolder => {
      const place = this.place(`${fx.HOME}\\${name}`, name);
      return { id, name, size, proposedPath: place.path, proposedToken: place.token };
    };
    // The account's folders, and any other folder the other devices have (scenarios add some).
    const known = [
      { id: "f-main", name: "Hangar Drive", size: 12_400_000_000 },
      { id: "f-photos", name: "Fotos", size: 48_000_000_000 },
      { id: "f-music", name: "Musik", size: 18_300_000_000 },
    ];
    const more = this.state.remoteFolders.filter(
      (folder) => !known.some((item) => item.id === folder.id),
    );
    const folders = [...known, ...more].map((folder) =>
      proposal(folder.id, folder.name, folder.size),
    );
    return { folders, free: 120_000_000_000 };
  }

  async joinFolders(choices: readonly FolderChoice[]): Promise<void> {
    await this.call("joinFolders");
    const now = this.now();
    const all = await this.listAccountFoldersQuiet();
    this.state = {
      ...baseState(now),
      folders: choices.map((choice) => ({
        id: choice.folderId,
        name: all.find((folder) => folder.id === choice.folderId)?.name ?? choice.folderId,
        path: this.placeOf(choice.token, "joinFolders").path,
        status: { kind: "downloading", count: 240 },
        freezeDays: null,
        notSyncedCount: 0,
      })),
      activity: [],
      conflicts: [],
      nameIssues: [],
    };
    this.state.sync.pendingFiles = 240;
    this.state.sync.bytesLeft = 9_800_000_000;
    this.emitSnapshot();
  }

  private listAccountFoldersQuiet(): Promise<{ id: string; name: string }[]> {
    return Promise.resolve([
      { id: "f-main", name: "Hangar Drive" },
      { id: "f-photos", name: "Fotos" },
      { id: "f-music", name: "Musik" },
    ]);
  }

  async recoverAccount(
    sheet: string,
    code: string,
    deviceName: string,
  ): Promise<Result<null, RecoverError | NameError>> {
    await this.call("recoverAccount");
    const link = sheet;
    if (hasSpace(link) || linkKind(link) !== "recover") return { ok: false, error: "unknown" };
    const fragment = (link.split("#")[1] ?? "").toLowerCase();
    if (fragment === "insecure") return { ok: false, error: "insecure" };
    if (fragment === "offline") return { ok: false, error: "unreachable" };
    if (fragment === "damaged") return { ok: false, error: "unknown" };
    const nameError = strictNameProblem(deviceName);
    if (nameError) return { ok: false, error: nameError };
    const clean = normalizeCode(code);
    if (clean.startsWith("H") && clean.length === 32) return { ok: false, error: "otherApp" };
    if (!/^[0-9A-HJKMNP-TV-Z]{32}$/.test(clean)) return { ok: false, error: "typo" };
    if (clean.startsWith("0000")) return { ok: false, error: "unknown" };
    if (clean.startsWith("1111")) return { ok: false, error: "used" };
    return { ok: true, value: null };
  }

  async setDeviceName(name: string): Promise<Result<null, NameError>> {
    await this.call("setDeviceName");
    const nameError = strictNameProblem(name);
    return nameError ? { ok: false, error: nameError } : { ok: true, value: null };
  }

  async recoveryDevices(): Promise<readonly Device[]> {
    await this.call("recoveryDevices");
    return fx.devices(this.now()).map((device) => ({ ...device, isThis: false }));
  }

  async finishRecoveryCleanup(remove: readonly DeviceId[]): Promise<RecoveryCode> {
    await this.call(`finishRecoveryCleanup:${String(remove.length)}`);
    this.recovery = this.newRecoveryCode();
    return this.recovery;
  }

  // Everyday

  async openFolder(folderId: FolderId | null, path?: string): Promise<void> {
    await this.call(`openFolder:${folderId ?? "default"}${path ? `:${path}` : ""}`);
  }

  async pause(duration: PauseDuration): Promise<void> {
    await this.call(`pause:${duration}`);
    this.state.sync.pause = { until: pauseUntil(duration, this.now()) };
    this.emitSnapshot();
  }

  async resume(): Promise<void> {
    await this.call("resume");
    this.state.sync.pause = null;
    this.state.folders = this.state.folders.map((folder) =>
      folder.status.kind === "paused" ? { ...folder, status: { kind: "upToDate" } } : folder,
    );
    this.emitSnapshot();
  }

  async syncNow(): Promise<void> {
    await this.call("syncNow");
    const waiting = this.state.sync.waitingMetered;
    this.state.sync.waitingMetered = 0;
    this.state.sync.pendingFiles += waiting;
    this.emitSnapshot();
  }

  async retryConnection(): Promise<void> {
    await this.call("retryConnection");
    this.state.sync.connection = { kind: "online" };
    this.state.sync.lastSync = this.now();
    this.emitSnapshot();
  }

  async pauseFolder(folderId: FolderId): Promise<void> {
    await this.call("pauseFolder");
    this.setStatus(folderId, { kind: "paused" });
    this.emitSnapshot();
  }

  async resumeFolder(folderId: FolderId): Promise<void> {
    await this.call("resumeFolder");
    this.setStatus(folderId, { kind: "upToDate" });
    this.emitSnapshot();
  }

  async addFolder(token: string): Promise<void> {
    await this.call("addFolder");
    const { path, name } = this.placeOf(token, "addFolder");
    this.places.delete(token);
    this.state.folders = [
      ...this.state.folders,
      {
        id: this.id("f"),
        name,
        path,
        status: { kind: "uploading", count: 12 },
        freezeDays: null,
        notSyncedCount: 0,
      },
    ];
    this.emitSnapshot();
  }

  async addAccountFolder(folderId: FolderId, token: string): Promise<void> {
    await this.call("addAccountFolder");
    const { path } = this.placeOf(token, "addAccountFolder");
    this.places.delete(token);
    const remote = this.state.remoteFolders.find((folder) => folder.id === folderId);
    const deleted = this.state.deletedFolders.find((folder) => folder.id === folderId);
    const name = remote?.name ?? deleted?.name ?? folderId;
    this.state.remoteFolders = this.state.remoteFolders.filter((folder) => folder.id !== folderId);
    this.state.folders = [
      ...this.state.folders,
      {
        id: folderId,
        name,
        path,
        status: { kind: "downloading", count: 86 },
        freezeDays: null,
        notSyncedCount: 0,
      },
    ];
    this.emitSnapshot();
  }

  async stopFolder(folderId: FolderId): Promise<void> {
    await this.call("stopFolder");
    const folder = this.state.folders.find((item) => item.id === folderId);
    this.state.folders = this.state.folders.filter((item) => item.id !== folderId);
    if (folder) {
      this.state.remoteFolders = [
        ...this.state.remoteFolders,
        { id: folder.id, name: folder.name, size: 4_000_000_000 },
      ];
    }
    this.state.warnings = this.state.warnings.filter(
      (warning) => !("folderId" in warning) || warning.folderId !== folderId,
    );
    this.emitSnapshot();
  }

  async deleteFolderEverywhere(folderId: FolderId): Promise<DeleteOutcome> {
    await this.call("deleteFolderEverywhere");
    if (this.controls.nativeConfirm === "no") return "kept";
    const folder = this.state.folders.find((item) => item.id === folderId);
    this.state.folders = this.state.folders.filter((item) => item.id !== folderId);
    if (folder) {
      this.state.deletedFolders = [
        ...this.state.deletedFolders,
        { id: folder.id, name: folder.name, daysLeft: this.state.account?.retentionDays ?? 30 },
      ];
    }
    this.emitSnapshot();
    return "deleted";
  }

  async restoreDeletedFolder(folderId: FolderId): Promise<void> {
    await this.call("restoreDeletedFolder");
    const deleted = this.state.deletedFolders.find((folder) => folder.id === folderId);
    this.state.deletedFolders = this.state.deletedFolders.filter(
      (folder) => folder.id !== folderId,
    );
    if (deleted) {
      this.state.remoteFolders = [
        ...this.state.remoteFolders,
        { id: deleted.id, name: deleted.name, size: 2_100_000_000 },
      ];
    }
    this.emitSnapshot();
  }

  async listNotSynced(folderId: FolderId): Promise<readonly NotSyncedEntry[]> {
    await this.call(`listNotSynced:${folderId}`);
    return fx.notSynced();
  }

  async getFolderNumber(
    folderId: FolderId,
  ): Promise<{ kind: "number"; number: NumberRows } | { kind: "offline" }> {
    await this.call(`getFolderNumber:${folderId}`);
    return this.controls.folderNumber === "offline"
      ? { kind: "offline" }
      : { kind: "number", number: fx.numberRows(folderId.length * 31) };
  }

  async restoreRemoteDeleted(activityId: string): Promise<number> {
    await this.call("restoreRemoteDeleted");
    const entry = this.state.activity.find((item) => item.id === activityId);
    return entry?.kind === "remoteDeleted" ? entry.count : 0;
  }

  // Problems

  async listMassDelete(warningId: string): Promise<readonly string[]> {
    await this.call("listMassDelete");
    const warning = this.state.warnings.find((item) => item.id === warningId);
    return fx.massDeleteList(warning?.kind === "massDelete" ? warning.count : 0);
  }

  async resolveMassDelete(warningId: string, decision: "restore" | "delete"): Promise<number> {
    await this.call(`resolveMassDelete:${decision}`);
    const warning = this.state.warnings.find((item) => item.id === warningId);
    this.removeWarning(warningId);
    this.emitSnapshot();
    return warning?.kind === "massDelete" ? warning.count : 0;
  }

  async findMissingFolder(folderId: FolderId): Promise<PickResult> {
    await this.call("findMissingFolder");
    const result = this.pick({ kind: "find", folderId });
    if (result.kind === "picked") {
      this.state.warnings = this.state.warnings.filter(
        (warning) => !(warning.kind === "missingFolder" && warning.folderId === folderId),
      );
      this.state.folders = this.state.folders.map((folder) =>
        folder.id === folderId
          ? { ...folder, path: result.path, status: { kind: "upToDate" } }
          : folder,
      );
      this.emitSnapshot();
      // The shell relocates the folder at once; the token names nothing to do.
      this.places.delete(result.token);
      return { ...result, token: "" };
    }
    return result;
  }

  async redownloadFolder(folderId: FolderId): Promise<void> {
    await this.call("redownloadFolder");
    this.state.warnings = this.state.warnings.filter(
      (warning) => !(warning.kind === "missingFolder" && warning.folderId === folderId),
    );
    this.setStatus(folderId, { kind: "downloading", count: 342 });
    this.emitSnapshot();
  }

  async getServerNumber(): Promise<{ number: NumberRows; command: string }> {
    await this.call("getServerNumber");
    return { number: fx.numberRows(3041), command: "hangar-drive-server server-key-number" };
  }

  async confirmServerNumber(): Promise<ServerConfirm> {
    await this.call("confirmServerNumber");
    if (this.controls.nativeConfirm === "no") return "declined";
    this.state.warnings = this.state.warnings.filter(
      (warning) => warning.kind !== "serverIdentity",
    );
    this.emitSnapshot();
    return "confirmed";
  }

  async fixServerWithOffer(
    link: string,
  ): Promise<Result<null, "notALink" | "otherAccount" | "expired">> {
    await this.call("fixServerWithOffer");
    const parsed = parsePairLink(link);
    if (!parsed.ok) {
      return { ok: false, error: parsed.error === "notALink" ? "notALink" : "expired" };
    }
    if (parsed.value === "otherAccount") return { ok: false, error: "otherAccount" };
    if (parsed.value === "expired") return { ok: false, error: "expired" };
    this.state.warnings = this.state.warnings.filter(
      (warning) => warning.kind !== "serverIdentity",
    );
    this.emitSnapshot();
    return { ok: true, value: null };
  }

  async checkOlderState(folderId: FolderId): Promise<"stillOlder" | "resolved"> {
    await this.call("checkOlderState");
    if (this.controls.olderCheck === "resolved") this.clearOlder(folderId);
    return this.controls.olderCheck;
  }

  private clearOlder(folderId: FolderId): void {
    this.state.warnings = this.state.warnings.filter(
      (warning) => !(warning.kind === "olderState" && warning.folderId === folderId),
    );
    this.setStatus(folderId, { kind: "upToDate" });
    this.emitSnapshot();
  }

  async reanchor(folderId: FolderId, compared: boolean): Promise<void> {
    await this.call(`reanchor:${compared ? "compared" : "blind"}`);
    this.clearOlder(folderId);
  }

  async dismissSuspect(warningId: string): Promise<void> {
    await this.call("dismissSuspect");
    this.removeWarning(warningId);
    this.emitSnapshot();
  }

  async acceptRemovedHeads(folderId: FolderId): Promise<AcceptedHeads> {
    await this.call(`acceptRemovedHeads:${folderId}`);
    const commits = new Set(
      this.state.removedHeads?.folderId === folderId
        ? this.state.removedHeads.heads.map((head) => head.commit)
        : [],
    );
    this.state.removedHeads = null;
    this.state.warnings = this.state.warnings.filter(
      (warning) => !(warning.kind === "removedHeads" && warning.folderId === folderId),
    );
    this.setStatus(folderId, { kind: "upToDate" });
    this.emitSnapshot();
    // Newest first: the entry after the oldest taken-in state is the one before all of them.
    const entries = fx.timeline(this.now(), folderId);
    const oldest = entries.reduce(
      (found, entry, index) => (commits.has(entry.id) ? index : found),
      -1,
    );
    const before = oldest === -1 ? undefined : entries[oldest + 1];
    return { count: commits.size, beforeEntryId: before?.id ?? null };
  }

  async openStorageSettings(): Promise<void> {
    await this.call("openStorageSettings");
  }

  async installUpdate(): Promise<UpdateOutcome> {
    await this.call("installUpdate");
    if (!this.updatesOn()) {
      throw new BackendError("updatesOff", "installUpdate", "updates are off");
    }
    switch (this.controls.update) {
      case "off":
      case "upToDate":
        return { kind: "upToDate" };
      case "installed":
        return { kind: "installed", version: "0.2.0" };
    }
  }

  private updatesOn(): boolean {
    return this.state.updates && this.controls.update !== "off";
  }

  async copyErrorReport(): Promise<void> {
    await this.call("copyErrorReport");
  }

  async previewErrorReport(): Promise<string> {
    await this.call("previewErrorReport");
    return [
      "Hangar Drive 0.1.0 (mock)",
      "OS: Windows 11 23H2",
      "Connection: online, last answer 2 s ago",
      "Folders: 2 (up to date: 2)",
      "Devices: 3",
      "Last errors: none",
    ].join("\n");
  }

  async saveErrorReport(): Promise<SaveResult> {
    await this.call("saveErrorReport");
    const result = this.saveResult(`${fx.HOME}\\Documents\\Hangar Drive Fehlerbericht.txt`);
    return result.kind === "inSyncFolder" || result.kind === "inCloudFolder"
      ? { kind: "saved", path: `${fx.HOME}\\Documents\\report.txt` }
      : result;
  }

  // Conflicts and names

  async listConflicts(): Promise<readonly ConflictGroup[]> {
    await this.call("listConflicts");
    return [...this.state.conflicts];
  }

  async openConflict(groupId: string): Promise<void> {
    await this.call(`openConflict:${groupId}`);
  }

  async keepConflictVersion(groupId: string, versionId: string): Promise<{ undoToken: string }> {
    await this.call(`keepConflictVersion:${versionId}`);
    const before = [...this.state.conflicts];
    this.state.conflicts = this.state.conflicts.filter((group) => group.id !== groupId);
    this.syncConflictBanner();
    this.emitSnapshot();
    const hadBanner =
      this.state.warnings.some((warning) => warning.kind === "conflicts") || before.length > 0;
    return {
      undoToken: this.undoable(() => {
        this.state.conflicts = before;
        if (hadBanner && !this.state.warnings.some((warning) => warning.kind === "conflicts")) {
          this.state.warnings = [
            ...this.state.warnings,
            { kind: "conflicts", id: "w-conflicts", count: before.length },
          ];
        }
        this.syncConflictBanner();
      }),
    };
  }

  async keepBothConflict(groupId: string): Promise<void> {
    await this.call("keepBothConflict");
    this.state.conflicts = this.state.conflicts.filter((group) => group.id !== groupId);
    this.syncConflictBanner();
    this.emitSnapshot();
  }

  async undo(token: string): Promise<void> {
    await this.call("undo");
    const revert = this.undoTokens.get(token);
    this.undoTokens.delete(token);
    revert?.();
    this.emitSnapshot();
  }

  async listNameIssues(): Promise<readonly NameIssue[]> {
    await this.call("listNameIssues");
    return [...this.state.nameIssues];
  }

  async renameNameIssue(issueId: string, name: string): Promise<Result<null, RenameError>> {
    await this.call("renameNameIssue");
    if (windowsNameProblem(name) || name.trim() === "") return { ok: false, error: "invalid" };
    if (name.toLowerCase() === "bericht.docx" || name.toLowerCase() === "notizen.txt") {
      return { ok: false, error: "exists" };
    }
    this.state.nameIssues = this.state.nameIssues.filter((issue) => issue.id !== issueId);
    this.syncNamesBanner();
    this.emitSnapshot();
    return { ok: true, value: null };
  }

  async ignoreNameIssue(issueId: string): Promise<void> {
    await this.call("ignoreNameIssue");
    this.state.nameIssues = this.state.nameIssues.filter((issue) => issue.id !== issueId);
    this.syncNamesBanner();
    this.emitSnapshot();
  }

  // Restore

  async getTimeline(folderId: FolderId, path?: string): Promise<Timeline> {
    await this.call(`getTimeline:${folderId}${path ? `:${path}` : ""}`);
    const entries = fx.timeline(this.now(), folderId);
    return {
      entries: path ? entries.filter((entry) => entry.changed > 0) : entries,
      expiredCount: path ? 0 : 23,
      retentionDays: this.state.account?.retentionDays ?? 30,
    };
  }

  async getTreeAt(folderId: FolderId, entryId: string): Promise<VersionTree> {
    await this.call(`getTreeAt:${folderId}:${entryId}`);
    const nodes = fx.tree(entryId);
    return {
      nodes,
      changed: nodes.filter((node) => node.kind === "file" && node.diff === "different").length,
      missing: nodes.filter((node) => node.kind === "file" && node.diff === "missing").length,
    };
  }

  private restoreOutcome(count: number, name: string): RestoreOutcome {
    switch (this.controls.restore) {
      case "done":
        return { kind: "done", count, renamedTo: null, undoToken: this.undoable(() => undefined) };
      case "renamed": {
        const dot = name.lastIndexOf(".");
        const stamp = new Date(this.now()).toISOString().slice(0, 10);
        const renamed =
          dot > 0
            ? `${name.slice(0, dot)} (wiederhergestellt ${stamp})${name.slice(dot)}`
            : `${name} (wiederhergestellt ${stamp})`;
        return {
          kind: "done",
          count,
          renamedTo: renamed,
          undoToken: this.undoable(() => undefined),
        };
      }
      case "waitBudget":
        return { kind: "waitBudget", jobId: this.id("job") };
      case "noSpace":
        return { kind: "noSpace" };
      case "expired":
        return { kind: "expired" };
      case "failed":
        return { kind: "failed" };
    }
  }

  async restoreFile(
    folderId: FolderId,
    _entryId: string,
    path: string,
    mode: "replace" | "copy",
  ): Promise<RestoreOutcome> {
    await this.call(`restoreFile:${mode}:${path}`);
    const name = path.split("/").pop() ?? path;
    const outcome = this.restoreOutcome(1, name);
    if (mode === "copy" && outcome.kind === "done" && !outcome.renamedTo) {
      const stamp = new Date(this.now()).toISOString().slice(0, 10);
      const dot = name.lastIndexOf(".");
      return {
        ...outcome,
        renamedTo:
          dot > 0
            ? `${name.slice(0, dot)} (wiederhergestellt ${stamp})${name.slice(dot)}`
            : `${name} (wiederhergestellt ${stamp})`,
      };
    }
    if (outcome.kind === "done") this.addRestoredActivity(folderId, name);
    return outcome;
  }

  private addRestoredActivity(folderId: FolderId, name: string): void {
    const entry: ActivityEntry = {
      kind: "file",
      id: this.id("a"),
      folderId,
      folderName: this.folderName(folderId),
      name,
      path: name,
      action: "restored",
      device: null,
      at: this.now(),
    };
    this.state.activity = [entry, ...this.state.activity].slice(0, 50);
    this.emitSnapshot();
  }

  async resetFolder(folderId: FolderId, entryId: string): Promise<RestoreOutcome> {
    await this.call(`resetFolder:${folderId}:${entryId}`);
    const outcome = this.restoreOutcome(fx.tree(entryId).length, "");
    return outcome.kind === "done" ? { ...outcome, renamedTo: null } : outcome;
  }

  async cancelRestore(jobId: string): Promise<void> {
    await this.call(`cancelRestore:${jobId}`);
  }

  async findBeforeDevice(
    folderId: FolderId,
    deviceId: DeviceId,
    from: Millis,
  ): Promise<string | null> {
    await this.call(`findBeforeDevice:${folderId}:${deviceId}`);
    const device = this.state.devices.find((item) => item.id === deviceId);
    const entries = fx.timeline(this.now(), folderId);
    const index = entries.findIndex((entry, i) => {
      const next = entries[i + 1];
      return entry.device === device?.name && entry.at >= from && next !== undefined;
    });
    const before = index === -1 ? undefined : entries[index + 1];
    return before?.id ?? null;
  }

  async getTrash(folderId: FolderId): Promise<readonly TrashItem[]> {
    await this.call(`getTrash:${folderId}`);
    return fx.trash(this.now()).filter((item) => !this.hiddenTrash.has(`${folderId}:${item.id}`));
  }

  async restoreTrash(folderId: FolderId, itemIds: readonly string[]): Promise<RestoreOutcome> {
    await this.call(`restoreTrash:${String(itemIds.length)}`);
    const outcome = this.restoreOutcome(itemIds.length, "");
    if (outcome.kind === "done") {
      for (const id of itemIds) this.hiddenTrash.add(`${folderId}:${id}`);
      return { ...outcome, renamedTo: null };
    }
    return outcome;
  }

  // Devices

  async listDevices(): Promise<DeviceList> {
    await this.call("listDevices");
    return { devices: [...this.state.devices], recoveryCreated: this.state.recoveryCreated };
  }

  async renameDevice(deviceId: DeviceId, name: string): Promise<Result<null, NameError>> {
    await this.call("renameDevice");
    const nameError = strictNameProblem(name);
    if (nameError) return { ok: false, error: nameError };
    this.state.devices = this.state.devices.map((device) =>
      device.id === deviceId ? { ...device, name } : device,
    );
    return { ok: true, value: null };
  }

  async getSafetyNumber(deviceId: DeviceId): Promise<NumberRows> {
    await this.call(`getSafetyNumber:${deviceId}`);
    return fx.numberRows(deviceId.length * 977);
  }

  async removeDevice(deviceId: DeviceId): Promise<void> {
    await this.call(`removeDevice:${deviceId}`);
    this.state.devices = this.state.devices.filter((device) => device.id !== deviceId);
    const others = this.state.devices.some((device) => !device.isThis);
    if (this.state.account) this.state.account = { ...this.state.account, hasOtherDevices: others };
    this.emitSnapshot();
  }

  async resetDevice(): Promise<void> {
    await this.call("resetDevice");
    this.state = scenarioState("setup", this.now());
    this.recovery = null;
    this.offer = null;
    this.places.clear();
    this.emitSnapshot();
  }

  async disconnectThisDevice(): Promise<void> {
    await this.call("disconnectThisDevice");
    this.state = scenarioState("setup", this.now());
    this.emitSnapshot();
  }

  async createPairingOffer(): Promise<PairingOffer> {
    await this.call("createPairingOffer");
    const id = this.id("offer");
    const qr = fx.fakeQr(this.counter * 97);
    this.offer = {
      id,
      link: `hangar-drive://pair#${id}Q8w3`,
      code: ["7KQ2", "MX9H", "TRW8", "CZB3", "NF6J", "AQ1V", "E5"],
      host: fx.HOST,
      account: fx.ACCOUNT,
      qr,
      qrSvg: fx.qrSvg(qr),
      expiresAt: this.now() + 10 * fx.MINUTE,
    };
    const answer = this.controls.pairAnswer;
    if (answer !== "none")
      this.later(4000, () => {
        this.answerOffer(answer);
      });
    return this.offer;
  }

  async copyPairingLink(offerId: string): Promise<void> {
    await this.call(`copyPairingLink:${offerId}`);
    if (this.offer) this.controls.clipboard = this.offer.link;
  }

  async answerPairRequest(offerId: string, accept: boolean): Promise<PairAnswer> {
    await this.call(`answerPairRequest:${accept ? "accept" : "decline"}`);
    const added = accept && this.controls.nativeConfirm === "yes";
    if (!added || this.offer?.id !== offerId) {
      this.offer = null;
      return "declined";
    }
    this.offer = null;
    const now = this.now();
    this.state.devices = [
      {
        id: this.id("d"),
        name: "MacBook",
        kind: "laptop",
        isThis: false,
        lastSeen: now,
        added: now,
      },
      ...this.state.devices,
    ];
    if (this.state.account) this.state.account = { ...this.state.account, hasOtherDevices: true };
    this.emitSnapshot();
    return "added";
  }

  async renewRecoveryCode(): Promise<RecoveryCode> {
    await this.call("renewRecoveryCode");
    this.recovery = this.newRecoveryCode();
    return this.recovery;
  }

  // Settings

  async getSettings(): Promise<Settings> {
    await this.call("getSettings");
    return this.state.settings;
  }

  async setAutostart(on: boolean): Promise<void> {
    await this.call("setAutostart");
    this.state.settings = { ...this.state.settings, autostart: on };
  }

  async setLanguage(language: Language | "system"): Promise<void> {
    await this.call(`setLanguage:${language}`);
    this.state.settings = { ...this.state.settings, language };
  }

  async getAbout(): Promise<About> {
    await this.call("getAbout");
    return { version: "0.1.0", build: null, updates: this.updatesOn() };
  }

  // Tray

  async updateTray(model: TrayModel): Promise<void> {
    this.tray = model;
    await Promise.resolve();
  }

  async showWindow(): Promise<void> {
    await this.call("showWindow");
  }

  async quit(): Promise<void> {
    await this.call("quit");
  }
}

// ---------------------------------------------------------------------------------------------
// Magic inputs

/**
 * What the shell lets the window read from the clipboard (clipboard.rs `readable`): a link of the
 * app, an invite, or a code; "" for anything else. White space inside a link is allowed here, as
 * the window removes it.
 */
export function readableClipboard(text: string): string {
  const trimmed = text.trim();
  const joined = trimmed.replace(/\s+/g, "").toLowerCase();
  const link =
    /^hangar-drive:\/\/(join|pair|recover)#/.test(joined) ||
    (/^https?:\/\//.test(joined) && joined.includes("/join#"));
  const groups = trimmed.split(/[\s-]+/).filter((group) => group !== "");
  const letters = groups.join("").length;
  const code =
    groups.length > 0 &&
    groups.every((group) => /^[0-9A-TV-Z]{2,8}$/i.test(group)) &&
    letters >= 8 &&
    letters <= 80 &&
    /\d/.test(trimmed);
  return link || code ? trimmed : "";
}

/** Both invite forms; the fragment `<token>.<server ID>.<pin>` marks a pinned server. */
function parseInvite(link: string): Result<InviteCheck, InviteError> {
  if (hasSpace(link)) return { ok: false, error: "notALink" };
  const text = link;
  const deep = /^hangar-drive:\/\/join#([^@]+)@(\S+)$/i.exec(text);
  const https = /^(https?:\/\/[^/#]+)[^#]*#(\S+)$/i.exec(text);
  const [base, fragment] = deep ? [deep[2] ?? "", deep[1] ?? ""] : [https?.[1], https?.[2]];
  if (base === undefined || fragment === undefined) return { ok: false, error: "notALink" };
  let url: URL;
  try {
    url = new URL(base);
  } catch {
    return { ok: false, error: "notALink" };
  }
  if (url.protocol === "http:" && url.hostname !== "localhost") {
    return { ok: false, error: "insecure" };
  }
  if (url.protocol !== "https:" && url.protocol !== "http:")
    return { ok: false, error: "notALink" };
  if (fragment === "used") return { ok: false, error: "used" };
  if (fragment === "expired") return { ok: false, error: "expired" };
  if (fragment === "offline") return { ok: false, error: "unreachable" };
  return { ok: true, value: { host: url.hostname, pinned: fragment.split(".").length >= 3 } };
}

/** The engine's link parsers refuse white space anywhere; the window removes it first. */
function hasSpace(link: string): boolean {
  return /\s/.test(link);
}

type PairOutcome = "ok" | "declined" | "otherAccount" | "expired";

function parsePairLink(link: string): Result<PairOutcome, PairError> {
  const match = /^hangar-drive:\/\/pair#(\S+)$/i.exec(link);
  if (!match) return { ok: false, error: "notALink" };
  const fragment = (match[1] ?? "").toLowerCase();
  if (fragment === "expired" || fragment === "damaged") return { ok: false, error: "expired" };
  if (fragment === "toomany") return { ok: false, error: "tooMany" };
  if (fragment === "offline") return { ok: false, error: "unreachable" };
  if (fragment === "other") return { ok: true, value: "otherAccount" };
  if (fragment === "declined") return { ok: true, value: "declined" };
  return { ok: true, value: "ok" };
}

function parseTyped(server: string, code: string): Result<PairOutcome, PairError> {
  const host = server.trim().toLowerCase();
  if (host.startsWith("http://") && !host.startsWith("http://localhost")) {
    return { ok: false, error: "insecure" };
  }
  if (host === "" || host.includes("offline")) return { ok: false, error: "unreachable" };
  const clean = normalizeCode(code);
  if (!/^[0-9A-HJKMNP-TV-Z]{26}$/.test(clean)) return { ok: false, error: "typo" };
  return { ok: true, value: "ok" };
}
