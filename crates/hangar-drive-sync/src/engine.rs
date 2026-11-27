//! The engine the app talks to: one control thread that owns the account, every folder, the
//! server connection and the local index, runs the control loop and answers commands.
//!
//! - [`Engine::spawn`] starts the thread and returns an [`EngineHandle`] and the event
//!   receiver. The ports are built inside the thread by the factory, so the engine owns them
//!   alone and nothing is shared between threads but the channels.
//! - [`EngineHandle::call`] runs one command on the thread ([`EngineCore`] methods) and waits for
//!   its answer. The Tauri commands of the app map one to one onto these methods (see the
//!   table in the crate docs); `Backend` methods that belong to the OS shell (clipboard, tray,
//!   window, autostart, file dialogs, printing, QR drawing) are the app's, not the engine's.
//! - Between commands the thread runs [`EngineCore::tick`]: account refresh, pending removal
//!   steps (N1), watcher events, the hourly full scan, one round per folder, open pairing offers.
//!   Every change of the snapshot is sent as [`BackendEvent::Snapshot`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::time::Duration;

use hangar_drive_crypto::devicelog::LogDevice;
use hangar_drive_crypto::folder_keys::{FolderEntry, FolderList};
use hangar_drive_crypto::identity::{
    folder_safety_number, safety_number, server_key_number, DeviceIdentity,
};
use hangar_drive_crypto::pairing::{
    OfferContent, PairingError, PairingOffer, PairingSecret, ServerAddress,
};
use hangar_drive_crypto::recovery::RecoveryCode;
use hangar_drive_crypto::Entropy;
use hangar_drive_protocol::api::{ErrorCode, Notice};
use hangar_drive_protocol::ids::{
    base64url, AccountId, CommitId, DeviceId, FolderId, InviteToken, ItemId, LogHash, LogHead,
    ServerId,
};
use hangar_drive_protocol::name::{check_display_name, windows_problem, WindowsNameProblem};
use serde::{Deserialize, Serialize};

use crate::account::{Account, Genesis};
use crate::api::*;
use crate::chunker::DynEntropy;
use crate::error::SyncError;
use crate::folder::{Ctx, FolderSettings, FolderState, FolderSync, StopReason, UndoState};
use crate::http::{HttpServer, ServerConfig, SessionIdentity};
use crate::names::LabelWords;
use crate::ports::{Clock, FileSystem, FsError, Keychain, NetError, ServerApi, Store};
use crate::removal::{accept_removed_heads, complete_pending, remove_devices, JobCtx};
use crate::tree::{NodeKind, Tree, ROOT};
use crate::watch::{ChangeSource, FolderWatcher};

const ENGINE_KEY: &str = "engine";
/// A full scan of every folder at least this often (ADR 0001, section 3).
pub const FULL_SCAN_INTERVAL_MS: i64 = 60 * 60 * 1000;
/// The server counts as silent after this long without an answer.
const SILENT_AFTER_MS: i64 = 2 * 60 * 1000;
/// The feed is polled at least this often while the event stream is down.
pub const POLL_INTERVAL_MS: i64 = 60 * 1000;
const MAX_ACTIVITY: usize = 50;
/// Undo tokens kept: the window offers "Undo" only right after an action.
const MAX_UNDO: usize = 20;
/// Hidden warnings kept (follow-up check N-3): warning IDs are per folder and kind, so a device
/// collects only a few; the bound keeps a window that hides in a loop from growing the
/// settings file, and the oldest ones fall out first.
pub const MAX_DISMISSED: usize = 64;
/// How often a restore that waits for the upload budget is tried again (UX 9.1: it runs by
/// itself once the budget allows, at the latest within a day).
pub const RESTORE_RETRY_MS: i64 = 15 * 60 * 1000;
/// The retention window a deleted folder can be brought back in, while the server does not
/// say it (ADR 0001, section 5: 30 days by default).
const RETENTION_DAYS: i64 = 30;
const DAY_MS: i64 = 24 * 60 * 60 * 1000;
/// Anomaly pins kept (ADR 0001, section 5): the server pins at most one commit per folder in its
/// cooldown, so a device sees few; the bound keeps a server that floods the feed with made up
/// pins from growing the settings file. The oldest fall out first.
const MAX_PINS: usize = 32;
/// A pin notice that ends within this much of this device's clock is a pin that lapsed (the
/// server sends the notice again with the end set to its own now when the pin cap lets it go);
/// the margin covers clock skew between server and device. A fresh pin lasts far longer.
const PIN_LAPSE_MARGIN_MS: i64 = 60 * 60 * 1000;
/// While the server reports this device as removed (security review H2), it signs in again
/// this often, each time with a fresh challenge and proof, instead of at every pass.
pub const REMOVAL_PROBE_MS: i64 = 60 * 60 * 1000;
/// The server CLI command that prints the server key number (`server/src/main.rs`), shown in
/// the comparison dialog (UX 8.3).
pub const SERVER_NUMBER_COMMAND: &str = "hangar-drive-server server-key-number";

/// Builds the sync root (and its watcher) for a local path.
pub type FsFactory =
    Box<dyn Fn(&Path) -> Result<(Box<dyn FileSystem>, Option<Box<dyn ChangeSource>>), FsError>>;
/// Builds the server connection.
pub type ServerFactory =
    Box<dyn Fn(&ServerConfig, Option<SessionIdentity>) -> Result<Box<dyn ServerApi>, NetError>>;

/// The real sync roots: [`crate::localfs::LocalFs`] with its watcher.
pub fn real_fs_factory() -> FsFactory {
    Box::new(|path| {
        let fs = crate::localfs::LocalFs::new(path)?;
        let watcher = FolderWatcher::start(&fs)
            .ok()
            .map(|w| Box::new(w) as Box<dyn ChangeSource>);
        Ok((Box::new(fs) as Box<dyn FileSystem>, watcher))
    })
}

/// Checks a folder as a sync root next to the existing roots and returns its canonical form.
pub type RootCheck = Box<dyn Fn(&Path, &[PathBuf]) -> Result<PathBuf, crate::roots::RootError>>;

/// The real root check: [`crate::roots::check_planned_root`], which is
/// [`crate::roots::check_root`] (security review M4) for an existing folder and checks a folder
/// that does not exist yet before the app creates it (security review L4).
pub fn real_root_check() -> RootCheck {
    Box::new(crate::roots::check_planned_root)
}

/// The real server: [`HttpServer`].
pub fn real_server_factory() -> ServerFactory {
    Box::new(|config, identity| {
        Ok(Box::new(HttpServer::new(config.clone(), identity)?) as Box<dyn ServerApi>)
    })
}

/// A prover that signs session challenges with `identity`.
pub fn prover(identity: DeviceIdentity) -> crate::http::Prover {
    Box::new(move |server, url, account, device, challenge| {
        identity.prove_session(server, url, account, device, challenge)
    })
}

/// What the engine needs from the platform.
pub struct EnginePorts {
    /// The local index.
    pub store: Box<dyn Store>,
    /// The OS keychain.
    pub keychain: Box<dyn Keychain>,
    /// The clock.
    pub clock: Box<dyn Clock>,
    /// Randomness.
    pub entropy: Box<dyn Entropy>,
    /// Sync roots.
    pub fs: FsFactory,
    /// Server connections.
    pub server: ServerFactory,
    /// Which folders may become sync roots ([`real_root_check`]).
    pub roots: RootCheck,
}

/// The engine's settings from the app.
#[derive(Debug, Clone, Default)]
pub struct EngineSettings {
    /// Conflict and restore labels in the UI language.
    pub words: LabelWords,
    /// The local time zone offset in minutes.
    pub tz_offset_minutes: i32,
    /// The device has a camera.
    pub camera: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Persisted {
    server_url: Option<String>,
    pin: Option<[u8; 32]>,
    folders: Vec<(FolderId, String)>,
    paused_until: Option<Option<i64>>,
    ignored_names: BTreeSet<String>,
    /// Warnings hidden on this device, oldest first, at most [`MAX_DISMISSED`].
    dismissed: Vec<String>,
    /// This device was removed from its account, by the device named here (empty when the name
    /// is not known); its secrets and its account are forgotten (security review L1). Cleared
    /// once the device belongs to an account again.
    removed_by: Option<String>,
    /// Restores that wait for the upload budget (UX 9.1), tried again by the loop.
    #[serde(default)]
    restore_jobs: Vec<RestoreJob>,
    /// The server answered this device's own proof with `device_removed` (security review H2).
    /// Kept across restarts; cleared by the first call the server accepts again.
    #[serde(default)]
    removal_report: Option<RemovalReport>,
    /// The account's folders as this device last saw them, to notice one that left the list.
    #[serde(default)]
    known_folders: Vec<(FolderId, String)>,
    /// Folders deleted everywhere with the time this device noticed it, while they can still be
    /// brought back (UX 6, "Gelöschte Ordner").
    #[serde(default)]
    deleted_folders: Vec<(FolderId, String, i64)>,
    /// Anomaly pins the server told this device about, oldest first, at most [`MAX_PINS`]
    /// (ADR 0001, section 5; UX 9.4). Kept across restarts: the feed tells each pin only once.
    #[serde(default)]
    pins: Vec<PinNotice>,
}

/// An anomaly pin from the change feed: the server pinned `commit`, the last commit of `folder`
/// before a burst of replaced or dropped objects, until `until_ms` (server time, Unix ms). The
/// device that wrote the burst is read from this device's verified history, never from the
/// server ([`EngineCore::suspect_warnings`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PinNotice {
    folder: FolderId,
    commit: CommitId,
    until_ms: i64,
    /// The pin ended before its time (the account's pin cap was full); the version then stays
    /// only for the normal retention window.
    lapsed: bool,
}

/// Takes a pin notice in: a new pin is added, a known one updated. A pin that ends at once, or
/// earlier than this device knew, lapsed.
fn note_pin(
    pins: &mut Vec<PinNotice>,
    folder: FolderId,
    commit: CommitId,
    until_ms: i64,
    now: i64,
) {
    let ends_now = until_ms <= now.saturating_add(PIN_LAPSE_MARGIN_MS);
    if let Some(known) = pins
        .iter_mut()
        .find(|p| p.folder == folder && p.commit == commit)
    {
        known.lapsed |= ends_now || until_ms < known.until_ms;
        known.until_ms = until_ms;
        return;
    }
    pins.push(PinNotice {
        folder,
        commit,
        until_ms,
        lapsed: ends_now,
    });
    let over = pins.len().saturating_sub(MAX_PINS);
    pins.drain(..over);
}

/// The server's reports that this device was removed that came without a removal this device
/// could verify (security review H2, `Persisted`): the first and the last one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct RemovalReport {
    first_ms: i64,
    last_ms: i64,
}

/// A restore that waits for the upload budget. It is computed again when it runs, on the then
/// current state, so whatever changed meanwhile stays as a version too (UX 9.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RestoreJob {
    id: String,
    folder: FolderId,
    kind: RestoreKind,
    next_try_ms: i64,
}

/// What a restore brings back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum RestoreKind {
    /// One file or directory of a timeline entry (`restoreFile`).
    File { entry: CommitId, path: Vec<String> },
    /// The whole folder at a timeline entry (`resetFolder`).
    Folder { entry: CommitId },
    /// Items of the trash, each with the entry that still had it (`restoreTrash`).
    Trash { items: Vec<(CommitId, ItemId)> },
}

/// What a restore did: the files, the name a file came back under when its own was taken, and
/// what it changed, for its undo token.
type Restored = (u64, Option<String>, Option<UndoState>);

/// The files another device deleted in one round, for "Wiederherstellen" in the activity list
/// (UX 8.1): the head before the round still holds them.
#[derive(Debug, Clone)]
struct RemoteDelete {
    folder: FolderId,
    commit: CommitId,
    items: Vec<ItemId>,
}

struct LocalFolder {
    sync: FolderSync,
    fs: Box<dyn FileSystem>,
    watcher: Option<Box<dyn ChangeSource>>,
    path: String,
    last_full_scan: i64,
    /// Rounds in a row that failed with an error other than "offline", and the last one: the
    /// window shows it once it persists ([`FAILED_ROUNDS_SHOWN`]), instead of the folder
    /// silently staying at "uploading" (finding E2E-2).
    failed_rounds: u32,
    last_error: Option<crate::error::ErrorKind>,
    /// Files the last rounds could not write for lack of space, with their sizes: the window
    /// shows "disk full" with what they need until they are written or the folder is in sync.
    disk_full: BTreeMap<ItemId, u64>,
}

/// Failed rounds in a row after which a folder's error is shown: a single failure (a head that
/// moved between pull and commit, say) heals in the next round and is not worth a banner.
const FAILED_ROUNDS_SHOWN: u32 = 3;

struct PendingAccount {
    url: String,
    invite: InviteToken,
    pin: Option<[u8; 32]>,
    server: ServerId,
    /// Entry 1, made before the code is shown so the sheet names its hash (N1).
    genesis: Genesis,
    name: String,
    code: RecoveryCode,
    check_group: u32,
}

/// A new recovery code shown to the person, waiting for the typed group (ux-concept 10.3).
struct Renewal {
    code: RecoveryCode,
    check_group: u32,
    /// Already in the log (after a recovery); otherwise the group check adds it and removes the
    /// old recovery device, so closing the dialog midway leaves the old code valid.
    added: bool,
}

/// A recovery between `recover_account` and `finish_recovery_cleanup`.
struct Recovering {
    /// The server address of the sheet, for the new code's sheet.
    url: String,
    /// The recovery session before its one append (ADR 0001, amendment "recovery in one
    /// piece, adds per day, delta check on a growing log", H1): the device list is read, and the
    /// new device joins only with the person's choice. Only in memory, so an end of the app in
    /// between leaves nothing in the account and the code unused.
    before_join: Option<RecoveryChoice>,
}

/// The recovery session waiting for the person's choice of devices to remove.
struct RecoveryChoice {
    sheet: crate::links::RecoverySheet,
    code: RecoveryCode,
    server: Box<dyn ServerApi>,
    identity_export: zeroize::Zeroizing<Vec<u8>>,
    device: DeviceId,
    name: String,
    devices: Vec<crate::recovery::LogDeviceInfo>,
    /// The head of the log `devices` was read from: the append is refused when the log moved
    /// on in between (security review "recovery" M1).
    shown: LogHead,
}

/// The stored marker of a recovery whose one append was sent (security review "recovery" H1).
/// Written, with the new device's identity in the keychain, right before the append goes out,
/// so that no failure after it (a lost answer, a head the server made up, the end of the app, a
/// failed join) can lose the only key the account may have left. It holds nothing secret. It
/// goes once the new device joined and wrote the barriers, or once the recovery device's own
/// verified log shows that the append did not go through.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingRecovery {
    account: AccountId,
    device: DeviceId,
    name: String,
    server_url: String,
    pin: Option<[u8; 32]>,
    server: ServerId,
    genesis: LogHash,
    /// The log head after the batch, computed by this device: the anchor the join checks.
    head: LogHead,
    /// Every device the batch removes, for the barriers.
    removed: Vec<DeviceId>,
}

/// The exported identity of a pending recovery's device.
type PendingKey = zeroize::Zeroizing<Vec<u8>>;

/// The store key of [`PendingRecovery`].
const RECOVERY_PENDING_KEY: &str = "recovery-pending";
/// The keychain entry of the new device's identity while a recovery is pending, with the
/// SHA-256 of the marker (follow-up review LOW 3: the local index is not protected, the
/// keychain is): format byte [`RECOVERY_KEY_FORMAT`], the 32 byte digest, the exported
/// identity. The join stores its own copy of the identity under the device identity's entry.
const RECOVERY_IDENTITY_KEY: &str = "recovery-identity";
/// The format of [`RECOVERY_IDENTITY_KEY`].
const RECOVERY_KEY_FORMAT: u8 = 1;

/// The SHA-256 of a stored marker.
fn marker_digest(marker: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(marker).into()
}

/// How an append of a recovery failed.
enum RecoveryAttempt {
    /// Nothing was sent: the account and the code are as they were.
    NotSent(SyncError),
    /// The append was sent, and the new device could not join (yet).
    Sent(SyncError),
}

/// The engine's error for a refusal of the recovery module.
fn recovery_error(error: crate::recovery::RecoveryError) -> SyncError {
    match error {
        crate::recovery::RecoveryError::Used => SyncError::RecoveryCodeUsed,
        crate::recovery::RecoveryError::Unknown | crate::recovery::RecoveryError::WrongSheet => {
            SyncError::RecoveryCodeUnknown
        }
        crate::recovery::RecoveryError::ListChanged => SyncError::RecoveryListChanged,
        crate::recovery::RecoveryError::Sync(e) => e,
    }
}

struct OpenOffer {
    secret: PairingSecret,
    expires_at: i64,
    request: Option<hangar_drive_protocol::api::PairingRequest>,
}

struct Joining {
    identity_export: zeroize::Zeroizing<Vec<u8>>,
    account: AccountId,
    device: DeviceId,
    name: String,
    offer: PairingOffer,
    server: Box<dyn ServerApi>,
    config: ServerConfig,
}

/// The engine's state on its thread (module docs).
pub struct EngineCore {
    ports: EnginePorts,
    settings: EngineSettings,
    folder_settings: FolderSettings,
    persisted: Persisted,
    account: Option<Account>,
    server: Option<Box<dyn ServerApi>>,
    folders: BTreeMap<FolderId, LocalFolder>,
    activity: VecDeque<ActivityEntry>,
    notices: Vec<ServerNotice>,
    /// Use and quota from the server's last quota notice; the storage line shows it.
    storage: Option<Storage>,
    connection: Connection,
    last_ok_ms: i64,
    last_sync: Option<i64>,
    last_file: Option<LastFile>,
    pin_mismatch: bool,
    pending: Option<PendingAccount>,
    recovering: Option<Recovering>,
    renewal: Option<Renewal>,
    offers: BTreeMap<String, OpenOffer>,
    joining: Option<Joining>,
    events: Vec<BackendEvent>,
    last_snapshot: Option<Snapshot>,
    counter: u64,
    /// Undo tokens of the last actions, oldest first (`undo`).
    undo: VecDeque<(String, FolderId, UndoState)>,
    /// The "deleted on another device" entries of the activity list, by entry ID.
    remote_deletes: BTreeMap<String, RemoteDelete>,
    /// The pin of the key whose server number was shown last (`getServerNumber`), the only one
    /// `confirmServerNumber` takes.
    server_candidate: Option<[u8; 32]>,
    /// A [`PendingRecovery`] is stored.
    recovery_pending: bool,
    /// The loop tries a pending recovery again from this time on.
    recovery_retry_at: i64,
}

fn hex_id<T: std::fmt::Display>(id: &T) -> String {
    id.to_string()
}

fn name_error(name: &str) -> Option<NameError> {
    match check_display_name(name, hangar_drive_protocol::api::MAX_DEVICE_NAME_LEN) {
        Ok(()) => None,
        Err(hangar_drive_protocol::name::DisplayNameError::EdgeWhitespace) => {
            Some(NameError::EdgeWhitespace)
        }
        Err(_) => Some(NameError::Blank),
    }
}

/// The sheet view of a recovery code's account: its server, its genesis anchor, the pin this
/// device trusts (N1) and, in the link, the code's anchor tag over account and anchor.
fn sheet_view(
    url: &str,
    server: ServerId,
    account: AccountId,
    genesis: LogHash,
    pin: Option<[u8; 32]>,
    code: &RecoveryCode,
) -> Result<RecoverySheetView, SyncError> {
    let sheet = crate::links::RecoverySheet::new(
        hangar_drive_crypto::pairing::parse_server_url(url)
            .map_err(|_| SyncError::Invalid("server url"))?,
        server,
        account,
        genesis,
        pin,
        code,
    )
    .map_err(|_| SyncError::Invalid("recovery anchor tag"))?;
    Ok(RecoverySheetView {
        server_url: sheet.server_url.to_string(),
        server_id: server.to_hex(),
        account_id: account.to_hex(),
        genesis_anchor: genesis.to_hex(),
        pin: pin.map(|p| hangar_drive_protocol::ids::base64url(&p)),
        link: crate::links::recovery_link(&sheet),
    })
}

/// The check group of a new code: one-based, never 1 (people copy the first group from memory).
fn pick_check_group(entropy: &mut dyn Entropy) -> Result<u32, SyncError> {
    let mut pick = [0u8; 1];
    entropy.fill(&mut pick)?;
    Ok(2 + u32::from(pick[0]) % 7)
}

/// Whether the typed group is the code's check group (case and surrounding space forgiven; the
/// window maps Crockford's look-alike letters before it sends).
fn group_matches(code: &RecoveryCode, check_group: u32, typed: &str) -> bool {
    let groups = group(&code.reveal(), 4);
    let index = usize::try_from(check_group.saturating_sub(1)).unwrap_or(0);
    let expected = groups.get(index).cloned().unwrap_or_default();
    !expected.is_empty() && typed.trim().to_ascii_uppercase() == expected
}

/// Whether a host label is punycode, which can hide a look-alike name (N3).
fn has_punycode(host: &str) -> bool {
    host.split(['.', ':'])
        .any(|label| label.len() >= 4 && label[..4].eq_ignore_ascii_case("xn--"))
}

fn random_id<const N: usize>(entropy: &mut dyn Entropy) -> Result<[u8; N], SyncError> {
    let mut bytes = [0u8; N];
    entropy.fill(&mut bytes)?;
    Ok(bytes)
}

fn group(text: &str, size: usize) -> Vec<String> {
    let chars: Vec<char> = text.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    chars.chunks(size).map(|c| c.iter().collect()).collect()
}

impl EngineCore {
    /// The engine with the stored state (account, folders, settings).
    pub fn open(ports: EnginePorts, settings: EngineSettings) -> Result<Self, SyncError> {
        let persisted: Persisted = match ports.store.account_value(ENGINE_KEY)? {
            Some(bytes) => {
                serde_json::from_slice(&bytes).map_err(|e| SyncError::Corrupt(e.to_string()))?
            }
            None => Persisted::default(),
        };
        let account = Account::load(&*ports.store, &*ports.keychain)?;
        let folder_settings = FolderSettings {
            words: settings.words.clone(),
            tz_offset_minutes: settings.tz_offset_minutes,
            ..FolderSettings::default()
        };
        let now = ports.clock.now_ms();
        let mut core = Self {
            ports,
            settings,
            folder_settings,
            persisted,
            account,
            server: None,
            folders: BTreeMap::new(),
            activity: VecDeque::new(),
            notices: Vec::new(),
            storage: None,
            connection: Connection::Online,
            last_ok_ms: now,
            last_sync: None,
            last_file: None,
            pin_mismatch: false,
            pending: None,
            recovering: None,
            renewal: None,
            offers: BTreeMap::new(),
            joining: None,
            events: Vec::new(),
            last_snapshot: None,
            counter: 0,
            undo: VecDeque::new(),
            remote_deletes: BTreeMap::new(),
            server_candidate: None,
            recovery_pending: false,
            recovery_retry_at: 0,
        };
        // A marker that does not read cannot be finished; it must not keep the app from
        // starting either (the key stays in the keychain).
        core.recovery_pending = core.pending_recovery().ok().flatten().is_some();
        // A key without its marker: the app ended between the two writes of `mark_recovery`,
        // before the append went out, or after the marker of a finished recovery was removed.
        // Either way no append waits for it.
        if !core.recovery_pending {
            if let Ok(Some(_)) = core.ports.keychain.load(RECOVERY_IDENTITY_KEY) {
                let _ = core.ports.keychain.delete(RECOVERY_IDENTITY_KEY);
            }
        }
        core.connect()?;
        for (id, path) in core.persisted.folders.clone() {
            core.open_folder_at(id, &path)?;
        }
        Ok(core)
    }

    fn connect(&mut self) -> Result<(), SyncError> {
        let (Some(account), Some(url)) = (&self.account, &self.persisted.server_url) else {
            return Ok(());
        };
        let mut config = ServerConfig::new(url, self.persisted.pin)?;
        // Every sign-in checks the server ID this device learnt at account creation or from a
        // verified pairing offer (security review L6).
        config.server = account.server_id();
        let identity = DeviceIdentity::import(&account.identity().export())
            .map_err(|_| SyncError::Corrupt("device identity".into()))?;
        let session = SessionIdentity {
            account: *account.id(),
            device: *account.device(),
            prover: prover(identity),
        };
        self.server = Some((self.ports.server)(&config, Some(session))?);
        Ok(())
    }

    fn save(&mut self) -> Result<(), SyncError> {
        if self.account.is_some() {
            self.persisted.removed_by = None;
        }
        let bytes =
            serde_json::to_vec(&self.persisted).map_err(|e| SyncError::Corrupt(e.to_string()))?;
        self.ports.store.put_account_value(ENGINE_KEY, &bytes)?;
        Ok(())
    }

    fn open_folder_at(&mut self, id: FolderId, path: &str) -> Result<(), SyncError> {
        let Some(account) = &self.account else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let sync = match FolderSync::load(account, id, &*self.ports.store)? {
            Some(s) => s,
            None => {
                let name = account
                    .folders()
                    .into_iter()
                    .find(|f| f.folder == id)
                    .map(|f| f.name)
                    .unwrap_or_default();
                FolderSync::new(account, id, &name)
            }
        };
        let (fs, watcher) = (self.ports.fs)(Path::new(path))?;
        self.folders.insert(
            id,
            LocalFolder {
                sync,
                fs,
                watcher,
                path: path.to_owned(),
                last_full_scan: 0,
                failed_rounds: 0,
                last_error: None,
                disk_full: BTreeMap::new(),
            },
        );
        Ok(())
    }

    fn now(&self) -> i64 {
        self.ports.clock.now_ms()
    }

    /// Takes the events collected since the last call.
    pub fn take_events(&mut self) -> Vec<BackendEvent> {
        std::mem::take(&mut self.events)
    }

    // -- The loop ---------------------------------------------------------------------------

    fn note_net(&mut self, error: &SyncError) {
        if let SyncError::Net(NetError::PinMismatch) = error {
            self.pin_mismatch = true;
        }
        if error.is_offline() {
            let since = self.last_ok_ms;
            if self.now() - since >= SILENT_AFTER_MS {
                self.connection = Connection::ServerSilent { since };
            }
        }
    }

    /// One pass of the control loop (module docs). Returns the events for the window.
    pub fn tick(&mut self) -> Vec<BackendEvent> {
        self.tick_recovery();
        // While the server reports this device as removed, sync stays stopped and the device
        // only signs in again now and then (security review H2).
        let report = self.persisted.removal_report;
        // A clock set back since the last report makes the probe due as well, or the device
        // would stay stopped until the clock caught up again, even once the server accepts it.
        let probe_due = report.is_none_or(|r| {
            let since = self.now() - r.last_ms;
            !(0..REMOVAL_PROBE_MS).contains(&since)
        });
        if probe_due {
            match self.tick_inner() {
                Ok(()) => {}
                // The server answered this device's own proof with "removed" (finding E2E-3).
                // A server can say that of any device, so the device forgets the account only
                // when the log the server sent with it continues its own verified log with a
                // valid removal of itself; otherwise it waits for the person (H2).
                Err(e) if e.is_device_removed() && self.account.is_some() => {
                    match self.verified_removal(&e) {
                        Some(by) => {
                            let _ = self.forget_device(Some(by));
                        }
                        None => self.note_removal_report(),
                    }
                }
                Err(e) => self.note_net(&e),
            }
            if self.account.is_some() && self.persisted.removal_report != report {
                let _ = self.save();
            }
        }
        self.after_recovery_join();
        self.poll_joining();
        let snapshot = self.snapshot();
        if self.last_snapshot.as_ref() != Some(&snapshot) {
            self.last_snapshot = Some(snapshot.clone());
            self.events.push(BackendEvent::Snapshot {
                snapshot: Box::new(snapshot),
            });
        }
        self.take_events()
    }

    /// A pending recovery ([`PendingRecovery`]) is tried again now and then, until its device
    /// joined, also after the app ended in between (security review "recovery" H1). Not while
    /// the person chooses the devices of a new attempt.
    fn tick_recovery(&mut self) {
        let now = self.now();
        if !self.recovery_pending
            || now < self.recovery_retry_at
            || self
                .recovering
                .as_ref()
                .is_some_and(|r| r.before_join.is_some())
        {
            return;
        }
        if let Err(e) = self.resume_recovery() {
            self.recovery_retry_at = now.saturating_add(POLL_INTERVAL_MS);
            self.note_net(&e);
        }
    }

    /// What the join after this device's recovery left for later: the barriers of the
    /// recovery's removals in a folder whose key ring opened only now (follow-up review LOW 2;
    /// without them the folder would stop at the removed devices' heads), and this device's
    /// name once a remaining device re-sealed the names (follow-up review LOW 5).
    fn after_recovery_join(&mut self) {
        if self.recovery_pending {
            return;
        }
        let Some(account) = self.account.as_mut() else {
            return;
        };
        if account.take_recovered_rings() {
            // The flag stays set, in memory and in every save the barrier job makes, until the
            // barriers are written; only then is the account saved without it, so an end of the
            // app in between writes them at the next start.
            account.keep_recovered_rings();
            let removed = account.removed_by_own_recovery();
            let written = if removed.is_empty() {
                Ok(0)
            } else {
                self.remove_with_barriers(&removed)
            };
            let saved = written.and_then(|_| match self.account.as_mut() {
                Some(account) => {
                    account.take_recovered_rings();
                    account.save(&mut *self.ports.store)
                }
                None => Ok(()),
            });
            if let Err(e) = saved {
                if let Some(account) = self.account.as_mut() {
                    account.keep_recovered_rings();
                }
                self.note_net(&e);
            }
        }
        let name_due = self.account.as_ref().is_some_and(|a| {
            a.device_names().is_some() && a.device_display_name(a.device()).is_none()
        });
        if name_due {
            if let Err(e) = self.write_own_name_if_missing() {
                self.note_net(&e);
            }
        }
    }

    /// The name of the device that removed this one, when the "removed" answer of the server
    /// carries device log entries that continue this device's own verified log (from the entry
    /// after its head, chained to its hash) and hold a valid removal of this device, checked by
    /// the device log verifier (security review H2). `None` for a bare code, forged or invalid
    /// entries and a chain that does not start at the own head: then nothing is forgotten
    /// without the person.
    fn verified_removal(&self, error: &SyncError) -> Option<String> {
        let SyncError::Net(NetError::DeviceRemoved(Some(log))) = error else {
            return None;
        };
        let account = self.account.as_ref()?;
        let by = account.state().removal_in(
            log.first_index,
            log.entries.iter().map(|e| e.as_bytes()),
            account.device(),
        )?;
        Some(account.device_display_name(&by).unwrap_or_default())
    }

    /// One more "removed" from the server without a removal this device could verify (security
    /// review H2). The account is never forgotten on it alone: only when the person confirms
    /// ([`Self::confirm_device_removed`]), or when a later answer carries a verified removal.
    fn note_removal_report(&mut self) {
        let now = self.now();
        let report = self.persisted.removal_report.get_or_insert(RemovalReport {
            first_ms: now,
            last_ms: now,
        });
        report.first_ms = report.first_ms.min(now);
        report.last_ms = now;
    }

    /// The person confirmed the server's "this device was removed" (`confirmDeviceRemoved`,
    /// security review H2): the account is forgotten as when the log shows the removal (L1),
    /// and the window keeps the "removed" warning until the device is set up again. Refused
    /// while the server reported nothing.
    pub fn confirm_device_removed(&mut self) -> Result<(), SyncError> {
        if self.persisted.removal_report.is_none() || self.account.is_none() {
            return Err(SyncError::Invalid("the server did not report a removal"));
        }
        self.forget_device(Some(String::new()))
    }

    fn paused(&self) -> bool {
        match self.persisted.paused_until {
            Some(Some(until)) => self.now() < until,
            Some(None) => true,
            None => false,
        }
    }

    fn tick_inner(&mut self) -> Result<(), SyncError> {
        let now = self.now();
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Ok(());
        };
        // Named in the next sign-in proof, so a "removed" answer brings the log from here (H2).
        server.set_known_log_length(account.state().len());
        // A new account whose first epoch or device names did not make it yet (finding E2E-1):
        // carried on here, also after a restart, before anything else uses the account.
        if account.setup_pending() {
            account.finish_setup(
                server.as_mut(),
                &mut *self.ports.keychain,
                &mut *self.ports.store,
                &mut *self.ports.entropy,
                u64::try_from(now).unwrap_or(0),
            )?;
        }
        let refresh = account.refresh(
            server.as_mut(),
            &mut *self.ports.keychain,
            &mut *self.ports.store,
        );
        let refresh = refresh?;
        // The server accepted this device's proof again: whatever it said before was not a
        // removal (security review H2).
        self.persisted.removal_report = None;
        self.last_ok_ms = now;
        self.connection = Connection::Online;
        self.pin_mismatch = false;
        if refresh.removed {
            let by = account
                .state()
                .last_removal_issuer()
                .and_then(|issuer| account.device_display_name(issuer))
                .unwrap_or_default();
            return self.forget_device(Some(by));
        }
        let mut quiet = Vec::new();
        if refresh.feed_reset {
            quiet.push(ServerNotice::OlderAccountState);
        }
        let pins_before = self.persisted.pins.clone();
        for notice in &refresh.notices {
            match notice {
                // ADR 0001, section 5: every device is told; the warning is built from the
                // stored pin in every snapshot (`suspect_warnings`).
                Notice::AnomalyPin {
                    folder,
                    commit,
                    until_ms,
                } => note_pin(
                    &mut self.persisted.pins,
                    *folder,
                    *commit,
                    i64::try_from(*until_ms).unwrap_or(i64::MAX),
                    now,
                ),
                Notice::QuotaWarning {
                    live_bytes,
                    quota_bytes,
                } => {
                    self.storage = Some(Storage {
                        used: *live_bytes,
                        quota: *quota_bytes,
                    });
                    quiet.push(ServerNotice::Quota);
                }
                Notice::RetainedOverQuota { .. } => quiet.push(ServerNotice::Retained),
                Notice::DeviceBudget { device } => quiet.push(ServerNotice::BudgetDevice {
                    device: account.device_display_name(device).unwrap_or_default(),
                }),
                Notice::AccountBudget => quiet.push(ServerNotice::BudgetAccount),
                Notice::DiskReserve => quiet.push(ServerNotice::ServerDisk),
                // The text names the retention window that still holds (UX 6.3).
                Notice::MinimumCountCap { .. } => quiet.push(ServerNotice::MinCount {
                    days: RETENTION_DAYS as u32,
                }),
                Notice::Unknown => {}
            }
        }
        // Each notice once: the feed repeats a condition that is raised again, and the list
        // lives as long as the app runs.
        for notice in quiet {
            if !self.notices.contains(&notice) {
                self.notices.push(notice);
            }
        }
        // Ended pins go once their version is past the retention window as well.
        self.persisted
            .pins
            .retain(|p| now <= p.until_ms.saturating_add(RETENTION_DAYS * DAY_MS));
        if self.persisted.pins != pins_before {
            self.save()?;
        }
        // Open offers: a new device may have answered.
        let offers: Vec<String> = self.offers.keys().cloned().collect();
        for id in offers {
            self.poll_offer(&id);
        }
        self.note_folder_list();
        if self.paused() {
            return Ok(());
        }
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Ok(());
        };
        // A removal step another device left open (N1).
        {
            let mut list: Vec<(&mut FolderSync, &dyn FileSystem)> = self
                .folders
                .values_mut()
                .map(|f| (&mut f.sync, &*f.fs))
                .collect();
            let mut jx = JobCtx {
                account,
                server: server.as_mut(),
                keychain: &mut *self.ports.keychain,
                store: &mut *self.ports.store,
                clock: &*self.ports.clock,
                entropy: &mut *self.ports.entropy,
                settings: &self.folder_settings,
            };
            if let Err(e) = complete_pending(&mut jx, &mut list) {
                if e.is_offline() || e.is_device_removed() {
                    return Err(e);
                }
            }
        }
        let ids: Vec<FolderId> = self.folders.keys().copied().collect();
        let mut all_in_sync = true;
        for id in ids {
            let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut())
            else {
                return Ok(());
            };
            let Some(folder) = self.folders.get_mut(&id) else {
                continue;
            };
            if let Some(watcher) = &folder.watcher {
                let changes = watcher.drain(Duration::ZERO);
                if changes.rescan {
                    folder.sync.request_full_scan();
                } else {
                    folder.sync.note_changes(changes.paths);
                }
            }
            let hourly = now - folder.last_full_scan >= FULL_SCAN_INTERVAL_MS;
            if hourly {
                folder.sync.request_full_scan();
                folder.last_full_scan = now;
                // The quarantine is cleaned with every hourly scan, not only when the app
                // starts (security review, info), so an app that runs for weeks keeps no file
                // past its 30 days.
                folder.fs.housekeeping(now);
            }
            // The head before the round still holds what another device deletes in it.
            let head_before = folder.sync.view().frontier().map(|e| e.commit);
            let mut cx = Ctx {
                account,
                server: server.as_mut(),
                keychain: &mut *self.ports.keychain,
                fs: &*folder.fs,
                store: &mut *self.ports.store,
                clock: &*self.ports.clock,
                entropy: &mut *self.ports.entropy,
                settings: &self.folder_settings,
            };
            let report = match folder.sync.round(&mut cx) {
                Ok(r) => {
                    folder.failed_rounds = 0;
                    folder.last_error = None;
                    // The caches of the index shrink with the hourly scan (security review,
                    // MEDIUM 3). A failure here costs only space and is tried again in an hour.
                    if hourly {
                        let _ = folder.sync.prune_cache(&mut cx);
                    }
                    r
                }
                Err(e) if e.is_offline() || e.is_device_removed() => return Err(e),
                Err(e) => {
                    // Not swallowed (finding E2E-2): the folder tries again from a full scan,
                    // and an error that persists is shown ([`Self::snapshot`]).
                    folder.sync.request_full_scan();
                    folder.failed_rounds = folder.failed_rounds.saturating_add(1);
                    folder.last_error = Some(e.code());
                    all_in_sync = false;
                    continue;
                }
            };
            all_in_sync &= report.in_sync;
            Self::note_disk_full(folder, &report);
            let name = folder.sync.meta().name.clone();
            let folder_id = hex_id(&id);
            if !report.removed_heads.is_empty() {
                let heads = report
                    .removed_heads
                    .iter()
                    .map(|h| RemovedHeadView {
                        commit: h.commit.to_hex(),
                        device_id: hex_id(&h.device),
                        device_name: self
                            .account
                            .as_ref()
                            .and_then(|a| a.device_display_name(&h.device))
                            .unwrap_or_default(),
                        sequence: h.sequence,
                    })
                    .collect();
                self.events.push(BackendEvent::RemovedHeads {
                    folder_id: folder_id.clone(),
                    heads,
                });
            }
            // Deletes another device made are one entry with "Wiederherstellen" (UX 8.1); those
            // of this device's own restores stay single entries.
            let deleter = folder
                .sync
                .meta()
                .timeline
                .iter()
                .rev()
                .find(|t| !t.side)
                .map(|t| t.device)
                .filter(|d| self.account.as_ref().is_some_and(|a| a.device() != d));
            let remote_deleted: Vec<&crate::folder::ItemChange> = match (deleter, head_before) {
                (Some(_), Some(_)) => report
                    .changes
                    .iter()
                    .filter(|c| c.incoming && c.action == crate::folder::ChangeAction::Deleted)
                    .collect(),
                _ => Vec::new(),
            };
            if let (Some(device), Some(commit), false) =
                (deleter, head_before, remote_deleted.is_empty())
            {
                self.counter += 1;
                let entry = format!("a-{}", self.counter);
                let count = remote_deleted.iter().filter(|c| !c.dir).count() as u64;
                self.remote_deletes.insert(
                    entry.clone(),
                    RemoteDelete {
                        folder: id,
                        commit,
                        items: remote_deleted.iter().map(|c| c.item).collect(),
                    },
                );
                self.activity.push_front(ActivityEntry::RemoteDeleted {
                    id: entry,
                    folder_id: folder_id.clone(),
                    folder_name: name.clone(),
                    count,
                    device: self
                        .account
                        .as_ref()
                        .and_then(|a| a.device_display_name(&device))
                        .unwrap_or_default(),
                    at: now,
                });
            }
            // One set, not a pass over the deletes per change (security review, LOW 2: a
            // round that deletes a million items made 10^12 comparisons here).
            let grouped: BTreeSet<ItemId> = remote_deleted.iter().map(|c| c.item).collect();
            for change in &report.changes {
                if grouped.contains(&change.item) {
                    continue;
                }
                let file_name = change.path.rsplit('/').next().unwrap_or("").to_owned();
                self.last_file = Some(LastFile {
                    name: file_name.clone(),
                    at: now,
                });
                self.counter += 1;
                let action = match change.action {
                    crate::folder::ChangeAction::Added | crate::folder::ChangeAction::Changed => {
                        FileAction::FromDevice
                    }
                    crate::folder::ChangeAction::Deleted => FileAction::Deleted,
                    crate::folder::ChangeAction::Moved => FileAction::Renamed,
                };
                self.activity.push_front(ActivityEntry::File {
                    id: format!("a-{}", self.counter),
                    folder_id: folder_id.clone(),
                    folder_name: name.clone(),
                    name: file_name,
                    path: change.path.clone(),
                    action,
                    device: None,
                    at: now,
                });
            }
            for copy in &report.copies {
                let path = folder
                    .sync
                    .remote()
                    .path_string(&copy.copy)
                    .unwrap_or_default();
                self.counter += 1;
                self.activity.push_front(ActivityEntry::File {
                    id: format!("a-{}", self.counter),
                    folder_id: folder_id.clone(),
                    folder_name: name.clone(),
                    name: path.rsplit('/').next().unwrap_or("").to_owned(),
                    path,
                    action: FileAction::TwoVersions,
                    device: None,
                    at: now,
                });
            }
            self.activity.truncate(MAX_ACTIVITY);
            let shown: BTreeSet<&str> = self.activity.iter().map(activity_id).collect();
            self.remote_deletes
                .retain(|id, _| shown.contains(id.as_str()));
        }
        if all_in_sync {
            self.last_sync = Some(now);
        }
        self.run_restore_jobs();
        Ok(())
    }

    /// Notices folders that left the account's folder list (deleted everywhere, here or on
    /// another device) and keeps them under "Gelöschte Ordner" while they can be brought back;
    /// a folder stopped as retired here syncs again once it is back in the list.
    fn note_folder_list(&mut self) {
        let Some(account) = self.account.as_ref().filter(|a| a.has_folder_list()) else {
            return;
        };
        let listed: Vec<(FolderId, String)> = account
            .folders()
            .into_iter()
            .map(|f| (f.folder, f.name))
            .collect();
        let now = self.now();
        let before = (
            self.persisted.known_folders.clone(),
            self.persisted.deleted_folders.clone(),
        );
        for (id, name) in &self.persisted.known_folders {
            let gone = !listed.iter().any(|(f, _)| f == id);
            if gone && !self.persisted.deleted_folders.iter().any(|(f, ..)| f == id) {
                self.persisted
                    .deleted_folders
                    .push((*id, name.clone(), now));
            }
        }
        self.persisted.deleted_folders.retain(|(id, _, at)| {
            !listed.iter().any(|(f, _)| f == id) && now - at < RETENTION_DAYS * DAY_MS
        });
        self.persisted.known_folders = listed.clone();
        if before
            != (
                self.persisted.known_folders.clone(),
                self.persisted.deleted_folders.clone(),
            )
        {
            let _ = self.save();
        }
        for (id, folder) in self.folders.iter_mut() {
            if listed.iter().any(|(f, _)| f == id) {
                let _ = folder.sync.clear_retired(&mut *self.ports.store);
            }
        }
    }

    // -- Snapshot ---------------------------------------------------------------------------

    fn folder_status(f: &LocalFolder) -> FolderStatus {
        match f.sync.state() {
            FolderState::Paused => FolderStatus::Paused,
            FolderState::Stopped(StopReason::OlderState) => FolderStatus::Stopped {
                reason: StopReasonApi::OlderState,
            },
            FolderState::Stopped(StopReason::RemovedHeads) => FolderStatus::Stopped {
                reason: StopReasonApi::RemovedHeads,
            },
            FolderState::Stopped(StopReason::TreeLimit) => FolderStatus::Stopped {
                reason: StopReasonApi::TreeLimit,
            },
            FolderState::Stopped(StopReason::LocalTooLarge) => FolderStatus::Stopped {
                reason: StopReasonApi::TooLarge,
            },
            FolderState::Stopped(_) => FolderStatus::Stopped {
                reason: StopReasonApi::Missing,
            },
            FolderState::Active => {
                let (up, down) = Self::pending(f);
                if up > 0 {
                    FolderStatus::Uploading { count: up }
                } else if down > 0 {
                    FolderStatus::Downloading { count: down }
                } else {
                    FolderStatus::UpToDate
                }
            }
        }
    }

    fn pending(f: &LocalFolder) -> (u64, u64) {
        let (local, synced, remote) = (f.sync.local(), f.sync.synced(), f.sync.remote());
        let files = |t: &Tree, other: &Tree| {
            t.iter()
                .filter(|(id, n)| !n.is_dir() && other.get(id) != Some(*n))
                .count() as u64
        };
        let skip = f.sync.cannot_sync().len() as u64;
        (
            files(local, synced),
            files(remote, synced).saturating_sub(skip),
        )
    }

    /// The banner of a folder whose rounds keep failing: the full quota, the server's full disk
    /// and a server that needs a newer app have their own (one per account); anything else is
    /// "the server refused", per folder.
    fn folder_error_warning(folder: &FolderId, kind: crate::error::ErrorKind) -> Warning {
        use crate::error::ErrorKind;
        match kind {
            ErrorKind::QuotaFull => Warning::QuotaFull {
                id: "quotaFull".into(),
            },
            ErrorKind::ServerDisk => Warning::ServerDisk {
                id: "serverDisk".into(),
            },
            ErrorKind::UpdateRequired => Warning::UpdateRequired {
                id: "updateRequired".into(),
            },
            _ => Warning::Refused {
                id: format!("refused-{folder}"),
            },
        }
    }

    /// Everything the window shows.
    pub fn snapshot(&self) -> Snapshot {
        let mut warnings = Vec::new();
        let mut folders = Vec::new();
        let mut pending_files = 0;
        let mut conflicts = 0u64;
        let mut names = 0u64;
        for (id, f) in &self.folders {
            let meta = f.sync.meta();
            let (up, down) = Self::pending(f);
            pending_files += up + down;
            folders.push(Folder {
                id: hex_id(id),
                name: meta.name.clone(),
                path: f.path.clone(),
                status: Self::folder_status(f),
                freeze_days: None,
                not_synced_count: meta.not_synced.len() as u64,
                bytes: f.sync.local_bytes(),
            });
            match f.sync.state() {
                FolderState::Stopped(StopReason::MarkerMissing) => {
                    warnings.push(Warning::MissingFolder {
                        id: format!("missing-{id}"),
                        folder_id: hex_id(id),
                        folder_name: meta.name.clone(),
                    })
                }
                FolderState::Stopped(StopReason::OlderState) => {
                    warnings.push(Warning::OlderState {
                        id: format!("older-{id}"),
                        folder_id: hex_id(id),
                        folder_name: meta.name.clone(),
                    })
                }
                FolderState::Stopped(StopReason::TreeLimit) => warnings.push(Warning::TreeLimit {
                    id: format!("treeLimit-{id}"),
                    folder_id: hex_id(id),
                    folder_name: meta.name.clone(),
                }),
                FolderState::Stopped(StopReason::RemovedHeads) => {
                    let mut devices: Vec<String> = meta
                        .removed_heads
                        .iter()
                        .map(|h| self.device_name_of(&h.device))
                        .collect();
                    devices.sort();
                    devices.dedup();
                    warnings.push(Warning::RemovedHeads {
                        id: format!("removedHeads-{id}"),
                        folder_id: hex_id(id),
                        folder_name: meta.name.clone(),
                        devices,
                        count: meta.removed_heads.len() as u64,
                    })
                }
                _ => {}
            }
            if let (true, Some(kind)) = (f.failed_rounds >= FAILED_ROUNDS_SHOWN, f.last_error) {
                let warning = Self::folder_error_warning(id, kind);
                if !warnings
                    .iter()
                    .any(|w| warning_id(w) == warning_id(&warning))
                {
                    warnings.push(warning);
                }
            }
            if !meta.held.is_empty() {
                let sample = meta
                    .held
                    .iter()
                    .take(3)
                    .filter_map(|i| f.sync.synced().get(i).map(|n| n.name.clone()))
                    .collect();
                warnings.push(Warning::MassDelete {
                    id: format!("massDelete-{id}"),
                    folder_id: hex_id(id),
                    folder_name: meta.name.clone(),
                    count: meta.held.len() as u64,
                    sample,
                });
            }
            let incoming = f.sync.incoming_held_files() as u64;
            if incoming > 0 {
                let synced = f.sync.synced();
                let sample = meta
                    .incoming_held
                    .iter()
                    .filter_map(|i| synced.get(i).filter(|n| !n.is_dir()))
                    .take(3)
                    .map(|n| n.name.clone())
                    .collect();
                // Named only when one device wrote every commit the deletes came with, with the
                // day the verified log added it, which a renamed device cannot change (L5).
                let writer = match meta.incoming_devices.iter().collect::<Vec<_>>()[..] {
                    [one] => Some(*one),
                    _ => None,
                };
                let device = writer
                    .map(|d| self.device_name_of(&d))
                    .filter(|n| !n.trim().is_empty());
                let device_added = writer.filter(|_| device.is_some()).and_then(|d| {
                    self.account
                        .as_ref()
                        .and_then(|a| a.device_added_ms(&d))
                        .and_then(|ms| i64::try_from(ms).ok())
                });
                warnings.push(Warning::IncomingDelete {
                    id: format!("incomingDelete-{id}"),
                    folder_id: hex_id(id),
                    folder_name: meta.name.clone(),
                    device,
                    device_added,
                    count: incoming,
                    sample,
                });
            }
            conflicts += Self::conflict_groups(f).len() as u64;
            names += f
                .sync
                .cannot_sync()
                .keys()
                .filter(|i| !self.persisted.ignored_names.contains(&format!("{id}:{i}")))
                .count() as u64;
        }
        let needed: u64 = self
            .folders
            .values()
            .flat_map(|f| f.disk_full.values())
            .fold(0u64, |sum, size| sum.saturating_add(*size));
        if self.folders.values().any(|f| !f.disk_full.is_empty()) {
            warnings.push(Warning::DiskFull {
                id: "diskFull".into(),
                needed,
            });
        }
        warnings.extend(self.suspect_warnings());
        if self.pin_mismatch {
            warnings.push(Warning::ServerIdentity {
                id: "serverIdentity".into(),
                has_other_device: self.account.as_ref().is_some_and(|a| {
                    a.state().current_devices().filter(|d| !d.recovery).count() > 1
                }),
            });
        }
        if let (Some(report), Some(_)) = (&self.persisted.removal_report, &self.account) {
            warnings.push(Warning::RemovalReported {
                id: "removalReported".into(),
                since: report.first_ms,
            });
        }
        if let (Some(by), None) = (&self.persisted.removed_by, &self.account) {
            warnings.push(Warning::Removed {
                id: "removed".into(),
                by: by.clone(),
            });
        }
        if self.recovery_pending && self.account.is_none() {
            warnings.push(Warning::RecoveryPending {
                id: "recoveryPending".into(),
            });
        }
        // Folder data the join after this device's recovery could not read (follow-up review
        // LOW 2).
        if let Some(account) = &self.account {
            let folders: Vec<String> = account
                .unreadable_folders()
                .into_iter()
                .map(|f| f.name)
                .collect();
            let folder_list = account.folder_list_unreadable();
            if !folders.is_empty() || folder_list {
                warnings.push(Warning::FoldersUnreadable {
                    id: "foldersUnreadable".into(),
                    folders,
                    folder_list,
                });
            }
        }
        // No code would work for this account (security review "recovery" L1).
        if self
            .account
            .as_ref()
            .is_some_and(|a| !a.setup_pending() && !a.state().current_devices().any(|d| d.recovery))
        {
            warnings.push(Warning::NoRecoveryCode {
                id: "noRecoveryCode".into(),
            });
        }
        if conflicts > 0 {
            warnings.push(Warning::Conflicts {
                id: "conflicts".into(),
                count: conflicts,
            });
        }
        if names > 0 {
            warnings.push(Warning::Names {
                id: "names".into(),
                count: names,
            });
        }
        warnings.retain(|w| !dismissible(w) || !self.persisted.dismissed.contains(&warning_id(w)));
        let remote_folders = self
            .account
            .as_ref()
            .map(|a| {
                a.folders()
                    .into_iter()
                    .filter(|f| !self.folders.contains_key(&f.folder))
                    .map(|f| RemoteFolder {
                        id: hex_id(&f.folder),
                        name: f.name,
                        size: 0,
                    })
                    .collect()
            })
            .unwrap_or_default();
        Snapshot {
            setup: if self.account.is_some() {
                SetupState::Done
            } else {
                SetupState::Needed
            },
            sync: SyncSummary {
                connection: self.connection,
                pause: self.persisted.paused_until.map(|until| Pause { until }),
                pending_files,
                bytes_left: 0,
                last_sync: self.last_sync,
                last_file: self.last_file.clone(),
                waiting_metered: 0,
                waiting_budget: 0,
            },
            folders,
            activity: self.activity.iter().cloned().collect(),
            warnings,
            notices: self.notices.clone(),
            storage: self.storage,
            account: self.account.as_ref().map(|a| AccountInfo {
                host: self
                    .persisted
                    .server_url
                    .as_deref()
                    .and_then(url_host)
                    .unwrap_or_default(),
                retention_days: 30,
                has_other_devices: a.state().current_devices().filter(|d| !d.recovery).count() > 1,
            }),
            remote_folders,
            deleted_folders: self
                .persisted
                .deleted_folders
                .iter()
                .filter_map(|(id, name, at)| {
                    let left = RETENTION_DAYS - (self.now() - at).max(0) / DAY_MS;
                    (left > 0).then(|| DeletedFolder {
                        id: hex_id(id),
                        name: name.clone(),
                        days_left: u32::try_from(left).unwrap_or(0),
                    })
                })
                .collect(),
            env: Environment {
                camera: self.settings.camera,
            },
        }
    }

    // -- Setup ------------------------------------------------------------------------------

    /// Checks an invite link (`checkInvite`): the host in its ASCII form and whether the link
    /// pins a key, so the window can warn before anything is sent (N3).
    pub fn check_invite(&mut self, link: &str) -> ApiResult<InviteCheck, InviteError> {
        match crate::links::parse_invite(link) {
            Ok(invite) => match url_host(invite.server_url.as_str()) {
                Some(host) => ApiResult::Ok(InviteCheck {
                    punycode: has_punycode(&host),
                    pinned: invite.pin.is_some(),
                    host,
                }),
                None => ApiResult::Err(InviteError::NotALink),
            },
            Err(crate::links::LinkError::Insecure) => ApiResult::Err(InviteError::Insecure),
            Err(_) => ApiResult::Err(InviteError::NotALink),
        }
    }

    /// Starts a new account (`beginAccount`): makes the recovery code; nothing is sent yet.
    pub fn begin_account(
        &mut self,
        link: &str,
        device_name: &str,
    ) -> Result<ApiResult<RecoveryCodeView, BeginError>, SyncError> {
        if self.account.is_some() {
            return Err(SyncError::Invalid(
                "this device already belongs to an account",
            ));
        }
        if let Some(e) = name_error(device_name) {
            return Ok(ApiResult::Err(match e {
                NameError::Blank => BeginError::Blank,
                NameError::EdgeWhitespace => BeginError::EdgeWhitespace,
            }));
        }
        let invite = match crate::links::parse_invite(link) {
            Ok(invite) => invite,
            Err(crate::links::LinkError::Insecure) => {
                return Ok(ApiResult::Err(BeginError::Insecure))
            }
            Err(_) => return Ok(ApiResult::Err(BeginError::NotALink)),
        };
        let url = invite.server_url.to_string();
        let account = AccountId::from_bytes(random_id(&mut *self.ports.entropy)?);
        // The sheet names the server ID, so it is learnt now, before the code is shown: the
        // challenge answers for any account and writes nothing on the server.
        let mut config = ServerConfig::new(&url, invite.pin)?;
        config.server = invite.server;
        let mut server = match (self.ports.server)(&config, None) {
            Ok(s) => s,
            Err(NetError::Tls(_)) | Err(NetError::PinMismatch) => {
                return Ok(ApiResult::Err(BeginError::Insecure))
            }
            Err(_) => return Ok(ApiResult::Err(BeginError::Unreachable)),
        };
        let probe = DeviceId::from_bytes(random_id(&mut *self.ports.entropy)?);
        let server_id = match server.challenge(&account, &probe) {
            Ok(c) => c.server,
            Err(NetError::Tls(_)) | Err(NetError::PinMismatch) => {
                return Ok(ApiResult::Err(BeginError::Insecure))
            }
            Err(_) => return Ok(ApiResult::Err(BeginError::Unreachable)),
        };
        if invite.server.is_some_and(|s| s != server_id) {
            return Ok(ApiResult::Err(BeginError::Insecure));
        }
        let code = RecoveryCode::generate(&mut DynEntropy(&mut *self.ports.entropy))?;
        let check_group = pick_check_group(&mut *self.ports.entropy)?;
        let groups = group(&code.reveal(), 4);
        // Entry 1 is made now, so the sheet can name its hash (N1); the recovery device it
        // lists is derived from the code alone. Nothing reaches the server before the group
        // check (ux-concept 4.2.1).
        let device = DeviceId::from_bytes(random_id(&mut *self.ports.entropy)?);
        let recovery_identity = code
            .identity()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let recovery_id = code
            .device_id()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let now = u64::try_from(self.now()).unwrap_or(0);
        let genesis = Genesis::new(
            &mut *self.ports.entropy,
            now,
            account,
            device,
            Some((&recovery_identity, recovery_id)),
        )?;
        let sheet = sheet_view(&url, server_id, account, genesis.hash()?, invite.pin, &code)?;
        self.pending = Some(PendingAccount {
            url,
            invite: invite.token,
            pin: invite.pin,
            server: server_id,
            genesis,
            name: device_name.to_owned(),
            code,
            check_group,
        });
        Ok(ApiResult::Ok(RecoveryCodeView {
            groups,
            check_group,
            sheet,
        }))
    }

    /// Checks the typed group of the recovery code (`confirmRecoveryGroup`): creates the account
    /// of a new setup, or, for a renewed code, makes the new code the account's only one.
    ///
    /// A new account is made in two steps (finding E2E-1): the invite is redeemed without a
    /// session, then this device signs in with its new identity for the first epoch and the
    /// device names. Should the second step fail, the account is stored already and the setup
    /// is carried on by calling this again or by the next tick, also after a restart; a failure
    /// before the server took the invite keeps the code, so the same group can be confirmed
    /// again.
    pub fn confirm_recovery_group(&mut self, typed: &str) -> Result<bool, SyncError> {
        if self.pending.is_none() && self.account.as_ref().is_some_and(Account::setup_pending) {
            self.finish_account_setup()?;
            return Ok(true);
        }
        let Some(pending) = &self.pending else {
            return self.confirm_renewal(typed);
        };
        if !group_matches(&pending.code, pending.check_group, typed) {
            return Ok(false);
        }
        let Some(pending) = self.pending.take() else {
            return Ok(false);
        };
        let mut config = ServerConfig::new(&pending.url, pending.pin)?;
        config.server = Some(pending.server);
        let created = (self.ports.server)(&config, None)
            .map_err(SyncError::from)
            .and_then(|mut server| {
                Account::create_from(
                    server.as_mut(),
                    &mut *self.ports.keychain,
                    &mut *self.ports.store,
                    pending.invite.clone(),
                    &pending.genesis,
                    &pending.name,
                )
            });
        let account = match created {
            Ok(account) => account,
            Err(e) => {
                // Nothing is stored; the server repeats a creation that went through as the same
                // success, so a confirmation after a lost answer carries on.
                self.pending = Some(pending);
                return Err(e);
            }
        };
        if account.server_id() != Some(pending.server) {
            // Another server than the one the code was made for: nothing of it may stay.
            drop(account);
            let _ = crate::account::forget(&mut *self.ports.store, &mut *self.ports.keychain);
            return Err(SyncError::Net(NetError::Protocol(
                "the server ID changed".into(),
            )));
        }
        self.account = Some(account);
        self.persisted.server_url = Some(pending.url);
        self.persisted.pin = pending.pin;
        self.save()?;
        self.connect()?;
        self.finish_account_setup()?;
        Ok(true)
    }

    /// The second step of a new account ([`Account::finish_setup`]) with this device's session.
    fn finish_account_setup(&mut self) -> Result<(), SyncError> {
        let now = u64::try_from(self.now()).unwrap_or(0);
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        account.finish_setup(
            server.as_mut(),
            &mut *self.ports.keychain,
            &mut *self.ports.store,
            &mut *self.ports.entropy,
            now,
        )
    }

    /// The group check of a renewed code (ux-concept 10.3).
    fn confirm_renewal(&mut self, typed: &str) -> Result<bool, SyncError> {
        let Some(renewal) = &self.renewal else {
            return Ok(false);
        };
        if !group_matches(&renewal.code, renewal.check_group, typed) {
            return Ok(false);
        }
        let Some(renewal) = self.renewal.take() else {
            return Ok(false);
        };
        if renewal.added {
            return Ok(true);
        }
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let recovery_identity = renewal
            .code
            .identity()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let recovery_id = renewal
            .code
            .device_id()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let old: Vec<DeviceId> = account
            .state()
            .current_devices()
            .filter(|d| d.recovery && d.id != recovery_id)
            .map(|d| d.id)
            .collect();
        let now = u64::try_from(self.ports.clock.now_ms()).unwrap_or(0);
        // The new code first: should the removal fail after this, both codes work, never none.
        account.add_recovery_device(
            server.as_mut(),
            &mut *self.ports.store,
            LogDevice::of(&recovery_identity, account.id(), recovery_id, true),
            now,
            &mut *self.ports.entropy,
        )?;
        if !old.is_empty() {
            self.remove_with_barriers(&old)?;
        }
        Ok(true)
    }

    /// A new recovery code for this account (`renewRecoveryCode`, ux-concept 10.3). Nothing
    /// changes until the person types the check group back ([`Self::confirm_recovery_group`]);
    /// the old code stays valid until then.
    pub fn renew_recovery_code(&mut self) -> Result<RecoveryCodeView, SyncError> {
        let choosing = self
            .recovering
            .as_ref()
            .is_some_and(|r| r.before_join.is_some());
        if self.pending.is_some() || choosing {
            return Err(SyncError::Invalid("the setup is not finished"));
        }
        let url = self
            .persisted
            .server_url
            .clone()
            .ok_or(SyncError::NotSetUp("no server"))?;
        let account = self
            .account
            .as_ref()
            .ok_or(SyncError::NotSetUp("no account"))?;
        let code = RecoveryCode::generate(&mut DynEntropy(&mut *self.ports.entropy))?;
        let sheet = self.own_sheet(account, &url, &code)?;
        let check_group = pick_check_group(&mut *self.ports.entropy)?;
        let groups = group(&code.reveal(), 4);
        // A recovery that joined but stopped before its new code ends here: this code replaces
        // it (security review "recovery" L1).
        self.recovering = None;
        self.renewal = Some(Renewal {
            code,
            check_group,
            added: false,
        });
        Ok(RecoveryCodeView {
            groups,
            check_group,
            sheet,
        })
    }

    /// The sheet of `code` for this device's account: its server, genesis anchor and the pin it
    /// trusts.
    fn own_sheet(
        &self,
        account: &Account,
        url: &str,
        code: &RecoveryCode,
    ) -> Result<RecoverySheetView, SyncError> {
        let server_id = account
            .server_id()
            .ok_or(SyncError::NotSetUp("the server ID is not known yet"))?;
        let genesis = account
            .state()
            .hash_at(1)
            .copied()
            .ok_or(SyncError::NotSetUp("the account log is empty"))?;
        sheet_view(
            url,
            server_id,
            *account.id(),
            genesis,
            self.persisted.pin,
            code,
        )
    }

    /// Account recovery with the recovery sheet (`recoverAccount`, open point A): `sheet` is
    /// the sheet's link `hangar-drive://recover#...` (the app builds it from the printed fields
    /// or a scan), `code` the typed code. The recovery session reads and checks the account's
    /// log (`crate::recovery::prepare`) and nothing is written yet; `recovery_devices` lists the
    /// devices, and `finish_recovery_cleanup` adds this installation, removes the chosen
    /// devices and the used recovery device and rotates in one append, then joins.
    ///
    /// With an earlier attempt of this account pending ([`PendingRecovery`]), its new device
    /// tries to join first; when that works the recovery goes on at `finish_recovery_cleanup`
    /// without a second append. Otherwise the recovery device's verified log tells: while it
    /// still lists the recovery device, the earlier append did not go through, the earlier
    /// attempt is dropped and this one starts afresh with the same code.
    pub fn recover_account(
        &mut self,
        sheet: &str,
        code: &str,
        device_name: &str,
    ) -> Result<ApiResult<(), RecoverError>, SyncError> {
        if self.account.is_some() {
            return Err(SyncError::Invalid(
                "this device already belongs to an account",
            ));
        }
        match name_error(device_name) {
            Some(NameError::Blank) => return Ok(ApiResult::Err(RecoverError::Blank)),
            Some(NameError::EdgeWhitespace) => {
                return Ok(ApiResult::Err(RecoverError::EdgeWhitespace))
            }
            None => {}
        }
        let sheet = match crate::links::parse_recovery_link(sheet) {
            Ok(s) => s,
            Err(crate::links::LinkError::Insecure) => {
                return Ok(ApiResult::Err(RecoverError::Insecure))
            }
            Err(_) => return Ok(ApiResult::Err(RecoverError::Unknown)),
        };
        let code = match RecoveryCode::parse(code) {
            Ok(c) => c,
            Err(hangar_drive_crypto::recovery::CodeError::Version(_)) => {
                return Ok(ApiResult::Err(RecoverError::OtherApp))
            }
            Err(_) => return Ok(ApiResult::Err(RecoverError::Typo)),
        };
        // A sheet the code was not made for is refused before anything is sent anywhere: a link
        // can come from anyone (security review "recovery link as phishing").
        if !sheet.is_for(&code) {
            return Ok(ApiResult::Err(RecoverError::WrongSheet));
        }
        let url = sheet.server_url.to_string();
        let pending = self.load_pending()?.map(|(marker, _)| marker);
        let mut resume_error = None;
        if let Some(marker) = &pending {
            if marker.account != sheet.account {
                return Err(SyncError::Invalid(
                    "a recovery of another account is not finished",
                ));
            }
            match self.resume_recovery() {
                Ok(_) => {
                    self.recovering = Some(Recovering {
                        url,
                        before_join: None,
                    });
                    return Ok(ApiResult::Ok(()));
                }
                Err(e) => resume_error = Some(e),
            }
        }
        let recovery_identity = code
            .identity()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let recovery_id = code
            .device_id()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let mut config = ServerConfig::new(&url, sheet.pin)?;
        config.server = Some(sheet.server);
        let net = |e: &NetError| match e {
            NetError::Tls(_) | NetError::PinMismatch => RecoverError::Insecure,
            NetError::Server(_) => RecoverError::Unknown,
            NetError::Protocol(_) => RecoverError::Unknown,
            _ => RecoverError::Unreachable,
        };
        let session = SessionIdentity {
            account: sheet.account,
            device: recovery_id,
            prover: prover(recovery_identity),
        };
        let mut recovery_server = match (self.ports.server)(&config, Some(session)) {
            Ok(s) => s,
            Err(e) => return Ok(ApiResult::Err(net(&e))),
        };
        // Steps 0 to 3: the log is read and checked, nothing is written. The new device joins
        // with the one append of `finish_recovery_cleanup`, once the person chose the devices
        // to remove.
        let prepared = match crate::recovery::prepare(recovery_server.as_mut(), &sheet, &code) {
            Ok(prepared) => prepared,
            // The earlier append went through (it removed the recovery device), and its device
            // cannot join yet: the account waits for it, never for a second append.
            Err(_) if pending.is_some() => {
                return Err(resume_error.unwrap_or(SyncError::Invalid("recovery pending")));
            }
            Err(crate::recovery::RecoveryError::Unknown) => {
                return Ok(ApiResult::Err(RecoverError::Unknown))
            }
            Err(crate::recovery::RecoveryError::Used) => {
                return Ok(ApiResult::Err(RecoverError::Used))
            }
            Err(crate::recovery::RecoveryError::WrongSheet) => {
                return Ok(ApiResult::Err(RecoverError::WrongSheet))
            }
            Err(crate::recovery::RecoveryError::Sync(SyncError::Net(e))) => {
                return Ok(ApiResult::Err(net(&e)))
            }
            Err(e) => return Err(recovery_error(e)),
        };
        if let Some(marker) = &pending {
            // The log still lists the recovery device, so the batch that removes it is not in;
            // the earlier attempt's device must not be in it either.
            if prepared.state.device(&marker.device).is_some() {
                return Err(resume_error.unwrap_or(SyncError::Invalid("recovery pending")));
            }
            self.clear_pending_recovery()?;
        }
        let shown = prepared
            .state
            .head()
            .ok_or(SyncError::Invalid("the account log is empty"))?;
        let identity = DeviceIdentity::generate(&mut DynEntropy(&mut *self.ports.entropy))
            .map_err(|_| SyncError::Invalid("identity"))?;
        let device = DeviceId::from_bytes(random_id(&mut *self.ports.entropy)?);
        self.recovering = Some(Recovering {
            url,
            before_join: Some(RecoveryChoice {
                sheet,
                code,
                server: recovery_server,
                identity_export: identity.export(),
                device,
                name: device_name.to_owned(),
                devices: prepared.devices,
                shown,
            }),
        });
        Ok(ApiResult::Ok(()))
    }

    /// Whether a [`PendingRecovery`] is stored.
    fn pending_recovery(&self) -> Result<Option<()>, SyncError> {
        Ok(self
            .ports
            .store
            .account_value(RECOVERY_PENDING_KEY)?
            .map(|_| ()))
    }

    /// The stored [`PendingRecovery`] with the new device's identity. The marker must be the
    /// one whose digest the keychain entry holds (follow-up review LOW 3): a changed marker, or
    /// one without its key, is refused, and nothing is acted on.
    fn load_pending(&self) -> Result<Option<(PendingRecovery, PendingKey)>, SyncError> {
        let Some(bytes) = self.ports.store.account_value(RECOVERY_PENDING_KEY)? else {
            return Ok(None);
        };
        let Some(entry) = self.ports.keychain.load(RECOVERY_IDENTITY_KEY)? else {
            return Err(SyncError::Corrupt(
                "the pending recovery's device key is missing".into(),
            ));
        };
        let (format, rest) = entry.split_first().unwrap_or((&0, &[]));
        if *format != RECOVERY_KEY_FORMAT || rest.len() <= 32 {
            return Err(SyncError::Corrupt(
                "the pending recovery's device key is malformed".into(),
            ));
        }
        let (digest, identity) = rest.split_at(32);
        if digest != marker_digest(&bytes).as_slice() {
            return Err(SyncError::Corrupt(
                "the pending recovery's marker was changed".into(),
            ));
        }
        let marker =
            serde_json::from_slice(&bytes).map_err(|e| SyncError::Corrupt(e.to_string()))?;
        Ok(Some((marker, zeroize::Zeroizing::new(identity.to_vec()))))
    }

    /// Records a recovery before its append goes out: the identity with the marker's digest
    /// into the keychain first, so a marker never points to a key that is not there.
    fn mark_recovery(
        &mut self,
        marker: &PendingRecovery,
        identity: &[u8],
    ) -> Result<(), SyncError> {
        let bytes = serde_json::to_vec(marker).map_err(|e| SyncError::Corrupt(e.to_string()))?;
        let mut entry = zeroize::Zeroizing::new(Vec::with_capacity(33 + identity.len()));
        entry.push(RECOVERY_KEY_FORMAT);
        entry.extend_from_slice(&marker_digest(&bytes));
        entry.extend_from_slice(identity);
        self.ports.keychain.store(RECOVERY_IDENTITY_KEY, &entry)?;
        if let Err(e) = self
            .ports
            .store
            .put_account_value(RECOVERY_PENDING_KEY, &bytes)
        {
            let _ = self.ports.keychain.delete(RECOVERY_IDENTITY_KEY);
            return Err(e.into());
        }
        self.recovery_pending = true;
        Ok(())
    }

    /// Drops the pending recovery: the marker first, then the key it points to. The recovery
    /// counts as pending until the marker is gone (follow-up review LOW 4); a key left behind
    /// without its marker is removed at the next start (`EngineCore::open`). The first failure
    /// is returned.
    fn clear_pending_recovery(&mut self) -> Result<(), SyncError> {
        self.ports
            .store
            .delete_account_value(RECOVERY_PENDING_KEY)?;
        self.recovery_pending = false;
        self.ports.keychain.delete(RECOVERY_IDENTITY_KEY)?;
        Ok(())
    }

    /// Finishes a recovery whose one append was sent ([`PendingRecovery`]): the new device signs
    /// in and joins at the head this device computed for the batch, so its own verified log,
    /// not the server's answer, tells whether the batch is in (security review "recovery" H1);
    /// a join that the app's end cut short is completed. Then the barriers with the batch's
    /// removals and this device's name. Returns whether a pending recovery was finished.
    /// Nothing is deleted on a failure: the marker stays for the next try.
    fn resume_recovery(&mut self) -> Result<bool, SyncError> {
        let Some((marker, bytes)) = self.load_pending()? else {
            self.recovery_pending = false;
            return Ok(false);
        };
        match &self.account {
            // Another account was set up since; its marker is not this device's business.
            Some(account) if *account.device() != marker.device => return Ok(false),
            Some(_) => {
                let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut())
                else {
                    return Err(SyncError::NotSetUp("no connection"));
                };
                account.complete_recovery_join(
                    server.as_mut(),
                    &mut *self.ports.keychain,
                    &mut *self.ports.store,
                    &mut *self.ports.entropy,
                )?;
            }
            None => {
                let import = || {
                    DeviceIdentity::import(&bytes)
                        .map_err(|_| SyncError::Corrupt("device identity".into()))
                };
                let mut config = ServerConfig::new(&marker.server_url, marker.pin)?;
                config.server = Some(marker.server);
                let session = SessionIdentity {
                    account: marker.account,
                    device: marker.device,
                    prover: prover(import()?),
                };
                Account::drop_unfinished_join(
                    &mut *self.ports.keychain,
                    &*self.ports.store,
                    &import()?,
                )?;
                let mut server = (self.ports.server)(&config, Some(session))?;
                let mut account = Account::join_recovered(
                    server.as_mut(),
                    &mut *self.ports.keychain,
                    &mut *self.ports.store,
                    &mut *self.ports.entropy,
                    import()?,
                    marker.account,
                    marker.device,
                    &marker.name,
                    // The new device's own view of the log must start with the sheet's entry 1
                    // too, and contain the head the recovery batch made (N1, N6, I1).
                    &[
                        LogHead {
                            index: 1,
                            hash: marker.genesis,
                        },
                        marker.head,
                    ],
                )?;
                account.set_server_id(marker.server);
                account.save(&mut *self.ports.store)?;
                self.account = Some(account);
                self.server = Some(server);
                self.persisted.server_url = Some(marker.server_url.clone());
                self.persisted.pin = marker.pin;
                self.save()?;
            }
        }
        // The batch made the removals; the job finds them in the log and re-seals and writes
        // the barriers with this device's own removal.
        self.remove_with_barriers(&marker.removed)?;
        self.write_own_name_if_missing()?;
        self.clear_pending_recovery()?;
        Ok(true)
    }

    /// This device's name into the sealed device names, if it is not there yet (finding
    /// E2E-4: the recovery device cannot write it). Not while this device could not read the
    /// names and another regular device is left (follow-up review LOW 5): a list of this device
    /// alone would drop every other name; that device re-seals the names under the new epoch,
    /// and the name follows at a later call.
    fn write_own_name_if_missing(&mut self) -> Result<(), SyncError> {
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let me = *account.device();
        let others = account
            .state()
            .current_devices()
            .any(|d| !d.recovery && d.id != me);
        if account.device_names().is_none() && others {
            return Ok(());
        }
        if account.device_display_name(&me).is_none() {
            let name = account.device_name().to_owned();
            account.set_device_name(
                server.as_mut(),
                &mut *self.ports.store,
                &me,
                &name,
                &mut *self.ports.entropy,
            )?;
        }
        Ok(())
    }

    /// The one append of a recovery and the join of the new device (steps 4 and 5 of
    /// `crate::recovery`): removes `remove` and every recovery device. The batch is built, the
    /// recovery is marked as pending, the batch goes out, and whatever the server answers, the
    /// new device tries to join at the head this device computed (security review "recovery"
    /// H1).
    fn append_recovery(
        &mut self,
        choice: &mut RecoveryChoice,
        url: &str,
        remove: &[DeviceId],
    ) -> Result<(), RecoveryAttempt> {
        let identity = DeviceIdentity::import(&choice.identity_export)
            .map_err(|_| RecoveryAttempt::NotSent(SyncError::Invalid("identity")))?;
        let entry = LogDevice::of(&identity, &choice.sheet.account, choice.device, false);
        let now = u64::try_from(self.now()).unwrap_or(0);
        let batch = crate::recovery::build_recovery(
            choice.server.as_mut(),
            &choice.sheet,
            &choice.code,
            &identity,
            entry,
            remove,
            &choice.shown,
            now,
            &mut *self.ports.entropy,
        )
        .map_err(|e| RecoveryAttempt::NotSent(recovery_error(e)))?;
        let marker = PendingRecovery {
            account: choice.sheet.account,
            device: choice.device,
            name: choice.name.clone(),
            server_url: url.to_owned(),
            pin: choice.sheet.pin,
            server: choice.sheet.server,
            genesis: choice.sheet.genesis,
            head: batch.head,
            removed: batch.removed.clone(),
        };
        self.mark_recovery(&marker, &choice.identity_export)
            .map_err(RecoveryAttempt::NotSent)?;
        let sent = crate::recovery::send_recovery(choice.server.as_mut(), &batch);
        match self.resume_recovery() {
            Ok(_) => Ok(()),
            Err(join_error) => Err(RecoveryAttempt::Sent(sent.err().unwrap_or(join_error))),
        }
    }

    /// After an append whose device could not join: whether the recovery device's verified log
    /// shows that the batch is not in (it still lists the recovery device, which the batch
    /// removes, and not the new device). Then the pending recovery is dropped, so the person
    /// can try again with the same code. When that log ends elsewhere than the one the person
    /// chose from (follow-up review M1: a device was added in between, and the batch built on
    /// the shorter log was refused), `choice` takes the new list and `Some(true)` asks the
    /// caller to answer [`SyncError::RecoveryListChanged`]; a retry with the old choice would
    /// leave the new device in the account unseen. `Some(false)`: not in, same log. `None`: in,
    /// or not known (a failure to read counts as "maybe in"), and the marker stays.
    fn settle_unsent(&mut self, choice: &mut RecoveryChoice) -> Option<bool> {
        if self.account.is_some() {
            return None;
        }
        let prepared =
            crate::recovery::prepare(choice.server.as_mut(), &choice.sheet, &choice.code).ok()?;
        let shown = prepared.state.head()?;
        if prepared.state.device(&choice.device).is_some() || self.clear_pending_recovery().is_err()
        {
            return None;
        }
        let changed = shown != choice.shown;
        if changed {
            choice.devices = prepared.devices;
            choice.shown = shown;
        }
        Some(changed)
    }

    /// The devices of the account besides this one during a recovery (`recoveryDevices`): every
    /// one is offered for removal. Before the join they come from the verified log, without
    /// names (the recovery session cannot open the sealed device names), with the time each was
    /// added. After [`SyncError::RecoveryListChanged`] the list is the new one.
    pub fn recovery_devices(&self) -> Result<Vec<Device>, SyncError> {
        if let Some(choice) = self
            .recovering
            .as_ref()
            .and_then(|r| r.before_join.as_ref())
        {
            return Ok(choice
                .devices
                .iter()
                .map(|d| Device {
                    id: hex_id(&d.id),
                    name: String::new(),
                    kind: DeviceKind::Laptop,
                    is_this: false,
                    last_seen: None,
                    added: i64::try_from(d.added_ms).unwrap_or(0),
                })
                .collect());
        }
        let list = self.list_devices()?;
        Ok(list.devices.into_iter().filter(|d| !d.is_this).collect())
    }

    /// Ends a recovery (`finishRecoveryCleanup`): removes the chosen old devices and every
    /// recovery device, so the used code stops working, rotates and writes the barriers, and
    /// adds the recovery device of a new code, which it returns with its sheet. A recovery
    /// before its join appends here, in one batch with the add of this device.
    ///
    /// Errors: [`SyncError::RecoveryListChanged`] when the account's devices changed since
    /// `recovery_devices` listed them (nothing written; the list is the new one). Any other
    /// error before the append leaves the choice, so the call can be repeated. After the append
    /// the recovery is pending until this device joined: repeating the call, typing the code
    /// again or the loop finishes it, and the device's key is kept until then.
    pub fn finish_recovery_cleanup(
        &mut self,
        remove: &[String],
    ) -> Result<RecoveryCodeView, SyncError> {
        let url = self
            .recovering
            .as_ref()
            .map(|r| r.url.clone())
            .ok_or(SyncError::Invalid("no recovery in progress"))?;
        let mut chosen = Vec::new();
        for text in remove {
            chosen.push(DeviceId::from_hex(text).map_err(|_| SyncError::Invalid("device"))?);
        }
        if let Some(mut choice) = self.recovering.as_mut().and_then(|r| r.before_join.take()) {
            let failed = match self.append_recovery(&mut choice, &url, &chosen) {
                Ok(()) => None,
                Err(RecoveryAttempt::NotSent(SyncError::RecoveryListChanged)) => {
                    // The person chooses again from the log as it is now.
                    if let Ok(prepared) = crate::recovery::prepare(
                        choice.server.as_mut(),
                        &choice.sheet,
                        &choice.code,
                    ) {
                        if let Some(shown) = prepared.state.head() {
                            choice.devices = prepared.devices;
                            choice.shown = shown;
                        }
                    }
                    Some((SyncError::RecoveryListChanged, true))
                }
                Err(RecoveryAttempt::NotSent(e)) => Some((e, true)),
                Err(RecoveryAttempt::Sent(e)) => match self.settle_unsent(&mut choice) {
                    Some(true) => Some((SyncError::RecoveryListChanged, true)),
                    Some(false) => Some((e, true)),
                    None => Some((e, false)),
                },
            };
            if let Some((error, keep)) = failed {
                if let (true, Some(recovering)) = (keep, self.recovering.as_mut()) {
                    recovering.before_join = Some(choice);
                }
                return Err(error);
            }
        } else if self.recovery_pending {
            self.resume_recovery()?;
        }
        let account = self
            .account
            .as_ref()
            .ok_or(SyncError::NotSetUp("no account"))?;
        let me = *account.device();
        let mut targets: Vec<DeviceId> = chosen
            .iter()
            .copied()
            .filter(|id| *id != me && account.state().device(id).is_some_and(|d| d.is_current()))
            .collect();
        targets.extend(
            account
                .state()
                .current_devices()
                .filter(|d| d.recovery)
                .map(|d| d.id),
        );
        targets.sort();
        targets.dedup();
        if !targets.is_empty() {
            self.remove_with_barriers(&targets)?;
        }
        self.write_own_name_if_missing()?;
        let code = RecoveryCode::generate(&mut DynEntropy(&mut *self.ports.entropy))?;
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let recovery_identity = code
            .identity()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let recovery_id = code
            .device_id()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let now = u64::try_from(self.ports.clock.now_ms()).unwrap_or(0);
        account.add_recovery_device(
            server.as_mut(),
            &mut *self.ports.store,
            LogDevice::of(&recovery_identity, account.id(), recovery_id, true),
            now,
            &mut *self.ports.entropy,
        )?;
        let account = self
            .account
            .as_ref()
            .ok_or(SyncError::NotSetUp("no account"))?;
        let sheet = self.own_sheet(account, &url, &code)?;
        let check_group = pick_check_group(&mut *self.ports.entropy)?;
        self.recovering = None;
        let groups = group(&code.reveal(), 4);
        // The code is in the log already; the group check only confirms it was written down.
        self.renewal = Some(Renewal {
            code,
            check_group,
            added: true,
        });
        Ok(RecoveryCodeView {
            groups,
            check_group,
            sheet,
        })
    }

    // -- Pairing ----------------------------------------------------------------------------

    /// Creates a pairing offer of this device (`createPairingOffer`).
    pub fn create_pairing_offer(&mut self) -> Result<PairingOfferView, SyncError> {
        let (Some(account), Some(server), Some(url)) = (
            self.account.as_ref(),
            self.server.as_mut(),
            self.persisted.server_url.as_deref(),
        ) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        // The slot is reserved before the offer is shown (server security review M2). A slot
        // another account holds (`AlreadyExists`) is skipped with a new secret; `RateLimited`
        // means this account has `MAX_OPEN_PAIRINGS` open slots, which the caller reports.
        let mut reserved = None;
        for _ in 0..3 {
            let secret = PairingSecret::generate(&mut DynEntropy(&mut *self.ports.entropy))?;
            let pairing_id = secret
                .pairing_id()
                .map_err(|_| SyncError::Invalid("pairing id"))?;
            match server.reserve_pairing(&pairing_id) {
                Ok(_) => {
                    reserved = Some((secret, pairing_id));
                    break;
                }
                Err(e) if e.code() == Some(ErrorCode::AlreadyExists) => continue,
                Err(e) => return Err(e.into()),
            }
        }
        let (secret, pairing_id) =
            reserved.ok_or(SyncError::Invalid("no free pairing slot on the server"))?;
        let expires_at = self.ports.clock.now_ms()
            + i64::try_from(hangar_drive_crypto::pairing::OFFER_LIFETIME_MS).unwrap_or(600_000);
        let code = group(&secret.reveal(), 4);
        let content = OfferContent {
            server_url: hangar_drive_crypto::pairing::parse_server_url(url)
                .map_err(|_| SyncError::Invalid("server url"))?,
            spki_pin: self.persisted.pin,
            server: account
                .server_id()
                .ok_or(SyncError::NotSetUp("the server ID is not known yet"))?,
            account: *account.id(),
            inviter: *account.device(),
            head: account.log_head()?,
            secret: PairingSecret::parse(&secret.reveal())
                .map_err(|_| SyncError::Invalid("pairing secret"))?,
            expires_at_ms: u64::try_from(expires_at).unwrap_or(0),
        };
        let offer = content
            .sign(account.identity())
            .map_err(|_| SyncError::Invalid("offer"))?;
        let bytes = offer.encode().map_err(|_| SyncError::Invalid("offer"))?;
        let id = pairing_id.to_string();
        self.offers.insert(
            id.clone(),
            OpenOffer {
                secret,
                expires_at,
                request: None,
            },
        );
        Ok(PairingOfferView {
            id,
            link: crate::links::pairing_link(&bytes),
            code,
            host: url_host(url).unwrap_or_default(),
            account: account.id().to_hex(),
            qr: None,
            expires_at,
        })
    }

    fn poll_offer(&mut self, id: &str) {
        let now = self.now();
        let (Some(account), Some(server)) = (self.account.as_ref(), self.server.as_mut()) else {
            return;
        };
        let Some(offer) = self.offers.get_mut(id) else {
            return;
        };
        if now > offer.expires_at {
            self.offers.remove(id);
            self.events.push(BackendEvent::PairRequestGone {
                offer_id: id.to_owned(),
            });
            return;
        }
        if offer.request.is_some() {
            return;
        }
        let Ok(pairing_id) = offer.secret.pairing_id() else {
            return;
        };
        let Ok(Some(request)) = server.get_pairing(&pairing_id) else {
            return;
        };
        let Ok(verified) = offer.secret.verify_request(account.id(), &request) else {
            return;
        };
        let safety = NumberRows::of(&safety_number(
            account.id(),
            &request.device,
            &verified.keys,
        ));
        offer.request = Some(request);
        let similar_to = self.similar_device_name(&verified.name, None);
        self.events.push(BackendEvent::PairRequest {
            request: PairRequestView {
                offer_id: id.to_owned(),
                device_name: verified.name,
                path: PairPath::Link,
                safety,
                similar_to,
            },
        });
    }

    /// The new device that answered an open offer, with its safety number, as the window was
    /// told it; `None` while nobody answered or for an unknown offer. The shell names both in
    /// its own confirmation before it accepts (security review L2).
    pub fn pair_request(&self, offer_id: &str) -> Option<PairRequestView> {
        let account = self.account.as_ref()?;
        let offer = self.offers.get(offer_id)?;
        let request = offer.request.as_ref()?;
        let verified = offer.secret.verify_request(account.id(), request).ok()?;
        Some(PairRequestView {
            offer_id: offer_id.to_owned(),
            similar_to: self.similar_device_name(&verified.name, None),
            device_name: verified.name,
            path: PairPath::Link,
            safety: NumberRows::of(&safety_number(
                account.id(),
                &request.device,
                &verified.keys,
            )),
        })
    }

    /// The person's answer to a new device (`answerPairRequest`). Accepted or declined, the
    /// slot is closed on the server afterwards, so the request does not wait there until it
    /// expires (finding E2E-6); a slot that could not be closed goes when it expires.
    pub fn answer_pair_request(&mut self, offer_id: &str, accept: bool) -> Result<(), SyncError> {
        let Some(offer) = self.offers.remove(offer_id) else {
            return Ok(());
        };
        let Some(request) = offer.request else {
            return Ok(());
        };
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let added = if accept {
            match offer.secret.verify_request(account.id(), &request) {
                Ok(verified) => {
                    let device = LogDevice {
                        id: request.device,
                        keys: verified.keys,
                        recovery: false,
                        proof: request.proof,
                    };
                    let now = u64::try_from(self.ports.clock.now_ms()).unwrap_or(0);
                    account.add_device(
                        server.as_mut(),
                        &mut *self.ports.store,
                        device,
                        &verified.name,
                        now,
                        &mut *self.ports.entropy,
                    )
                }
                Err(_) => Err(SyncError::Invalid("pairing request")),
            }
        } else {
            Ok(())
        };
        if let Ok(pairing_id) = offer.secret.pairing_id() {
            let _ = server.close_pairing(&pairing_id);
        }
        added
    }

    /// What a link names, read offline before anything is sent (`inspectLink`, N2): an
    /// invite, a pairing offer or a recovery sheet, with its host and account. The window shows
    /// them and connects only after the person confirmed. Nothing is checked against a server
    /// and nothing is kept; an expired offer is reported by `startPairing`.
    pub fn inspect_link(&self, link: &str) -> ApiResult<InspectedLink, LinkProblem> {
        use crate::links::LinkError;
        let problem = |e: LinkError| match e {
            LinkError::NotALink => LinkProblem::NotALink,
            LinkError::Malformed => LinkProblem::Damaged,
            LinkError::Insecure => LinkProblem::Insecure,
        };
        let host_of = |url: &str| url_host(url).ok_or(LinkProblem::Damaged);
        let inspected = match crate::links::parse_invite(link) {
            Ok(invite) => host_of(invite.server_url.as_str()).map(|host| InspectedLink::Invite {
                punycode: has_punycode(&host),
                host,
                pinned: invite.pin.is_some(),
            }),
            Err(LinkError::NotALink) => match crate::links::parse_pairing_link(link) {
                Ok(bytes) => match PairingOffer::decode(&bytes) {
                    Ok(offer) => {
                        host_of(offer.content.server_url.as_str()).map(|host| InspectedLink::Pair {
                            punycode: has_punycode(&host),
                            host,
                            account: offer.content.account.to_hex(),
                            pinned: offer.content.spki_pin.is_some(),
                        })
                    }
                    Err(_) => Err(LinkProblem::Damaged),
                },
                Err(LinkError::NotALink) => match crate::links::parse_recovery_link(link) {
                    Ok(sheet) => {
                        host_of(sheet.server_url.as_str()).map(|host| InspectedLink::Recover {
                            punycode: has_punycode(&host),
                            host,
                            account: sheet.account.to_hex(),
                            pinned: sheet.pin.is_some(),
                        })
                    }
                    Err(e) => Err(problem(e)),
                },
                Err(e) => Err(problem(e)),
            },
            Err(e) => Err(problem(e)),
        };
        match inspected {
            Ok(link) => ApiResult::Ok(link),
            Err(e) => ApiResult::Err(e),
        }
    }

    /// Starts pairing on a new device with the link of an offer (`startPairing`).
    pub fn start_pairing(
        &mut self,
        link: &str,
        device_name: &str,
    ) -> Result<ApiResult<NumberRows, PairError>, SyncError> {
        // Only a device without an account pairs (security review H1). A set-up device that
        // joined another account would overwrite its own identity in the keychain, and the
        // clean-up of a failed join would delete its epoch secrets; a window that called this
        // on a set-up device could so move it, and the folders the person then adds, into a
        // stranger's account. A second pairing while one is open is refused for the same reason.
        if self.account.is_some() || self.joining.is_some() {
            return Err(SyncError::Invalid(
                "this device already belongs to an account or is pairing",
            ));
        }
        let Ok(bytes) = crate::links::parse_pairing_link(link) else {
            return Ok(ApiResult::Err(PairError::NotALink));
        };
        let Ok(offer) = PairingOffer::decode(&bytes) else {
            return Ok(ApiResult::Err(PairError::NotALink));
        };
        if offer
            .check_fresh(u64::try_from(self.now()).unwrap_or(0))
            .is_err()
        {
            return Ok(ApiResult::Err(PairError::Expired));
        }
        let identity = DeviceIdentity::generate(&mut DynEntropy(&mut *self.ports.entropy))
            .map_err(|_| SyncError::Invalid("identity"))?;
        let mut device_bytes = [0u8; 16];
        self.ports.entropy.fill(&mut device_bytes)?;
        let device = DeviceId::from_bytes(device_bytes);
        let account = offer.content.account;
        let request = offer
            .content
            .secret
            .request(
                &identity,
                &account,
                device,
                device_name,
                &mut DynEntropy(&mut *self.ports.entropy),
            )
            .map_err(|_| SyncError::Invalid("pairing request"))?;
        let mut config =
            ServerConfig::new(offer.content.server_url.as_str(), offer.content.spki_pin)?;
        config.server = Some(offer.content.server);
        let session = SessionIdentity {
            account,
            device,
            prover: prover(
                DeviceIdentity::import(&identity.export())
                    .map_err(|_| SyncError::Invalid("identity"))?,
            ),
        };
        let mut server = match (self.ports.server)(&config, Some(session)) {
            Ok(s) => s,
            Err(NetError::Tls(_)) => return Ok(ApiResult::Err(PairError::Insecure)),
            Err(_) => return Ok(ApiResult::Err(PairError::Unreachable)),
        };
        let pairing_id = offer
            .content
            .secret
            .pairing_id()
            .map_err(|_| SyncError::Invalid("pairing id"))?;
        match server.post_pairing(&pairing_id, &request) {
            Ok(()) => {}
            Err(e) if e.code() == Some(ErrorCode::NotFound) => {
                return Ok(ApiResult::Err(PairError::Expired))
            }
            Err(_) => return Ok(ApiResult::Err(PairError::Unreachable)),
        }
        let safety = NumberRows::of(&safety_number(&account, &device, &identity.public_keys()));
        self.joining = Some(Joining {
            identity_export: identity.export(),
            account,
            device,
            name: device_name.to_owned(),
            offer,
            server,
            config,
        });
        Ok(ApiResult::Ok(safety))
    }

    /// Forgets the account on this device (security review L1): the device identity and every
    /// epoch secret leave the keychain, the stored account and the folders' sync state leave the
    /// index, and the engine is back at the setup. The files in the folders stay where they are.
    /// `removed_by` keeps the "this device was removed" warning until the device is set up
    /// again. Every step is tried; the first failure is returned.
    fn forget_device(&mut self, removed_by: Option<String>) -> Result<(), SyncError> {
        let mut first =
            crate::account::forget(&mut *self.ports.store, &mut *self.ports.keychain).err();
        // A pending recovery's key goes too: forgetting is the person's choice, or the device
        // was removed.
        if self.recovery_pending {
            if let Err(e) = self.clear_pending_recovery() {
                first.get_or_insert(e);
            }
        }
        for (id, _) in &self.persisted.folders {
            if let Err(e) = self.ports.store.delete_folder(id) {
                first.get_or_insert(e.into());
            }
        }
        self.account = None;
        self.server = None;
        self.folders.clear();
        self.activity.clear();
        self.notices.clear();
        self.storage = None;
        self.pin_mismatch = false;
        self.pending = None;
        self.recovering = None;
        self.renewal = None;
        self.offers.clear();
        self.joining = None;
        self.last_sync = None;
        self.last_file = None;
        self.undo.clear();
        self.remote_deletes.clear();
        self.server_candidate = None;
        self.persisted = Persisted {
            removed_by,
            ..Persisted::default()
        };
        if let Err(e) = self.save() {
            first.get_or_insert(e);
        }
        first.map_or(Ok(()), Err)
    }

    /// Resets this device (`resetDevice`): the account is forgotten as when the device is
    /// removed ([`Self::forget_device`]), without the warning. For "pair again" after a removal
    /// and for starting over.
    ///
    /// Refused with [`SyncError::RecoveryPending`] while a recovery sent its append and this
    /// device has not joined yet (follow-up review LOW 7): its key may be the account's only
    /// one. [`Self::reset_device_discarding_recovery`] resets anyway.
    pub fn reset_device(&mut self) -> Result<(), SyncError> {
        if self.recovery_pending && self.account.is_none() {
            return Err(SyncError::RecoveryPending);
        }
        self.forget_device(None)
    }

    /// Resets this device also while a recovery is pending (`resetDeviceDiscardingRecovery`):
    /// the pending recovery's key leaves the keychain with every other secret. Only after the
    /// person confirmed that the account may then be lost for good.
    pub fn reset_device_discarding_recovery(&mut self) -> Result<(), SyncError> {
        self.forget_device(None)
    }

    /// Disconnects this device from its account (`disconnectThisDevice`): after "these are not
    /// my devices" right after joining (N2), and from the device list. A device never removes
    /// itself from the account log (ADR 0001, section 4), and the server has no call that ends a
    /// session, so the device forgets the account here at once, as a reset does: its identity
    /// and every epoch secret leave the keychain, the account and the folders' sync state leave
    /// the index, and the session token, which lives only in memory, goes with the server
    /// connection and runs out on the server within the hour. The device stays in the
    /// account's log until a device of that account removes it; without its keys it can
    /// neither sign in nor open anything (ADR 0001, section 4, "Disconnecting this device").
    /// Files in the folders stay where they are.
    pub fn disconnect_this_device(&mut self) -> Result<(), SyncError> {
        self.forget_device(None)
    }

    /// Stops a pairing of this new device (`cancelPairing`).
    pub fn cancel_pairing(&mut self) {
        self.joining = None;
    }

    fn poll_joining(&mut self) {
        let Some(joining) = self.joining.as_mut() else {
            return;
        };
        if joining
            .offer
            .check_fresh(u64::try_from(self.ports.clock.now_ms()).unwrap_or(0))
            .is_err()
        {
            self.joining = None;
            self.events.push(BackendEvent::PairResult {
                result: PairResult::Failed {
                    error: PairError::Expired,
                },
            });
            return;
        }
        let Ok(identity) = DeviceIdentity::import(&joining.identity_export) else {
            return;
        };
        let keys = identity.public_keys();
        let joined = Account::join(
            joining.server.as_mut(),
            &mut *self.ports.keychain,
            &mut *self.ports.store,
            identity,
            joining.account,
            joining.device,
            &joining.name,
            &[joining.offer.content.head],
        );
        let mut account = match joined {
            Ok(account) => account,
            Err(SyncError::AlreadySetUp) => {
                // An identity or account is already stored here (security review H1): the join
                // touched nothing and never will, so the pairing ends instead of retrying.
                self.joining = None;
                self.events.push(BackendEvent::PairResult {
                    result: PairResult::Failed {
                        error: PairError::OtherAccount,
                    },
                });
                return;
            }
            // Not added yet (or the server is down): try again at the next tick.
            Err(_) => return,
        };
        if hangar_drive_crypto::pairing::check_joined(
            account.state(),
            &joining.offer,
            &joining.device,
            &keys,
        )
        .is_err()
        {
            // The join stored the other account and its secrets; none of it may stay (security
            // review L1).
            drop(account);
            let _ = crate::account::forget(&mut *self.ports.store, &mut *self.ports.keychain);
            self.joining = None;
            self.events.push(BackendEvent::PairResult {
                result: PairResult::Failed {
                    error: PairError::OtherAccount,
                },
            });
            return;
        }
        account.set_server_id(joining.offer.content.server);
        let _ = account.save(&mut *self.ports.store);
        let Some(joining) = self.joining.take() else {
            return;
        };
        self.persisted.server_url = Some(joining.config.url.to_string());
        self.persisted.pin = joining.config.pin;
        self.account = Some(account);
        self.server = Some(joining.server);
        let _ = self.save();
        // The account's devices, for the person to confirm these are their own (N2).
        let devices = self
            .list_devices()
            .map(|list| list.devices)
            .unwrap_or_default();
        self.events.push(BackendEvent::PairResult {
            result: PairResult::Joined { devices },
        });
    }

    // -- Folders ----------------------------------------------------------------------------

    /// Adds a new folder of the account at `path` (`addFolder`, `finishSetup`).
    pub fn add_folder(&mut self, path: &str, name: &str) -> Result<String, SyncError> {
        self.check_root(path, None)?;
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let mut bytes = [0u8; 16];
        self.ports.entropy.fill(&mut bytes)?;
        let id = FolderId::from_bytes(bytes);
        account.create_folder(
            server.as_mut(),
            &mut *self.ports.store,
            id,
            name,
            &mut *self.ports.entropy,
        )?;
        self.attach(id, path)?;
        Ok(hex_id(&id))
    }

    /// Syncs an existing folder of the account at `path` (`addAccountFolder`, `joinFolders`).
    /// A place that already holds files is joined (ADR 0001, section 3).
    pub fn add_account_folder(&mut self, folder: &str, path: &str) -> Result<(), SyncError> {
        let id = parse_folder(folder)?;
        self.check_root(path, Some(id))?;
        self.attach(id, path)
    }

    fn attach(&mut self, id: FolderId, path: &str) -> Result<(), SyncError> {
        self.open_folder_at(id, path)?;
        if let Some(f) = self.folders.get(&id) {
            f.sync.write_marker(&*f.fs)?;
        }
        self.persisted.folders.retain(|(f, _)| *f != id);
        self.persisted.folders.push((id, path.to_owned()));
        self.save()
    }

    /// Stops syncing a folder on this device; its files stay (`stopFolder`).
    pub fn stop_folder(&mut self, folder: &str) -> Result<(), SyncError> {
        let id = parse_folder(folder)?;
        self.folders.remove(&id);
        self.ports.store.delete_folder(&id)?;
        self.persisted.folders.retain(|(f, _)| *f != id);
        self.save()
    }

    /// Removes a folder for all devices (`deleteFolderEverywhere`): the folder list without it,
    /// then the retire call. Its versions stay restorable for the window.
    pub fn delete_folder_everywhere(&mut self, folder: &str) -> Result<(), SyncError> {
        let id = parse_folder(folder)?;
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let mut list = account.folders();
        list.retain(|f| f.folder != id);
        account.put_folder_list(
            server.as_mut(),
            hangar_drive_crypto::folder_keys::FolderList::new(list)?,
            &mut *self.ports.entropy,
        )?;
        server.retire(&id)?;
        let name = self.folders.get(&id).map(|f| f.sync.meta().name.clone());
        if let Some(name) = name.or_else(|| {
            self.persisted
                .known_folders
                .iter()
                .find(|(f, _)| *f == id)
                .map(|(_, n)| n.clone())
        }) {
            if !self
                .persisted
                .deleted_folders
                .iter()
                .any(|(f, ..)| *f == id)
            {
                let now = self.now();
                self.persisted.deleted_folders.push((id, name, now));
            }
        }
        self.persisted.known_folders.retain(|(f, _)| *f != id);
        self.stop_folder(folder)
    }

    /// Brings a folder deleted everywhere back within the retention window
    /// (`restoreDeletedFolder`, ADR 0001, section 3, "Folder list"): the server's retire call is
    /// undone, then the folder list names it again. It shows under "Ordner hinzufügen" on every
    /// device; a device that still syncs it carries on. Both steps may be repeated: a folder that
    /// is no longer retired is fine.
    pub fn restore_deleted_folder(&mut self, folder: &str) -> Result<(), SyncError> {
        let id = parse_folder(folder)?;
        let name = self
            .persisted
            .deleted_folders
            .iter()
            .find(|(f, ..)| *f == id)
            .map(|(_, name, _)| name.clone())
            .ok_or(SyncError::Invalid("unknown deleted folder"))?;
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        match server.bring_back(&id) {
            Ok(()) => {}
            // The server answers so for a folder that is not retired (any more).
            Err(e) if e.code() == Some(ErrorCode::BadRequest) => {}
            Err(e) if e.code() == Some(ErrorCode::NotFound) => {
                // The window passed meanwhile; the folder cannot come back.
                self.persisted.deleted_folders.retain(|(f, ..)| *f != id);
                self.save()?;
                return Err(e.into());
            }
            Err(e) => return Err(e.into()),
        }
        account.refresh(
            server.as_mut(),
            &mut *self.ports.keychain,
            &mut *self.ports.store,
        )?;
        let mut list = account.folders();
        if !list.iter().any(|f| f.folder == id) {
            list.push(FolderEntry {
                folder: id,
                name: name.clone(),
            });
            account.put_folder_list(
                server.as_mut(),
                FolderList::new(list)?,
                &mut *self.ports.entropy,
            )?;
        }
        self.persisted.deleted_folders.retain(|(f, ..)| *f != id);
        if !self.persisted.known_folders.iter().any(|(f, _)| *f == id) {
            self.persisted.known_folders.push((id, name));
        }
        self.save()
    }

    /// Pauses all syncing (`pause`); `until` for "tomorrow" comes from the app (local midnight).
    pub fn pause(&mut self, duration: PauseDuration, until: Option<i64>) -> Result<(), SyncError> {
        self.persisted.paused_until = Some(match duration {
            PauseDuration::Hour => Some(self.now() + 3_600_000),
            PauseDuration::Tomorrow => until.or(Some(self.now() + 12 * 3_600_000)),
            PauseDuration::Manual => None,
        });
        self.save()
    }

    /// Resumes (`resume`).
    pub fn resume(&mut self) -> Result<(), SyncError> {
        self.persisted.paused_until = None;
        self.save()
    }

    /// Pauses or resumes one folder (`pauseFolder`, `resumeFolder`).
    pub fn set_folder_paused(&mut self, folder: &str, paused: bool) -> Result<(), SyncError> {
        let id = parse_folder(folder)?;
        let f = self
            .folders
            .get_mut(&id)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        f.sync.set_paused(paused, &mut *self.ports.store)
    }

    /// Entries never synced (`listNotSynced`).
    pub fn list_not_synced(&self, folder: &str) -> Result<Vec<NotSyncedEntry>, SyncError> {
        let f = self.folder(folder)?;
        Ok(f.sync
            .meta()
            .not_synced
            .iter()
            .map(|(path, reason)| NotSyncedEntry {
                path: path.clone(),
                reason: if reason == "link" { "link" } else { "system" }.into(),
            })
            .collect())
    }

    /// The folder safety number of the current head (`getFolderNumber`), after one pull so it
    /// is never an outdated frontier; `None` without a connection.
    pub fn get_folder_number(&mut self, folder: &str) -> Result<Option<NumberRows>, SyncError> {
        let id = parse_folder(folder)?;
        if let Err(e) = self.tick_inner() {
            if e.is_offline() {
                return Ok(None);
            }
        }
        let account = self
            .account
            .as_ref()
            .ok_or(SyncError::NotSetUp("no account"))?;
        let f = self
            .folders
            .get(&id)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        Ok(f.sync.view().frontier().map(|e| {
            NumberRows::of(&folder_safety_number(
                account.id(),
                &id,
                &e.commit,
                e.height,
            ))
        }))
    }

    /// The new place of a missing folder (`findMissingFolder`): the marker there must name the
    /// folder.
    pub fn relocate_folder(&mut self, folder: &str, path: &str) -> Result<bool, SyncError> {
        let id = parse_folder(folder)?;
        self.check_root(path, Some(id))?;
        let (fs, watcher) = (self.ports.fs)(Path::new(path))?;
        let mut buf = [0u8; 64];
        let n = fs
            .read_at(&crate::folder::marker_path(), 0, &mut buf)
            .unwrap_or(0);
        if &buf[..n] != id.to_hex().as_bytes() {
            return Ok(false);
        }
        let f = self
            .folders
            .get_mut(&id)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        f.fs = fs;
        f.watcher = watcher;
        f.path = path.to_owned();
        f.sync.clear_stop(&mut *self.ports.store)?;
        f.sync.request_full_scan();
        self.persisted.folders.retain(|(x, _)| *x != id);
        self.persisted.folders.push((id, path.to_owned()));
        self.save()?;
        Ok(true)
    }

    /// "Download again" for a missing folder (`redownloadFolder`, UX 8.2): the folder's old
    /// place, which the app created again, is filled from the server's tree. Nothing is deleted
    /// anywhere; files that are at the place already are joined as at a first sync (ADR 0001,
    /// section 3). Only for a folder that stopped because its place went missing.
    pub fn redownload_folder(&mut self, folder: &str) -> Result<(), SyncError> {
        let id = parse_folder(folder)?;
        let f = self
            .folders
            .get(&id)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        if f.sync.state() != FolderState::Stopped(StopReason::MarkerMissing) {
            return Err(SyncError::Invalid("the folder is not missing"));
        }
        let path = f.path.clone();
        self.check_root(&path, Some(id))?;
        let (fs, watcher) = (self.ports.fs)(Path::new(&path))?;
        let f = self
            .folders
            .get_mut(&id)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        f.fs = fs;
        f.watcher = watcher;
        f.last_full_scan = 0;
        f.failed_rounds = 0;
        f.last_error = None;
        f.sync.forget_disk(&mut *self.ports.store)?;
        f.sync.write_marker(&*f.fs)
    }

    /// The path of a synced folder, for the app to create its place again
    /// (`redownloadFolder`).
    pub fn folder_path(&self, folder: &str) -> Result<String, SyncError> {
        Ok(self.folder(folder)?.path.clone())
    }

    /// Checks `path` as a sync root against every other folder's root (security review M4);
    /// `except` is the folder that moves there.
    fn check_root(&self, path: &str, except: Option<FolderId>) -> Result<PathBuf, SyncError> {
        let existing: Vec<PathBuf> = self
            .persisted
            .folders
            .iter()
            .filter(|(id, _)| Some(*id) != except)
            .map(|(_, p)| PathBuf::from(p))
            .collect();
        Ok((self.ports.roots)(Path::new(path), &existing)?)
    }

    /// Whether `path` may become a sync root (`pickFolder`), with `except` the folder that would
    /// move there; `None` when it may. The window shows the reason before anything is created.
    pub fn check_folder(&self, path: &str, except: Option<&str>) -> Option<FolderRefusalView> {
        use crate::roots::RootError;
        let except = except.and_then(|f| FolderId::from_hex(f).ok());
        let error = match self.check_root(path, except) {
            Ok(_) => return None,
            Err(SyncError::Root(e)) => e,
            Err(_) => {
                return Some(FolderRefusalView {
                    reason: FolderRefusal::NoAccess,
                    folder: None,
                })
            }
        };
        let reason = match error {
            RootError::Unresolved(_) => FolderRefusal::NoAccess,
            RootError::Overlaps => FolderRefusal::Nested,
            RootError::DriveRoot => FolderRefusal::Root,
            // A shell junction is a system object to Windows Explorer, so the window says the
            // folder belongs to the system.
            RootError::HoldsIndex
            | RootError::System
            | RootError::OtherCloud(_)
            | RootError::ShellJunction => FolderRefusal::System,
        };
        let folder = if reason == FolderRefusal::Nested {
            self.overlapping_folder(path, except)
        } else {
            None
        };
        Some(FolderRefusalView { reason, folder })
    }

    /// The name of the synced folder `path` lies in or around.
    fn overlapping_folder(&self, path: &str, except: Option<FolderId>) -> Option<String> {
        let canonical = |p: &str| {
            std::fs::canonicalize(p)
                .map(|c| crate::roots::key(&c))
                .unwrap_or_else(|_| crate::roots::key(Path::new(p)))
        };
        let wanted = canonical(path);
        self.folders
            .iter()
            .filter(|(id, _)| Some(**id) != except)
            .find(|(_, f)| crate::roots::overlap(&wanted, &canonical(&f.path)))
            .map(|(_, f)| f.sync.meta().name.clone())
    }

    fn folder(&self, folder: &str) -> Result<&LocalFolder, SyncError> {
        let id = parse_folder(folder)?;
        self.folders
            .get(&id)
            .ok_or(SyncError::Invalid("unknown folder"))
    }

    // -- Problems ---------------------------------------------------------------------------

    /// The names of the held deletes (`listMassDelete`).
    pub fn list_mass_delete(&self, folder: &str) -> Result<Vec<String>, SyncError> {
        let f = self.folder(folder)?;
        Ok(f.sync
            .meta()
            .held
            .iter()
            .filter_map(|i| f.sync.synced().path_string(i))
            .collect())
    }

    /// The person's decision on held deletes (`resolveMassDelete`).
    pub fn resolve_mass_delete(&mut self, folder: &str, restore: bool) -> Result<u64, SyncError> {
        let id = parse_folder(folder)?;
        let f = self
            .folders
            .get_mut(&id)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        Ok(f.sync.resolve_held(restore, &mut *self.ports.store)? as u64)
    }

    /// The paths of the held incoming file deletes (`listIncomingDelete`).
    pub fn list_incoming_delete(&self, folder: &str) -> Result<Vec<String>, SyncError> {
        let f = self.folder(folder)?;
        let synced = f.sync.synced();
        Ok(f.sync
            .meta()
            .incoming_held
            .iter()
            .filter(|i| synced.get(i).is_some_and(|n| !n.is_dir()))
            .filter_map(|i| synced.path_string(i))
            .collect())
    }

    /// The state of the held incoming deletes, for binding an approval to what the person saw
    /// ([`FolderSync::approve_incoming`]).
    pub fn incoming_delete_revision(&self, folder: &str) -> Result<u64, SyncError> {
        Ok(self.folder(folder)?.sync.meta().incoming_revision)
    }

    /// The person's decision on held incoming deletes (`resolveIncomingDelete`): `restore`
    /// brings the files back on every device with a new commit; otherwise exactly the deletes
    /// of `revision` are carried out here. Returns the files.
    pub fn resolve_incoming_delete(
        &mut self,
        folder: &str,
        restore: bool,
        revision: u64,
    ) -> Result<u64, SyncError> {
        if restore {
            return self.with_ctx(folder, |sync, cx| sync.restore_incoming(cx));
        }
        let id = parse_folder(folder)?;
        let f = self
            .folders
            .get_mut(&id)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        Ok(f.sync.approve_incoming(revision, &mut *self.ports.store)? as u64)
    }

    /// Whether the server still shows an older state (`checkOlderState`).
    pub fn check_older_state(&mut self, folder: &str) -> Result<bool, SyncError> {
        let id = parse_folder(folder)?;
        let f = self
            .folders
            .get(&id)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        Ok(matches!(
            f.sync.state(),
            FolderState::Stopped(StopReason::OlderState)
        ))
    }

    /// The re-anchor after the person confirmed (`reanchor`).
    pub fn reanchor(&mut self, folder: &str) -> Result<(), SyncError> {
        let id = parse_folder(folder)?;
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let f = self
            .folders
            .get_mut(&id)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        let mut cx = Ctx {
            account,
            server: server.as_mut(),
            keychain: &mut *self.ports.keychain,
            fs: &*f.fs,
            store: &mut *self.ports.store,
            clock: &*self.ports.clock,
            entropy: &mut *self.ports.entropy,
            settings: &self.folder_settings,
        };
        f.sync.reanchor(&mut cx)
    }

    /// The server key number of the key the server presents instead of the pinned one
    /// (`getServerNumber`, ADR 0001, section 6, "Pin rotation"), with the server CLI command
    /// that prints the number of the server's own key. The key comes from the aborted handshake
    /// and is trusted only once the person confirmed that both numbers match
    /// ([`Self::confirm_server_number`]).
    pub fn server_number(&mut self) -> Result<ServerNumberView, SyncError> {
        let server = self
            .account
            .as_ref()
            .and_then(Account::server_id)
            .ok_or(SyncError::NotSetUp("no account"))?;
        let mut seen = self.server.as_ref().and_then(|s| s.seen_pin());
        if seen.is_none() {
            // One more attempt shows the server's key again.
            if let Err(e) = self.tick_inner() {
                self.note_net(&e);
            }
            seen = self.server.as_ref().and_then(|s| s.seen_pin());
        }
        let pin = seen.ok_or(SyncError::Invalid("the server presents no other key"))?;
        self.server_candidate = Some(pin);
        Ok(ServerNumberView {
            number: NumberRows::of(&server_key_number(&server, &pin)),
            command: SERVER_NUMBER_COMMAND.to_owned(),
            pin,
        })
    }

    /// The person confirmed that the server number matches the server CLI's
    /// (`confirmServerNumber`): the key whose number was shown becomes the pin, and the device
    /// connects with it. Never any other key: `expected_pin` is the pin of the number the
    /// person compared ([`ServerNumberView::pin`]), and it is taken only while it is still the
    /// candidate of the last shown number (security review N7). A number shown again for
    /// another key in between, by another window call or because the server presented another
    /// key, makes this fail and keeps the old pin.
    pub fn confirm_server_number(&mut self, expected_pin: &[u8; 32]) -> Result<(), SyncError> {
        let candidate = self
            .server_candidate
            .ok_or(SyncError::Invalid("no server number was shown"))?;
        // A pin is a public key hash, not a secret: a plain comparison is enough.
        if candidate != *expected_pin {
            return Err(SyncError::Invalid(
                "the server number shown is not the one confirmed",
            ));
        }
        self.server_candidate = None;
        let pin = candidate;
        self.persisted.pin = Some(pin);
        self.save()?;
        self.connect()?;
        self.pin_mismatch = false;
        Ok(())
    }

    /// The new server identity from a pairing offer of a device that still connects
    /// (`fixServerWithOffer`, ADR 0001, section 6, "Pin rotation"): only the server URL and the
    /// pin are taken, and only from an offer of this account and server whose signature verifies
    /// against a current, regular device of the verified log. This device does not pair again.
    pub fn fix_server_with_offer(
        &mut self,
        link: &str,
    ) -> Result<ApiResult<(), FixServerError>, SyncError> {
        let Some(offer) = crate::links::parse_pairing_link(link)
            .ok()
            .and_then(|bytes| PairingOffer::decode(&bytes).ok())
        else {
            return Ok(ApiResult::Err(FixServerError::NotALink));
        };
        if offer
            .check_fresh(u64::try_from(self.now()).unwrap_or(0))
            .is_err()
        {
            return Ok(ApiResult::Err(FixServerError::Expired));
        }
        let account = self
            .account
            .as_ref()
            .ok_or(SyncError::NotSetUp("no account"))?;
        let server = account
            .server_id()
            .ok_or(SyncError::NotSetUp("the server ID is not known yet"))?;
        let address = match offer.server_address(account.state(), &server) {
            Ok(address) => address,
            Err(PairingError::AheadOfLog { .. }) => {
                match self.address_after_log_check(&offer, &server)? {
                    Some(address) => address,
                    None => return Ok(ApiResult::Err(FixServerError::OtherAccount)),
                }
            }
            Err(_) => return Ok(ApiResult::Err(FixServerError::OtherAccount)),
        };
        self.persisted.server_url = Some(address.url.to_string());
        self.persisted.pin = address.spki_pin;
        self.save()?;
        self.connect()?;
        self.pin_mismatch = false;
        self.server_candidate = None;
        Ok(ApiResult::Ok(()))
    }

    /// An offer whose log head is newer than this device's verified log (ADR 0001, section 6).
    /// The offer's signature is checked before anything of the offered server is used
    /// (security review M2): the log is read through a temporary connection to the offered
    /// address into a fresh `AccountState`, which must contain this device's own verified head,
    /// and the offer is checked against that state. Nothing is stored and the account is not
    /// refreshed, so a forged offer that points at a server of the attacker's changes no feed
    /// cursor, record or log of this device; the old address stays on any failure. Only once
    /// the address is taken does the normal refresh read the log through it.
    fn address_after_log_check(
        &mut self,
        offer: &PairingOffer,
        server: &ServerId,
    ) -> Result<Option<ServerAddress>, SyncError> {
        let account = self
            .account
            .as_ref()
            .ok_or(SyncError::NotSetUp("no account"))?;
        let own_head = account.log_head()?;
        let mut config =
            ServerConfig::new(offer.content.server_url.as_str(), offer.content.spki_pin)?;
        config.server = Some(*server);
        let identity = DeviceIdentity::import(&account.identity().export())
            .map_err(|_| SyncError::Corrupt("device identity".into()))?;
        let session = SessionIdentity {
            account: *account.id(),
            device: *account.device(),
            prover: prover(identity),
        };
        let checked = (self.ports.server)(&config, Some(session))
            .map_err(SyncError::from)
            .and_then(|mut temporary| {
                let state = crate::recovery::fetch_log(temporary.as_mut(), *account.id())?;
                // Verified from this device's own anchor: the log it already verified.
                state.check_anchor(&own_head)?;
                Ok(offer.server_address(&state, server).ok())
            });
        match checked {
            Ok(address) => Ok(address),
            Err(e) if e.is_offline() => Err(e),
            Err(_) => Ok(None),
        }
    }

    /// Hides a warning on this device only (`dismissSuspect`; ADR 0001, section 5: no shared
    /// dismissal). Only a warning the engine shows right now and that may be hidden (follow-up
    /// check N-3): an ID the window makes up would otherwise hide a warning before it appears,
    /// and "removed, the server says" is only ever confirmed, never hidden. The list keeps the
    /// newest [`MAX_DISMISSED`] IDs.
    pub fn dismiss_warning(&mut self, warning_id: &str) -> Result<(), SyncError> {
        let shown = self.snapshot().warnings;
        let warning = shown
            .iter()
            .find(|w| self::warning_id(w) == warning_id)
            .ok_or(SyncError::Invalid("no such warning is shown"))?;
        if !dismissible(warning) {
            return Err(SyncError::Invalid("this warning cannot be hidden"));
        }
        remember_dismissed(&mut self.persisted.dismissed, warning_id);
        self.save()
    }

    // -- Conflicts and names ----------------------------------------------------------------

    fn conflict_groups(f: &LocalFolder) -> Vec<(ItemId, Vec<ItemId>)> {
        let tree = f.sync.local();
        let mut groups: BTreeMap<ItemId, Vec<ItemId>> = BTreeMap::new();
        for (id, node) in tree.iter() {
            if let Some(original) = node.conflict_of {
                if tree.contains(&original) {
                    groups.entry(original).or_default().push(*id);
                }
            }
        }
        groups.into_iter().collect()
    }

    /// Every conflict group (`listConflicts`).
    pub fn list_conflicts(&self) -> Vec<ConflictGroup> {
        let mut out = Vec::new();
        for (fid, f) in &self.folders {
            let tree = f.sync.local();
            for (original, copies) in Self::conflict_groups(f) {
                let Some(orig) = tree.get(&original) else {
                    continue;
                };
                let version = |id: &ItemId, is_original: bool| {
                    let node = tree.get(id)?;
                    let (modified, size) =
                        node.kind.file().map_or((0, 0), |v| (v.mtime_ms, v.size));
                    Some(ConflictVersion {
                        id: hex_id(id),
                        name: node.name.clone(),
                        device: String::new(),
                        modified,
                        size,
                        original: is_original,
                    })
                };
                let case_only = copies.iter().all(|c| {
                    tree.get(c).is_some_and(|n| {
                        n.kind == orig.kind
                            && hangar_drive_protocol::name::collision(&n.name, &orig.name).is_some()
                    })
                });
                let mut versions: Vec<ConflictVersion> =
                    version(&original, true).into_iter().collect();
                versions.extend(copies.iter().filter_map(|c| version(c, false)));
                out.push(ConflictGroup {
                    id: format!("{fid}:{original}"),
                    folder_id: hex_id(fid),
                    folder_name: f.sync.meta().name.clone(),
                    path: tree.path_string(&original).unwrap_or_default(),
                    kind: if case_only {
                        ConflictKind::CaseOnly
                    } else {
                        ConflictKind::Content
                    },
                    versions,
                });
            }
        }
        out
    }

    fn split_group(group_id: &str) -> Result<(FolderId, ItemId), SyncError> {
        let (f, i) = group_id
            .split_once(':')
            .ok_or(SyncError::Invalid("group id"))?;
        Ok((
            parse_folder(f)?,
            ItemId::from_hex(i).map_err(|_| SyncError::Invalid("item id"))?,
        ))
    }

    /// "Keep both" (`keepBothConflict`): every copy of the group drops its link.
    pub fn keep_both_conflict(&mut self, group_id: &str) -> Result<(), SyncError> {
        let (fid, original) = Self::split_group(group_id)?;
        let f = self
            .folders
            .get_mut(&fid)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        let copies: Vec<ItemId> = f
            .sync
            .local()
            .iter()
            .filter(|(_, n)| n.conflict_of == Some(original))
            .map(|(id, _)| *id)
            .collect();
        for copy in copies {
            f.sync.drop_conflict_link(&copy, &mut *self.ports.store)?;
        }
        Ok(())
    }

    /// "Keep this" (`keepConflictVersion`): the original's file takes the chosen content and
    /// the copies are deleted; the other contents stay restorable through the history. Returns
    /// an undo token ([`Self::undo`]), empty when the server holds nothing of the group yet.
    pub fn keep_conflict_version(
        &mut self,
        group_id: &str,
        version: &str,
    ) -> Result<String, SyncError> {
        let (fid, original) = Self::split_group(group_id)?;
        let chosen = ItemId::from_hex(version).map_err(|_| SyncError::Invalid("item id"))?;
        let f = self
            .folders
            .get_mut(&fid)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        let tree = f.sync.local().clone();
        // The group as the server holds it now, for the undo: the original and every copy.
        let before = UndoState::of(
            f.sync.remote(),
            std::iter::once(original).chain(
                tree.iter()
                    .filter(|(_, n)| n.conflict_of == Some(original))
                    .map(|(id, _)| *id),
            ),
        );
        let orig_path = tree.path(&original).ok_or(SyncError::Invalid("original"))?;
        if chosen != original {
            let chosen_path = tree.path(&chosen).ok_or(SyncError::Invalid("version"))?;
            let orig_stat =
                f.fs.stat(&orig_path)?
                    .ok_or(SyncError::Invalid("original"))?;
            let size = f.fs.stat(&chosen_path)?.map_or(0, |s| s.size);
            let fs = &*f.fs;
            let mut buf = vec![0u8; usize::try_from(size.min(64 * 1024 * 1024)).unwrap_or(0)];
            let mut offset = 0u64;
            let mut fill = |w: &mut dyn std::io::Write| -> Result<(), FsError> {
                loop {
                    let n = fs.read_at(&chosen_path, offset, &mut buf)?;
                    if n == 0 {
                        return Ok(());
                    }
                    w.write_all(&buf[..n])
                        .map_err(|e| FsError::Io(e.to_string()))?;
                    offset += n as u64;
                }
            };
            fs.write_atomic(
                &orig_path,
                &mut fill,
                orig_stat.mtime_ms.max(self.ports.clock.now_ms()),
                orig_stat.executable,
                Some(crate::ports::Expect {
                    size: orig_stat.size,
                    mtime_ms: orig_stat.mtime_ms,
                    file_id: orig_stat.file_id,
                }),
            )?;
        }
        for (id, node) in tree.iter() {
            if node.conflict_of == Some(original) {
                if let (Some(path), NodeKind::File(v)) = (tree.path(id), &node.kind) {
                    f.fs.remove_file(
                        &path,
                        crate::ports::Expect {
                            size: v.size,
                            mtime_ms: v.mtime_ms,
                            file_id: None,
                        },
                    )?;
                }
            }
        }
        f.sync.request_full_scan();
        Ok(self.remember_undo(fid, Some(before)).unwrap_or_default())
    }

    /// Items this device cannot hold (`listNameIssues`).
    pub fn list_name_issues(&self) -> Vec<NameIssue> {
        let mut out = Vec::new();
        for (fid, f) in &self.folders {
            let remote = f.sync.remote();
            for item in f.sync.cannot_sync().keys() {
                let id = format!("{fid}:{item}");
                if self.persisted.ignored_names.contains(&id) {
                    continue;
                }
                let Some(node) = remote.get(item) else {
                    continue;
                };
                let dir = if node.parent == ROOT {
                    String::new()
                } else {
                    remote.path_string(&node.parent).unwrap_or_default()
                };
                let reason = name_reason(&node.name);
                out.push(NameIssue {
                    id,
                    folder_id: hex_id(fid),
                    folder_name: f.sync.meta().name.clone(),
                    dir,
                    name: node.name.clone(),
                    reason,
                    device: String::new(),
                });
            }
        }
        out
    }

    /// Renames an item this device cannot hold, on the server, for every device
    /// (`renameNameIssue`).
    pub fn rename_name_issue(
        &mut self,
        issue_id: &str,
        name: &str,
    ) -> Result<ApiResult<(), RenameError>, SyncError> {
        if hangar_drive_protocol::name::check_name(name).is_err() || windows_problem(name).is_some()
        {
            return Ok(ApiResult::Err(RenameError::Invalid));
        }
        let (fid, item) = Self::split_group(issue_id)?;
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let f = self
            .folders
            .get_mut(&fid)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        let mut tree = f.sync.remote().clone();
        let mut node = tree.get(&item).cloned().ok_or(SyncError::Invalid("item"))?;
        if !tree
            .colliding_children(&node.parent, name, &item)
            .is_empty()
        {
            return Ok(ApiResult::Err(RenameError::Exists));
        }
        node.name = name.to_owned();
        node.conflict_of = None;
        tree.insert(item, node);
        let mut cx = Ctx {
            account,
            server: server.as_mut(),
            keychain: &mut *self.ports.keychain,
            fs: &*f.fs,
            store: &mut *self.ports.store,
            clock: &*self.ports.clock,
            entropy: &mut *self.ports.entropy,
            settings: &self.folder_settings,
        };
        f.sync.publish_tree(&mut cx, tree)?;
        f.sync.clear_cannot_sync(&item, &mut *self.ports.store)?;
        Ok(ApiResult::Ok(()))
    }

    /// Hides a name issue on this device (`ignoreNameIssue`).
    pub fn ignore_name_issue(&mut self, issue_id: &str) -> Result<(), SyncError> {
        self.persisted.ignored_names.insert(issue_id.to_owned());
        self.save()
    }

    // -- Restore ----------------------------------------------------------------------------

    fn with_ctx<T>(
        &mut self,
        folder: &str,
        f: impl FnOnce(&mut FolderSync, &mut Ctx<'_>) -> Result<T, SyncError>,
    ) -> Result<T, SyncError> {
        let id = parse_folder(folder)?;
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let lf = self
            .folders
            .get_mut(&id)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        let mut cx = Ctx {
            account,
            server: server.as_mut(),
            keychain: &mut *self.ports.keychain,
            fs: &*lf.fs,
            store: &mut *self.ports.store,
            clock: &*self.ports.clock,
            entropy: &mut *self.ports.entropy,
            settings: &self.folder_settings,
        };
        f(&mut lf.sync, &mut cx)
    }

    /// The folder's history, newest first, at most `limit` entries (`getTimeline`).
    pub fn get_timeline(&mut self, folder: &str, limit: usize) -> Result<Timeline, SyncError> {
        let names: BTreeMap<DeviceId, String> = self
            .account
            .as_ref()
            .map(|a| {
                a.state()
                    .current_devices()
                    .map(|d| (d.id, a.device_display_name(&d.id).unwrap_or_default()))
                    .collect()
            })
            .unwrap_or_default();
        self.with_ctx(folder, |sync, cx| {
            let heads: Vec<crate::folder::TimelineRec> = sync
                .meta()
                .timeline
                .iter()
                .filter(|t| !t.side)
                .rev()
                .take(limit.max(1) + 1)
                .cloned()
                .collect();
            let mut entries = Vec::new();
            let mut expired = 0u64;
            let mut trees: Vec<Option<Tree>> = Vec::new();
            for t in &heads {
                trees.push(sync.tree_at(cx, &t.commit).ok());
            }
            for (i, t) in heads.iter().enumerate().take(limit.max(1)) {
                let (changed, added, deleted) = match (trees.get(i), trees.get(i + 1)) {
                    (Some(Some(now)), Some(Some(before))) => diff_counts(before, now),
                    (Some(Some(now)), _) => (0, now.count_files() as u64, 0),
                    _ => {
                        expired += 1;
                        (0, 0, 0)
                    }
                };
                entries.push(TimelineEntry {
                    id: t.commit.to_hex(),
                    at: t.seen_at_ms,
                    device: names.get(&t.device).cloned().unwrap_or_default(),
                    changed,
                    added,
                    deleted,
                    reanchored: t.reanchor,
                });
            }
            Ok(Timeline {
                entries,
                expired_count: expired,
                retention_days: 30,
            })
        })
    }

    /// The tree of a timeline entry compared with now (`getTreeAt`).
    pub fn get_tree_at(&mut self, folder: &str, entry: &str) -> Result<VersionTree, SyncError> {
        let commit = hangar_drive_protocol::ids::CommitId::from_hex(entry)
            .map_err(|_| SyncError::Invalid("entry"))?;
        self.with_ctx(folder, |sync, cx| {
            let old = sync.tree_at(cx, &commit)?;
            let now = sync.remote();
            let mut nodes = Vec::new();
            let (mut changed, mut missing) = (0, 0);
            let mut ids: Vec<ItemId> = old.ids().copied().collect();
            ids.sort_by_key(|i| old.path_string(i));
            for id in ids {
                let Some(node) = old.get(&id) else { continue };
                let diff = match (&node.kind, now.get(&id)) {
                    (_, None) => FileDiff::Missing,
                    (NodeKind::File(a), Some(n)) => match n.kind.file() {
                        Some(b) if a.same_content(b) => FileDiff::Same,
                        Some(b) if b.mtime_ms > a.mtime_ms => FileDiff::Newer,
                        _ => FileDiff::Different,
                    },
                    (NodeKind::Directory, Some(_)) => FileDiff::Same,
                };
                if !node.is_dir() {
                    match diff {
                        FileDiff::Missing => missing += 1,
                        FileDiff::Different | FileDiff::Newer => changed += 1,
                        FileDiff::Same => {}
                    }
                }
                nodes.push(TreeNode {
                    path: old.path_string(&id).unwrap_or_default(),
                    name: node.name.clone(),
                    depth: u32::try_from(old.depth(&id)).unwrap_or(u32::MAX),
                    kind: if node.is_dir() {
                        TreeNodeKind::Dir
                    } else {
                        TreeNodeKind::File
                    },
                    diff,
                });
            }
            Ok(VersionTree {
                nodes,
                changed,
                missing,
            })
        })
    }

    /// Restores one file or directory of a timeline entry (`restoreFile`). The answer carries
    /// an undo token; a restore the upload budget holds back waits as a job.
    pub fn restore_file(
        &mut self,
        folder: &str,
        entry: &str,
        path: &str,
    ) -> Result<RestoreOutcome, SyncError> {
        let id = parse_folder(folder)?;
        let kind = RestoreKind::File {
            entry: CommitId::from_hex(entry).map_err(|_| SyncError::Invalid("entry"))?,
            path: path
                .split('/')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect(),
        };
        let result = self.run_restore(id, &kind);
        Ok(self.restore_answer(id, kind, result))
    }

    /// What [`Self::reset_folder`] to `entry` would change, for the native question asked
    /// before every reset (follow-up check N-1): the folder's name and how many files of its
    /// current state the entry does not hold, which disappear on every device.
    pub fn reset_folder_preview(
        &mut self,
        folder: &str,
        entry: &str,
    ) -> Result<ResetPreview, SyncError> {
        let commit = CommitId::from_hex(entry).map_err(|_| SyncError::Invalid("entry"))?;
        self.with_ctx(folder, |sync, cx| {
            let old = sync.tree_at(cx, &commit)?;
            let now = sync.remote();
            let vanishing = now
                .iter()
                .filter(|(id, node)| !node.is_dir() && !old.contains(id))
                .count() as u64;
            Ok(ResetPreview {
                folder_name: sync.meta().name.clone(),
                vanishing,
            })
        })
    }

    /// Restores the whole folder to a timeline entry (`resetFolder`), with an undo token; a
    /// waiting reset is computed again when it runs.
    pub fn reset_folder(&mut self, folder: &str, entry: &str) -> Result<RestoreOutcome, SyncError> {
        let id = parse_folder(folder)?;
        let kind = RestoreKind::Folder {
            entry: CommitId::from_hex(entry).map_err(|_| SyncError::Invalid("entry"))?,
        };
        let result = self.run_restore(id, &kind);
        Ok(self.restore_answer(id, kind, result))
    }

    /// Runs a restore on the current state.
    fn run_restore(&mut self, folder: FolderId, kind: &RestoreKind) -> Result<Restored, SyncError> {
        let hex = hex_id(&folder);
        match kind {
            RestoreKind::File { entry, path } => self.with_ctx(&hex, |sync, cx| {
                let old = sync.tree_at(cx, entry)?;
                let item = old.lookup(path).ok_or(SyncError::Invalid("path"))?;
                let original = old.get(&item).map(|n| n.name.clone()).unwrap_or_default();
                let name = sync.restore_item(cx, entry, &item)?;
                let renamed = (name != original).then_some(name);
                Ok((1, renamed, sync.take_last_action()))
            }),
            RestoreKind::Folder { entry } => self.with_ctx(&hex, |sync, cx| {
                sync.restore_folder(cx, entry)?;
                let files = sync.remote().count_files() as u64;
                Ok((files, None, sync.take_last_action()))
            }),
            RestoreKind::Trash { items } => self.with_ctx(&hex, |sync, cx| {
                let mut by_entry: BTreeMap<CommitId, Vec<ItemId>> = BTreeMap::new();
                for (entry, item) in items {
                    by_entry.entry(*entry).or_default().push(*item);
                }
                let mut count = 0;
                let mut undo: Option<UndoState> = None;
                for (entry, ids) in &by_entry {
                    count += sync.restore_items(cx, entry, ids)?;
                    if let Some(change) = sync.take_last_action() {
                        match &mut undo {
                            Some(all) => all.merge(change),
                            None => undo = Some(change),
                        }
                    }
                }
                Ok((count, None, undo))
            }),
        }
    }

    /// The window's answer to a restore: done with its undo token, a job for a restore the
    /// upload budget holds back, or why nothing changed.
    fn restore_answer(
        &mut self,
        folder: FolderId,
        kind: RestoreKind,
        result: Result<Restored, SyncError>,
    ) -> RestoreOutcome {
        match result {
            Ok((count, renamed_to, change)) => RestoreOutcome::Done {
                count,
                renamed_to,
                undo_token: self.remember_undo(folder, change),
            },
            Err(e) => match restore_refusal(e) {
                RestoreOutcome::WaitBudget { .. } => match self.add_restore_job(folder, kind) {
                    Ok(job_id) => RestoreOutcome::WaitBudget { job_id },
                    Err(_) => RestoreOutcome::Failed,
                },
                other => other,
            },
        }
    }

    fn add_restore_job(
        &mut self,
        folder: FolderId,
        kind: RestoreKind,
    ) -> Result<String, SyncError> {
        let id = base64url(&random_id::<12>(&mut *self.ports.entropy)?);
        let next_try_ms = self.now() + RESTORE_RETRY_MS;
        self.persisted.restore_jobs.push(RestoreJob {
            id: id.clone(),
            folder,
            kind,
            next_try_ms,
        });
        self.save()?;
        Ok(id)
    }

    /// Stops a restore that waits for the upload budget (`cancelRestore`); a job that ran or
    /// was stopped already is no error.
    pub fn cancel_restore(&mut self, job_id: &str) -> Result<(), SyncError> {
        let before = self.persisted.restore_jobs.len();
        self.persisted.restore_jobs.retain(|j| j.id != job_id);
        if self.persisted.restore_jobs.len() != before {
            self.save()?;
        }
        Ok(())
    }

    /// Tries the waiting restores that are due again. One the budget still holds back, or that
    /// cannot reach the server, waits on; one that ran or can no longer run (expired, no room,
    /// the folder is gone) leaves the list.
    fn run_restore_jobs(&mut self) {
        let now = self.now();
        let due: Vec<RestoreJob> = self
            .persisted
            .restore_jobs
            .iter()
            .filter(|j| j.next_try_ms <= now)
            .cloned()
            .collect();
        if due.is_empty() {
            return;
        }
        for job in due {
            let wait = match self.run_restore(job.folder, &job.kind) {
                Ok(_) => false,
                Err(e) if e.is_offline() => true,
                Err(e) => matches!(restore_refusal(e), RestoreOutcome::WaitBudget { .. }),
            };
            if wait {
                if let Some(j) = self
                    .persisted
                    .restore_jobs
                    .iter_mut()
                    .find(|j| j.id == job.id)
                {
                    j.next_try_ms = now + RESTORE_RETRY_MS;
                }
            } else {
                self.persisted.restore_jobs.retain(|j| j.id != job.id);
            }
        }
        let _ = self.save();
    }

    /// Keeps what an action changed under a new undo token; `None` when it changed nothing or
    /// no token could be drawn (the window then offers no undo).
    fn remember_undo(&mut self, folder: FolderId, change: Option<UndoState>) -> Option<String> {
        let change = change.filter(|c| !c.is_empty())?;
        let token = base64url(&random_id::<16>(&mut *self.ports.entropy).ok()?);
        self.undo.push_back((token.clone(), folder, change));
        while self.undo.len() > MAX_UNDO {
            self.undo.pop_front();
        }
        Some(token)
    }

    /// Undoes a restore, a folder reset or a "keep this" (`undo`, UX 7 and 9): a new commit puts
    /// the items the action touched back in their state before it, so the history keeps both
    /// and changes of other devices since stay. A token is used once.
    pub fn undo(&mut self, token: &str) -> Result<(), SyncError> {
        let index = self
            .undo
            .iter()
            .position(|(t, _, _)| t == token)
            .ok_or(SyncError::Invalid("unknown undo token"))?;
        let (_, folder, change) = self
            .undo
            .get(index)
            .cloned()
            .ok_or(SyncError::Invalid("unknown undo token"))?;
        self.with_ctx(&hex_id(&folder), |sync, cx| sync.revert(cx, &change))?;
        self.undo.remove(index);
        Ok(())
    }

    /// Brings back the files another device deleted, from an activity entry
    /// (`restoreRemoteDeleted`, UX 8.1): one commit with every file that is still gone, at its
    /// old place; a file that is back already stays as it is. Returns the files that came back.
    pub fn restore_remote_deleted(&mut self, activity_id: &str) -> Result<u64, SyncError> {
        let delete = self
            .remote_deletes
            .get(activity_id)
            .cloned()
            .ok_or(SyncError::Invalid("unknown activity entry"))?;
        self.with_ctx(&hex_id(&delete.folder), |sync, cx| {
            let back = sync.restore_items(cx, &delete.commit, &delete.items)?;
            sync.take_last_action();
            Ok(back)
        })
    }

    /// "Undo a device" (`findBeforeDevice`, ADR 0001, section 5): the last head before the first
    /// head after `from` that contains a commit by `device`, as head or side commit.
    pub fn find_before_device(
        &self,
        folder: &str,
        device: &str,
        from: i64,
    ) -> Result<Option<String>, SyncError> {
        let f = self.folder(folder)?;
        let device = DeviceId::from_hex(device).map_err(|_| SyncError::Invalid("device"))?;
        let timeline = &f.sync.meta().timeline;
        let mut previous_head: Option<String> = None;
        for (i, t) in timeline.iter().enumerate() {
            if t.side {
                continue;
            }
            let side_by_device = i > 0
                && timeline
                    .get(i - 1)
                    .is_some_and(|s| s.side && s.sequence == t.sequence && s.device == device);
            if t.seen_at_ms >= from && (t.device == device || side_by_device) {
                return Ok(previous_head);
            }
            previous_head = Some(t.commit.to_hex());
        }
        Ok(None)
    }

    /// Items deleted within the retained history (`getTrash`), at most `depth` heads back.
    pub fn get_trash(&mut self, folder: &str, depth: usize) -> Result<Vec<TrashItem>, SyncError> {
        let names: BTreeMap<DeviceId, String> = self
            .account
            .as_ref()
            .map(|a| {
                a.state()
                    .current_devices()
                    .map(|d| (d.id, a.device_display_name(&d.id).unwrap_or_default()))
                    .collect()
            })
            .unwrap_or_default();
        self.with_ctx(folder, |sync, cx| {
            let heads: Vec<crate::folder::TimelineRec> = sync
                .meta()
                .timeline
                .iter()
                .filter(|t| !t.side)
                .rev()
                .take(depth.max(1))
                .cloned()
                .collect();
            let current = sync.remote().clone();
            let mut seen = BTreeSet::new();
            let mut out = Vec::new();
            let mut newer: Option<&crate::folder::TimelineRec> = None;
            for t in &heads {
                let Ok(tree) = sync.tree_at(cx, &t.commit) else {
                    continue;
                };
                for (id, node) in tree.iter() {
                    if node.is_dir() || current.contains(id) || !seen.insert(*id) {
                        continue;
                    }
                    let dir = if node.parent == ROOT {
                        String::new()
                    } else {
                        tree.path_string(&node.parent).unwrap_or_default()
                    };
                    let deleted_by = newer.unwrap_or(t);
                    out.push(TrashItem {
                        id: format!("{}:{}", t.commit.to_hex(), id.to_hex()),
                        name: node.name.clone(),
                        dir,
                        deleted_at: deleted_by.seen_at_ms,
                        device: names.get(&deleted_by.device).cloned().unwrap_or_default(),
                    });
                }
                newer = Some(t);
            }
            Ok(out)
        })
    }

    /// Restores trash items (`restoreTrash`): one commit per timeline entry they come from,
    /// with one undo token for all of them.
    pub fn restore_trash(
        &mut self,
        folder: &str,
        items: &[String],
    ) -> Result<RestoreOutcome, SyncError> {
        let id = parse_folder(folder)?;
        let mut picked = Vec::with_capacity(items.len());
        for item in items {
            let (commit, item) = item
                .split_once(':')
                .ok_or(SyncError::Invalid("trash item"))?;
            picked.push((
                CommitId::from_hex(commit).map_err(|_| SyncError::Invalid("trash item"))?,
                ItemId::from_hex(item).map_err(|_| SyncError::Invalid("trash item"))?,
            ));
        }
        let kind = RestoreKind::Trash { items: picked };
        let result = self.run_restore(id, &kind);
        Ok(self.restore_answer(id, kind, result))
    }

    // -- Devices ----------------------------------------------------------------------------

    /// The devices of the account (`listDevices`).
    pub fn list_devices(&self) -> Result<DeviceList, SyncError> {
        let account = self
            .account
            .as_ref()
            .ok_or(SyncError::NotSetUp("no account"))?;
        let devices = account
            .state()
            .current_devices()
            .filter(|d| !d.recovery)
            .map(|d| Device {
                id: hex_id(&d.id),
                name: account.device_display_name(&d.id).unwrap_or_default(),
                kind: DeviceKind::Laptop,
                is_this: d.id == *account.device(),
                last_seen: None,
                added: account
                    .device_added_ms(&d.id)
                    .and_then(|ms| i64::try_from(ms).ok())
                    .unwrap_or(0),
            })
            .collect();
        let recovery_created = account
            .state()
            .current_devices()
            .find(|d| d.recovery)
            .and_then(|d| account.device_added_ms(&d.id))
            .and_then(|ms| i64::try_from(ms).ok())
            .unwrap_or(0);
        Ok(DeviceList {
            devices,
            recovery_created,
        })
    }

    /// A device's safety number (`getSafetyNumber`).
    pub fn get_safety_number(&self, device: &str) -> Result<NumberRows, SyncError> {
        let account = self
            .account
            .as_ref()
            .ok_or(SyncError::NotSetUp("no account"))?;
        let id = DeviceId::from_hex(device).map_err(|_| SyncError::Invalid("device"))?;
        let record = account
            .state()
            .device(&id)
            .ok_or(SyncError::Invalid("unknown device"))?;
        Ok(NumberRows::of(&safety_number(
            account.id(),
            &id,
            &record.keys,
        )))
    }

    /// The name of a current device of the account (recovery devices aside, `except` aside)
    /// that looks the same as `name` (`hangar_drive_protocol::name::looks_alike`: NFKC, default
    /// ignorables dropped, case folded, Latin, Cyrillic and Greek homoglyphs), checked when a
    /// device is named, renamed or paired. `None` without an account.
    pub fn similar_device_name(&self, name: &str, except: Option<&str>) -> Option<String> {
        let account = self.account.as_ref()?;
        let except = except.and_then(|e| DeviceId::from_hex(e).ok());
        account
            .state()
            .current_devices()
            .filter(|d| !d.recovery && Some(d.id) != except)
            .filter_map(|d| account.device_display_name(&d.id))
            .find(|other| hangar_drive_protocol::name::looks_alike(other, name))
    }

    /// Renames a device (`renameDevice`, `setDeviceName`). A name that looks the same as
    /// another device's ([`Self::similar_device_name`]) is refused with
    /// [`DeviceNameError::LooksLike`] unless `allow_look_alike`, which the app passes only after
    /// the native question that names the other device.
    pub fn rename_device(
        &mut self,
        device: &str,
        name: &str,
        allow_look_alike: bool,
    ) -> Result<ApiResult<(), DeviceNameError>, SyncError> {
        if let Some(e) = name_error(name) {
            return Ok(ApiResult::Err(e.into()));
        }
        if !allow_look_alike && self.similar_device_name(name, Some(device)).is_some() {
            return Ok(ApiResult::Err(DeviceNameError::LooksLike));
        }
        let id = DeviceId::from_hex(device).map_err(|_| SyncError::Invalid("device"))?;
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        account.set_device_name(
            server.as_mut(),
            &mut *self.ports.store,
            &id,
            name,
            &mut *self.ports.entropy,
        )?;
        Ok(ApiResult::Ok(()))
    }

    /// Sets the limits this device holds its own folders to (`FolderSettings::max_tree_items`,
    /// `max_tree_depth`). Only for tests that play a device which ignores them, such as a
    /// compromised one; what a device takes in from the server stays bounded by
    /// `codec::MAX_TREE_ITEMS` and `MAX_TREE_DEPTH` whatever is set here.
    #[doc(hidden)]
    pub fn set_tree_limits(&mut self, max_items: usize, max_depth: usize) {
        self.folder_settings.max_tree_items = max_items;
        self.folder_settings.max_tree_depth = max_depth;
    }

    /// Removes a device (`removeDevice`): removal and rotation, re-seal, barriers (N1), and the
    /// heads of the removed device the barriers cover (N2) as a suspect warning source.
    pub fn remove_device(&mut self, device: &str) -> Result<usize, SyncError> {
        let id = DeviceId::from_hex(device).map_err(|_| SyncError::Invalid("device"))?;
        self.remove_with_barriers(&[id])
    }

    /// The removal job for `targets` with a barrier in every folder of the account: the
    /// folders synced here, and the others through a folder state without a local root, which
    /// is stored and taken up when the folder is synced here later. Without it a folder synced
    /// later would find the removed devices' last heads without a barrier and stop to ask the
    /// person (security review H1). Returns the heads of removed devices the barriers cover.
    fn remove_with_barriers(&mut self, targets: &[DeviceId]) -> Result<usize, SyncError> {
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        account.refresh(
            server.as_mut(),
            &mut *self.ports.keychain,
            &mut *self.ports.store,
        )?;
        let elsewhere: Vec<FolderId> = account
            .folders()
            .into_iter()
            .map(|f| f.folder)
            .filter(|f| !self.folders.contains_key(f) && account.ring(f).is_some())
            .collect();
        let mut detached: Vec<FolderSync> = Vec::new();
        for id in elsewhere {
            let name = account
                .folders()
                .into_iter()
                .find(|f| f.folder == id)
                .map(|f| f.name)
                .unwrap_or_default();
            detached.push(match FolderSync::load(account, id, &*self.ports.store)? {
                Some(f) => f,
                None => FolderSync::new(account, id, &name),
            });
        }
        // The barrier path reads and writes only the chain, never the disk.
        let nowhere = crate::ports::NoLocalRoot;
        let mut list: Vec<(&mut FolderSync, &dyn FileSystem)> = self
            .folders
            .values_mut()
            .map(|f| (&mut f.sync, &*f.fs))
            .collect();
        for f in detached.iter_mut() {
            list.push((f, &nowhere));
        }
        let mut jx = JobCtx {
            account,
            server: server.as_mut(),
            keychain: &mut *self.ports.keychain,
            store: &mut *self.ports.store,
            clock: &*self.ports.clock,
            entropy: &mut *self.ports.entropy,
            settings: &self.folder_settings,
        };
        let outcome = remove_devices(&mut jx, &mut list, targets)?;
        Ok(outcome.removed_heads.len())
    }

    /// The person takes in the heads of a removed device that stopped a folder
    /// (`acceptRemovedHeads`, security review H1): the barrier after them is written, the folder
    /// syncs again, and the window offers "Undo a device" for them: the answer names the
    /// timeline entry right before the first of them.
    pub fn accept_removed_heads(&mut self, folder: &str) -> Result<AcceptedHeads, SyncError> {
        let id = parse_folder(folder)?;
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let lf = self
            .folders
            .get_mut(&id)
            .ok_or(SyncError::Invalid("unknown folder"))?;
        let mut jx = JobCtx {
            account,
            server: server.as_mut(),
            keychain: &mut *self.ports.keychain,
            store: &mut *self.ports.store,
            clock: &*self.ports.clock,
            entropy: &mut *self.ports.entropy,
            settings: &self.folder_settings,
        };
        let first = lf.sync.removed_heads().iter().map(|h| h.sequence).min();
        let outcome = accept_removed_heads(&mut jx, &mut lf.sync, &*lf.fs)?;
        let before_entry_id = first.and_then(|first| {
            lf.sync
                .meta()
                .timeline
                .iter()
                .rfind(|t| !t.side && t.sequence < first)
                .map(|t| t.commit.to_hex())
        });
        Ok(AcceptedHeads {
            count: outcome.removed_heads.len() as u64,
            before_entry_id,
        })
    }

    /// Keeps the files a round could not write for lack of space (with their sizes) until they
    /// are written or the folder is in sync; the snapshot shows them as "disk full".
    fn note_disk_full(folder: &mut LocalFolder, report: &crate::folder::RoundReport) {
        for (item, error) in &report.failed {
            if matches!(error, crate::apply::ActionError::DiskFull) {
                let size = match folder.sync.remote().get(item).map(|n| &n.kind) {
                    Some(NodeKind::File(v)) => v.size,
                    _ => 0,
                };
                folder.disk_full.insert(*item, size);
            }
        }
        if report.in_sync {
            folder.disk_full.clear();
        } else {
            let written: BTreeSet<ItemId> = report
                .changes
                .iter()
                .filter(|c| c.incoming)
                .map(|c| c.item)
                .collect();
            folder.disk_full.retain(|id, _| !written.contains(id));
        }
    }

    /// The "suspect device" warnings of the stored anomaly pins (ADR 0001, section 5; UX 9.4).
    /// The device is named only when this device's own verified history shows it dropping a
    /// burst after the pinned commit ([`burst_writer`]): the pin itself comes from the server,
    /// which could place it before any device's commit, so its position alone names nobody
    /// (MEDIUM 3 of the follow-up review). Otherwise, for a folder not synced here, or while its
    /// new commits have not arrived, the device stays empty and the window names the folder
    /// instead, without "Gerät entfernen".
    fn suspect_warnings(&self) -> Vec<Warning> {
        let (Some(account), false) = (&self.account, self.persisted.pins.is_empty()) else {
            return Vec::new();
        };
        let listed = account.folders();
        self.persisted
            .pins
            .iter()
            .filter_map(|pin| {
                let local = self.folders.get(&pin.folder);
                let folder_name = match local {
                    Some(f) => f.sync.meta().name.clone(),
                    None => listed.iter().find(|f| f.folder == pin.folder)?.name.clone(),
                };
                let device = local.and_then(|f| burst_writer(&f.sync.meta().timeline, &pin.commit));
                Some(Warning::Suspect {
                    id: format!("suspect-{}-{}", pin.folder, pin.commit),
                    device_id: device.map(|d| hex_id(&d)).unwrap_or_default(),
                    device_name: device.map(|d| self.device_name_of(&d)).unwrap_or_default(),
                    folder_id: hex_id(&pin.folder),
                    folder_name,
                    entry_id: pin.commit.to_hex(),
                    days: RETENTION_DAYS as u32,
                    until: pin.until_ms,
                    lapsed: pin.lapsed,
                })
            })
            .collect()
    }

    fn device_name_of(&self, device: &DeviceId) -> String {
        self.account
            .as_ref()
            .and_then(|a| a.device_display_name(device))
            .unwrap_or_default()
    }

    /// The about box's version.
    pub fn version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }
}

/// File objects a burst drops at least, at most required, and the share of the folder's file
/// objects in between: the server's default thresholds (ADR 0001, section 5, "Burst
/// threshold").
const BURST_MIN_OBJECTS: u64 = 20;
const BURST_MAX_OBJECTS: u64 = 500;
const BURST_PERCENT: u64 = 30;
/// The server's rolling window of the burst signal.
const BURST_WINDOW_MS: i64 = 60 * 60 * 1000;

/// The device whose verified heads after `pinned` in `timeline` drop a burst (MEDIUM 3 of the
/// follow-up review): within the hour after the first of them, by this device's own count of
/// each head's dropped file objects ([`crate::folder::TimelineRec::dropped_files`]), at least
/// the server's share of the folder's file objects before them and its object count (at most
/// all of them, for a small folder). A head
/// whose drop was not counted names nobody, and a full delta counts chunks only, so a barrier
/// or a repair that keeps the tree never names its writer. `None`: no device drops a burst, or
/// the pinned commit is not in this device's history.
fn burst_writer(timeline: &[crate::folder::TimelineRec], pinned: &CommitId) -> Option<DeviceId> {
    let at = timeline.iter().find(|t| t.commit == *pinned)?.sequence;
    let mut heads: Vec<&crate::folder::TimelineRec> = timeline
        .iter()
        .filter(|t| !t.side && t.sequence > at)
        .collect();
    heads.sort_by_key(|t| t.sequence);
    let first = heads.first()?;
    let before = first.files_before?;
    let count = before
        .saturating_mul(BURST_PERCENT)
        .div_ceil(100)
        .clamp(BURST_MIN_OBJECTS, BURST_MAX_OBJECTS)
        // A folder with fewer file objects than the count: all of them, as an operator count
        // below the default would allow; never zero.
        .min(before)
        .max(1);
    let until = first.seen_at_ms.saturating_add(BURST_WINDOW_MS);
    let mut dropped: BTreeMap<DeviceId, u64> = BTreeMap::new();
    for t in heads.iter().filter(|t| t.seen_at_ms <= until) {
        let Some(n) = t.dropped_files else {
            continue;
        };
        let sum = dropped.entry(t.device).or_default();
        *sum = sum.saturating_add(n);
        if *sum >= count && sum.saturating_mul(100) >= before.saturating_mul(BURST_PERCENT) {
            return Some(t.device);
        }
    }
    None
}

/// Why this device cannot hold an entry named `name`, as the window explains it. A short name
/// alias (security review N14) and a shell junction name (follow-up review of the Windows
/// handles, M1) are reserved on Windows like a device name.
fn name_reason(name: &str) -> NameReason {
    match windows_problem(name) {
        Some(WindowsNameProblem::ForbiddenCharacter(c)) => NameReason::Char {
            char: c.to_string(),
        },
        Some(WindowsNameProblem::Reserved)
        | Some(WindowsNameProblem::ShortNameAlias)
        | Some(WindowsNameProblem::ShellJunction) => NameReason::Reserved {
            name: name.to_owned(),
        },
        Some(WindowsNameProblem::TrailingDotOrSpace) => NameReason::Trailing,
        Some(WindowsNameProblem::ControlCharacter) => NameReason::Control,
        Some(WindowsNameProblem::TooLong) | None => NameReason::CannotCreate,
    }
}

/// Adds `id` as the newest hidden warning and lets the oldest fall out beyond
/// [`MAX_DISMISSED`].
fn remember_dismissed(dismissed: &mut Vec<String>, id: &str) {
    dismissed.retain(|d| d != id);
    dismissed.push(id.to_owned());
    let over = dismissed.len().saturating_sub(MAX_DISMISSED);
    dismissed.drain(..over);
}

/// Whether the person may hide `w` on this device. An allowlist: only "suspect device" has a
/// "That was me" in the window (`dismissSuspect`); every other kind stays until its cause is
/// gone or the person decides in its dialog. A removal the server reports in particular is
/// only confirmed (`confirmDeviceRemoved`): hidden, the device would stay stopped without a
/// word (follow-up check N-3). A new kind is not hideable until it is added here.
fn dismissible(w: &Warning) -> bool {
    match w {
        Warning::Suspect { .. } => true,
        // Only the empty folder list can be acknowledged; a folder that cannot be opened yet
        // stays named until it opens or leaves the list.
        Warning::FoldersUnreadable { folders, .. } => folders.is_empty(),
        _ => false,
    }
}

fn warning_id(w: &Warning) -> String {
    serde_json::to_value(w)
        .ok()
        .and_then(|v| v.get("id").and_then(|i| i.as_str()).map(str::to_owned))
        .unwrap_or_default()
}

fn url_host(url: &str) -> Option<String> {
    let parsed = reqwest::Url::parse(url).ok()?;
    let host = parsed.host_str()?.to_owned();
    Some(match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host,
    })
}

fn parse_folder(folder: &str) -> Result<FolderId, SyncError> {
    FolderId::from_hex(folder).map_err(|_| SyncError::Invalid("folder id"))
}

fn diff_counts(before: &Tree, now: &Tree) -> (u64, u64, u64) {
    let (mut changed, mut added, mut deleted) = (0, 0, 0);
    for (id, node) in now.iter().filter(|(_, n)| !n.is_dir()) {
        match before.get(id) {
            None => added += 1,
            Some(b) if b != node => changed += 1,
            _ => {}
        }
    }
    for (id, node) in before.iter() {
        if !node.is_dir() && !now.contains(id) {
            deleted += 1;
        }
    }
    (changed, added, deleted)
}

/// Why a restore changed nothing, as the window says it; `WaitBudget` names no job yet.
fn restore_refusal(error: SyncError) -> RestoreOutcome {
    match error {
        SyncError::Net(e) => match e.code() {
            Some(ErrorCode::BudgetExceeded) => RestoreOutcome::WaitBudget {
                job_id: String::new(),
            },
            Some(ErrorCode::QuotaExceeded) => RestoreOutcome::NoSpace,
            Some(ErrorCode::MissingObjects) | Some(ErrorCode::NotFound) => RestoreOutcome::Expired,
            _ => RestoreOutcome::Failed,
        },
        _ => RestoreOutcome::Failed,
    }
}

fn activity_id(entry: &ActivityEntry) -> &str {
    match entry {
        ActivityEntry::File { id, .. }
        | ActivityEntry::Group { id, .. }
        | ActivityEntry::RemoteDeleted { id, .. }
        | ActivityEntry::CameBack { id, .. } => id,
    }
}

// ------------------------------------------------------------------------------------------
// The thread
// ------------------------------------------------------------------------------------------

type Job = Box<dyn FnOnce(&mut EngineCore) + Send>;

/// Sends commands to the engine thread.
#[derive(Clone)]
pub struct EngineHandle {
    jobs: Sender<Job>,
}

impl std::fmt::Debug for EngineHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EngineHandle").finish_non_exhaustive()
    }
}

impl EngineHandle {
    /// Runs `command` on the engine thread and returns its answer.
    pub fn call<T: Send + 'static>(
        &self,
        command: impl FnOnce(&mut EngineCore) -> T + Send + 'static,
    ) -> Result<T, SyncError> {
        let (tx, rx) = channel();
        self.jobs
            .send(Box::new(move |core| {
                let _ = tx.send(command(core));
            }))
            .map_err(|_| SyncError::Stopped)?;
        rx.recv().map_err(|_| SyncError::Stopped)
    }
}

/// The engine thread (module docs).
#[derive(Debug)]
pub struct Engine;

impl Engine {
    /// Starts the engine thread. `make` builds the core on the thread (so its ports never cross
    /// threads); `tick` is the pause between loop passes when no command arrives.
    pub fn spawn(
        make: impl FnOnce() -> Result<EngineCore, SyncError> + Send + 'static,
        tick: Duration,
    ) -> Result<(EngineHandle, Receiver<BackendEvent>), SyncError> {
        let (jobs, job_rx) = channel::<Job>();
        let (event_tx, events) = channel();
        let (ready_tx, ready_rx) = channel();
        std::thread::Builder::new()
            .name("hangar-drive-sync".into())
            .spawn(move || {
                let mut core = match make() {
                    Ok(core) => {
                        let _ = ready_tx.send(Ok(()));
                        core
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                loop {
                    match job_rx.recv_timeout(tick) {
                        Ok(job) => job(&mut core),
                        Err(RecvTimeoutError::Timeout) => {}
                        Err(RecvTimeoutError::Disconnected) => return,
                    }
                    for event in core.tick() {
                        if event_tx.send(event).is_err() {
                            return;
                        }
                    }
                }
            })
            .map_err(|_| SyncError::Stopped)?;
        ready_rx.recv().map_err(|_| SyncError::Stopped)??;
        Ok((EngineHandle { jobs }, events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The window explains each Windows name problem; a shell junction name reads as reserved,
    // not as "cannot create" (follow-up review of the Windows handles, M1).
    #[test]
    fn every_windows_name_problem_has_its_reason() {
        let reserved = |name: &str| NameReason::Reserved {
            name: name.to_owned(),
        };
        let junction = "Bilder.{0AFACED1-E828-11D1-9187-B532F1E9575D}";
        assert_eq!(name_reason(junction), reserved(junction));
        assert_eq!(name_reason("REPORT~2.DOC"), reserved("REPORT~2.DOC"));
        assert_eq!(name_reason("nul.txt"), reserved("nul.txt"));
        assert_eq!(name_reason("a:b"), NameReason::Char { char: ":".into() });
        assert_eq!(name_reason("a."), NameReason::Trailing);
        assert_eq!(name_reason("a\u{1}b"), NameReason::Control);
        assert_eq!(name_reason(&"x".repeat(300)), NameReason::CannotCreate);
        assert_eq!(name_reason("plain.txt"), NameReason::CannotCreate);
    }

    // Follow-up check N-3: the hidden warnings are bounded, the oldest fall out first, and one
    // hidden again counts as the newest.
    #[test]
    fn hidden_warnings_are_bounded_and_the_oldest_fall_out() {
        let mut list = Vec::new();
        for n in 0..(MAX_DISMISSED + 10) {
            remember_dismissed(&mut list, &format!("w{n}"));
        }
        assert_eq!(list.len(), MAX_DISMISSED);
        assert_eq!(list.first().map(String::as_str), Some("w10"));
        remember_dismissed(&mut list, "w10");
        assert_eq!(list.len(), MAX_DISMISSED);
        assert_eq!(list.last().map(String::as_str), Some("w10"));
        assert_eq!(list.first().map(String::as_str), Some("w11"));
    }

    // ADR 0001, section 5: a pin notice is kept once per folder and commit; one that ends at
    // once, or earlier than known, lapsed; a flood of made up pins stays bounded.
    #[test]
    fn pin_notices_are_kept_once_and_a_lapse_is_noticed() {
        let now = 1_795_651_200_000;
        let folder = FolderId::from_bytes([1; 16]);
        let commit = |n: u8| CommitId::from_bytes([n; 32]);
        let mut pins = Vec::new();
        note_pin(&mut pins, folder, commit(1), now + 90 * DAY_MS, now);
        note_pin(&mut pins, folder, commit(1), now + 90 * DAY_MS, now);
        assert_eq!(pins.len(), 1);
        assert!(!pins[0].lapsed);
        // The pin cap let it go: the server sends it again, ending at its own now.
        note_pin(&mut pins, folder, commit(1), now + 5_000, now);
        assert_eq!(pins.len(), 1);
        assert!(pins[0].lapsed);
        assert_eq!(pins[0].until_ms, now + 5_000);
        // A device that only sees the lapse (the feed keeps the newest entry per pin).
        note_pin(&mut pins, folder, commit(2), now - 1_000, now);
        assert!(pins[1].lapsed);
        for n in 0..(MAX_PINS as u8 + 5) {
            note_pin(&mut pins, folder, commit(10 + n), now + DAY_MS, now);
        }
        assert_eq!(pins.len(), MAX_PINS);
        assert_eq!(
            pins.last().map(|p| p.commit),
            Some(commit(10 + MAX_PINS as u8 + 4))
        );
    }

    fn burst_rec(
        commit: u8,
        sequence: u64,
        device: u8,
        side: bool,
        dropped: Option<(u64, u64)>,
    ) -> crate::folder::TimelineRec {
        crate::folder::TimelineRec {
            commit: CommitId::from_bytes([commit; 32]),
            sequence,
            device: DeviceId::from_bytes([device; 16]),
            seen_at_ms: 0,
            reanchor: false,
            side,
            root: hangar_drive_protocol::ids::ObjectId::from_bytes([0; 32]),
            dropped_files: dropped.map(|d| d.0),
            files_before: dropped.map(|d| d.1),
        }
    }

    // The device of a suspect warning is the one whose verified heads after the pinned commit
    // drop a burst by this device's own count, side commits aside.
    #[test]
    fn the_burst_writer_comes_from_the_timeline() {
        let timeline = vec![
            burst_rec(1, 1, 7, false, Some((0, 100))),
            burst_rec(2, 2, 7, false, Some((0, 100))),
            burst_rec(4, 3, 8, true, None),
            burst_rec(3, 3, 9, false, Some((20, 100))),
            burst_rec(5, 4, 9, false, Some((15, 80))),
        ];
        let pinned = CommitId::from_bytes([2; 32]);
        // 35 of 100 file objects over two heads of device 9.
        assert_eq!(
            burst_writer(&timeline, &pinned),
            Some(DeviceId::from_bytes([9; 16]))
        );
        assert_eq!(
            burst_writer(&timeline, &CommitId::from_bytes([5; 32])),
            None
        );
        assert_eq!(
            burst_writer(&timeline, &CommitId::from_bytes([6; 32])),
            None
        );
    }

    // MEDIUM 3 (a): a server that places a pin right before a commit of a device that drops
    // nothing names nobody, and a head whose drop was not counted names nobody either.
    #[test]
    fn a_pin_before_a_commit_that_drops_nothing_names_no_device() {
        let timeline = vec![
            burst_rec(1, 1, 7, false, Some((0, 100))),
            burst_rec(2, 2, 8, false, Some((0, 100))),
            burst_rec(3, 3, 8, false, Some((1, 100))),
        ];
        assert_eq!(
            burst_writer(&timeline, &CommitId::from_bytes([1; 32])),
            None
        );
        let uncounted = vec![
            burst_rec(1, 1, 7, false, Some((0, 100))),
            burst_rec(2, 2, 8, false, None),
        ];
        assert_eq!(
            burst_writer(&uncounted, &CommitId::from_bytes([1; 32])),
            None
        );
    }

    // MEDIUM 3 (b): after a removal, the barrier's full delta drops the removed device's
    // garbage from the server's live set and sets off a pin before it; the barrier keeps the
    // tree, so it drops no counted file object and its writer is not named.
    #[test]
    fn a_barrier_after_a_pin_does_not_name_its_writer() {
        let timeline = vec![
            burst_rec(1, 1, 9, false, Some((0, 40))),
            burst_rec(2, 2, 7, false, Some((0, 40))),
        ];
        assert_eq!(
            burst_writer(&timeline, &CommitId::from_bytes([1; 32])),
            None
        );
    }

    // Only "suspect device" may be hidden; every other kind is refused, the removal report
    // above all.
    #[test]
    fn only_the_suspect_warning_can_be_hidden() {
        assert!(dismissible(&Warning::Suspect {
            id: "suspect-d-f".into(),
            device_id: "d".into(),
            device_name: "Laptop".into(),
            folder_id: "f".into(),
            folder_name: "Docs".into(),
            entry_id: "e".into(),
            days: 30,
            until: 0,
            lapsed: false,
        }));
        assert!(!dismissible(&Warning::DiskFull {
            id: "diskFull".into(),
            needed: 1,
        }));
        assert!(!dismissible(&Warning::RemovalReported {
            id: "removalReported".into(),
            since: 0,
        }));
        assert!(!dismissible(&Warning::Refused {
            id: "refused".into(),
        }));
        assert!(!dismissible(&Warning::Conflicts {
            id: "conflicts".into(),
            count: 1,
        }));
        assert!(!dismissible(&Warning::Names {
            id: "names".into(),
            count: 1,
        }));
        assert!(!dismissible(&Warning::UpdateRequired {
            id: "updateRequired".into(),
        }));
    }
}
