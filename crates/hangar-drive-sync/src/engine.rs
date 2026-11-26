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
use hangar_drive_crypto::identity::{folder_safety_number, safety_number, DeviceIdentity};
use hangar_drive_crypto::pairing::{OfferContent, PairingOffer, PairingSecret};
use hangar_drive_crypto::recovery::RecoveryCode;
use hangar_drive_crypto::Entropy;
use hangar_drive_protocol::api::{ErrorCode, Notice};
use hangar_drive_protocol::ids::{AccountId, DeviceId, FolderId, InviteToken, ItemId, ServerId};
use hangar_drive_protocol::name::{check_display_name, windows_problem, WindowsNameProblem};
use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::api::*;
use crate::chunker::DynEntropy;
use crate::error::SyncError;
use crate::folder::{Ctx, FolderSettings, FolderState, FolderSync, StopReason};
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

/// The real root check: [`crate::roots::check_root`] (security review M4).
pub fn real_root_check() -> RootCheck {
    Box::new(crate::roots::check_root)
}

/// The real server: [`HttpServer`].
pub fn real_server_factory() -> ServerFactory {
    Box::new(|config, identity| {
        Ok(Box::new(HttpServer::new(config.clone(), identity)?) as Box<dyn ServerApi>)
    })
}

/// A prover that signs session challenges with `identity`.
pub fn prover(identity: DeviceIdentity) -> crate::http::Prover {
    Box::new(move |server, account, device, challenge| {
        identity.prove_session(server, account, device, challenge)
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
    dismissed: BTreeSet<String>,
}

struct LocalFolder {
    sync: FolderSync,
    fs: Box<dyn FileSystem>,
    watcher: Option<Box<dyn ChangeSource>>,
    path: String,
    last_full_scan: i64,
}

struct PendingAccount {
    url: String,
    invite: InviteToken,
    pin: Option<[u8; 32]>,
    server: ServerId,
    account: AccountId,
    name: String,
    code: RecoveryCode,
    check_group: u32,
}

/// A recovered installation between `recover_account` and `finish_recovery_cleanup`.
struct Recovering {
    /// The server address of the sheet, for the new code's sheet.
    url: String,
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
    connection: Connection,
    last_ok_ms: i64,
    last_sync: Option<i64>,
    last_file: Option<LastFile>,
    pin_mismatch: bool,
    removed: bool,
    pending: Option<PendingAccount>,
    recovering: Option<Recovering>,
    offers: BTreeMap<String, OpenOffer>,
    joining: Option<Joining>,
    events: Vec<BackendEvent>,
    last_snapshot: Option<Snapshot>,
    counter: u64,
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

/// The sheet view of a recovery code's account.
fn sheet_view(
    url: &str,
    server: ServerId,
    account: AccountId,
) -> Result<RecoverySheetView, SyncError> {
    let sheet = crate::links::RecoverySheet {
        server_url: hangar_drive_crypto::pairing::parse_server_url(url)
            .map_err(|_| SyncError::Invalid("server url"))?,
        server,
        account,
    };
    Ok(RecoverySheetView {
        server_url: sheet.server_url.to_string(),
        server_id: server.to_hex(),
        account_id: account.to_hex(),
        link: crate::links::recovery_link(&sheet),
    })
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
            connection: Connection::Online,
            last_ok_ms: now,
            last_sync: None,
            last_file: None,
            pin_mismatch: false,
            removed: false,
            pending: None,
            recovering: None,
            offers: BTreeMap::new(),
            joining: None,
            events: Vec::new(),
            last_snapshot: None,
            counter: 0,
        };
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
        if let Err(e) = self.tick_inner() {
            self.note_net(&e);
        }
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
        if self.removed {
            return Ok(());
        }
        let refresh = account.refresh(
            server.as_mut(),
            &mut *self.ports.keychain,
            &mut *self.ports.store,
        );
        let refresh = refresh?;
        self.last_ok_ms = now;
        self.connection = Connection::Online;
        self.pin_mismatch = false;
        if refresh.removed {
            self.removed = true;
            return Ok(());
        }
        for notice in &refresh.notices {
            match notice {
                Notice::RetainedOverQuota { .. } => self.notices.push(ServerNotice::Retained),
                Notice::DeviceBudget { device } => self.notices.push(ServerNotice::BudgetDevice {
                    device: account.device_display_name(device).unwrap_or_default(),
                }),
                Notice::MinimumCountCap { .. } => {
                    self.notices.push(ServerNotice::MinCount { days: 0 })
                }
                _ => {}
            }
        }
        self.notices.dedup();
        // Open offers: a new device may have answered.
        let offers: Vec<String> = self.offers.keys().cloned().collect();
        for id in offers {
            self.poll_offer(&id);
        }
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
                if e.is_offline() {
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
            if now - folder.last_full_scan >= FULL_SCAN_INTERVAL_MS {
                folder.sync.request_full_scan();
                folder.last_full_scan = now;
            }
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
                Ok(r) => r,
                Err(e) if e.is_offline() => return Err(e),
                Err(e) => {
                    folder.sync.request_full_scan();
                    let _ = e;
                    all_in_sync = false;
                    continue;
                }
            };
            all_in_sync &= report.in_sync;
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
            for change in &report.changes {
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
        }
        if all_in_sync {
            self.last_sync = Some(now);
        }
        Ok(())
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
            conflicts += Self::conflict_groups(f).len() as u64;
            names += f
                .sync
                .cannot_sync()
                .keys()
                .filter(|i| !self.persisted.ignored_names.contains(&format!("{id}:{i}")))
                .count() as u64;
        }
        if self.pin_mismatch {
            warnings.push(Warning::ServerIdentity {
                id: "serverIdentity".into(),
                has_other_device: self.account.as_ref().is_some_and(|a| {
                    a.state().current_devices().filter(|d| !d.recovery).count() > 1
                }),
            });
        }
        if self.removed {
            warnings.push(Warning::Removed {
                id: "removed".into(),
                by: String::new(),
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
        warnings.retain(|w| !self.persisted.dismissed.contains(&warning_id(w)));
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
            storage: None,
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
            deleted_folders: Vec::new(),
            env: Environment {
                camera: self.settings.camera,
            },
        }
    }

    // -- Setup ------------------------------------------------------------------------------

    /// Checks an invite link (`checkInvite`).
    pub fn check_invite(&mut self, link: &str) -> ApiResult<String, InviteError> {
        match crate::links::parse_invite(link) {
            Ok(invite) => match url_host(invite.server_url.as_str()) {
                Some(host) => ApiResult::Ok(host),
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
    ) -> Result<ApiResult<RecoveryCodeView, InviteError>, SyncError> {
        if let Some(e) = name_error(device_name) {
            return Ok(ApiResult::Err(match e {
                NameError::Blank | NameError::EdgeWhitespace => InviteError::NotALink,
            }));
        }
        let invite = match crate::links::parse_invite(link) {
            Ok(invite) => invite,
            Err(crate::links::LinkError::Insecure) => {
                return Ok(ApiResult::Err(InviteError::Insecure))
            }
            Err(_) => return Ok(ApiResult::Err(InviteError::NotALink)),
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
                return Ok(ApiResult::Err(InviteError::Insecure))
            }
            Err(_) => return Ok(ApiResult::Err(InviteError::Unreachable)),
        };
        let probe = DeviceId::from_bytes(random_id(&mut *self.ports.entropy)?);
        let server_id = match server.challenge(&account, &probe) {
            Ok(c) => c.server,
            Err(NetError::Tls(_)) | Err(NetError::PinMismatch) => {
                return Ok(ApiResult::Err(InviteError::Insecure))
            }
            Err(_) => return Ok(ApiResult::Err(InviteError::Unreachable)),
        };
        if invite.server.is_some_and(|s| s != server_id) {
            return Ok(ApiResult::Err(InviteError::Insecure));
        }
        let code = RecoveryCode::generate(&mut DynEntropy(&mut *self.ports.entropy))?;
        let mut pick = [0u8; 1];
        self.ports.entropy.fill(&mut pick)?;
        let check_group = 2 + u32::from(pick[0]) % 7;
        let groups = group(&code.reveal(), 4);
        let sheet = sheet_view(&url, server_id, account)?;
        self.pending = Some(PendingAccount {
            url,
            invite: invite.token,
            pin: invite.pin,
            server: server_id,
            account,
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

    /// Checks the typed group of the recovery code and creates the account
    /// (`confirmRecoveryGroup`).
    pub fn confirm_recovery_group(&mut self, typed: &str) -> Result<bool, SyncError> {
        let Some(pending) = &self.pending else {
            return Ok(false);
        };
        let groups = group(&pending.code.reveal(), 4);
        let index = usize::try_from(pending.check_group.saturating_sub(1)).unwrap_or(0);
        let expected = groups.get(index).cloned().unwrap_or_default();
        if typed.trim().to_ascii_uppercase() != expected {
            return Ok(false);
        }
        let Some(pending) = self.pending.take() else {
            return Ok(false);
        };
        let mut config = ServerConfig::new(&pending.url, pending.pin)?;
        config.server = Some(pending.server);
        let mut server = (self.ports.server)(&config, None)?;
        let account_id = pending.account;
        let device = DeviceId::from_bytes(random_id(&mut *self.ports.entropy)?);
        // The recovery device is derived from the code alone, so the sheet needs no device ID.
        let recovery_identity = pending
            .code
            .identity()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let recovery_id = pending
            .code
            .device_id()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let now = u64::try_from(self.now()).unwrap_or(0);
        let account = Account::create(
            server.as_mut(),
            &mut *self.ports.keychain,
            &mut *self.ports.store,
            &mut *self.ports.entropy,
            now,
            pending.invite,
            account_id,
            device,
            &pending.name,
            Some((&recovery_identity, recovery_id)),
        )?;
        if account.server_id() != Some(pending.server) {
            return Err(SyncError::Net(NetError::Protocol(
                "the server ID changed".into(),
            )));
        }
        self.account = Some(account);
        self.persisted.server_url = Some(pending.url);
        self.persisted.pin = pending.pin;
        self.save()?;
        self.connect()?;
        Ok(true)
    }

    /// Account recovery with the recovery sheet (`recoverAccount`, open point A): `sheet` is
    /// the sheet's link `hangar-drive://recover#...` (the app builds it from the printed fields
    /// or a scan), `code` the typed code. The new installation is added by the recovery
    /// device (`crate::recovery`) and joins the account; `recovery_devices` and
    /// `finish_recovery_cleanup` follow.
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
        if name_error(device_name).is_some() {
            return Err(SyncError::Invalid("device name"));
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
        let recovery_identity = code
            .identity()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let recovery_id = code
            .device_id()
            .map_err(|_| SyncError::Invalid("recovery identity"))?;
        let url = sheet.server_url.to_string();
        let mut config = ServerConfig::new(&url, None)?;
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
        let identity = DeviceIdentity::generate(&mut DynEntropy(&mut *self.ports.entropy))
            .map_err(|_| SyncError::Invalid("identity"))?;
        let device = DeviceId::from_bytes(random_id(&mut *self.ports.entropy)?);
        let entry = LogDevice::of(&identity, &sheet.account, device, false);
        let now = u64::try_from(self.now()).unwrap_or(0);
        let anchor = match crate::recovery::add_device_with_code(
            recovery_server.as_mut(),
            sheet.account,
            &code,
            entry,
            now,
            &mut *self.ports.entropy,
        ) {
            Ok(head) => head,
            Err(crate::recovery::RecoveryError::Unknown) => {
                return Ok(ApiResult::Err(RecoverError::Unknown))
            }
            Err(crate::recovery::RecoveryError::Used) => {
                return Ok(ApiResult::Err(RecoverError::Used))
            }
            Err(crate::recovery::RecoveryError::Sync(SyncError::Net(e))) => {
                return Ok(ApiResult::Err(net(&e)))
            }
            Err(crate::recovery::RecoveryError::Sync(e)) => return Err(e),
        };
        drop(recovery_server);
        let session = SessionIdentity {
            account: sheet.account,
            device,
            prover: prover(
                DeviceIdentity::import(&identity.export())
                    .map_err(|_| SyncError::Invalid("identity"))?,
            ),
        };
        let mut server = (self.ports.server)(&config, Some(session))?;
        let mut account = Account::join(
            server.as_mut(),
            &mut *self.ports.keychain,
            &mut *self.ports.store,
            identity,
            sheet.account,
            device,
            device_name,
            Some(anchor),
        )?;
        account.set_server_id(sheet.server);
        account.save(&mut *self.ports.store)?;
        self.account = Some(account);
        self.server = Some(server);
        self.persisted.server_url = Some(url.clone());
        self.persisted.pin = None;
        self.recovering = Some(Recovering { url });
        self.save()?;
        Ok(ApiResult::Ok(()))
    }

    /// The devices of the account besides this one after a recovery (`recoveryDevices`): every
    /// one is offered for removal.
    pub fn recovery_devices(&self) -> Result<Vec<Device>, SyncError> {
        let list = self.list_devices()?;
        Ok(list.devices.into_iter().filter(|d| !d.is_this).collect())
    }

    /// Ends a recovery (`finishRecoveryCleanup`): removes the chosen old devices and every
    /// recovery device, so the used code stops working, rotates and writes the barriers, and
    /// adds the recovery device of a new code, which it returns with its sheet.
    pub fn finish_recovery_cleanup(
        &mut self,
        remove: &[String],
    ) -> Result<RecoveryCodeView, SyncError> {
        let url = self
            .recovering
            .as_ref()
            .map(|r| r.url.clone())
            .ok_or(SyncError::Invalid("no recovery in progress"))?;
        let account = self
            .account
            .as_ref()
            .ok_or(SyncError::NotSetUp("no account"))?;
        let me = *account.device();
        let mut targets: Vec<DeviceId> = Vec::new();
        for text in remove {
            let id = DeviceId::from_hex(text).map_err(|_| SyncError::Invalid("device"))?;
            if id != me && account.state().device(&id).is_some_and(|d| d.is_current()) {
                targets.push(id);
            }
        }
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
        let server_id = account
            .server_id()
            .ok_or(SyncError::NotSetUp("the server ID is not known yet"))?;
        let sheet = sheet_view(&url, server_id, *account.id())?;
        let mut pick = [0u8; 1];
        self.ports.entropy.fill(&mut pick)?;
        self.recovering = None;
        Ok(RecoveryCodeView {
            groups: group(&code.reveal(), 4),
            check_group: 2 + u32::from(pick[0]) % 7,
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
        let Ok(keys) = offer.secret.verify_request(account.id(), &request) else {
            return;
        };
        let safety = NumberRows::of(&safety_number(account.id(), &request.device, &keys));
        self.events.push(BackendEvent::PairRequest {
            request: PairRequestView {
                offer_id: id.to_owned(),
                device_name: request.name.clone(),
                path: PairPath::Link,
                safety,
            },
        });
        offer.request = Some(request);
    }

    /// The person's answer to a new device (`answerPairRequest`).
    pub fn answer_pair_request(&mut self, offer_id: &str, accept: bool) -> Result<(), SyncError> {
        let Some(offer) = self.offers.remove(offer_id) else {
            return Ok(());
        };
        let Some(request) = offer.request else {
            return Ok(());
        };
        if !accept {
            return Ok(());
        }
        let (Some(account), Some(server)) = (self.account.as_mut(), self.server.as_mut()) else {
            return Err(SyncError::NotSetUp("no account"));
        };
        let keys = offer
            .secret
            .verify_request(account.id(), &request)
            .map_err(|_| SyncError::Invalid("pairing request"))?;
        let device = LogDevice {
            id: request.device,
            keys,
            recovery: false,
            proof: request.proof,
        };
        let now = u64::try_from(self.ports.clock.now_ms()).unwrap_or(0);
        account.add_device(
            server.as_mut(),
            &mut *self.ports.store,
            device,
            &request.name,
            now,
            &mut *self.ports.entropy,
        )
    }

    /// Starts pairing on a new device with the link of an offer (`startPairing`).
    pub fn start_pairing(
        &mut self,
        link: &str,
        device_name: &str,
    ) -> Result<ApiResult<NumberRows, PairError>, SyncError> {
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
            .request(&identity, &account, device, device_name)
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
            Some(joining.offer.content.head),
        );
        let Ok(mut account) = joined else {
            // Not added yet (or the server is down): try again at the next tick.
            return;
        };
        if hangar_drive_crypto::pairing::check_joined(
            account.state(),
            &joining.offer,
            &joining.device,
            &keys,
        )
        .is_err()
        {
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
        self.events.push(BackendEvent::PairResult {
            result: PairResult::Joined,
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
        self.stop_folder(folder)
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

    /// Hides a warning on this device only (`dismissSuspect`; ADR 0001, section 5: no shared
    /// dismissal).
    pub fn dismiss_warning(&mut self, warning_id: &str) -> Result<(), SyncError> {
        self.persisted.dismissed.insert(warning_id.to_owned());
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
    /// an undo token (the current head, for a restore).
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
        let token = f
            .sync
            .view()
            .frontier()
            .map(|e| e.commit.to_hex())
            .unwrap_or_default();
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
        Ok(token)
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
                let reason = match windows_problem(&node.name) {
                    Some(WindowsNameProblem::ForbiddenCharacter(c)) => NameReason::Char {
                        char: c.to_string(),
                    },
                    Some(WindowsNameProblem::Reserved) => NameReason::Reserved {
                        name: node.name.clone(),
                    },
                    Some(WindowsNameProblem::TrailingDotOrSpace) => NameReason::Trailing,
                    Some(WindowsNameProblem::ControlCharacter) => NameReason::Control,
                    _ => NameReason::CannotCreate,
                };
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

    /// Restores one file or directory of a timeline entry (`restoreFile`).
    pub fn restore_file(
        &mut self,
        folder: &str,
        entry: &str,
        path: &str,
    ) -> Result<RestoreOutcome, SyncError> {
        let commit = hangar_drive_protocol::ids::CommitId::from_hex(entry)
            .map_err(|_| SyncError::Invalid("entry"))?;
        let names: Vec<String> = path
            .split('/')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        let result = self.with_ctx(folder, |sync, cx| {
            let old = sync.tree_at(cx, &commit)?;
            let item = old.lookup(&names).ok_or(SyncError::Invalid("path"))?;
            let original = old.get(&item).map(|n| n.name.clone()).unwrap_or_default();
            let name = sync.restore_item(cx, &commit, &item)?;
            Ok((name, original))
        });
        Ok(restore_outcome(result.map(|(name, original)| {
            (1, (name != original).then_some(name))
        })))
    }

    /// Restores the whole folder to a timeline entry (`resetFolder`).
    pub fn reset_folder(&mut self, folder: &str, entry: &str) -> Result<RestoreOutcome, SyncError> {
        let commit = hangar_drive_protocol::ids::CommitId::from_hex(entry)
            .map_err(|_| SyncError::Invalid("entry"))?;
        let result = self.with_ctx(folder, |sync, cx| {
            sync.restore_folder(cx, &commit)?;
            Ok(sync.remote().count_files() as u64)
        });
        Ok(restore_outcome(result.map(|n| (n, None))))
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

    /// Restores trash items (`restoreTrash`).
    pub fn restore_trash(
        &mut self,
        folder: &str,
        items: &[String],
    ) -> Result<RestoreOutcome, SyncError> {
        let mut count = 0u64;
        for item in items {
            let (commit, id) = item
                .split_once(':')
                .ok_or(SyncError::Invalid("trash item"))?;
            let commit = hangar_drive_protocol::ids::CommitId::from_hex(commit)
                .map_err(|_| SyncError::Invalid("trash item"))?;
            let id = ItemId::from_hex(id).map_err(|_| SyncError::Invalid("trash item"))?;
            match self.with_ctx(folder, |sync, cx| sync.restore_item(cx, &commit, &id)) {
                Ok(_) => count += 1,
                Err(e) => return Ok(restore_outcome(Err(e))),
            }
        }
        Ok(RestoreOutcome::Done {
            count,
            renamed_to: None,
            undo_token: None,
        })
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

    /// Renames a device (`renameDevice`, `setDeviceName`).
    pub fn rename_device(
        &mut self,
        device: &str,
        name: &str,
    ) -> Result<ApiResult<(), NameError>, SyncError> {
        if let Some(e) = name_error(name) {
            return Ok(ApiResult::Err(e));
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
    /// syncs again, and the window offers "Undo a device" for them (`findBeforeDevice`).
    /// Returns how many heads the barrier covers.
    pub fn accept_removed_heads(&mut self, folder: &str) -> Result<usize, SyncError> {
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
        let outcome = accept_removed_heads(&mut jx, &mut lf.sync, &*lf.fs)?;
        Ok(outcome.removed_heads.len())
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

fn restore_outcome(result: Result<(u64, Option<String>), SyncError>) -> RestoreOutcome {
    match result {
        Ok((count, renamed_to)) => RestoreOutcome::Done {
            count,
            renamed_to,
            undo_token: None,
        },
        Err(SyncError::Net(e)) => match e.code() {
            Some(ErrorCode::BudgetExceeded) => RestoreOutcome::WaitBudget {
                job_id: String::new(),
            },
            Some(ErrorCode::QuotaExceeded) => RestoreOutcome::NoSpace,
            Some(ErrorCode::MissingObjects) | Some(ErrorCode::NotFound) => RestoreOutcome::Expired,
            _ => RestoreOutcome::Failed,
        },
        Err(_) => RestoreOutcome::Failed,
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
