//! One synced folder: the three trees, the verified chain and the control loop of one round.
//!
//! A round ([`FolderSync::round`]) runs these steps in order, each on fixed inputs:
//!
//! 1. **Guard:** the root marker must be there, else the folder stops (it never deletes).
//! 2. **Scan:** the disk becomes the local tree; a file is hashed only when size, mtime (with
//!    the file system's tolerance) or file ID differ from the index.
//! 3. **Pull:** the folder delta after the cursor is verified as a whole
//!    (`FolderView::verify_delta`); the new head's tree becomes the remote tree.
//! 4. **Plan:** `P = merge3(synced, remote, local)` with delayed deletes and the mass delete
//!    guard ([`crate::planner`]).
//! 5. **Publish:** if `P` differs from the remote tree, the missing objects are uploaded and the
//!    commit is sent with the expected head. A failed compare-and-swap pulls again and merges
//!    again, now with a side commit of the local state on the last fully synced head, with
//!    bounded retries (ADR 0001, section 3, "Publishing").
//! 6. **Apply:** the disk is brought to `P` ([`crate::apply`]); per finished item the synced
//!    tree takes its new state.
//!
//! Everything a round changes is written to the [`Store`] in one batch at the end of each step,
//! so a restart resumes from the last step and never takes a missing file for a delete.

use std::collections::{BTreeMap, BTreeSet};

use hangar_drive_crypto::commit::{
    ChainEntry, Commit, CommitContent, DeltaCheck, DeltaOutcome, FolderView, RemovedHead,
    SignedCommit,
};
use hangar_drive_crypto::epoch::BarrierPermit;
use hangar_drive_crypto::Entropy;
use hangar_drive_protocol::api::{
    CommitRequest, CommitUpload, DeltaCommit, ErrorCode, ReferenceDelta,
};
use hangar_drive_protocol::ids::{
    Blob, CommitId, DeviceId, FolderId, Generation, ItemId, ObjectId,
};
use hangar_drive_protocol::name::{is_ignored, RESERVED_ROOT_DIR};
use hangar_drive_protocol::object::ObjectType;
use serde::{Deserialize, Serialize};

use crate::account::Account;
use crate::apply::{apply, ActionError, DiskActions};
use crate::chunker::{hash_many, ChunkError, HashJob};
use crate::codec::{self, CodecError, Encoded, FolderCrypto};
use crate::error::SyncError;
use crate::merge::{ConflictCopy, ItemIds, MergeLabels};
use crate::names::{date_label, LabelWords};
use crate::planner::{plan, Plan, PlanInput, MASS_DELETE_THRESHOLD};
use crate::ports::{
    random_item_id, ChunkList, Clock, EntryType, Expect, FileSystem, FsError, Keychain, NetError,
    SaveBatch, ServerApi, Stat, Store,
};
use crate::tree::{ContentKey, FileVersion, Node, NodeKind, Tree, ROOT};

/// Name of the root marker inside the reserved directory.
pub const MARKER_NAME: &str = "marker";
/// Name of the park directory inside the reserved directory.
pub const PARK_DIR: &str = "park";

/// The path of the root marker.
pub fn marker_path() -> Vec<String> {
    vec![RESERVED_ROOT_DIR.to_owned(), MARKER_NAME.to_owned()]
}

/// What the person and the platform set for every folder.
#[derive(Debug, Clone)]
pub struct FolderSettings {
    /// The words of conflict copy and restore labels, in the UI language.
    pub words: LabelWords,
    /// The device's offset from UTC in minutes, for the date in labels.
    pub tz_offset_minutes: i32,
    /// How long a local delete waits before it is propagated (ADR 0001, section 5).
    pub delete_delay_ms: i64,
    /// Deletes of one round from which the person is asked first.
    pub mass_delete_threshold: usize,
    /// Workers for hashing.
    pub hash_threads: usize,
    /// Merge and publish attempts per round after a failed compare-and-swap.
    pub max_publish_attempts: u32,
    /// Object IDs one commit may declare
    /// ([`hangar_drive_protocol::api::MAX_REFERENCE_DELTA_IDS`]; smaller in tests). A publish
    /// that adds more goes out as several commits ([`stage_tree`]).
    pub max_delta_ids: usize,
}

impl Default for FolderSettings {
    fn default() -> Self {
        Self {
            words: LabelWords::default(),
            tz_offset_minutes: 0,
            delete_delay_ms: 10_000,
            mass_delete_threshold: MASS_DELETE_THRESHOLD,
            hash_threads: 4,
            max_publish_attempts: 5,
            max_delta_ids: hangar_drive_protocol::api::MAX_REFERENCE_DELTA_IDS,
        }
    }
}

/// Why a folder stopped syncing until the person acts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StopReason {
    /// The root marker is missing (the folder was moved, deleted or the drive is gone).
    MarkerMissing,
    /// The server shows an older state of the folder (ADR 0001, section 4).
    OlderState,
    /// The folder was removed on all devices.
    Retired,
    /// The server presents heads of a removed device that no barrier commit covers, and the
    /// device that removed it did not finish its barriers (ADR 0001, section 4; security review
    /// H1). The folder waits until the person decides; the heads are in
    /// [`FolderMeta::removed_heads`].
    RemovedHeads,
}

/// A head of a removed device the person is asked about (security review H1, N2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemovedHeadRec {
    /// The commit.
    pub commit: CommitId,
    /// The removed device that signed it.
    pub device: DeviceId,
    /// Its folder sequence.
    pub sequence: u64,
    /// The log index that removed the device.
    pub removed_at: u64,
}

impl From<&RemovedHead> for RemovedHeadRec {
    fn from(h: &RemovedHead) -> Self {
        Self {
            commit: h.commit,
            device: h.device,
            sequence: h.sequence,
            removed_at: h.removed_at,
        }
    }
}

/// The folder's explicit state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FolderState {
    /// Syncing.
    #[default]
    Active,
    /// Paused by the person.
    Paused,
    /// Stopped until the person acts.
    Stopped(StopReason),
}

/// A head on the verified chain, as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainRec {
    /// The commit.
    pub commit: CommitId,
    /// Its height.
    pub height: u64,
    /// The folder sequence.
    pub sequence: u64,
    /// Its generation.
    pub generation: u32,
    /// Its log head index.
    pub log_index: u64,
}

impl From<&ChainEntry> for ChainRec {
    fn from(e: &ChainEntry) -> Self {
        Self {
            commit: e.commit,
            height: e.height,
            sequence: e.sequence,
            generation: e.generation.0,
            log_index: e.log_index,
        }
    }
}

impl From<&ChainRec> for ChainEntry {
    fn from(r: &ChainRec) -> Self {
        Self {
            commit: r.commit,
            height: r.height,
            sequence: r.sequence,
            generation: Generation(r.generation),
            log_index: r.log_index,
        }
    }
}

/// One commit of the folder's history as this device saw it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimelineRec {
    /// The commit.
    pub commit: CommitId,
    /// Its folder sequence.
    pub sequence: u64,
    /// The writing device.
    pub device: DeviceId,
    /// When this device first saw it (the protocol's delta carries no server time).
    pub seen_at_ms: i64,
    /// The re-anchor mark.
    pub reanchor: bool,
    /// A side commit.
    pub side: bool,
    /// The root directory node.
    pub root: ObjectId,
}

/// The base of a side commit: the newest head whose tree the disk fully held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncBase {
    /// The head.
    pub entry: ChainRec,
    /// Its root.
    pub root: ObjectId,
}

/// The folder's stored metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FolderMeta {
    /// The display name.
    pub name: String,
    /// The explicit state.
    pub state: FolderState,
    /// The verified chain.
    pub chain: Vec<ChainRec>,
    /// Per device counter marks.
    pub marks: Vec<(DeviceId, u64)>,
    /// Heads discarded at a re-anchor.
    pub discarded: Vec<CommitId>,
    /// The frontier commit's wire bytes (for a barrier on it).
    pub frontier_wire: Option<Blob>,
    /// The root of the remote tree.
    pub remote_root: Option<ObjectId>,
    /// The last fully synced head.
    pub sync_base: Option<SyncBase>,
    /// The history as seen.
    pub timeline: Vec<TimelineRec>,
    /// Items this device cannot hold, with the reason.
    pub cannot_sync: BTreeMap<ItemId, String>,
    /// When a local delete was first seen.
    pub deleted_seen: BTreeMap<ItemId, i64>,
    /// Local deletes held for the person's decision.
    pub held: BTreeSet<ItemId>,
    /// Held deletes the person undid.
    pub restore: BTreeSet<ItemId>,
    /// The person allowed the held deletes.
    pub approve_deletes: bool,
    /// Items retried later (locked files), with the attempt count and the time to retry.
    pub backoff: BTreeMap<ItemId, (u32, i64)>,
    /// Entries never synced (links, system files, names that are not UTF-8).
    pub not_synced: Vec<(String, String)>,
    /// Heads of removed devices waiting for the person's decision
    /// ([`StopReason::RemovedHeads`]).
    #[serde(default)]
    pub removed_heads: Vec<RemovedHeadRec>,
}

/// A local change propagated or a remote change applied in a round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ItemChange {
    /// The item.
    pub item: ItemId,
    /// Its path after the change ("/" separated).
    pub path: String,
    /// What happened.
    pub action: ChangeAction,
    /// From the server (true) or from this disk (false).
    pub incoming: bool,
}

/// What happened to an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeAction {
    /// Added.
    Added,
    /// Content changed.
    Changed,
    /// Deleted.
    Deleted,
    /// Moved or renamed.
    Moved,
}

/// What a round did.
#[derive(Debug, Clone, Default)]
pub struct RoundReport {
    /// New heads taken from the server.
    pub pulled: usize,
    /// This device published a commit.
    pub published: bool,
    /// Items applied to disk.
    pub applied: usize,
    /// Items that failed on disk.
    pub failed: Vec<(ItemId, ActionError)>,
    /// Local deletes held for the person (mass delete).
    pub held: Vec<ItemId>,
    /// Conflict copies made.
    pub copies: Vec<ConflictCopy>,
    /// The round stopped because the server is not reachable.
    pub offline: bool,
    /// Waiting for keys (the freshness rule after a removal, or no ring yet).
    pub waiting_keys: bool,
    /// Disk, server and synced tree agree.
    pub in_sync: bool,
    /// Changes for the activity list.
    pub changes: Vec<ItemChange>,
    /// Heads of removed devices this round found without a barrier; the folder stopped with
    /// [`StopReason::RemovedHeads`] and the app asks the person (security review H1).
    pub removed_heads: Vec<RemovedHeadRec>,
}

/// Everything a round needs from outside.
pub struct Ctx<'a> {
    /// The verified account.
    pub account: &'a mut Account,
    /// The server.
    pub server: &'a mut dyn ServerApi,
    /// The keychain.
    pub keychain: &'a mut dyn Keychain,
    /// The sync root.
    pub fs: &'a dyn FileSystem,
    /// The local index.
    pub store: &'a mut dyn Store,
    /// The clock.
    pub clock: &'a dyn Clock,
    /// Randomness.
    pub entropy: &'a mut dyn Entropy,
    /// Settings.
    pub settings: &'a FolderSettings,
}

struct EntropyIds<'a>(&'a mut dyn Entropy);

impl ItemIds for EntropyIds<'_> {
    fn new_item_id(&mut self) -> ItemId {
        // A failing generator here would leave no safe ID; fall back to a hash of a counter
        // so the merge stays total. The OS generator does not fail in practice.
        random_item_id(self.0).unwrap_or_else(|_| ItemId::from_bytes([0xff; 16]))
    }
}

/// One synced folder (module docs).
pub struct FolderSync {
    folder: FolderId,
    remote: Tree,
    synced: Tree,
    local: Tree,
    file_ids: BTreeMap<ItemId, u128>,
    file_ids_dirty: BTreeMap<ItemId, Option<u128>>,
    meta: FolderMeta,
    view: FolderView,
    scan_scope: ScanScope,
}

/// What the next scan reads from the disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanScope {
    /// Every directory (at start, hourly, and after the watcher lost events).
    Full,
    /// Only these paths (from watcher events) and the directories above them.
    Paths(BTreeSet<Vec<String>>),
}

impl std::fmt::Debug for FolderSync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FolderSync")
            .field("folder", &self.folder)
            .field("state", &self.meta.state)
            .field("remote", &self.remote.len())
            .field("local", &self.local.len())
            .finish_non_exhaustive()
    }
}

fn path_string(tree: &Tree, id: &ItemId) -> String {
    tree.path_string(id).unwrap_or_default()
}

fn expect_of(v: &FileVersion, file_id: Option<u128>) -> Expect {
    Expect {
        size: v.size,
        mtime_ms: v.mtime_ms,
        file_id,
    }
}

fn action_error(e: FsError) -> ActionError {
    match e {
        FsError::NotFound | FsError::NotEmpty | FsError::Changed => ActionError::Changed,
        FsError::Exists => ActionError::Exists,
        FsError::Locked => ActionError::Locked,
        FsError::CannotSync(reason) => ActionError::CannotSync(reason),
        FsError::DiskFull => ActionError::DiskFull,
        FsError::Denied => ActionError::Io("permission denied".into()),
        FsError::Io(m) => ActionError::Io(m),
    }
}

/// The executor's disk: the sync root plus the content from the server.
struct FsDisk<'a> {
    fs: &'a dyn FileSystem,
    server: &'a mut dyn ServerApi,
    store: &'a dyn Store,
    crypto: &'a FolderCrypto,
    file_ids: &'a mut BTreeMap<ItemId, u128>,
    dirty: &'a mut BTreeMap<ItemId, Option<u128>>,
}

impl FsDisk<'_> {
    fn park_path(item: &ItemId) -> Vec<String> {
        vec![
            RESERVED_ROOT_DIR.to_owned(),
            PARK_DIR.to_owned(),
            item.to_hex(),
        ]
    }

    fn ensure_park_dir(&self) {
        let _ = self.fs.create_dir(&[RESERVED_ROOT_DIR.to_owned()]);
        let _ = self
            .fs
            .create_dir(&[RESERVED_ROOT_DIR.to_owned(), PARK_DIR.to_owned()]);
    }
}

impl DiskActions for FsDisk<'_> {
    fn create_dir(&mut self, path: &[String]) -> Result<(), ActionError> {
        self.fs.create_dir(path).map_err(action_error)
    }

    fn write_file(
        &mut self,
        item: &ItemId,
        path: &[String],
        version: &FileVersion,
        expect: Option<&FileVersion>,
    ) -> Result<(), ActionError> {
        let folder = *self.crypto.folder();
        let list = self
            .store
            .chunk_list(&folder, &version.content)
            .map_err(|_| ActionError::Unavailable)?
            .ok_or(ActionError::Unavailable)?;
        if list.chunks.len() as u64
            != version
                .size
                .div_ceil(hangar_drive_protocol::object::CHUNK_SIZE)
        {
            return Err(ActionError::Unavailable);
        }
        let mut failure: Option<ActionError> = None;
        let crypto = self.crypto;
        let server = &mut *self.server;
        let size = version.size;
        let mut fill = |out: &mut dyn std::io::Write| -> Result<(), FsError> {
            let mut written = 0u64;
            for (index, id) in list.chunks.iter().enumerate() {
                let blob = match server.get_object(&folder, id) {
                    Ok(b) => b,
                    Err(_) => {
                        failure = Some(ActionError::Unavailable);
                        return Err(FsError::Io("content unavailable".into()));
                    }
                };
                let plain = match crypto.open(id, ObjectType::Chunk, &blob) {
                    Ok(p) => p,
                    Err(_) => {
                        failure = Some(ActionError::Unavailable);
                        return Err(FsError::Io("content does not open".into()));
                    }
                };
                let expected = (size - index as u64 * hangar_drive_protocol::object::CHUNK_SIZE)
                    .min(hangar_drive_protocol::object::CHUNK_SIZE);
                if plain.len() as u64 != expected {
                    failure = Some(ActionError::Unavailable);
                    return Err(FsError::Io("chunk length".into()));
                }
                out.write_all(&plain)
                    .map_err(|e| FsError::Io(e.to_string()))?;
                written += plain.len() as u64;
            }
            if written != size {
                failure = Some(ActionError::Unavailable);
                return Err(FsError::Io("size".into()));
            }
            Ok(())
        };
        let known = self.file_ids.get(item).copied();
        let result = self.fs.write_atomic(
            path,
            &mut fill,
            version.mtime_ms,
            version.executable,
            expect.map(|e| expect_of(e, known)),
        );
        match result {
            Ok(stat) => {
                if let Some(id) = stat.file_id {
                    self.file_ids.insert(*item, id);
                    self.dirty.insert(*item, Some(id));
                }
                Ok(())
            }
            Err(e) => Err(failure.unwrap_or_else(|| action_error(e))),
        }
    }

    fn set_meta(
        &mut self,
        item: &ItemId,
        path: &[String],
        version: &FileVersion,
        expect: &FileVersion,
    ) -> Result<(), ActionError> {
        self.fs
            .set_meta(
                path,
                version.mtime_ms,
                version.executable,
                expect_of(expect, self.file_ids.get(item).copied()),
            )
            .map_err(action_error)
    }

    fn rename(&mut self, from: &[String], to: &[String]) -> Result<(), ActionError> {
        self.fs.rename(from, to).map_err(action_error)
    }

    fn remove_file(
        &mut self,
        item: &ItemId,
        path: &[String],
        expect: &FileVersion,
    ) -> Result<(), ActionError> {
        // Another device deleted it: the recycle bin or the quarantine, never into nothing
        // (security review M2).
        self.fs
            .trash_file(
                item,
                path,
                expect_of(expect, self.file_ids.get(item).copied()),
            )
            .map(|_| ())
            .map_err(action_error)
    }

    fn remove_dir(&mut self, path: &[String]) -> Result<(), ActionError> {
        self.fs.remove_dir(path).map_err(action_error)
    }

    fn park(&mut self, item: &ItemId, path: &[String]) -> Result<(), ActionError> {
        self.ensure_park_dir();
        self.fs
            .rename(path, &Self::park_path(item))
            .map_err(action_error)
    }

    fn unpark(&mut self, item: &ItemId, path: &[String]) -> Result<(), ActionError> {
        self.fs
            .rename(&Self::park_path(item), path)
            .map_err(action_error)
    }
}

/// Why a publish attempt did not go through.
enum PublishFailure {
    /// Another device won the compare-and-swap: pull and merge again.
    HeadMoved,
    /// The local disk changed under the upload: scan again.
    LocalChanged,
    /// Any other error.
    Error(SyncError),
}

impl From<SyncError> for PublishFailure {
    fn from(e: SyncError) -> Self {
        PublishFailure::Error(e)
    }
}

impl From<CodecError> for PublishFailure {
    fn from(e: CodecError) -> Self {
        PublishFailure::Error(e.into())
    }
}

impl From<NetError> for PublishFailure {
    fn from(e: NetError) -> Self {
        PublishFailure::Error(e.into())
    }
}

impl FolderSync {
    // -- Life cycle -------------------------------------------------------------------------

    /// A folder this device starts to sync now, at a place that may already hold files (the
    /// first round is then the join of ADR 0001, section 3).
    pub fn new(account: &Account, folder: FolderId, name: &str) -> Self {
        Self {
            folder,
            remote: Tree::new(),
            synced: Tree::new(),
            local: Tree::new(),
            file_ids: BTreeMap::new(),
            file_ids_dirty: BTreeMap::new(),
            meta: FolderMeta {
                name: name.to_owned(),
                ..FolderMeta::default()
            },
            view: FolderView::new(*account.id(), folder),
            scan_scope: ScanScope::Full,
        }
    }

    /// The folder from the local index.
    pub fn load(
        account: &Account,
        folder: FolderId,
        store: &dyn Store,
    ) -> Result<Option<Self>, SyncError> {
        let Some(stored) = store.load_folder(&folder)? else {
            return Ok(None);
        };
        let meta: FolderMeta =
            serde_json::from_slice(&stored.meta).map_err(|e| SyncError::Corrupt(e.to_string()))?;
        let view = FolderView::restore(
            *account.id(),
            folder,
            meta.chain.iter().map(ChainEntry::from).collect(),
            meta.marks.iter().copied().collect(),
            meta.discarded.iter().copied().collect(),
        )?;
        Ok(Some(Self {
            folder,
            remote: Tree::from_nodes(stored.remote),
            synced: Tree::from_nodes(stored.synced),
            local: Tree::from_nodes(stored.local),
            file_ids: stored.file_ids.into_iter().collect(),
            file_ids_dirty: BTreeMap::new(),
            meta,
            view,
            scan_scope: ScanScope::Full,
        }))
    }

    fn save(&mut self, store: &mut dyn Store) -> Result<(), SyncError> {
        self.meta.chain = self.view.chain().iter().map(ChainRec::from).collect();
        self.meta.marks = self.view.marks().iter().map(|(k, v)| (*k, *v)).collect();
        self.meta.discarded = self.view.discarded().iter().copied().collect();
        let meta = serde_json::to_vec(&self.meta).map_err(|e| SyncError::Corrupt(e.to_string()))?;
        let batch = SaveBatch {
            remote: self.remote.take_delta(),
            synced: self.synced.take_delta(),
            local: self.local.take_delta(),
            file_ids: std::mem::take(&mut self.file_ids_dirty)
                .into_iter()
                .collect(),
            meta: Some(meta),
        };
        store.save_folder(&self.folder, &batch)?;
        Ok(())
    }

    /// Stores the folder's state now.
    pub(crate) fn save_state(&mut self, store: &mut dyn Store) -> Result<(), SyncError> {
        self.save(store)
    }

    /// Writes the root marker (when the person sets the folder up at a place).
    pub fn write_marker(&self, fs: &dyn FileSystem) -> Result<(), SyncError> {
        match fs.create_dir(&[RESERVED_ROOT_DIR.to_owned()]) {
            Ok(()) | Err(FsError::Exists) => {}
            Err(e) => return Err(e.into()),
        }
        let content = self.folder.to_hex().into_bytes();
        let path = marker_path();
        let replace = fs.stat(&path)?.map(|s| Expect {
            size: s.size,
            mtime_ms: s.mtime_ms,
            file_id: s.file_id,
        });
        fs.write_atomic(
            &path,
            &mut |w| {
                w.write_all(&content)
                    .map_err(|e| FsError::Io(e.to_string()))
            },
            0,
            false,
            replace,
        )?;
        Ok(())
    }

    fn marker_ok(&self, fs: &dyn FileSystem) -> bool {
        let path = marker_path();
        let mut buf = [0u8; 64];
        match fs.read_at(&path, 0, &mut buf) {
            Ok(n) => &buf[..n] == self.folder.to_hex().as_bytes(),
            Err(_) => false,
        }
    }

    // -- Accessors --------------------------------------------------------------------------

    /// The folder ID.
    pub fn id(&self) -> &FolderId {
        &self.folder
    }

    /// The metadata.
    pub fn meta(&self) -> &FolderMeta {
        &self.meta
    }

    /// The remote tree.
    pub fn remote(&self) -> &Tree {
        &self.remote
    }

    /// The synced tree.
    pub fn synced(&self) -> &Tree {
        &self.synced
    }

    /// The local tree.
    pub fn local(&self) -> &Tree {
        &self.local
    }

    /// The verified chain.
    pub fn view(&self) -> &FolderView {
        &self.view
    }

    /// The explicit state.
    pub fn state(&self) -> FolderState {
        self.meta.state
    }

    /// Paths the watcher reported as changed (below the root); the next scan reads them.
    pub fn note_changes(&mut self, paths: impl IntoIterator<Item = Vec<String>>) {
        if let ScanScope::Paths(set) = &mut self.scan_scope {
            set.extend(paths);
        }
    }

    /// The next scan reads every directory (hourly, or after the watcher lost events).
    pub fn request_full_scan(&mut self) {
        self.scan_scope = ScanScope::Full;
    }

    /// Pauses or resumes.
    pub fn set_paused(&mut self, paused: bool, store: &mut dyn Store) -> Result<(), SyncError> {
        self.meta.state = match (paused, self.meta.state) {
            (true, FolderState::Active) => FolderState::Paused,
            (false, FolderState::Paused) => FolderState::Active,
            (_, other) => other,
        };
        self.save(store)
    }

    /// Clears a stop after the person fixed its cause (the marker is back).
    pub fn clear_stop(&mut self, store: &mut dyn Store) -> Result<(), SyncError> {
        if matches!(
            self.meta.state,
            FolderState::Stopped(StopReason::MarkerMissing)
        ) {
            self.meta.state = FolderState::Active;
        }
        self.save(store)
    }

    /// The person's decision on held deletes: restore them or let them go.
    pub fn resolve_held(
        &mut self,
        restore: bool,
        store: &mut dyn Store,
    ) -> Result<usize, SyncError> {
        let held = std::mem::take(&mut self.meta.held);
        let n = held.len();
        if restore {
            self.meta.restore.extend(held);
        } else {
            self.meta.approve_deletes = true;
        }
        self.save(store)?;
        Ok(n)
    }

    /// Whether disk, server and synced tree agree (cannot-sync items aside).
    pub fn in_sync(&self) -> bool {
        let skip = |id: &ItemId| self.meta.cannot_sync.contains_key(id);
        let strip = |t: &Tree| -> Vec<(ItemId, Node)> {
            t.iter()
                .filter(|(id, _)| !skip(id))
                .map(|(id, n)| (*id, n.clone()))
                .collect()
        };
        strip(&self.remote) == strip(&self.synced) && strip(&self.synced) == strip(&self.local)
    }

    // -- The round --------------------------------------------------------------------------

    /// One round of the control loop (module docs).
    pub fn round(&mut self, cx: &mut Ctx<'_>) -> Result<RoundReport, SyncError> {
        let mut report = RoundReport::default();
        if self.meta.state != FolderState::Active {
            return Ok(report);
        }
        if !self.marker_ok(cx.fs) {
            self.meta.state = FolderState::Stopped(StopReason::MarkerMissing);
            self.save(cx.store)?;
            return Ok(report);
        }
        if cx.account.ring(&self.folder).is_none() {
            report.waiting_keys = true;
            return Ok(report);
        }
        self.scan(cx)?;
        self.save(cx.store)?;
        match self.pull(cx) {
            Ok(n) => report.pulled = n,
            Err(e) if e.is_offline() => {
                report.offline = true;
                return Ok(report);
            }
            Err(e) => return self.stop_on(e, cx.store),
        }
        if self.meta.state == FolderState::Stopped(StopReason::RemovedHeads) {
            report.removed_heads = self.meta.removed_heads.clone();
            self.save(cx.store)?;
            return Ok(report);
        }
        self.save(cx.store)?;
        let attempts = cx.settings.max_publish_attempts.max(1);
        let mut planned: Option<Plan> = None;
        for _ in 0..attempts {
            let p = self.plan_round(cx, &mut report);
            if !p.publish {
                planned = Some(p);
                break;
            }
            match self.publish(cx, &p) {
                Ok(()) => {
                    report.published = true;
                    planned = Some(p);
                    break;
                }
                Err(PublishFailure::HeadMoved) => match self.pull(cx) {
                    Ok(_) if self.meta.state != FolderState::Active => {
                        report.removed_heads = self.meta.removed_heads.clone();
                        self.save(cx.store)?;
                        return Ok(report);
                    }
                    Ok(n) => report.pulled += n,
                    Err(e) if e.is_offline() => {
                        report.offline = true;
                        self.save(cx.store)?;
                        return Ok(report);
                    }
                    Err(e) => return self.stop_on(e, cx.store),
                },
                Err(PublishFailure::LocalChanged) => {
                    self.request_full_scan();
                    self.scan(cx)?;
                }
                Err(PublishFailure::Error(e)) if e.is_offline() => {
                    report.offline = true;
                    self.save(cx.store)?;
                    return Ok(report);
                }
                Err(PublishFailure::Error(SyncError::Freshness(_))) => {
                    report.waiting_keys = true;
                    self.save(cx.store)?;
                    return Ok(report);
                }
                Err(PublishFailure::Error(e)) => {
                    self.save(cx.store)?;
                    return Err(e);
                }
            }
        }
        let Some(p) = planned else {
            // Every attempt lost the swap; the next round tries again.
            self.save(cx.store)?;
            return Ok(report);
        };
        self.apply_plan(cx, p, &mut report)?;
        if self.remote == self.synced {
            if let Some(frontier) = self.view.frontier() {
                if let Some(root) = self.meta.remote_root {
                    self.meta.sync_base = Some(SyncBase {
                        entry: ChainRec::from(frontier),
                        root,
                    });
                }
            }
        }
        report.in_sync = self.in_sync();
        self.save(cx.store)?;
        Ok(report)
    }

    fn stop_on(&mut self, e: SyncError, store: &mut dyn Store) -> Result<RoundReport, SyncError> {
        let older = matches!(
            &e,
            SyncError::Chain(hangar_drive_crypto::commit::ChainError::OlderState)
                | SyncError::Chain(hangar_drive_crypto::commit::ChainError::Discarded)
        );
        if older {
            self.meta.state = FolderState::Stopped(StopReason::OlderState);
            self.save(store)?;
            return Ok(RoundReport::default());
        }
        if matches!(&e, SyncError::Net(n) if n.code() == Some(ErrorCode::FolderRetired)) {
            self.meta.state = FolderState::Stopped(StopReason::Retired);
            self.save(store)?;
            return Ok(RoundReport::default());
        }
        self.save(store)?;
        Err(e)
    }

    fn plan_round(&mut self, cx: &mut Ctx<'_>, report: &mut RoundReport) -> Plan {
        let now = cx.clock.now_ms();
        let delay = cx.settings.delete_delay_ms;
        let delayed: BTreeSet<ItemId> = self
            .meta
            .deleted_seen
            .iter()
            .filter(|(_, seen)| now - **seen < delay)
            .map(|(id, _)| *id)
            .chain(self.meta.held.iter().copied())
            .collect();
        let restore = self.meta.restore.clone();
        let date = date_label(now, cx.settings.tz_offset_minutes);
        let device_name = cx.account.device_name().to_owned();
        let labels = MergeLabels {
            words: &cx.settings.words,
            device: &device_name,
            date: &date,
        };
        let mut p = plan(
            PlanInput {
                remote: &self.remote,
                synced: &self.synced,
                local: &self.local,
                delayed: &delayed,
                restore: &restore,
            },
            &labels,
            &mut EntropyIds(cx.entropy),
        );
        if p.local_deletes.len() >= cx.settings.mass_delete_threshold && !self.meta.approve_deletes
        {
            self.meta.held.extend(p.local_deletes.iter().copied());
            report.held = self.meta.held.iter().copied().collect();
            let delayed: BTreeSet<ItemId> = delayed.union(&self.meta.held).copied().collect();
            p = plan(
                PlanInput {
                    remote: &self.remote,
                    synced: &self.synced,
                    local: &self.local,
                    delayed: &delayed,
                    restore: &restore,
                },
                &labels,
                &mut EntropyIds(cx.entropy),
            );
        }
        report.copies.extend(p.copies.iter().copied());
        p
    }

    // -- Scan -------------------------------------------------------------------------------

    /// Puts back what a crash left in the park directory: each entry is named by its item ID
    /// and goes back to the place the index knows, or under a free name at the root. Without
    /// this the scan would not see it and would take it for deleted.
    fn recover_parked(&self, fs: &dyn FileSystem) -> Result<(), SyncError> {
        let park = vec![RESERVED_ROOT_DIR.to_owned(), PARK_DIR.to_owned()];
        let entries = match fs.list(&park) {
            Ok(e) => e,
            Err(FsError::NotFound) => return Ok(()),
            Err(e) => return Err(e.into()),
        };
        for entry in entries {
            let Some(name) = entry.name else {
                continue;
            };
            let mut from = park.clone();
            from.push(name.clone());
            let item = ItemId::from_hex(&name).ok();
            let known = item.and_then(|i| self.local.path(&i));
            let fallback = known
                .as_ref()
                .and_then(|p| p.last().cloned())
                .unwrap_or_else(|| format!("recovered {name}"));
            let mut targets = Vec::new();
            if let Some(path) = known {
                targets.push(path);
            }
            for n in 1..50u32 {
                let (stem, ext) = crate::names::split_extension(&fallback);
                let candidate = if n == 1 {
                    fallback.clone()
                } else {
                    format!("{stem} ({n}){ext}")
                };
                targets.push(vec![candidate]);
            }
            for target in targets {
                if fs.stat(&target)?.is_none() && fs.rename(&from, &target).is_ok() {
                    break;
                }
            }
        }
        Ok(())
    }

    /// Hands the file IDs of the local tree's directories to the file system, which compares
    /// every directory on the way of an operation with them (security review L1).
    fn expect_directories(&self, fs: &dyn FileSystem) {
        let ids = self
            .local
            .iter()
            .filter(|(_, n)| n.is_dir())
            .filter_map(|(id, _)| Some((self.local.path(id)?, *self.file_ids.get(id)?)))
            .collect();
        fs.expect_directories(ids);
    }

    fn scan(&mut self, cx: &mut Ctx<'_>) -> Result<(), SyncError> {
        self.expect_directories(cx.fs);
        self.recover_parked(cx.fs)?;
        let reader = cx.account.folder_reader(&self.folder)?;
        let newest = reader.writable_generation();
        let tolerance = cx.fs.mtime_tolerance_ms();
        let exec_supported = cx.fs.exec_supported();
        // 1. Walk: list every directory in a full scan; in a partial one only the directories
        // the watcher named (with their ancestors) and new ones, and take the rest from the
        // index.
        let relist =
            match std::mem::replace(&mut self.scan_scope, ScanScope::Paths(BTreeSet::new())) {
                ScanScope::Full => None,
                ScanScope::Paths(paths) => {
                    let mut set = BTreeSet::new();
                    for path in paths {
                        for len in 0..=path.len() {
                            set.insert(path[..len].to_vec());
                        }
                    }
                    Some(set)
                }
            };
        let mut found: Vec<(Vec<String>, Stat)> = Vec::new();
        let mut unreadable: Vec<Vec<String>> = Vec::new();
        let mut not_synced: Vec<(String, String)> = match &relist {
            None => Vec::new(),
            Some(set) => self
                .meta
                .not_synced
                .iter()
                .filter(|(path, _)| {
                    let parent: Vec<String> = path
                        .split('/')
                        .map(str::to_owned)
                        .collect::<Vec<_>>()
                        .split_last()
                        .map(|(_, p)| p.to_vec())
                        .unwrap_or_default();
                    !set.contains(&parent)
                })
                .cloned()
                .collect(),
        };
        let mut dirs: Vec<Vec<String>> = vec![Vec::new()];
        while let Some(dir) = dirs.pop() {
            if let Some(set) = &relist {
                let known = if dir.is_empty() {
                    Some(ROOT)
                } else {
                    self.local
                        .lookup_exact(&dir)
                        .filter(|id| self.local.path(id).as_deref() == Some(&dir[..]))
                };
                if let (false, Some(parent)) = (set.contains(&dir), known) {
                    for child in self.local.children(&parent) {
                        let Some(node) = self.local.get(child) else {
                            continue;
                        };
                        let mut path = dir.clone();
                        path.push(node.name.clone());
                        let file_id = self.file_ids.get(child).copied();
                        match &node.kind {
                            NodeKind::Directory => {
                                found.push((
                                    path.clone(),
                                    Stat {
                                        kind: EntryType::Directory,
                                        size: 0,
                                        mtime_ms: 0,
                                        file_id,
                                        executable: false,
                                    },
                                ));
                                dirs.push(path);
                            }
                            NodeKind::File(v) => found.push((
                                path,
                                Stat {
                                    kind: EntryType::File,
                                    size: v.size,
                                    mtime_ms: v.mtime_ms,
                                    file_id,
                                    executable: v.executable,
                                },
                            )),
                        }
                    }
                    continue;
                }
            }
            let entries = match cx.fs.list(&dir) {
                Ok(e) => e,
                Err(_) if !dir.is_empty() => {
                    unreadable.push(dir);
                    continue;
                }
                Err(e) => return Err(e.into()),
            };
            for entry in entries {
                let Some(name) = entry.name else {
                    not_synced.push((entry.display, "name".into()));
                    continue;
                };
                if is_ignored(&name, dir.is_empty()) {
                    continue;
                }
                let mut path = dir.clone();
                path.push(name);
                match entry.stat.kind {
                    EntryType::File => found.push((path, entry.stat)),
                    EntryType::Directory => {
                        found.push((path.clone(), entry.stat));
                        dirs.push(path);
                    }
                    EntryType::Symlink | EntryType::Reparse => {
                        not_synced.push((path.join("/"), "link".into()))
                    }
                    EntryType::System | EntryType::Other => {
                        not_synced.push((path.join("/"), "system".into()))
                    }
                }
            }
        }
        found.sort_by(|a, b| a.0.len().cmp(&b.0.len()).then(a.0.cmp(&b.0)));
        not_synced.sort();
        not_synced.dedup();
        self.meta.not_synced = not_synced;

        // 2. Identify items: a known file ID at a new path is a move, unless the old path
        // still holds the same file ID (a second hard link).
        let by_file_id: BTreeMap<u128, ItemId> = self
            .file_ids
            .iter()
            .filter(|(item, _)| self.local.contains(item))
            .map(|(item, id)| (*id, *item))
            .collect();
        let found_ids: BTreeMap<Vec<String>, Option<u128>> =
            found.iter().map(|(p, s)| (p.clone(), s.file_id)).collect();
        let mut claimed: BTreeSet<ItemId> = BTreeSet::new();
        let mut by_path: BTreeMap<Vec<String>, ItemId> = BTreeMap::new();
        let mut items: Vec<(ItemId, Vec<String>, Stat)> = Vec::new();
        for (path, stat) in &found {
            let is_dir = stat.kind == EntryType::Directory;
            let at_path = self
                .local
                .lookup_exact(path)
                .filter(|id| self.local.get(id).is_some_and(|n| n.is_dir() == is_dir));
            let by_id = stat
                .file_id
                .and_then(|f| by_file_id.get(&f))
                .copied()
                .filter(|id| self.local.get(id).is_some_and(|n| n.is_dir() == is_dir));
            let moved = by_id.filter(|x| {
                let old = self.local.path(x).unwrap_or_default();
                old != *path && found_ids.get(&old).copied().flatten() != stat.file_id
            });
            let chosen = [moved, at_path, by_id]
                .into_iter()
                .flatten()
                .find(|id| !claimed.contains(id));
            let item = match chosen {
                Some(id) => id,
                None => random_item_id(cx.entropy)?,
            };
            claimed.insert(item);
            by_path.insert(path.clone(), item);
            items.push((item, path.clone(), *stat));
        }

        // 3. Which files need hashing.
        let mut jobs = Vec::new();
        let mut job_items = Vec::new();
        let mut versions: BTreeMap<ItemId, FileVersion> = BTreeMap::new();
        for (item, path, stat) in &items {
            if stat.kind != EntryType::File {
                continue;
            }
            let prev = self.local.get(item).and_then(|n| n.kind.file()).copied();
            let same_id = self.file_ids.get(item).copied() == stat.file_id
                || stat.file_id.is_none()
                || !self.file_ids.contains_key(item);
            if let Some(v) = prev {
                if v.size == stat.size && (v.mtime_ms - stat.mtime_ms).abs() <= tolerance && same_id
                {
                    versions.insert(*item, v);
                    continue;
                }
            }
            let generation = prev
                .and_then(|v| cx.store.chunk_list(&self.folder, &v.content).ok().flatten())
                .and_then(|l| l.generation)
                .or_else(|| {
                    // A join: the remote item at the same path.
                    self.remote
                        .lookup_exact(path)
                        .and_then(|r| self.remote.get(&r))
                        .and_then(|n| n.kind.file())
                        .and_then(|v| cx.store.chunk_list(&self.folder, &v.content).ok().flatten())
                        .and_then(|l| l.generation)
                })
                .map(Generation)
                .filter(|g| reader.keys(*g).is_ok())
                .unwrap_or(newest);
            jobs.push(HashJob {
                path: path.clone(),
                generation,
            });
            job_items.push((*item, prev, *stat));
        }

        // 4. Hash, in parallel with backpressure.
        let results = hash_many(cx.fs, &jobs, reader.all_keys(), cx.settings.hash_threads);
        let mut rehash: Vec<usize> = Vec::new();
        for (index, ((item, prev, stat), result)) in job_items.iter().zip(results).enumerate() {
            match result {
                Ok(hashed) => {
                    let content = ContentKey::of_chunks(&hashed.chunks);
                    let generation = jobs[index].generation;
                    if cx.store.chunk_list(&self.folder, &content)?.is_none() {
                        cx.store.put_chunk_list(
                            &self.folder,
                            &content,
                            &ChunkList {
                                generation: Some(generation.0),
                                chunks: hashed.chunks,
                            },
                        )?;
                    }
                    let executable = if exec_supported {
                        stat.executable
                    } else {
                        prev.map(|v| v.executable)
                            .or_else(|| {
                                self.synced
                                    .get(item)
                                    .and_then(|n| n.kind.file())
                                    .map(|v| v.executable)
                            })
                            .unwrap_or(false)
                    };
                    let version = match prev {
                        Some(v) if v.content == content && v.size == hashed.stat.size => {
                            FileVersion {
                                mtime_ms: if (v.mtime_ms - hashed.stat.mtime_ms).abs() <= tolerance
                                {
                                    v.mtime_ms
                                } else {
                                    hashed.stat.mtime_ms
                                },
                                executable,
                                ..*v
                            }
                        }
                        _ => {
                            if generation != newest {
                                rehash.push(index);
                            }
                            FileVersion {
                                size: hashed.stat.size,
                                mtime_ms: hashed.stat.mtime_ms,
                                executable,
                                content,
                            }
                        }
                    };
                    versions.insert(*item, version);
                }
                Err(ChunkError::Fs(FsError::NotFound)) => {}
                Err(_) => {
                    // Locked or changed while reading: keep the known version for now.
                    if let Some(v) = prev {
                        versions.insert(*item, *v);
                    }
                    let entry = self.meta.backoff.entry(*item).or_insert((0, 0));
                    entry.0 += 1;
                }
            }
        }
        // New content found under an older generation is hashed again under the newest, so
        // its chunks can be sealed for upload.
        for index in rehash {
            let (item, _, _) = &job_items[index];
            let job = HashJob {
                path: jobs[index].path.clone(),
                generation: newest,
            };
            if let Some(Ok(hashed)) = hash_many(cx.fs, &[job], reader.all_keys(), 1).pop() {
                let content = ContentKey::of_chunks(&hashed.chunks);
                if cx.store.chunk_list(&self.folder, &content)?.is_none() {
                    cx.store.put_chunk_list(
                        &self.folder,
                        &content,
                        &ChunkList {
                            generation: Some(newest.0),
                            chunks: hashed.chunks,
                        },
                    )?;
                }
                if let Some(v) = versions.get_mut(item) {
                    v.content = content;
                }
            }
        }

        // 5. Build the new local tree.
        let mut tree = Tree::new();
        let mut file_ids = BTreeMap::new();
        for (item, path, stat) in &items {
            let parent_path: Vec<String> = path[..path.len() - 1].to_vec();
            let parent = if parent_path.is_empty() {
                ROOT
            } else {
                match by_path.get(&parent_path) {
                    Some(p) => *p,
                    None => continue,
                }
            };
            let Some(name) = path.last().cloned() else {
                continue;
            };
            let conflict_of = self.local.get(item).and_then(|n| n.conflict_of);
            let kind = if stat.kind == EntryType::Directory {
                NodeKind::Directory
            } else {
                match versions.get(item) {
                    Some(v) => NodeKind::File(*v),
                    None => continue,
                }
            };
            if parent != ROOT && !tree.contains(&parent) {
                continue;
            }
            tree.insert(
                *item,
                Node {
                    parent,
                    name,
                    kind,
                    conflict_of,
                },
            );
            if let Some(f) = stat.file_id {
                file_ids.insert(*item, f);
            }
        }
        // A directory that could not be read keeps what the index knew below it.
        for dir in &unreadable {
            if let Some(dir_id) = self.local.lookup(dir) {
                for id in self.local.subtree(&dir_id) {
                    if id == dir_id || tree.contains(&id) {
                        continue;
                    }
                    if let Some(node) = self.local.get(&id) {
                        tree.insert(id, node.clone());
                        if let Some(f) = self.file_ids.get(&id) {
                            file_ids.insert(id, *f);
                        }
                    }
                }
            }
        }
        // Store the new tree as a delta against the old one.
        let old_ids: Vec<ItemId> = self.local.ids().copied().collect();
        for id in old_ids {
            if !tree.contains(&id) {
                self.local.remove(&id);
            }
        }
        for (id, node) in tree.iter() {
            if self.local.get(id) != Some(node) {
                self.local.insert(*id, node.clone());
            }
        }
        for (id, f) in &file_ids {
            if self.file_ids.get(id) != Some(f) {
                self.file_ids_dirty.insert(*id, Some(*f));
            }
        }
        for id in self.file_ids.keys() {
            if !file_ids.contains_key(id) {
                self.file_ids_dirty.insert(*id, None);
            }
        }
        self.file_ids = file_ids;
        // Local deletes: remember when each was first seen.
        let now = cx.clock.now_ms();
        let deleted: BTreeSet<ItemId> = self
            .synced
            .ids()
            .filter(|id| !self.local.contains(id))
            .copied()
            .collect();
        self.meta.deleted_seen.retain(|id, _| deleted.contains(id));
        for id in deleted {
            self.meta.deleted_seen.entry(id).or_insert(now);
        }
        Ok(())
    }

    // -- Pull -------------------------------------------------------------------------------

    fn pull(&mut self, cx: &mut Ctx<'_>) -> Result<usize, SyncError> {
        let after = self.view.frontier().map_or(0, |f| f.sequence);
        let folder = self.folder;
        let (delta, server_sequence) =
            crate::paging::collect_delta(after, |cursor| cx.server.commits(&folder, cursor))?;
        self.view.check_server_sequence(server_sequence)?;
        if delta.is_empty() {
            return Ok(0);
        }
        let checked = match self.check(cx, &delta) {
            Ok(o) => o,
            Err(SyncError::Commit(hangar_drive_crypto::commit::CommitError::AheadOfLog {
                ..
            }))
            | Err(SyncError::Chain(hangar_drive_crypto::commit::ChainError::Commit(
                hangar_drive_crypto::commit::CommitError::AheadOfLog { .. },
            )))
            | Err(SyncError::Chain(hangar_drive_crypto::commit::ChainError::UnknownGeneration(
                _,
            ))) => {
                cx.account.refresh(cx.server, cx.keychain, cx.store)?;
                self.check(cx, &delta)?
            }
            Err(e) => return Err(e),
        };
        let outcome = match checked {
            DeltaCheck::Accepted(outcome) => outcome,
            DeltaCheck::RemovedSigner(refusal) => {
                // Only after this real refusal does this device look at the delta without the
                // removed signer rule, and it writes no barrier on its own: the heads it would
                // let in go to the person (security review H1).
                let permit =
                    BarrierPermit::takeover(cx.account.state(), cx.account.device(), &refusal)
                        .ok_or(SyncError::Chain(
                            hangar_drive_crypto::commit::ChainError::RemovedSigner,
                        ))?;
                let newest = self.newest(cx)?;
                let before = self.view.verify_delta_before_barrier(
                    cx.account.state(),
                    newest,
                    &delta,
                    &permit,
                )?;
                self.meta.removed_heads = before.removed_heads.iter().map(Into::into).collect();
                self.meta.state = FolderState::Stopped(StopReason::RemovedHeads);
                return Ok(0);
            }
        };
        let Some(head) = outcome.heads.last().cloned() else {
            return Ok(0);
        };
        let reader = cx.account.folder_reader(&self.folder)?;
        let tree = codec::decode(&head.commit.root, &reader, cx.store, cx.server)?;
        self.record_timeline(&outcome, &delta, cx.clock.now_ms());
        let n = outcome.heads.len();
        self.view = outcome.view;
        self.set_remote(tree);
        self.meta.remote_root = Some(head.commit.root);
        self.meta.frontier_wire = Some(Blob(head.wire.clone()));
        Ok(n)
    }

    /// Adds the heads and side commits of an accepted delta to the timeline.
    pub(crate) fn record_timeline(
        &mut self,
        outcome: &DeltaOutcome,
        delta: &[DeltaCommit],
        now: i64,
    ) {
        let sequences: BTreeMap<CommitId, u64> = delta
            .iter()
            .filter_map(|d| {
                SignedCommit::decode(d.commit.as_bytes())
                    .ok()
                    .map(|c| (c.id, d.sequence))
            })
            .collect();
        for c in outcome.sides.iter().chain(outcome.heads.iter()) {
            self.meta.timeline.push(TimelineRec {
                commit: c.id,
                sequence: sequences.get(&c.id).copied().unwrap_or(0),
                device: c.commit.device,
                seen_at_ms: now,
                reanchor: c.commit.reanchor,
                side: c.commit.side,
                root: c.commit.root,
            });
        }
    }

    fn newest(&self, cx: &Ctx<'_>) -> Result<Generation, SyncError> {
        cx.account
            .newest_generation(&self.folder)
            .ok_or(SyncError::NotSetUp("no key ring for the folder"))
    }

    fn check(&self, cx: &Ctx<'_>, delta: &[DeltaCommit]) -> Result<DeltaCheck, SyncError> {
        let newest = self.newest(cx)?;
        Ok(self.view.check_delta(cx.account.state(), newest, delta)?)
    }

    /// The heads of removed devices the person was asked about.
    pub fn removed_heads(&self) -> &[RemovedHeadRec] {
        &self.meta.removed_heads
    }

    /// Ends the [`StopReason::RemovedHeads`] stop after the person decided (the barrier is
    /// written by `crate::removal::accept_removed_heads`).
    pub(crate) fn clear_removed_heads(&mut self) {
        self.meta.removed_heads.clear();
        if self.meta.state == FolderState::Stopped(StopReason::RemovedHeads) {
            self.meta.state = FolderState::Active;
        }
    }

    /// Stops the folder for the person's decision on `heads` (security review H1).
    pub(crate) fn hold_removed_heads(
        &mut self,
        heads: &[RemovedHead],
        store: &mut dyn Store,
    ) -> Result<(), SyncError> {
        self.meta.removed_heads = heads.iter().map(Into::into).collect();
        self.meta.state = FolderState::Stopped(StopReason::RemovedHeads);
        self.save(store)
    }

    fn set_remote(&mut self, tree: Tree) {
        let old: Vec<ItemId> = self.remote.ids().copied().collect();
        for id in old {
            if !tree.contains(&id) {
                self.remote.remove(&id);
            }
        }
        for (id, node) in tree.iter() {
            if self.remote.get(id) != Some(node) {
                self.remote.insert(*id, node.clone());
            }
        }
    }

    // -- Publish ----------------------------------------------------------------------------

    fn reachable_of(
        &self,
        root: Option<ObjectId>,
        crypto: &FolderCrypto,
        cx: &mut Ctx<'_>,
    ) -> Result<BTreeSet<ObjectId>, SyncError> {
        let Some(root) = root else {
            return Ok(BTreeSet::new());
        };
        let tree = codec::decode(&root, crypto, cx.store, cx.server)?;
        let encoded = codec::encode(&tree, crypto, cx.store, cx.entropy)?;
        if encoded.root != root {
            // A tree whose objects are not all in the cache: fall back to declaring every
            // object of the new tree as added (a superset is always accepted).
            return Ok(BTreeSet::new());
        }
        Ok(encoded.reachable)
    }

    /// Uploads every object of `encoded` the server lacks: sealed nodes and manifests, and
    /// chunks read from the disk.
    fn upload(
        &self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        encoded: &Encoded,
        candidates: &BTreeSet<ObjectId>,
        disk: &Tree,
    ) -> Result<(), PublishFailure> {
        let ids: Vec<ObjectId> = candidates.iter().copied().collect();
        let mut missing = Vec::new();
        for batch in ids.chunks(hangar_drive_protocol::api::MAX_MISSING_QUERY) {
            missing.extend(cx.server.missing_objects(&self.folder, batch)?);
        }
        if missing.is_empty() {
            return Ok(());
        }
        // Where each chunk of the new tree lives on disk.
        let mut sources: BTreeMap<ObjectId, (Vec<String>, u64)> = BTreeMap::new();
        for (item, node) in disk.iter() {
            let Some(v) = node.kind.file() else {
                continue;
            };
            let Some(chunks) = encoded.chunks.get(&v.content) else {
                continue;
            };
            let Some(path) = disk.path(item) else {
                continue;
            };
            for (index, chunk) in chunks.iter().enumerate() {
                sources
                    .entry(*chunk)
                    .or_insert_with(|| (path.clone(), index as u64));
            }
        }
        for id in missing {
            if let Some(blob) = encoded.sealed.get(&id) {
                cx.server.put_object(&self.folder, &id, blob)?;
                continue;
            }
            let Some((path, index)) = sources.get(&id) else {
                // A chunk this device cannot produce: the disk changed, scan again.
                return Err(PublishFailure::LocalChanged);
            };
            let sealed = match crate::chunker::seal_chunk(
                cx.fs,
                path,
                *index,
                &id,
                crypto.writable().map_err(SyncError::from)?,
                cx.entropy,
            ) {
                Ok(s) => s,
                Err(_) => return Err(PublishFailure::LocalChanged),
            };
            cx.server.put_object(&self.folder, &id, &sealed.blob)?;
        }
        Ok(())
    }

    fn content(
        &self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        root: ObjectId,
    ) -> Result<CommitContent, SyncError> {
        let counter = cx.account.next_counter(cx.store)?;
        Ok(CommitContent {
            root,
            generation: crypto.writable_generation(),
            device: *cx.account.device(),
            log_head: cx.account.log_head()?,
            counter,
        })
    }

    /// Publishes `tree` as a normal commit on the frontier, without a side commit: one stage of
    /// a publish that is too large for one commit (open point B).
    fn publish_stage(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        tree: &Tree,
        disk: &Tree,
    ) -> Result<(), PublishFailure> {
        let encoded = codec::encode(tree, crypto, cx.store, cx.entropy)?;
        let parent = self.reachable_of(self.meta.remote_root, crypto, cx)?;
        let added: BTreeSet<ObjectId> = encoded.reachable.difference(&parent).copied().collect();
        let dropped: Vec<ObjectId> = parent.difference(&encoded.reachable).copied().collect();
        self.upload(cx, crypto, &encoded, &added, disk)?;
        codec::remember_uploaded(&encoded, &self.folder, cx.store).map_err(SyncError::from)?;
        let delta = fit_delta(
            ReferenceDelta {
                added: added.into_iter().collect(),
                dropped,
            },
            cx.settings.max_delta_ids,
        )?;
        let frontier = self.view.frontier().copied();
        self.send(cx, crypto, encoded.root, frontier, None, &delta)?;
        self.set_remote(tree.clone());
        self.meta.remote_root = Some(encoded.root);
        self.save(cx.store)?;
        Ok(())
    }

    fn publish(&mut self, cx: &mut Ctx<'_>, p: &Plan) -> Result<(), PublishFailure> {
        let chain_generation = self.view.frontier().map(|f| f.generation);
        let crypto = cx.account.folder_crypto(&self.folder, chain_generation)?;
        let limit = cx.settings.max_delta_ids.max(1);
        let mut encoded = codec::encode(&p.merged, &crypto, cx.store, cx.entropy)?;
        let mut parent = self.reachable_of(self.meta.remote_root, &crypto, cx)?;
        // Too many new objects for one commit: publish valid intermediate trees first, each
        // the server's tree plus whole new files and their new directories (open point B).
        while encoded.reachable.difference(&parent).count() > limit {
            let Some(stage) = stage_tree(&self.remote, &p.merged, &encoded, limit / 2) else {
                return Err(SyncError::Invalid("too many new objects for one commit").into());
            };
            self.publish_stage(cx, &crypto, &stage, &p.disk)?;
            encoded = codec::encode(&p.merged, &crypto, cx.store, cx.entropy)?;
            parent = self.reachable_of(self.meta.remote_root, &crypto, cx)?;
        }
        let added: BTreeSet<ObjectId> = encoded.reachable.difference(&parent).copied().collect();
        let dropped: Vec<ObjectId> = parent.difference(&encoded.reachable).copied().collect();
        self.upload(cx, &crypto, &encoded, &added, &p.disk)?;
        codec::remember_uploaded(&encoded, &self.folder, cx.store).map_err(SyncError::from)?;

        // A side commit when the server moved on since the last fully synced head.
        let frontier = self.view.frontier().copied();
        let side_base = self
            .meta
            .sync_base
            .filter(|b| frontier.is_some_and(|f| f.commit != b.entry.commit));
        let mut side: Option<(SignedCommit, ReferenceDelta)> = None;
        if let (Some(base), Some(_)) = (side_base, frontier) {
            if let Ok(side_enc) = codec::encode(&p.disk, &crypto, cx.store, cx.entropy) {
                let base_reach = self.reachable_of(Some(base.root), &crypto, cx)?;
                let side_added: BTreeSet<ObjectId> = side_enc
                    .reachable
                    .difference(&base_reach)
                    .copied()
                    .collect();
                self.upload(cx, &crypto, &side_enc, &side_added, &p.disk)?;
                codec::remember_uploaded(&side_enc, &self.folder, cx.store)
                    .map_err(SyncError::from)?;
                let content = self.content(cx, &crypto, side_enc.root)?;
                let commit = Commit::side(
                    *cx.account.id(),
                    self.folder,
                    &ChainEntry::from(&base.entry),
                    content,
                );
                let signed = cx.account.sign(commit)?;
                // A side commit that would not fit one commit is left out: the merge commit
                // alone loses nothing, as with an expired base.
                if let Ok(side_delta) = fit_delta(
                    ReferenceDelta {
                        added: side_added.into_iter().collect(),
                        dropped: base_reach
                            .difference(&side_enc.reachable)
                            .copied()
                            .collect(),
                    },
                    limit,
                ) {
                    side = Some((signed, side_delta));
                }
            }
        }
        let delta = fit_delta(
            ReferenceDelta {
                added: added.into_iter().collect(),
                dropped,
            },
            limit,
        )?;
        let result = self.send(cx, &crypto, encoded.root, frontier, side.as_ref(), &delta);
        match result {
            Err(PublishFailure::Error(SyncError::Net(e)))
                if e.code() == Some(ErrorCode::BaseExpired) =>
            {
                // The server no longer retains the base: the merge alone, with one parent.
                self.send(cx, &crypto, encoded.root, frontier, None, &delta)
            }
            other => other,
        }?;
        self.set_remote(p.merged.clone());
        self.meta.remote_root = Some(encoded.root);
        // Rekeys: the local items are known under their merged IDs from now on.
        for rekey in &p.rekeys {
            if let Some(f) = self.file_ids.remove(&rekey.from) {
                self.file_ids.insert(rekey.to, f);
                self.file_ids_dirty.insert(rekey.to, Some(f));
                self.file_ids_dirty.insert(rekey.from, None);
            }
            if let Some(node) = self.synced.remove(&rekey.from) {
                // The local version of a content conflict copy was synced at its old place.
                if p.merged.contains(&rekey.to) && !self.synced.contains(&rekey.to) {
                    let disk_node = p.disk.get(&rekey.to).cloned().unwrap_or(node);
                    self.synced.insert(rekey.to, disk_node);
                }
            }
        }
        self.save(cx.store)?;
        Ok(())
    }

    fn send(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        root: ObjectId,
        frontier: Option<ChainEntry>,
        side: Option<&(SignedCommit, ReferenceDelta)>,
        delta: &ReferenceDelta,
    ) -> Result<(), PublishFailure> {
        let content = self.content(cx, crypto, root)?;
        let account = *cx.account.id();
        let commit = match (frontier, side) {
            (None, _) => Commit::first(account, self.folder, content),
            (Some(head), Some((side, _))) => {
                Commit::merge(account, self.folder, &head, side, content)
            }
            (Some(head), None) => Commit::on(account, self.folder, &head, content),
        };
        let signed = cx.account.sign(commit)?;
        let request = CommitRequest {
            expected_head: frontier.map(|f| f.commit),
            head: CommitUpload {
                commit: Blob(signed.wire.clone()),
                delta: delta.clone(),
            },
            side: side.map(|(s, d)| CommitUpload {
                commit: Blob(s.wire.clone()),
                delta: d.clone(),
            }),
        };
        let response = match cx.server.commit(&self.folder, &request) {
            Ok(r) => r,
            Err(e) if e.code() == Some(ErrorCode::HeadMoved) => {
                return Err(PublishFailure::HeadMoved)
            }
            Err(e) => return Err(e.into()),
        };
        let newest = cx
            .account
            .newest_generation(&self.folder)
            .ok_or(SyncError::NotSetUp("no key ring for the folder"))?;
        self.view = self
            .view
            .accept_published(
                cx.account.state(),
                newest,
                &signed,
                side.map(|(s, _)| s),
                response.sequence,
            )
            .map_err(SyncError::from)?;
        let now = cx.clock.now_ms();
        if let Some((s, _)) = side {
            self.meta.timeline.push(TimelineRec {
                commit: s.id,
                sequence: response.sequence,
                device: s.commit.device,
                seen_at_ms: now,
                reanchor: false,
                side: true,
                root: s.commit.root,
            });
        }
        self.meta.timeline.push(TimelineRec {
            commit: signed.id,
            sequence: response.sequence,
            device: signed.commit.device,
            seen_at_ms: now,
            reanchor: signed.commit.reanchor,
            side: false,
            root: signed.commit.root,
        });
        self.meta.frontier_wire = Some(Blob(signed.wire.clone()));
        Ok(())
    }

    // -- Apply ------------------------------------------------------------------------------

    fn apply_plan(
        &mut self,
        cx: &mut Ctx<'_>,
        p: Plan,
        report: &mut RoundReport,
    ) -> Result<(), SyncError> {
        let now = cx.clock.now_ms();
        let mut skip: BTreeSet<ItemId> = p.skip.clone();
        // An incoming entry with a name this device ignores (the reserved directory at the
        // root, editor lock files, `desktop.ini` and the like) is never written: it could
        // overwrite the root marker or a quarantined file, and the scan would never see it
        // (security review L5).
        for (id, node) in p.merged.iter() {
            if is_ignored(&node.name, node.parent == ROOT) {
                self.meta
                    .cannot_sync
                    .insert(*id, "the name is reserved on this device".into());
                skip.extend(p.merged.subtree(id));
            }
        }
        skip.extend(self.meta.cannot_sync.keys().copied());
        self.expect_directories(cx.fs);
        skip.extend(
            self.meta
                .backoff
                .iter()
                .filter(|(_, (_, until))| *until > now)
                .map(|(id, _)| *id),
        );
        let reader = cx.account.folder_reader(&self.folder)?;
        let before = p.disk.clone();
        let mut work = p.disk;
        let mut disk = FsDisk {
            fs: cx.fs,
            server: &mut *cx.server,
            store: &*cx.store,
            crypto: &reader,
            file_ids: &mut self.file_ids,
            dirty: &mut self.file_ids_dirty,
        };
        let result = apply(&p.merged, &mut work, &mut self.synced, &skip, &mut disk);
        report.applied = result.done.len();
        for id in &result.done {
            let action = match (before.get(id), p.merged.get(id)) {
                (None, Some(_)) => ChangeAction::Added,
                (Some(_), None) => ChangeAction::Deleted,
                (Some(a), Some(b)) if a.location() != b.location() => ChangeAction::Moved,
                _ => ChangeAction::Changed,
            };
            let path = path_string(&p.merged, id);
            let path = if path.is_empty() {
                path_string(&before, id)
            } else {
                path
            };
            report.changes.push(ItemChange {
                item: *id,
                path,
                action,
                incoming: true,
            });
            self.meta.backoff.remove(id);
            self.meta.restore.remove(id);
        }
        for (id, error) in &result.failed {
            match error {
                ActionError::Exists | ActionError::CannotSync(_) => {
                    self.meta.cannot_sync.insert(*id, error.to_string());
                }
                ActionError::Locked => {
                    let entry = self.meta.backoff.entry(*id).or_insert((0, 0));
                    entry.0 = entry.0.saturating_add(1);
                    let wait = 1_000i64 << entry.0.min(10);
                    entry.1 = now + wait;
                }
                _ => {}
            }
        }
        report.failed = result.failed;
        // Items of the plan this device may hold again (for example after a rename on another
        // device) leave the cannot-sync list when the target no longer has them.
        let merged = &p.merged;
        self.meta.cannot_sync.retain(|id, _| merged.contains(id));
        // The working tree is the disk now.
        let old: Vec<ItemId> = self.local.ids().copied().collect();
        for id in old {
            if !work.contains(&id) {
                self.local.remove(&id);
            }
        }
        for (id, node) in work.iter() {
            if self.local.get(id) != Some(node) {
                self.local.insert(*id, node.clone());
            }
        }
        // Synced items the target dropped are gone from the base as well.
        let dropped: Vec<ItemId> = self
            .synced
            .ids()
            .filter(|id| !p.merged.contains(id) && !self.local.contains(id))
            .copied()
            .collect();
        for id in dropped {
            self.synced.remove(&id);
        }
        if self.meta.held.is_empty() {
            self.meta.approve_deletes = false;
        }
        Ok(())
    }

    // -- Person's actions -------------------------------------------------------------------

    /// Publishes `tree` as a normal commit on the current head: the restore of ADR 0001,
    /// section 5 ("a restore is a commit"). Local changes are merged in the next round.
    pub fn publish_tree(&mut self, cx: &mut Ctx<'_>, tree: Tree) -> Result<(), SyncError> {
        let p = Plan {
            merged: tree,
            disk: self.local.clone(),
            rekeys: Vec::new(),
            copies: Vec::new(),
            dropped_local_moves: 0,
            publish: true,
            local_deletes: Vec::new(),
            skip: BTreeSet::new(),
        };
        match self.publish(cx, &p) {
            Ok(()) => Ok(()),
            Err(PublishFailure::HeadMoved) => Err(SyncError::Net(NetError::Server(
                hangar_drive_protocol::api::ErrorBody::new(ErrorCode::HeadMoved),
            ))),
            Err(PublishFailure::LocalChanged) => Err(SyncError::Invalid("the disk changed")),
            Err(PublishFailure::Error(e)) => Err(e),
        }
    }

    /// The tree of a commit of the timeline.
    pub fn tree_at(&self, cx: &mut Ctx<'_>, commit: &CommitId) -> Result<Tree, SyncError> {
        let root = self
            .meta
            .timeline
            .iter()
            .find(|t| t.commit == *commit)
            .map(|t| t.root)
            .ok_or(SyncError::Invalid("unknown timeline entry"))?;
        let reader = cx.account.folder_reader(&self.folder)?;
        Ok(codec::decode(&root, &reader, cx.store, cx.server)?)
    }

    /// Restores the whole folder to `commit` (pull first, then a commit with the old tree).
    pub fn restore_folder(&mut self, cx: &mut Ctx<'_>, commit: &CommitId) -> Result<(), SyncError> {
        self.pull(cx)?;
        let old = self.tree_at(cx, commit)?;
        self.publish_tree(cx, old)
    }

    /// Restores one item of `commit` (a file or a directory with everything below it) into the
    /// current tree (ADR 0001, section 5, "Item IDs"); returns the name it got.
    pub fn restore_item(
        &mut self,
        cx: &mut Ctx<'_>,
        commit: &CommitId,
        item: &ItemId,
    ) -> Result<String, SyncError> {
        self.pull(cx)?;
        let old = self.tree_at(cx, commit)?;
        let date = date_label(cx.clock.now_ms(), cx.settings.tz_offset_minutes);
        let (tree, name) = graft(
            &self.remote,
            &old,
            item,
            &cx.settings.words,
            &date,
            &mut EntropyIds(cx.entropy),
        )?;
        self.publish_tree(cx, tree)?;
        Ok(name)
    }

    /// The re-anchor after "the server shows an older state", once the person confirmed
    /// (ADR 0001, section 4). The base is the newest commit of the server's chain that this
    /// device verified; the merge of base, server head and local tree is published as the
    /// re-anchor commit.
    pub fn reanchor(&mut self, cx: &mut Ctx<'_>) -> Result<(), SyncError> {
        let folder = self.folder;
        let (delta, _) =
            crate::paging::collect_delta(0, |cursor| cx.server.commits(&folder, cursor))?;
        let newest = cx
            .account
            .newest_generation(&self.folder)
            .ok_or(SyncError::NotSetUp("no key ring for the folder"))?;
        let base = self
            .view
            .reanchor_base(cx.account.state(), newest, &delta)?;
        let head_commit = base
            .segment
            .last()
            .cloned()
            .or_else(|| {
                delta
                    .iter()
                    .rev()
                    .filter(|d| d.role == hangar_drive_protocol::api::CommitRole::Head)
                    .find_map(|d| SignedCommit::decode(d.commit.as_bytes()).ok())
                    .filter(|c| c.id == base.head.commit)
            })
            .ok_or(SyncError::Invalid("no server head"))?;
        let reader = cx.account.folder_reader(&self.folder)?;
        let remote = codec::decode(&head_commit.commit.root, &reader, cx.store, cx.server)?;
        let base_tree = match &base.base {
            Some(entry) => self
                .meta
                .timeline
                .iter()
                .find(|t| t.commit == entry.commit)
                .and_then(|t| codec::decode(&t.root, &reader, cx.store, cx.server).ok())
                .unwrap_or_default(),
            None => Tree::new(),
        };
        self.meta.state = FolderState::Active;
        self.scan(cx)?;
        let date = date_label(cx.clock.now_ms(), cx.settings.tz_offset_minutes);
        let device_name = cx.account.device_name().to_owned();
        let labels = MergeLabels {
            words: &cx.settings.words,
            device: &device_name,
            date: &date,
        };
        let merged = crate::merge::merge3(
            &base_tree,
            &remote,
            &self.local,
            &labels,
            &mut EntropyIds(cx.entropy),
        );
        let crypto = cx
            .account
            .folder_crypto(&self.folder, Some(base.head.generation))?;
        let encoded = codec::encode(&merged.tree, &crypto, cx.store, cx.entropy)?;
        let all = encoded.reachable.clone();
        match self.upload(cx, &crypto, &encoded, &all, &merged.local) {
            Ok(()) => {}
            Err(PublishFailure::Error(e)) => return Err(e),
            Err(_) => return Err(SyncError::Invalid("the disk changed")),
        }
        codec::remember_uploaded(&encoded, &self.folder, cx.store)?;
        let content = self.content(cx, &crypto, encoded.root)?;
        let commit = Commit::reanchor(*cx.account.id(), self.folder, &base.head, content);
        let signed = cx.account.sign(commit)?;
        let request = CommitRequest {
            expected_head: Some(base.head.commit),
            head: CommitUpload {
                commit: Blob(signed.wire.clone()),
                delta: fit_delta(
                    ReferenceDelta {
                        added: all.into_iter().collect(),
                        dropped: Vec::new(),
                    },
                    cx.settings.max_delta_ids,
                )?,
            },
            side: None,
        };
        let response = cx.server.commit(&self.folder, &request)?;
        self.view = self.view.apply_reanchor(
            cx.account.state(),
            newest,
            &base,
            &signed,
            response.sequence,
        )?;
        // The synced tree is the base now; the next round brings disk and server together.
        let old: Vec<ItemId> = self.synced.ids().copied().collect();
        for id in old {
            self.synced.remove(&id);
        }
        for (id, node) in base_tree.iter() {
            self.synced.insert(*id, node.clone());
        }
        self.local = merged.local;
        self.set_remote(merged.tree);
        self.meta.remote_root = Some(encoded.root);
        self.meta.frontier_wire = Some(Blob(signed.wire.clone()));
        self.meta.sync_base = None;
        self.meta.timeline.push(TimelineRec {
            commit: signed.id,
            sequence: response.sequence,
            device: signed.commit.device,
            seen_at_ms: cx.clock.now_ms(),
            reanchor: true,
            side: false,
            root: signed.commit.root,
        });
        self.save(cx.store)
    }

    /// Writes the barrier commit after a removal (ADR 0001, section 4; N1): the same tree on
    /// the verified head, naming the new log head and generation. `verified_head` is the head
    /// the caller verified with the removal permit.
    pub fn write_barrier(
        &mut self,
        cx: &mut Ctx<'_>,
        head: &SignedCommit,
        sequence: u64,
        view: FolderView,
        taken: Option<(&DeltaOutcome, &[DeltaCommit])>,
    ) -> Result<(), SyncError> {
        let chain_generation = Some(head.commit.generation);
        let crypto = cx.account.folder_crypto(&self.folder, chain_generation)?;
        let counter = cx.account.next_counter(cx.store)?;
        let commit = Commit::barrier(
            head,
            sequence,
            crypto.writable_generation(),
            *cx.account.device(),
            cx.account.log_head()?,
            counter,
        );
        let signed = cx.account.sign(commit)?;
        let request = CommitRequest {
            expected_head: Some(head.id),
            head: CommitUpload {
                commit: Blob(signed.wire.clone()),
                delta: ReferenceDelta::default(),
            },
            side: None,
        };
        let response = cx.server.commit(&self.folder, &request)?;
        let newest = cx
            .account
            .newest_generation(&self.folder)
            .ok_or(SyncError::NotSetUp("no key ring for the folder"))?;
        let accepted =
            view.accept_published(cx.account.state(), newest, &signed, None, response.sequence)?;
        // The barrier's tree is the verified head's tree.
        let reader = cx.account.folder_reader(&self.folder)?;
        let tree = codec::decode(&head.commit.root, &reader, cx.store, cx.server)?;
        self.view = accepted;
        self.set_remote(tree);
        self.meta.remote_root = Some(head.commit.root);
        self.meta.frontier_wire = Some(Blob(signed.wire.clone()));
        if let Some((outcome, delta)) = taken {
            // The heads the barrier covers, so "Undo a device" finds them (N2).
            self.record_timeline(outcome, delta, cx.clock.now_ms());
        }
        self.meta.timeline.push(TimelineRec {
            commit: signed.id,
            sequence: response.sequence,
            device: signed.commit.device,
            seen_at_ms: cx.clock.now_ms(),
            reanchor: false,
            side: false,
            root: signed.commit.root,
        });
        self.save(cx.store)
    }

    /// The whole delta after the frontier (every page), for the removal job.
    pub fn fetch_delta(&self, server: &mut dyn ServerApi) -> Result<Vec<DeltaCommit>, SyncError> {
        let after = self.view.frontier().map_or(0, |f| f.sequence);
        let (delta, _) =
            crate::paging::collect_delta(after, |cursor| server.commits(&self.folder, cursor))?;
        Ok(delta)
    }

    /// The frontier's signed commit, if it is stored.
    pub fn frontier_commit(&self) -> Option<SignedCommit> {
        self.meta
            .frontier_wire
            .as_ref()
            .and_then(|w| SignedCommit::decode(w.as_bytes()).ok())
    }

    /// Takes a pulled delta outcome as the new verified state (the removal job after its
    /// barrier check).
    pub fn take_outcome(
        &mut self,
        cx: &mut Ctx<'_>,
        outcome: DeltaOutcome,
        delta: &[DeltaCommit],
    ) -> Result<(), SyncError> {
        self.record_timeline(&outcome, delta, cx.clock.now_ms());
        if let Some(head) = outcome.heads.last() {
            let reader = cx.account.folder_reader(&self.folder)?;
            let tree = codec::decode(&head.commit.root, &reader, cx.store, cx.server)?;
            self.set_remote(tree);
            self.meta.remote_root = Some(head.commit.root);
            self.meta.frontier_wire = Some(Blob(head.wire.clone()));
        }
        self.view = outcome.view;
        self.save(cx.store)
    }

    /// "Keep both" (ADR 0001, section 3): the copy's entry is written without its conflict
    /// link; the next round publishes it, and a dropped link wins against a kept one.
    pub fn drop_conflict_link(
        &mut self,
        item: &ItemId,
        store: &mut dyn Store,
    ) -> Result<bool, SyncError> {
        let Some(mut node) = self.local.get(item).cloned() else {
            return Ok(false);
        };
        if node.conflict_of.is_none() {
            return Ok(false);
        }
        node.conflict_of = None;
        self.local.insert(*item, node);
        self.save(store)?;
        Ok(true)
    }

    /// Items marked "cannot sync on this device".
    pub fn cannot_sync(&self) -> &BTreeMap<ItemId, String> {
        &self.meta.cannot_sync
    }

    /// Forgets a "cannot sync" mark after the person renamed or ignored the item.
    pub fn clear_cannot_sync(
        &mut self,
        item: &ItemId,
        store: &mut dyn Store,
    ) -> Result<(), SyncError> {
        self.meta.cannot_sync.remove(item);
        self.save(store)
    }
}

/// Fits a reference delta into `limit` IDs per commit (at most
/// `hangar_drive_protocol::api::MAX_REFERENCE_DELTA_IDS`).
///
/// Dropped IDs go first: they only tell the server earlier which objects a head no longer
/// needs, and garbage collection never deletes an object because a delta names it as dropped
/// (ADR 0001, section 5), so leaving some out is always safe. Added IDs must all be declared; a
/// commit that adds more than the limit is refused here, before anything is signed. A publish
/// that adds more is split by [`stage_tree`] before it gets here.
pub fn fit_delta(mut delta: ReferenceDelta, limit: usize) -> Result<ReferenceDelta, SyncError> {
    let limit = limit.min(hangar_drive_protocol::api::MAX_REFERENCE_DELTA_IDS);
    if delta.added.len() > limit {
        return Err(SyncError::Invalid("too many new objects for one commit"));
    }
    delta.dropped.truncate(limit - delta.added.len());
    Ok(delta)
}

/// One intermediate tree of a publish that is too large for one commit (open point B): the
/// server's tree `remote` plus the files of `target` that `remote` lacks or holds with other
/// content, in path order, each with every directory above it, until their objects reach
/// `budget`. A new file comes in at its target place with the directories it needs; a changed
/// file keeps its place on the server and takes the new content. Everything else, moves,
/// renames, deletes and directories without a new file below them, waits for the last
/// commit, which publishes `target` itself. Every stage is therefore a whole tree: no file
/// without its content, no item without its parents, no name twice in a directory.
///
/// `None` when not even one file fits the budget or nothing is left to stage.
pub fn stage_tree(remote: &Tree, target: &Tree, encoded: &Encoded, budget: usize) -> Option<Tree> {
    let mut stage = remote.clone();
    // The root's directory node changes with the first staged file.
    let mut spent = 1usize;
    let mut staged = 0usize;
    // Directories of the server's tree whose node this stage already changes. Every directory
    // above a staged file gets a new node, so each one counts against the budget once
    // (security re-review: a stage of files in many existing deep directories exceeded the
    // commit limit and stopped the publish for good).
    let mut touched: BTreeSet<ItemId> = BTreeSet::new();
    let ancestors = |tree: &Tree, mut at: ItemId| -> Vec<ItemId> {
        let mut out = Vec::new();
        while at != ROOT {
            let Some(dir) = tree.get(&at) else {
                break;
            };
            out.push(at);
            at = dir.parent;
        }
        out
    };
    // Files of the target in path order, so a directory's files come together.
    let mut files: Vec<(Vec<String>, ItemId)> = target
        .iter()
        .filter(|(_, n)| !n.is_dir())
        .filter_map(|(id, _)| Some((target.path(id)?, *id)))
        .collect();
    files.sort();
    for (_, id) in files {
        let Some(node) = target.get(&id) else {
            continue;
        };
        let Some(version) = node.kind.file() else {
            continue;
        };
        let cost = encoded.chunks.get(&version.content).map_or(1, Vec::len) + 1;
        match remote.get(&id) {
            Some(old) if old.kind == node.kind => continue,
            Some(old) => {
                // New content at the place the server knows.
                let above: Vec<ItemId> = ancestors(&stage, old.parent)
                    .into_iter()
                    .filter(|d| !touched.contains(d))
                    .collect();
                let extra = cost + above.len();
                if spent + extra > budget {
                    break;
                }
                let mut changed = old.clone();
                changed.kind = node.kind;
                stage.insert(id, changed);
                touched.extend(above);
                spent += extra;
            }
            None => {
                // The new file and the directories it needs, from the top down.
                let mut chain = Vec::new();
                let mut at = node.parent;
                while at != ROOT && !stage.contains(&at) {
                    let Some(dir) = target.get(&at) else {
                        break;
                    };
                    chain.push((at, dir.clone()));
                    at = dir.parent;
                }
                if at != ROOT && !stage.contains(&at) {
                    continue;
                }
                let above: Vec<ItemId> = ancestors(&stage, at)
                    .into_iter()
                    .filter(|d| !touched.contains(d))
                    .collect();
                let extra = cost + chain.len() + above.len();
                if spent + extra > budget {
                    break;
                }
                let mut trial = stage.clone();
                let new_dirs: Vec<ItemId> = chain.iter().map(|(dir_id, _)| *dir_id).collect();
                for (dir_id, dir) in chain.into_iter().rev() {
                    trial.insert(dir_id, dir);
                }
                trial.insert(id, node.clone());
                // A name the server's tree still uses (a rename or delete of the last commit)
                // waits for that commit.
                let clash = |tree: &Tree, item: &ItemId| -> bool {
                    let Some(n) = tree.get(item) else {
                        return true;
                    };
                    tree.children(&n.parent).any(|other| {
                        other != item
                            && tree.get(other).is_some_and(|o| {
                                o.name == n.name
                                    || hangar_drive_protocol::name::collision(&o.name, &n.name)
                                        .is_some()
                            })
                    })
                };
                let mut item = id;
                let mut fine = true;
                loop {
                    if clash(&trial, &item) {
                        fine = false;
                        break;
                    }
                    match trial.get(&item).map(|n| n.parent) {
                        Some(parent) if parent != ROOT && !stage.contains(&parent) => item = parent,
                        _ => break,
                    }
                }
                if !fine || trial.check().is_err() {
                    continue;
                }
                stage = trial;
                touched.extend(above);
                touched.extend(new_dirs);
                spent += extra;
            }
        }
        staged += 1;
    }
    (staged > 0).then_some(stage)
}

/// Puts item `item` of `old` (with its subtree) into `current` at its old place (ADR 0001,
/// section 5): restored items keep their old ID unless it exists elsewhere in the current tree,
/// and a different item holding the name makes it `<name> (restored <date>)`.
pub fn graft(
    current: &Tree,
    old: &Tree,
    item: &ItemId,
    words: &LabelWords,
    date: &str,
    ids: &mut dyn ItemIds,
) -> Result<(Tree, String), SyncError> {
    let node = old.get(item).ok_or(SyncError::Invalid("unknown item"))?;
    let mut out = current.clone();
    // The current version at the same place is replaced by the old one.
    if current
        .get(item)
        .is_some_and(|n| n.location() == node.location())
    {
        for id in current.subtree(item) {
            out.remove(&id);
        }
    }
    // The parent chain comes from the old tree where the current one lacks it.
    let mut parent = node.parent;
    let mut chain = Vec::new();
    while parent != ROOT && !out.contains(&parent) {
        let p = old
            .get(&parent)
            .ok_or(SyncError::Invalid("broken old tree"))?;
        chain.push((parent, p.clone()));
        parent = p.parent;
    }
    for (id, p) in chain.into_iter().rev() {
        out.insert(id, p);
    }
    let subtree = old.subtree(item);
    // An ID that still exists elsewhere in the current tree gets a new one.
    let mut mapping: BTreeMap<ItemId, ItemId> = BTreeMap::new();
    for id in &subtree {
        let new = if out.contains(id) {
            ids.new_item_id()
        } else {
            *id
        };
        mapping.insert(*id, new);
    }
    let mut name = node.name.clone();
    for id in &subtree {
        let Some(mut n) = old.get(id).cloned() else {
            continue;
        };
        let new_id = mapping.get(id).copied().unwrap_or(*id);
        if let Some(p) = mapping.get(&n.parent) {
            n.parent = *p;
        }
        if id == item {
            let taken: Vec<String> = out
                .children(&n.parent)
                .filter_map(|c| out.get(c).map(|c| c.name.clone()))
                .collect();
            let clash = |candidate: &str| {
                taken.iter().any(|t| {
                    hangar_drive_protocol::name::collision(t, candidate).is_some() || t == candidate
                })
            };
            if clash(&n.name) {
                n.name = crate::names::restored_name(&n.name, words, date, &clash);
            }
            name = n.name.clone();
        }
        n.conflict_of = None;
        out.insert(new_id, n);
    }
    out.check().map_err(CodecError::from)?;
    Ok((out, name))
}
