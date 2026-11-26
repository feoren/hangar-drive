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
    ChainEntry, Commit, CommitContent, DeltaCheck, DeltaDigest, DeltaOutcome, FolderView,
    RemovedHead, SignedCommit,
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
/// How soon a folder stopped as too large tries again after a change in it.
const TOO_LARGE_RETRY_MS: i64 = 60 * 1000;

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
    /// The most items a folder may hold ([`codec::MAX_TREE_ITEMS`]; smaller in tests).
    pub max_tree_items: usize,
    /// The deepest item a folder may hold ([`codec::MAX_TREE_DEPTH`]; smaller in tests).
    pub max_tree_depth: usize,
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
            max_tree_items: codec::MAX_TREE_ITEMS,
            max_tree_depth: codec::MAX_TREE_DEPTH,
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
    /// The server's head holds a tree beyond the limits of a folder (deeper than
    /// `codec::MAX_TREE_DEPTH` or with more than `codec::MAX_TREE_ITEMS` items, security review
    /// M3). The head's commit verified and is the folder's frontier, but its tree was never
    /// taken in, so nothing of it reaches the disk. A restore ("Undo a device") publishes on
    /// that head without decoding its tree and makes the folder active again.
    TreeLimit,
    /// The folder on this disk is beyond the same limits (follow-up check N-4): more items
    /// than [`FolderSettings::max_tree_items`] or one deeper than
    /// [`FolderSettings::max_tree_depth`], found by the scan or in the tree to publish. Nothing
    /// is published, since no other device would take such a tree in. The folder tries again
    /// with a full scan once the person changed something in it, or with the hourly scan.
    LocalTooLarge,
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
    /// File objects (manifests and chunks; of a full delta, chunks only) the commit dropped
    /// from its first parent's tree, as this device's check of its delta counted them (ADR
    /// 0001, amendment "reference deltas bound to the tree"); `None` when not counted. "Undo a
    /// device" names the writer of a burst only from these counts.
    #[serde(default)]
    pub dropped_files: Option<u64>,
    /// File objects of the first parent's tree, counted with [`Self::dropped_files`].
    #[serde(default)]
    pub files_before: Option<u64>,
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
    /// The next commit of this device carries a full reference delta, because the server's
    /// live set may not match the tree: the server refused a diff as not fitting it, a pulled
    /// commit's delta could not be checked, or a mismatching head of a removed device came in
    /// behind a barrier (ADR 0001, amendment "reference deltas bound to the tree").
    #[serde(default)]
    pub full_next: bool,
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
    /// The item is a directory.
    pub dir: bool,
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

/// What a person's action (a restore, "keep this") changed in the folder: every item it
/// touched with its node before the action, `None` for an item the action made. Undoing the
/// action ([`FolderSync::revert`]) is a new commit that puts exactly these items back (ADR 0001,
/// section 5: a restore is a commit), so changes of other devices since stay.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct UndoState {
    items: BTreeMap<ItemId, Option<Node>>,
}

impl UndoState {
    /// The items `after` differs from `before` in, with their state in `before`.
    pub fn between(before: &Tree, after: &Tree) -> Self {
        let mut items = BTreeMap::new();
        for (id, node) in before.iter() {
            if after.get(id) != Some(node) {
                items.insert(*id, Some(node.clone()));
            }
        }
        for id in after.ids() {
            if !before.contains(id) {
                items.insert(*id, None);
            }
        }
        Self { items }
    }

    /// The state of those of these items that `tree` holds now; an item it lacks is left out,
    /// so an undo never removes what the server never had.
    pub fn of(tree: &Tree, items: impl IntoIterator<Item = ItemId>) -> Self {
        Self {
            items: items
                .into_iter()
                .filter_map(|id| tree.get(&id).map(|node| (id, Some(node.clone()))))
                .collect(),
        }
    }

    /// Adds the items of a later action; an item both touched keeps its state before the first.
    pub fn merge(&mut self, later: UndoState) {
        for (id, node) in later.items {
            self.items.entry(id).or_insert(node);
        }
    }

    /// Whether the action changed nothing.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// `tree` with every item back in its state before the action: items the action made leave
    /// with everything below them, the others take their old node.
    pub fn apply_to(&self, tree: &Tree) -> Result<Tree, SyncError> {
        let mut out = tree.clone();
        for (id, node) in &self.items {
            if node.is_none() {
                for below in out.subtree(id) {
                    out.remove(&below);
                }
            }
        }
        for (id, node) in &self.items {
            if let Some(node) = node {
                out.insert(*id, node.clone());
            }
        }
        out.check().map_err(CodecError::from)?;
        Ok(out)
    }
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
    /// When the scan last found the folder too large ([`StopReason::LocalTooLarge`]); a
    /// change in the folder tries again at most once a minute. Not stored.
    too_large_at: Option<i64>,
    /// What the last commit of a person's action changed ([`FolderSync::publish_tree`]), until
    /// the engine takes it for an undo; not stored.
    last_action: Option<UndoState>,
    /// Contents whose chunks an upload could not seal under the writable generation; the next
    /// scan hashes their files again under it, even when size and time are unchanged. Chunk IDs
    /// are keyed per generation, so a file hashed before a key rotation and not uploaded since
    /// (or one whose old chunks the server's collection deleted) names IDs that only an older
    /// generation produces. Uploads never use older keys, since a removed device knows them, so
    /// without this every publish ended in [`PublishFailure::LocalChanged`]. Not stored: after a
    /// restart the next failed upload finds the contents again.
    rehash: BTreeSet<ContentKey>,
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

/// Free space a download leaves on the sync root's volume at least, on top of the file itself:
/// room for the operating system, the local index and other programs, so a burst of files from
/// another device never fills this device's disk (security review M2 of the download path).
/// 256 MiB is about what Windows keeps before it warns about low space.
const DISK_RESERVE_MIN: u64 = 256 * 1024 * 1024;
/// The share of the volume, in percent, a download leaves free (LOW 4 of the follow-up
/// review): 256 MiB alone is nothing on a large disk, where system updates, swap and the
/// recycle bin need gigabytes, and a full disk breaks every program, not only this one.
const DISK_RESERVE_PERCENT: u64 = 5;
/// The reserve at most: 5 % of a 4 TB disk would hold back 200 GB the person paid for. 10 GiB
/// covers a system feature update and a working swap file.
const DISK_RESERVE_MAX: u64 = 10 * 1024 * 1024 * 1024;

/// The free space a download leaves on a volume of `volume` bytes: 5 % of it, between 256 MiB
/// and 10 GiB, or 256 MiB when the size is unknown.
pub fn disk_reserve(volume: Option<u64>) -> u64 {
    volume.map_or(DISK_RESERVE_MIN, |v| {
        (v / 100)
            .saturating_mul(DISK_RESERVE_PERCENT)
            .clamp(DISK_RESERVE_MIN, DISK_RESERVE_MAX)
    })
}

/// Whether a file of `size` bytes may be written with `free` bytes free on a volume of
/// `volume` bytes. Unknown free space is no room: a manifest may name the same chunk up to its
/// limit, so a file can be far larger than what the server stores, and without a reading this
/// device cannot bound what it writes. Every supported platform reports the space; `None`
/// means the call failed, and the file waits for the next round (backoff) as on a full disk.
pub fn room_for(size: u64, free: Option<u64>, volume: Option<u64>) -> bool {
    free.is_some_and(|f| f >= size.saturating_add(disk_reserve(volume)))
}

/// Bytes one apply run fetches at most; a file that would go beyond waits for the next round.
/// The first file of a run is always taken, so a single file larger than this still comes.
/// It is a bound on network traffic per round, not on the disk: it limits what one round
/// downloads before the next round checks the head and local changes again (1 GiB is about
/// 90 s at 100 Mbit/s). The disk is guarded per file by [`room_for`], against the free space
/// read right before that file.
const ROUND_DOWNLOAD_BYTES: u64 = 1024 * 1024 * 1024;

/// Plaintext a write keeps of chunks its manifest names again later, so a repeated chunk ID is
/// fetched and opened once while memory stays bounded (16 chunks of 4 MiB); beyond it, the chunk
/// is fetched again.
const CHUNK_CACHE_BYTES: u64 = 64 * 1024 * 1024;

/// The executor's disk: the sync root plus the content from the server.
struct FsDisk<'a> {
    fs: &'a dyn FileSystem,
    server: &'a mut dyn ServerApi,
    store: &'a dyn Store,
    crypto: &'a FolderCrypto,
    file_ids: &'a mut BTreeMap<ItemId, u128>,
    dirty: &'a mut BTreeMap<ItemId, Option<u128>>,
    /// Bytes fetched in this apply run ([`ROUND_DOWNLOAD_BYTES`]).
    downloaded: u64,
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
        let size = version.size;
        // Checked before anything is fetched: a manifest may name the same chunk up to its
        // limit, so the file can be far larger than what the server stores and the quota
        // counts. Without room the file waits (the caller backs off) and nothing is written.
        if !room_for(size, self.fs.free_bytes(), self.fs.volume_bytes()) {
            return Err(ActionError::DiskFull);
        }
        if self.downloaded > 0 && self.downloaded.saturating_add(size) > ROUND_DOWNLOAD_BYTES {
            return Err(ActionError::Unavailable);
        }
        // How often each chunk is still to come, so a repeated one is kept until its last use.
        let mut left: BTreeMap<ObjectId, u64> = BTreeMap::new();
        for id in &list.chunks {
            *left.entry(*id).or_default() += 1;
        }
        let mut failure: Option<ActionError> = None;
        let crypto = self.crypto;
        let server = &mut *self.server;
        let downloaded = &mut self.downloaded;
        let mut fill = |out: &mut dyn std::io::Write| -> Result<(), FsError> {
            let mut written = 0u64;
            let mut cache: BTreeMap<ObjectId, zeroize::Zeroizing<Vec<u8>>> = BTreeMap::new();
            let mut cached = 0u64;
            for (index, id) in list.chunks.iter().enumerate() {
                let remaining = left.get_mut(id).map_or(0, |n| {
                    *n = n.saturating_sub(1);
                    *n
                });
                let plain = match cache.remove(id) {
                    Some(p) => {
                        cached = cached.saturating_sub(p.len() as u64);
                        p
                    }
                    None => {
                        let blob = match server.get_object(&folder, id) {
                            Ok(b) => b,
                            Err(_) => {
                                failure = Some(ActionError::Unavailable);
                                return Err(FsError::Io("content unavailable".into()));
                            }
                        };
                        *downloaded = downloaded.saturating_add(blob.len() as u64);
                        match crypto.open(id, ObjectType::Chunk, &blob) {
                            Ok(p) => p,
                            Err(_) => {
                                failure = Some(ActionError::Unavailable);
                                return Err(FsError::Io("content does not open".into()));
                            }
                        }
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
                if remaining > 0 && cached.saturating_add(plain.len() as u64) <= CHUNK_CACHE_BYTES {
                    cached += plain.len() as u64;
                    cache.insert(*id, plain);
                }
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
            too_large_at: None,
            last_action: None,
            rehash: BTreeSet::new(),
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
            too_large_at: None,
            last_action: None,
            rehash: BTreeSet::new(),
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
        if self.meta.state == FolderState::Stopped(StopReason::LocalTooLarge) {
            if !self.retry_too_large(cx.clock.now_ms()) {
                return Ok(report);
            }
            self.meta.state = FolderState::Active;
            self.request_full_scan();
        }
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
        if self.meta.state != FolderState::Active {
            return Ok(report);
        }
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
        // A delta this device could not check, or a barrier that kept the empty diff: the
        // server's live set may not match the tree, so it is repaired now with the same tree
        // and a full delta, without waiting for a local change (ADR 0001, amendment "reference
        // deltas bound to the tree").
        if self.meta.full_next && self.meta.state == FolderState::Active {
            match self.repair(cx) {
                Ok(()) => report.published = true,
                Err(PublishFailure::Error(e)) if e.is_offline() => {
                    report.offline = true;
                    self.save(cx.store)?;
                    return Ok(report);
                }
                // Stays due: the next round or publish tries again.
                Err(_) => {}
            }
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
            // The merged tree can be larger than the disk's and the server's tree alone; one
            // beyond the limits is never published (follow-up check N-4).
            if !p
                .merged
                .within(cx.settings.max_tree_items, cx.settings.max_tree_depth)
            {
                self.stop_too_large(cx.clock.now_ms());
                self.save(cx.store)?;
                return Ok(report);
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

    /// Stops the folder as too large for a folder (follow-up check N-4); the next try waits for
    /// a change in the folder or the hourly scan ([`Self::retry_too_large`]).
    fn stop_too_large(&mut self, now: i64) {
        self.meta.state = FolderState::Stopped(StopReason::LocalTooLarge);
        self.scan_scope = ScanScope::Paths(BTreeSet::new());
        self.too_large_at = Some(now);
    }

    /// Whether a folder stopped as too large tries again now: after the hourly full scan was
    /// requested, or after a change the watcher reported, at most once a minute, so a folder
    /// that keeps changing is not walked up to its limit in every round.
    fn retry_too_large(&self, now: i64) -> bool {
        match &self.scan_scope {
            ScanScope::Full => true,
            ScanScope::Paths(paths) => {
                !paths.is_empty()
                    && self
                        .too_large_at
                        .is_none_or(|at| !(0..TOO_LARGE_RETRY_MS).contains(&(now - at)))
            }
        }
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
        // The limits of a folder (follow-up check N-4), checked while walking, so a folder far
        // beyond them is not read to its end: more items than a device decodes, or an item
        // deeper than it decodes.
        let (max_items, max_depth) = (cx.settings.max_tree_items, cx.settings.max_tree_depth);
        let beyond = |found: &[(Vec<String>, Stat)]| {
            found.len() > max_items || found.last().is_some_and(|(p, _)| p.len() > max_depth)
        };
        while let Some(dir) = dirs.pop() {
            if beyond(&found) {
                self.stop_too_large(cx.clock.now_ms());
                return Ok(());
            }
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
        if beyond(&found) {
            self.stop_too_large(cx.clock.now_ms());
            return Ok(());
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

        // 3. Which files need hashing. An unchanged file whose chunks an upload could not seal
        // ([`FolderSync::rehash`]) is hashed again under the newest generation.
        let rehash_contents = std::mem::take(&mut self.rehash);
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
                    if !rehash_contents.contains(&v.content) {
                        versions.insert(*item, v);
                        continue;
                    }
                    jobs.push(HashJob {
                        path: path.clone(),
                        generation: newest,
                    });
                    job_items.push((*item, prev, *stat));
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
        let checked = self.verify_tree_deltas(cx, &outcome, &delta)?;
        let reader = cx.account.folder_reader(&self.folder)?;
        let decoded = if checked.limit {
            // A head on the way is beyond the limits: its delta could not be checked, and the
            // folder stops as for a head beyond the limits (HIGH 1 of the follow-up review).
            Err(codec::CodecError::Limit)
        } else {
            codec::decode(&head.commit.root, &reader, cx.store, cx.server)
        };
        let tree = match decoded {
            Ok(tree) => tree,
            Err(codec::CodecError::Limit) => {
                // The commits verified, so they are the folder's chain and its history; only
                // the head's tree stays out (security review M3). The remote tree keeps the last
                // one taken in, and the folder waits for a restore, which carries a full delta.
                self.record_timeline(&outcome, &delta, cx.clock.now_ms());
                self.annotate_timeline(&checked.drops);
                self.meta.full_next = true;
                let n = outcome.heads.len();
                self.view = outcome.view;
                self.meta.remote_root = Some(head.commit.root);
                self.meta.frontier_wire = Some(Blob(head.wire.clone()));
                self.meta.sync_base = None;
                self.meta.state = FolderState::Stopped(StopReason::TreeLimit);
                return Ok(n);
            }
            Err(e) => return Err(e.into()),
        };
        self.record_timeline(&outcome, &delta, cx.clock.now_ms());
        self.annotate_timeline(&checked.drops);
        let n = outcome.heads.len();
        self.view = outcome.view;
        self.set_remote(tree);
        self.meta.remote_root = Some(head.commit.root);
        self.meta.frontier_wire = Some(Blob(head.wire.clone()));
        Ok(n)
    }

    /// Checks every head and side commit of an accepted delta against the trees (ADR 0001,
    /// amendment "reference deltas bound to the tree"): the delta digest it signed must be the
    /// digest of `reachable(tree)` against `reachable(first parent's tree)` (a side commit's:
    /// its base), or of `reachable(tree)` alone for a full delta. The server applied exactly that
    /// delta to its live set, so a commit whose delta does not fit its tree would let the
    /// collection delete live data or keep garbage live: it is refused like a commit with a bad
    /// signature, and the folder stops until the person removes the device that wrote it.
    ///
    /// - A mismatching commit of a device the verified log has removed since is let through:
    ///   such commits come in only behind a barrier that the removing device or the person
    ///   accepted.
    /// - A tree the server no longer holds (an object is gone) is accepted as unreadable only
    ///   for a commit whose call is older than [`UNREADABLE_AFTER_MS`] by the server's unsigned
    ///   time, or whose time the server already dropped because it expired: only then may the
    ///   collection have taken its trees. For a younger commit of a current device it is a
    ///   mismatch, so a device cannot hide a forged delta behind a tree it never uploaded
    ///   (HIGH 1 of the follow-up review). The server decides retention anyway, so trusting its
    ///   time here gives it nothing it lacks.
    /// - A tree beyond the limits stops the folder as [`StopReason::TreeLimit`] does
    ///   ([`TreeCheck::limit`]).
    ///
    /// Whatever is let through or cannot be checked sets [`FolderMeta::full_next`], and the
    /// round then writes a repair commit at once ([`Self::repair`]), which resets the server's
    /// live set to the tree whatever happened before.
    fn verify_tree_deltas(
        &mut self,
        cx: &mut Ctx<'_>,
        outcome: &DeltaOutcome,
        delta: &[DeltaCommit],
    ) -> Result<TreeCheck, SyncError> {
        let mut check = TreeCheck::default();
        if outcome.heads.is_empty() && outcome.sides.is_empty() {
            return Ok(check);
        }
        let now = u64::try_from(cx.clock.now_ms()).unwrap_or(0);
        let times: BTreeMap<CommitId, Option<u64>> = delta
            .iter()
            .filter_map(|d| {
                SignedCommit::decode(d.commit.as_bytes())
                    .ok()
                    .map(|c| (c.id, d.server_ms))
            })
            .collect();
        let old_enough = |id: &CommitId| match times.get(id).copied().flatten() {
            None => true,
            Some(at) => now.saturating_sub(at) > UNREADABLE_AFTER_MS,
        };
        let reader = cx.account.folder_reader(&self.folder)?;
        let mut roots: BTreeMap<CommitId, ObjectId> = self
            .meta
            .timeline
            .iter()
            .map(|t| (t.commit, t.root))
            .collect();
        if let (Some(frontier), Some(root)) = (self.view.frontier(), self.meta.remote_root) {
            roots.insert(frontier.commit, root);
        }
        for head in &outcome.heads {
            roots.insert(head.id, head.commit.root);
        }
        let mut sets: BTreeMap<ObjectId, Readable> = BTreeMap::new();
        let empty = Readable::Set(codec::Reachable::default());
        for c in outcome.heads.iter().chain(outcome.sides.iter()) {
            let after = readable_set(&c.commit.root, &reader, cx, &mut sets)?;
            let before = match c.commit.parents.first() {
                None => empty.clone(),
                Some(parent) => match roots.get(parent).copied() {
                    None => Readable::Gone,
                    Some(root) => readable_set(&root, &reader, cx, &mut sets)?,
                },
            };
            let verdict = match (&after, &before) {
                (Readable::Limit, _) | (_, Readable::Limit) => {
                    check.limit = true;
                    Verdict::Unchecked
                }
                (Readable::Set(after), _) if c.commit.delta.full => {
                    Verdict::of(DeltaDigest::full(&after.all) == c.commit.delta)
                }
                (Readable::Set(after), Readable::Set(before)) => {
                    let fits = DeltaDigest::diff(&before.all, &after.all) == c.commit.delta;
                    if fits && !c.commit.side {
                        check
                            .drops
                            .insert(c.id, DropCount::of(before, after, false));
                    }
                    Verdict::of(fits)
                }
                // A tree the server no longer holds: only an old enough commit may have lost it.
                _ if old_enough(&c.id) => Verdict::Unchecked,
                _ => Verdict::Mismatch,
            };
            if c.commit.delta.full && !c.commit.side {
                if let (Readable::Set(before), Readable::Set(after)) = (&before, &after) {
                    if verdict == Verdict::Fits {
                        check.drops.insert(c.id, DropCount::of(before, after, true));
                    }
                }
            }
            match verdict {
                Verdict::Fits => {}
                Verdict::Unchecked => self.meta.full_next = true,
                Verdict::Mismatch => {
                    let current = cx
                        .account
                        .state()
                        .device(&c.commit.device)
                        .is_some_and(|d| d.is_current());
                    if current {
                        return Err(SyncError::Chain(
                            hangar_drive_crypto::commit::ChainError::Commit(
                                hangar_drive_crypto::commit::CommitError::DeltaMismatch,
                            ),
                        ));
                    }
                    self.meta.full_next = true;
                }
            }
        }
        Ok(check)
    }

    /// Writes what [`Self::verify_tree_deltas`] counted into the timeline records just added.
    fn annotate_timeline(&mut self, drops: &BTreeMap<CommitId, DropCount>) {
        for rec in self
            .meta
            .timeline
            .iter_mut()
            .rev()
            .take(drops.len().max(1) * 2 + 2)
        {
            if let Some(d) = drops.get(&rec.commit) {
                rec.dropped_files = Some(d.dropped);
                rec.files_before = Some(d.before);
            }
        }
    }

    /// The repair commit: the remote tree once more on the frontier, with a full delta, so the
    /// server's live set is the tree again (ADR 0001, amendment "reference deltas bound to the
    /// tree"). Every directory node and manifest is sealed again and every object the server
    /// lacks is uploaded first, also one the collection deleted; chunks come from the disk.
    fn repair(&mut self, cx: &mut Ctx<'_>) -> Result<(), PublishFailure> {
        let Some(frontier) = self.view.frontier().copied() else {
            self.meta.full_next = false;
            return Ok(());
        };
        let crypto = cx
            .account
            .folder_crypto(&self.folder, Some(frontier.generation))?;
        let tree = self.remote.clone();
        let fresh = codec::encode_fresh(&tree, &crypto, cx.store, cx.entropy)?;
        let (delta, digest) = full_delta(&fresh.reachable, cx.settings.max_delta_ids)
            .ok_or(SyncError::Invalid("too many objects for one commit"))?;
        let disk = self.local.clone();
        self.upload(cx, &crypto, &fresh, &fresh.reachable, &disk)?;
        codec::remember_uploaded(&fresh, &self.folder, cx.store).map_err(SyncError::from)?;
        self.send(
            cx,
            &crypto,
            fresh.root,
            Some(frontier),
            None,
            &delta,
            digest,
        )?;
        self.meta.full_next = false;
        self.meta.remote_root = Some(fresh.root);
        self.save(cx.store)?;
        Ok(())
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
                dropped_files: None,
                files_before: None,
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
        // The objects themselves, not a decoded tree (security review M3): the parent may be a
        // head beyond the limits of a folder that a restore replaces.
        Ok(codec::reachable(&root, crypto, cx.store, cx.server)?)
    }

    /// Uploads every object of `encoded` the server lacks: sealed nodes and manifests, and
    /// chunks read from the disk. A chunk that does not seal to its ID marks its content for
    /// the next scan to hash again ([`FolderSync::rehash`]).
    fn upload(
        &mut self,
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
        let mut sources: BTreeMap<ObjectId, (Vec<String>, u64, ContentKey)> = BTreeMap::new();
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
                    .or_insert_with(|| (path.clone(), index as u64, v.content));
            }
        }
        for id in &missing {
            if let Some(blob) = encoded.sealed.get(id) {
                cx.server.put_object(&self.folder, id, blob)?;
                continue;
            }
            let Some((path, index, content)) = sources.get(id) else {
                // A chunk this device cannot produce: the disk changed, scan again.
                return Err(PublishFailure::LocalChanged);
            };
            let sealed = match crate::chunker::seal_chunk(
                cx.fs,
                path,
                *index,
                id,
                crypto.writable().map_err(SyncError::from)?,
                cx.entropy,
            ) {
                Ok(s) => s,
                Err(_) => {
                    self.mark_rehash(cx, crypto, *content, &missing, &sources)?;
                    return Err(PublishFailure::LocalChanged);
                }
            };
            cx.server.put_object(&self.folder, id, &sealed.blob)?;
        }
        Ok(())
    }

    /// Marks `failed` for the next scan to hash again. When its chunks were hashed under an
    /// older generation than the writable one, every other content with chunks the server lacks
    /// and an older generation is marked as well, so a rotation costs one failed publish, not
    /// one per pending file. A file that merely changed marks only itself: the others still
    /// seal and are not read twice.
    fn mark_rehash(
        &mut self,
        cx: &Ctx<'_>,
        crypto: &FolderCrypto,
        failed: ContentKey,
        missing: &[ObjectId],
        sources: &BTreeMap<ObjectId, (Vec<String>, u64, ContentKey)>,
    ) -> Result<(), SyncError> {
        self.rehash.insert(failed);
        let writable = crypto.writable_generation().0;
        let older = |content: &ContentKey| -> Result<bool, SyncError> {
            Ok(cx
                .store
                .chunk_list(&self.folder, content)?
                .and_then(|l| l.generation)
                .is_some_and(|g| g != writable))
        };
        if !older(&failed)? {
            return Ok(());
        }
        let pending: BTreeSet<ContentKey> = missing
            .iter()
            .filter_map(|id| sources.get(id).map(|(_, _, c)| *c))
            .collect();
        let mut stale = Vec::new();
        for content in pending {
            if older(&content)? {
                stale.push(content);
            }
        }
        self.rehash.extend(stale);
        Ok(())
    }

    fn content(
        &self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        root: ObjectId,
        delta: DeltaDigest,
    ) -> Result<CommitContent, SyncError> {
        let counter = cx.account.next_counter(cx.store)?;
        Ok(CommitContent {
            root,
            generation: crypto.writable_generation(),
            device: *cx.account.device(),
            log_head: cx.account.log_head()?,
            counter,
            delta,
        })
    }

    /// Uploads what the encoded `tree` needs and commits it on `frontier`, with `side` if given
    /// (ADR 0001, amendment "reference deltas bound to the tree"); returns the committed root.
    /// The head's delta is a diff against `parent`, the first parent's reachable set, or the
    /// full set when the diff does not fit one commit or [`FolderMeta::full_next`] asks for it.
    ///
    /// - The server no longer retains the side commit's base: the merge alone, with one parent.
    /// - The server's live set does not fit the diff (`delta_mismatch`): another device broke
    ///   it. The same tree goes out again with a full delta and without the side commit, every
    ///   directory node and manifest sealed again ([`codec::encode_fresh`]), and every object of
    ///   the tree the server lacks, also one the collection deleted, uploaded first. That
    ///   repairs the live set, so an honest device is never locked out of a folder.
    #[allow(clippy::too_many_arguments)]
    fn commit_encoded(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        tree: &Tree,
        encoded: &Encoded,
        parent: &BTreeSet<ObjectId>,
        frontier: Option<ChainEntry>,
        side: Option<&(SignedCommit, ReferenceDelta)>,
        disk: &Tree,
    ) -> Result<ObjectId, PublishFailure> {
        let limit = cx.settings.max_delta_ids;
        let wants_full = self.meta.full_next && full_delta(&encoded.reachable, limit).is_some();
        if !wants_full {
            let (delta, digest) = head_delta(parent, &encoded.reachable, limit, false)?;
            if !digest.full {
                let added: BTreeSet<ObjectId> = delta.added.iter().copied().collect();
                self.upload(cx, crypto, encoded, &added, disk)?;
                codec::remember_uploaded(encoded, &self.folder, cx.store)
                    .map_err(SyncError::from)?;
                let code = |r: &Result<(), PublishFailure>| match r {
                    Err(PublishFailure::Error(SyncError::Net(e))) => e.code(),
                    _ => None,
                };
                let mut result =
                    self.send(cx, crypto, encoded.root, frontier, side, &delta, digest);
                if side.is_some() && code(&result) == Some(ErrorCode::BaseExpired) {
                    result = self.send(cx, crypto, encoded.root, frontier, None, &delta, digest);
                }
                if code(&result) != Some(ErrorCode::DeltaMismatch) {
                    result?;
                    return Ok(encoded.root);
                }
                self.meta.full_next = true;
            }
        }
        let fresh = codec::encode_fresh(tree, crypto, cx.store, cx.entropy)?;
        let (delta, digest) = full_delta(&fresh.reachable, limit)
            .ok_or(SyncError::Invalid("too many objects for one commit"))?;
        self.upload(cx, crypto, &fresh, &fresh.reachable, disk)?;
        codec::remember_uploaded(&fresh, &self.folder, cx.store).map_err(SyncError::from)?;
        self.send(cx, crypto, fresh.root, frontier, None, &delta, digest)?;
        self.meta.full_next = false;
        Ok(fresh.root)
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
        let frontier = self.view.frontier().copied();
        let root =
            self.commit_encoded(cx, crypto, tree, &encoded, &parent, frontier, None, disk)?;
        self.set_remote(tree.clone());
        self.meta.remote_root = Some(root);
        self.save(cx.store)?;
        Ok(())
    }

    fn publish(&mut self, cx: &mut Ctx<'_>, p: &Plan) -> Result<(), PublishFailure> {
        let chain_generation = self.view.frontier().map(|f| f.generation);
        let crypto = cx.account.folder_crypto(&self.folder, chain_generation)?;
        let limit = delta_limit(cx.settings.max_delta_ids);
        let mut encoded = codec::encode(&p.merged, &crypto, cx.store, cx.entropy)?;
        let mut parent = self.reachable_of(self.meta.remote_root, &crypto, cx)?;
        // Too many changes for one commit, as a diff and as the full set: publish valid
        // intermediate trees first, each the server's tree plus whole new files and their new
        // directories (open point B). Half the limit for the new objects leaves room for the
        // old versions a stage drops.
        while !fits_one_commit(&parent, &encoded.reachable, limit) {
            let Some(stage) = stage_tree(&self.remote, &p.merged, &encoded, limit / 2) else {
                return Err(SyncError::Invalid("too many changes for one commit").into());
            };
            self.publish_stage(cx, &crypto, &stage, &p.disk)?;
            encoded = codec::encode(&p.merged, &crypto, cx.store, cx.entropy)?;
            parent = self.reachable_of(self.meta.remote_root, &crypto, cx)?;
        }

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
                // A side commit's delta is always a diff against its base. One that would not
                // fit one commit is left out: the merge commit alone loses nothing, as with an
                // expired base.
                if let Some((side_delta, side_digest)) =
                    diff_delta(&base_reach, &side_enc.reachable, limit)
                {
                    let side_added: BTreeSet<ObjectId> = side_delta.added.iter().copied().collect();
                    self.upload(cx, &crypto, &side_enc, &side_added, &p.disk)?;
                    codec::remember_uploaded(&side_enc, &self.folder, cx.store)
                        .map_err(SyncError::from)?;
                    let content = self.content(cx, &crypto, side_enc.root, side_digest)?;
                    let commit = Commit::side(
                        *cx.account.id(),
                        self.folder,
                        &ChainEntry::from(&base.entry),
                        content,
                    );
                    let signed = cx.account.sign(commit)?;
                    side = Some((signed, side_delta));
                }
            }
        }
        let root = self.commit_encoded(
            cx,
            &crypto,
            &p.merged,
            &encoded,
            &parent,
            frontier,
            side.as_ref(),
            &p.disk,
        )?;
        self.set_remote(p.merged.clone());
        self.meta.remote_root = Some(root);
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

    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        root: ObjectId,
        frontier: Option<ChainEntry>,
        side: Option<&(SignedCommit, ReferenceDelta)>,
        delta: &ReferenceDelta,
        digest: DeltaDigest,
    ) -> Result<(), PublishFailure> {
        let content = self.content(cx, crypto, root, digest)?;
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
                dropped_files: None,
                files_before: None,
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
            dropped_files: None,
            files_before: None,
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
            downloaded: 0,
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
            let dir = before
                .get(id)
                .or_else(|| p.merged.get(id))
                .is_some_and(Node::is_dir);
            report.changes.push(ItemChange {
                item: *id,
                path,
                action,
                incoming: true,
                dir,
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
                // Waits for space instead of being tried every round: from one minute,
                // doubling up to 32 minutes; the wait ends once the file is written.
                ActionError::DiskFull => {
                    let entry = self.meta.backoff.entry(*id).or_insert((0, 0));
                    entry.0 = entry.0.saturating_add(1);
                    let wait = 60_000i64 << entry.0.saturating_sub(1).min(5);
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
        let change = UndoState::between(&self.remote, &tree);
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
            Ok(()) => {
                self.last_action = Some(change);
                // A restore replaced a head beyond the limits (M3): the folder syncs again.
                if self.meta.state == FolderState::Stopped(StopReason::TreeLimit) {
                    self.meta.state = FolderState::Active;
                    self.request_full_scan();
                    self.save(cx.store)?;
                }
                Ok(())
            }
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

    /// Restores several items of `commit` that are gone from the current tree, in one commit
    /// (an incoming delete undone from the activity list, UX 8.1); an item that is back already
    /// is left as it is, so a newer version is never replaced. Returns the files that came back.
    pub fn restore_items(
        &mut self,
        cx: &mut Ctx<'_>,
        commit: &CommitId,
        items: &[ItemId],
    ) -> Result<u64, SyncError> {
        self.pull(cx)?;
        let old = self.tree_at(cx, commit)?;
        let date = date_label(cx.clock.now_ms(), cx.settings.tz_offset_minutes);
        let mut tree = self.remote.clone();
        for item in items {
            if tree.contains(item) || !old.contains(item) {
                continue;
            }
            tree = graft(
                &tree,
                &old,
                item,
                &cx.settings.words,
                &date,
                &mut EntropyIds(cx.entropy),
            )?
            .0;
        }
        let back = tree
            .iter()
            .filter(|(id, n)| !n.is_dir() && !self.remote.contains(id))
            .count() as u64;
        if back > 0 {
            self.publish_tree(cx, tree)?;
        }
        Ok(back)
    }

    /// What the last commit of a person's action changed, for its undo token; taken once.
    pub fn take_last_action(&mut self) -> Option<UndoState> {
        self.last_action.take()
    }

    /// Undoes a person's action (`undo`): local changes go out first (a "keep this" lives on
    /// the disk until its round), then a new commit puts the items `undo` names back in their
    /// state before the action. Nothing of the history is removed.
    pub fn revert(&mut self, cx: &mut Ctx<'_>, undo: &UndoState) -> Result<(), SyncError> {
        let report = self.round(cx)?;
        if report.offline {
            return Err(SyncError::Net(NetError::Unreachable));
        }
        let tree = undo.apply_to(&self.remote)?;
        if tree == self.remote {
            return Ok(());
        }
        self.publish_tree(cx, tree)?;
        // The undo itself is not undone again.
        self.last_action = None;
        Ok(())
    }

    /// "Download again" for a folder whose place went missing (UX 8.2): this device forgets
    /// what it held on disk, so the next round fills the empty place from the server's tree.
    /// The verified chain, its marks and the history stay, so the folder keeps its protection
    /// against an older state and its versions (ADR 0001, section 4).
    pub fn forget_disk(&mut self, store: &mut dyn Store) -> Result<(), SyncError> {
        let synced: Vec<ItemId> = self.synced.ids().copied().collect();
        for id in synced {
            self.synced.remove(&id);
        }
        let local: Vec<ItemId> = self.local.ids().copied().collect();
        for id in local {
            self.local.remove(&id);
        }
        for id in std::mem::take(&mut self.file_ids).into_keys() {
            self.file_ids_dirty.insert(id, None);
        }
        self.meta.sync_base = None;
        self.meta.deleted_seen.clear();
        self.meta.held.clear();
        self.meta.restore.clear();
        self.meta.approve_deletes = false;
        self.meta.backoff.clear();
        self.meta.not_synced.clear();
        if self.meta.state == FolderState::Stopped(StopReason::MarkerMissing) {
            self.meta.state = FolderState::Active;
        }
        self.scan_scope = ScanScope::Full;
        self.save(store)
    }

    /// Syncs again a folder that stopped because it was retired, once it is in the account's
    /// folder list again (another device brought it back); returns whether it was stopped so.
    pub fn clear_retired(&mut self, store: &mut dyn Store) -> Result<bool, SyncError> {
        if self.meta.state != FolderState::Stopped(StopReason::Retired) {
            return Ok(false);
        }
        self.meta.state = FolderState::Active;
        self.request_full_scan();
        self.save(store)?;
        Ok(true)
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
        // Every node sealed again: the server that showed the older state may lack objects the
        // store lists as uploaded, and the full delta below asks for all of them.
        let encoded = codec::encode_fresh(&merged.tree, &crypto, cx.store, cx.entropy)?;
        let all = encoded.reachable.clone();
        match self.upload(cx, &crypto, &encoded, &all, &merged.local) {
            Ok(()) => {}
            Err(PublishFailure::Error(e)) => return Err(e),
            Err(_) => return Err(SyncError::Invalid("the disk changed")),
        }
        codec::remember_uploaded(&encoded, &self.folder, cx.store)?;
        // A full delta: the server's live set may be anything after the older state, and the
        // full set replaces it (ADR 0001, amendment "reference deltas bound to the tree").
        let (delta, digest) = full_delta(&all, cx.settings.max_delta_ids)
            .ok_or(SyncError::Invalid("too many objects for one commit"))?;
        let content = self.content(cx, &crypto, encoded.root, digest)?;
        let commit = Commit::reanchor(*cx.account.id(), self.folder, &base.head, content);
        let signed = cx.account.sign(commit)?;
        let request = CommitRequest {
            expected_head: Some(base.head.commit),
            head: CommitUpload {
                commit: Blob(signed.wire.clone()),
                delta,
            },
            side: None,
        };
        let response = cx.server.commit(&self.folder, &request)?;
        self.meta.full_next = false;
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
            dropped_files: None,
            files_before: None,
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
        // A full delta of the tree when it fits one commit: the removed device may have
        // broken the server's live set, and the barrier resets it to the tree it keeps (ADR
        // 0001, amendment "reference deltas bound to the tree"). If the tree cannot be read or
        // the server lacks some of its objects, the barrier keeps the empty diff and this
        // device's next publish carries the full delta, with the objects uploaded again.
        let full = match readable_set(&head.commit.root, &crypto, cx, &mut BTreeMap::new())? {
            Readable::Set(reach) => full_delta(&reach.all, cx.settings.max_delta_ids),
            Readable::Gone | Readable::Limit => None,
        };
        let mut attempts = Vec::new();
        attempts.extend(full);
        attempts.push((
            ReferenceDelta::default(),
            DeltaDigest::diff(&BTreeSet::new(), &BTreeSet::new()),
        ));
        let mut accepted_response = None;
        let mut signed_barrier = None;
        let mut last_error = None;
        for (delta, digest) in attempts {
            let counter = cx.account.next_counter(cx.store)?;
            let commit = Commit::barrier(
                head,
                sequence,
                crypto.writable_generation(),
                *cx.account.device(),
                cx.account.log_head()?,
                counter,
                digest,
            );
            let signed = cx.account.sign(commit)?;
            let request = CommitRequest {
                expected_head: Some(head.id),
                head: CommitUpload {
                    commit: Blob(signed.wire.clone()),
                    delta,
                },
                side: None,
            };
            match cx.server.commit(&self.folder, &request) {
                Ok(r) => {
                    self.meta.full_next = !digest.full;
                    accepted_response = Some(r);
                    signed_barrier = Some(signed);
                    break;
                }
                // The removal must finish even when the full delta cannot pass now: objects
                // the server lacks, a live set it does not fit, or bytes it would make live
                // again beyond the quota or a budget (MEDIUM 2 of the follow-up review). The
                // empty diff goes out, and the repair follows once it can.
                Err(e)
                    if digest.full
                        && matches!(
                            e.code(),
                            Some(
                                ErrorCode::MissingObjects
                                    | ErrorCode::DeltaMismatch
                                    | ErrorCode::BudgetExceeded
                                    | ErrorCode::QuotaExceeded
                            )
                        ) =>
                {
                    last_error = Some(e);
                }
                Err(e) => return Err(e.into()),
            }
        }
        let (Some(response), Some(signed)) = (accepted_response, signed_barrier) else {
            return Err(last_error.map_or(SyncError::Invalid("no barrier sent"), Into::into));
        };
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
            dropped_files: None,
            files_before: None,
        });
        if self.meta.full_next {
            // The barrier kept the empty diff: repair at once where it can (objects the server
            // lacks are uploaded now); otherwise the flag stays and the next round tries again,
            // so a failure here never fails the removal.
            let _ = self.repair(cx);
        }
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
        let checked = self.verify_tree_deltas(cx, &outcome, delta)?;
        self.record_timeline(&outcome, delta, cx.clock.now_ms());
        self.annotate_timeline(&checked.drops);
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

/// The IDs one commit's delta may list: the setting, at least 1 and at most
/// `hangar_drive_protocol::api::MAX_REFERENCE_DELTA_IDS`.
fn delta_limit(setting: usize) -> usize {
    setting.clamp(1, hangar_drive_protocol::api::MAX_REFERENCE_DELTA_IDS)
}

/// The diff from the reachable set `before` to `after`, if it fits `limit` IDs (ADR 0001,
/// amendment "reference deltas bound to the tree"). A diff is exact: every verifying device
/// recomputes it from the trees, so no ID may be left out, not even a dropped one.
pub fn diff_delta(
    before: &BTreeSet<ObjectId>,
    after: &BTreeSet<ObjectId>,
    limit: usize,
) -> Option<(ReferenceDelta, DeltaDigest)> {
    let added: Vec<ObjectId> = after.difference(before).copied().collect();
    let dropped: Vec<ObjectId> = before.difference(after).copied().collect();
    if added.len().saturating_add(dropped.len()) > delta_limit(limit) {
        return None;
    }
    let digest = DeltaDigest::of(false, &added, &dropped)?;
    Some((ReferenceDelta { added, dropped }, digest))
}

/// The full delta of the reachable set `all`, if it fits `limit` IDs.
pub fn full_delta(all: &BTreeSet<ObjectId>, limit: usize) -> Option<(ReferenceDelta, DeltaDigest)> {
    if all.len() > delta_limit(limit) {
        return None;
    }
    let added: Vec<ObjectId> = all.iter().copied().collect();
    let digest = DeltaDigest::of(true, &added, &[])?;
    Some((
        ReferenceDelta {
            added,
            dropped: Vec::new(),
        },
        digest,
    ))
}

/// A head's delta from `before` to `after`: the diff, or the full set when the diff does not
/// fit or `prefer_full` asks for it and the full set fits. Neither fitting is refused here,
/// before anything is signed; a publish that large is split by [`stage_tree`] first.
pub fn head_delta(
    before: &BTreeSet<ObjectId>,
    after: &BTreeSet<ObjectId>,
    limit: usize,
    prefer_full: bool,
) -> Result<(ReferenceDelta, DeltaDigest), SyncError> {
    let full = || full_delta(after, limit);
    let chosen = if prefer_full {
        full().or_else(|| diff_delta(before, after, limit))
    } else {
        diff_delta(before, after, limit).or_else(full)
    };
    chosen.ok_or(SyncError::Invalid("too many changes for one commit"))
}

/// Whether a commit from `before` to `after` fits one delta of `limit` IDs, as a diff or as
/// the full set.
fn fits_one_commit(before: &BTreeSet<ObjectId>, after: &BTreeSet<ObjectId>, limit: usize) -> bool {
    let limit = delta_limit(limit);
    after.len() <= limit
        || after
            .difference(before)
            .count()
            .saturating_add(before.difference(after).count())
            <= limit
}

/// How old a commit must be, by the server's time of its call, before a device accepts that
/// the server no longer holds its trees (ADR 0001, amendment "reference deltas bound to the
/// tree"). One day: the shortest retention an operator can set
/// (`HANGAR_DRIVE_RETENTION_DAYS` is at least 1), so no honest server's collection takes a
/// tree any sooner.
pub const UNREADABLE_AFTER_MS: u64 = 24 * 60 * 60 * 1000;

/// A tree as a delta check reads it.
#[derive(Debug, Clone)]
enum Readable {
    /// The objects, with their kinds.
    Set(codec::Reachable),
    /// An object the server no longer holds.
    Gone,
    /// Beyond the limits of a folder.
    Limit,
}

/// The outcome of checking one commit's delta.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Fits,
    Mismatch,
    Unchecked,
}

impl Verdict {
    fn of(fits: bool) -> Self {
        if fits {
            Verdict::Fits
        } else {
            Verdict::Mismatch
        }
    }
}

/// File objects a head dropped from its first parent's tree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DropCount {
    /// Dropped file objects.
    pub dropped: u64,
    /// File objects of the parent's tree.
    pub before: u64,
}

impl DropCount {
    /// Manifests and chunks dropped from `before` to `after`. A full delta counts chunks only:
    /// a barrier or a repair seals manifests again, which renames them without dropping a
    /// file, while the chunks of a dropped file go in every case.
    fn of(before: &codec::Reachable, after: &codec::Reachable, full: bool) -> Self {
        let chunks_after: BTreeSet<&ObjectId> = after.chunks().collect();
        let mut dropped = before
            .chunks()
            .filter(|id| !chunks_after.contains(id))
            .count() as u64;
        let mut count_before = before.chunks().count() as u64;
        if !full {
            dropped += before.manifests.difference(&after.manifests).count() as u64;
            count_before += before.manifests.len() as u64;
        }
        Self {
            dropped,
            before: count_before,
        }
    }
}

/// What [`FolderSync::verify_tree_deltas`] found besides a refusal.
#[derive(Debug, Clone, Default)]
struct TreeCheck {
    /// A tree on the way is beyond the limits of a folder.
    limit: bool,
    /// File objects each checked head dropped, for "Undo a device" ([`TimelineRec`]).
    drops: BTreeMap<CommitId, DropCount>,
}

/// The reachable objects of `root`, from `cache` or the objects (see [`Readable`]).
fn readable_set(
    root: &ObjectId,
    crypto: &FolderCrypto,
    cx: &mut Ctx<'_>,
    cache: &mut BTreeMap<ObjectId, Readable>,
) -> Result<Readable, SyncError> {
    if let Some(known) = cache.get(root) {
        return Ok(known.clone());
    }
    let read = match codec::reachable_typed(root, crypto, cx.store, cx.server) {
        Ok(set) => Readable::Set(set),
        Err(CodecError::Limit) => Readable::Limit,
        Err(CodecError::Net(NetError::Server(body))) if body.code == ErrorCode::NotFound => {
            Readable::Gone
        }
        Err(e) => return Err(e.into()),
    };
    cache.insert(*root, read.clone());
    Ok(read)
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
