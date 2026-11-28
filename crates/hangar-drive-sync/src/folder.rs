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

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use hangar_drive_crypto::commit::{
    ChainEntry, Commit, CommitContent, DeltaDigest, FolderView, RemovedHead, SignedCommit,
};
use hangar_drive_crypto::epoch::BarrierPermit;
use hangar_drive_crypto::Entropy;
use hangar_drive_protocol::api::{CommitRequest, CommitUpload, ErrorCode, ReferenceDelta};
use hangar_drive_protocol::ids::{
    Blob, CommitId, DeviceId, FolderId, Generation, ItemId, ObjectId,
};
use hangar_drive_protocol::name::{is_ignored, RESERVED_ROOT_DIR};
use hangar_drive_protocol::object::ObjectType;
use serde::{Deserialize, Serialize};

mod pull;

pub use pull::MAX_PULL_COMMITS;
pub(crate) use pull::{PullMode, PullVerdict, Pulled};

use crate::account::Account;
use crate::apply::{apply, ActionError, DiskActions};
use crate::chunker::{hash_many, ChunkError, HashJob, PartialHash};
use crate::codec::{self, CodecError, Encoded, FolderCrypto};
use crate::download::{FetchLane, Fetched, DOWNLOAD_WORKERS, FETCH_WINDOW_BYTES};
use crate::error::SyncError;
use crate::interrupt::Interrupt;
use crate::merge::{ConflictCopy, ItemIds, MergeLabels};
use crate::names::{date_label, LabelWords};
use crate::planner::{hold_deletes, plan, Plan, PlanInput, MASS_DELETE_THRESHOLD};
use crate::ports::{
    random_item_id, ChunkList, Clock, EntryType, Expect, FileSystem, FsError, Keychain, NetError,
    PartialFile, SaveBatch, ServerApi, Stat, Store,
};
use crate::tree::{ContentKey, FileVersion, NameIndex, Node, NodeKind, Tree, ROOT};
use crate::upload::{
    draw_nonce, Done, Lane, Next, Outcome, Payload, Sealers, Work, UPLOAD_WORKERS,
};
use bytes::Bytes;

/// Name of the root marker inside the reserved directory.
pub const MARKER_NAME: &str = "marker";
/// Name of the park directory inside the reserved directory.
pub const PARK_DIR: &str = "park";
/// The window over which the mass delete guard adds up this device's local deletes (security
/// review, LOW 1): a guard per round let a slow delete through, 50 files every 10 seconds
/// never reached 100 in one round.
pub const DELETE_WINDOW_MS: i64 = 10 * 60 * 1000;
/// The long window of the mass delete guards (security review M3): deletes since the last
/// decision add up over a day, so 99 deletes every 10 minutes do not slip through, and the share
/// of the folder is taken of the fewest files it held over the day, so files added just before a
/// delete do not dilute it.
pub const LONG_DELETE_WINDOW_MS: i64 = 24 * 60 * 60 * 1000;
/// The steps in which the folder's file count is kept for the long window: the fewest per hour.
const FILE_COUNT_STEP_MS: i64 = 60 * 60 * 1000;
/// The most files remembered as having just arrived (deleting them again is ordinary work, not
/// a mass delete); past it the oldest are forgotten and then count like any other file, which
/// only makes the guard ask sooner.
pub const FRESH_FILES_CAP: usize = 20_000;
/// How long the cache of the local index keeps the nodes of the history
/// ([`FolderSync::prune_cache`]): the server's default retention of 30 days.
pub const HISTORY_CACHE_MS: i64 = 30 * 24 * 60 * 60 * 1000;
/// How soon a folder stopped as too large tries again after a change in it.
const TOO_LARGE_RETRY_MS: i64 = 60 * 1000;
/// Bytes an upload sends before it commits the files that are complete so far (an intermediate
/// commit, [`FolderSettings::stage_bytes`]): other devices see a large first upload grow, and the
/// server's collection, which deletes uploads no commit names after a day
/// (`server/src/service/retention.rs`), never takes what went up before.
pub const STAGE_BYTES: u64 = 256 * 1024 * 1024;
/// Objects an upload sends before an intermediate commit, for many small files
/// ([`FolderSettings::stage_objects`]).
pub const STAGE_OBJECTS: usize = 8192;
/// The least time between two intermediate commits of a folder
/// ([`FolderSettings::stage_interval_ms`]), well within the server's limit of commits per device
/// and minute.
pub const STAGE_INTERVAL_MS: i64 = 30_000;
/// The least time the upload phase of a round gets once it starts, also when the folder's share
/// of the pass is small (several folders share it) or its scan spent it.
const UPLOAD_FLOOR_MS: i64 = 250;
/// The least time between two publishes of the engine's rounds of one folder
/// ([`FolderSettings::publish_interval_ms`]).
pub const PUBLISH_INTERVAL_MS: i64 = 5_000;
/// Commits a folder's rounds may make at once before [`PUBLISH_INTERVAL_MS`] paces them.
pub const PUBLISH_BURST: u32 = 3;
/// Upload jobs a folder keeps across rounds: the publish's own and those of its stages.
const MAX_UPLOAD_JOBS: usize = 4;

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
    /// The most commits one pull reads ([`MAX_PULL_COMMITS`]; smaller in tests).
    pub max_pull_commits: usize,
    /// The work budget of one round in milliseconds of [`Clock`] time, or `None` for a round
    /// that runs to its end. Hashing, uploads and downloads stop at a clean point once it is
    /// spent and the next round carries on ([`RoundReport::more`]), so the engine thread stays
    /// responsive during a large first upload. The engine sets it; direct callers that expect
    /// a whole round (tests, restores) leave it unset.
    pub work_budget_ms: Option<i64>,
    /// Bytes an upload sends before it commits the complete files so far ([`STAGE_BYTES`];
    /// smaller in tests).
    pub stage_bytes: u64,
    /// Objects an upload sends before it commits the complete files so far
    /// ([`STAGE_OBJECTS`]).
    pub stage_objects: usize,
    /// The least time between two intermediate commits ([`STAGE_INTERVAL_MS`]; 0 in tests).
    pub stage_interval_ms: i64,
    /// How often a round of this folder commits at most, after a burst of
    /// [`PUBLISH_BURST`] commits: one more per interval ([`PUBLISH_INTERVAL_MS`] in the engine,
    /// 0 for direct callers: no limit). A file rewritten every second (a log, a database)
    /// otherwise made a commit per change and ran into the server's commit limit per device,
    /// whose wait then held the engine thread for every folder (security review of the client
    /// changes, MEDIUM 1). Only the commit waits; the upload goes on. The first changes after a
    /// quiet spell go out at once; the person's actions (restores, undo) are not held.
    pub publish_interval_ms: i64,
    /// Commits the next round may send, the device's share of the server's limit left over all
    /// folders, intermediate and side commits included; `None`: no limit. The engine sets it
    /// per round.
    pub commit_allowance: Option<u32>,
    /// Pull the folder's commits only when asked ([`FolderSync::request_pull`],
    /// [`FolderSync::note_remote_head`]) instead of in every round. The engine sets it and asks
    /// when the change feed names a new head of the folder, at start, after a lost connection or
    /// an error, and every hour; direct callers of [`FolderSync::round`] pull in every round.
    pub pull_on_demand: bool,
    /// Objects one upload sends at once ([`UPLOAD_WORKERS`]; at most
    /// [`crate::upload::MAX_UPLOAD_WORKERS`], 1 sends one at a time on the round's thread).
    pub upload_workers: usize,
    /// Commands waiting for the engine thread ([`Interrupt`]): a round with a work budget stops
    /// at its next clean point once one waits, as at the end of its budget. A round without a
    /// budget never looks at it.
    pub interrupt: Interrupt,
    /// Where the round reports the bytes it moved, for live progress in the window
    /// ([`crate::progress`]); the engine sets it.
    pub progress: crate::progress::Progress,
    /// The bytes the download lanes of every folder hold ahead together
    /// ([`crate::download::FETCH_ACCOUNT_BYTES`]); the engine's folders share it.
    pub fetch_budget: crate::download::FetchBudget,
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
            max_pull_commits: MAX_PULL_COMMITS,
            work_budget_ms: None,
            stage_bytes: STAGE_BYTES,
            stage_objects: STAGE_OBJECTS,
            stage_interval_ms: STAGE_INTERVAL_MS,
            publish_interval_ms: 0,
            commit_allowance: None,
            pull_on_demand: false,
            upload_workers: UPLOAD_WORKERS,
            interrupt: Interrupt::default(),
            progress: crate::progress::Progress::default(),
            fetch_budget: crate::download::FetchBudget::default(),
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
    /// Held deletes the person let go: exactly these pass the mass delete guard, not deletes
    /// that came later (security review, LOW 1). Each leaves the set once it went out.
    #[serde(default)]
    pub approved: BTreeSet<ItemId>,
    /// Local deletes this device propagated, as (time, count), for the guard's window of
    /// [`DELETE_WINDOW_MS`]; deletes the person approved are not counted.
    #[serde(default)]
    pub recent_deletes: Vec<(i64, u64)>,
    /// Local file deletes this device propagated since the person's last decision, as (time,
    /// count), for the long window [`LONG_DELETE_WINDOW_MS`]; approved deletes and files that
    /// only just arrived are not counted.
    #[serde(default)]
    pub long_deletes: Vec<(i64, u64)>,
    /// The fewest files the synced tree held per hour, as (hour start, count), within
    /// [`LONG_DELETE_WINDOW_MS`]: the size of the folder the guards take a share of. Kept only
    /// while the folder was fully synced once (a first download is no baseline).
    #[serde(default)]
    pub file_minimums: Vec<(i64, u64)>,
    /// Files that came into the synced tree within [`LONG_DELETE_WINDOW_MS`] of a folder that
    /// was fully synced already, with the time; at most [`FRESH_FILES_CAP`].
    #[serde(default)]
    pub fresh_files: BTreeMap<ItemId, i64>,
    /// Deletes another device made that this device keeps on its disk and in its synced tree
    /// until the person decides (ADR 0001, amendment "incoming mass deletes"): files and the
    /// directories deleted with them.
    #[serde(default)]
    pub incoming_held: BTreeSet<ItemId>,
    /// Grows by one whenever [`Self::incoming_held`] gains items, so an approval names the
    /// state the person saw ([`FolderSync::approve_incoming`]).
    #[serde(default)]
    pub incoming_revision: u64,
    /// The devices that wrote the commits the held deletes came with, from the verified
    /// timeline; the question names the device when it is one.
    #[serde(default)]
    pub incoming_devices: BTreeSet<DeviceId>,
    /// Incoming deletes the person let go, or that this device's own action made: exactly these
    /// pass the guard. Each leaves the set once it is no longer an incoming delete.
    #[serde(default)]
    pub incoming_approved: BTreeSet<ItemId>,
    /// Incoming file deletes this device carried out since the person's last decision, as
    /// (time, count), for the long window [`LONG_DELETE_WINDOW_MS`] (which holds the short one);
    /// approved ones and files that only just arrived are not counted.
    #[serde(default)]
    pub recent_incoming: Vec<(i64, u64)>,
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
    /// The round stopped at its work budget ([`FolderSettings::work_budget_ms`]) or at the
    /// download bound of a round with work left: the next round should follow right away.
    pub more: bool,
    /// Commit calls the round sent (intermediate, side and repair commits included), for the
    /// engine's commit budget of the device.
    pub commits: u32,
    /// The round held its publish back until this time ([`FolderSettings::publish_interval_ms`],
    /// [`FolderSettings::commit_allowance`]); the engine wakes for it.
    pub held_until: Option<i64>,
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

/// New item IDs from the generator. The merge needs an ID whenever it asks, so a failing
/// generator still gets one, distinct within the run, and the failure is kept: the caller
/// refuses the result ([`EntropyIds::check`]) instead of publishing it. Before, every ID after a
/// failure was the same constant, so two new items could share one ID (security review, info).
struct EntropyIds<'a> {
    entropy: &'a mut dyn Entropy,
    failed: Option<hangar_drive_crypto::EntropyError>,
    fallback: u64,
}

impl<'a> EntropyIds<'a> {
    fn new(entropy: &'a mut dyn Entropy) -> Self {
        Self {
            entropy,
            failed: None,
            fallback: 0,
        }
    }

    /// The generator's failure, if it failed during the run.
    fn check(self) -> Result<(), SyncError> {
        match self.failed {
            Some(e) => Err(e.into()),
            None => Ok(()),
        }
    }
}

impl ItemIds for EntropyIds<'_> {
    fn new_item_id(&mut self) -> ItemId {
        match random_item_id(self.entropy) {
            Ok(id) => id,
            Err(e) => {
                self.failed.get_or_insert(e);
                self.fallback += 1;
                let mut bytes = [0xff; 16];
                bytes[8..].copy_from_slice(&self.fallback.to_be_bytes());
                ItemId::from_bytes(bytes)
            }
        }
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
    /// Whether the local tree shows the disk: after a scan of this run, or loaded non-empty from
    /// the index. A new folder's empty tree says nothing about its size yet. Not stored.
    local_known: bool,
    /// The length of the timeline when the disk was last brought to the plan: the commits after
    /// it are the ones whose deletes the next plan sees, for naming the writing device. Not
    /// stored: after a restart the held deletes keep the devices they were stored with.
    applied_timeline: usize,
    /// The work budget of the running round ([`FolderSettings::work_budget_ms`]); `None`
    /// outside a round and for a round without a budget. Not stored.
    budget: Option<Budget>,
    /// Bytes the current upload still has to send, while one is under way or stopped at the
    /// budget; the window shows them as what is left. Not stored.
    upload_left: Option<u64>,
    /// New files a scan left unhashed when the budget was spent, with their sizes; the next
    /// scan lists their directories again, also in a partial scan, and the snapshot counts
    /// them as files still to upload. Not stored: a restart scans in full.
    deferred: BTreeMap<Vec<String>, u64>,
    /// Known files a scan left unhashed when the budget was spent: they keep their known
    /// version, and the next scan lists their directories again. Not stored.
    recheck: BTreeSet<Vec<String>>,
    /// Large files whose hashing stopped part way ([`ChunkError::Paused`]), by path: the next
    /// scan goes on from there while the file is unchanged. Not stored.
    partial_hashes: BTreeMap<Vec<String>, PartialHash>,
    /// Uploads under way, kept across rounds ([`UploadJob`]), newest last. Not stored.
    jobs: Vec<UploadJob>,
    /// The download lane of a round that stopped with chunks in flight or fetched and not
    /// written yet ([`crate::download`]); the next round takes them from it. Not stored.
    fetch: Option<FetchLane>,
    /// Downloads in parts under way: chunks in the part file of each content
    /// ([`FileSystem::partial_write`]). Not stored: the part files go when the root is opened.
    partial_downloads: BTreeMap<ContentKey, PartialDownload>,
    /// Objects the server held or received during the uploads under way: a new upload (the plan
    /// changed while the last one ran) asks only for the others, and asks for every candidate
    /// again before its commit. Cleared with every finished publish. Not stored.
    known_present: BTreeSet<ObjectId>,
    /// A publish the budget cut, continued by the next round while nothing it was planned from
    /// changed ([`PendingPublish`]). Not stored: a restart plans and asks again.
    pending: Option<PendingPublish>,
    /// Counts the rounds and the person's publishes, so an upload knows whether its last ask of
    /// the server was in the running one. Not stored.
    round_seq: u64,
    /// When the upload phase of the running round ends ([`FolderSync::upload_deadline`]).
    upload_until: Option<i64>,
    /// When this device last made an intermediate commit of a large upload. Not stored.
    last_stage_ms: Option<i64>,
    /// The next round pulls the server's commits (with [`FolderSettings::pull_on_demand`]). Set
    /// at start, by the engine and after a failed round. Not stored.
    pull_due: bool,
    /// The last round ended with disk, server and synced tree in agreement, and nothing was
    /// stored outside a round since; [`FolderSync::wants_round`] skips such a folder. Not stored.
    quiet: bool,
    /// A round runs: its own saves are no change by the person. Not stored.
    in_round: bool,
    /// The metadata as last written, so a save without a change writes nothing. Not stored.
    saved_meta: Option<Vec<u8>>,
    /// The last scan hashed at least one file: a round that leaves remote items alone for files
    /// waiting for their hash asks for the next round at once only then, so a scan that made no
    /// progress does not drive the loop without its pause (security review of the client
    /// changes, LOW 3). Not stored.
    hashed_in_scan: bool,
    /// The commits a round of this folder may still make at once, and when the bucket was last
    /// filled ([`FolderSettings::publish_interval_ms`]). Not stored.
    publish_tokens: u32,
    publish_filled_ms: Option<i64>,
    /// A held publish waits until then; the folder's rounds wait as well, unless a pull is due.
    /// Not stored.
    hold_until: Option<i64>,
    /// The running round holds publishes by the interval and the allowance (a round of the
    /// loop, not one the person's undo runs). Not stored.
    gated: bool,
    /// Commits the running round may still send (`None`: no limit), and the ones it sent.
    commits_left: Option<u32>,
    commits_sent: u32,
    /// The commit calls of the last round, also of one that failed ([`Self::round_commits`]).
    round_commits: u32,
    /// The running round stopped at its budget somewhere ([`RoundReport::more`]). Not stored.
    cut: bool,
}

/// The objects one upload still has to send, kept across rounds, so a round cut at its budget
/// goes on where it stopped instead of asking the server about every object again (finding A of
/// the second performance review). Not stored.
#[derive(Debug)]
struct UploadJob {
    /// The root of the encoded tree the upload is for.
    root: ObjectId,
    /// The writable generation its chunks are sealed under.
    generation: u32,
    /// A digest of the candidates it was made for.
    candidates: [u8; 32],
    /// Objects still to send, in read order: chunks the disk cannot produce first (they end
    /// the upload at once), then chunks by path and chunk index, then sealed nodes and
    /// manifests.
    queue: VecDeque<ObjectId>,
    /// The bytes of each queued object.
    sizes: BTreeMap<ObjectId, u64>,
    /// Where each queued chunk lives on disk: path, chunk index and content.
    sources: BTreeMap<ObjectId, (Vec<String>, u64, ContentKey)>,
    /// Bytes still to send.
    left: u64,
    /// Objects sent in round `sent_round`: the next round asks whether the server kept them.
    sent: Vec<ObjectId>,
    sent_round: u64,
    /// Bytes and objects sent since the last intermediate commit.
    since_stage: (u64, usize),
    /// The round whose ask covered every candidate; in any other round the upload asks again
    /// before it reports done, since the server deletes uploads no commit names after a day.
    asked_round: u64,
    /// The server lost objects this upload sent (a hostile or broken server): its cuts do not
    /// ask for an immediate next round, so the loop keeps its pause (security review of the
    /// budget, L2).
    stalled: bool,
    /// The lane of objects a round left in flight when it ended (at its budget or for a
    /// waiting command), so the next round books their results; `None` once nothing is in
    /// flight, which ends its workers.
    flight: Option<Lane>,
}

/// How a staged upload stopped.
enum UploadStep {
    /// Every candidate is on the server.
    Done,
    /// Enough went up for an intermediate commit; these objects are still queued.
    StageDue(BTreeSet<ObjectId>),
}

/// Why an upload loop stops dispatching ([`FolderSync::dispatch`]).
enum Stop {
    /// Every candidate is on the server.
    Done,
    /// Enough went up for an intermediate commit.
    Stage,
    /// The round's upload deadline passed.
    Yield,
    /// A chunk is no longer what the disk holds.
    Changed,
    /// A failure to report.
    Error(PublishFailure),
}

impl Stop {
    /// Sets `stop` to `next` unless it already holds a failure: a failure of an object still in
    /// flight replaces an ordinary end, and the first failure is the one reported.
    fn halt(stop: &mut Option<Stop>, next: Stop) {
        if !matches!(stop, Some(Stop::Changed | Stop::Error(_))) {
            *stop = Some(next);
        }
    }
}

/// A publish whose upload the budget cut: the plan and its encoding, reused by the next round
/// while the key matches, so that round goes on uploading without planning and sealing again.
#[derive(Debug)]
struct PendingPublish {
    key: PendingKey,
    plan: Plan,
    encoded: Option<Encoded>,
}

/// What a pending publish was planned from: the three trees (their editions change with every
/// insert and remove), the server's head and root, and the writable generation. Anything else a
/// plan reads is changed by the person's actions, which store outside a round and drop the
/// pending publish ([`FolderSync::save`]).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingKey {
    trees: (u64, u64, u64),
    frontier: Option<CommitId>,
    remote_root: Option<ObjectId>,
    generation: Option<u32>,
}

/// What the window's numbers of a folder depend on ([`FolderSync::summary_key`]): equal keys
/// give equal counts and sizes, so the engine keeps them until the key changes instead of
/// walking every tree for each snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SummaryKey {
    trees: (u64, u64, u64),
    local_known: bool,
    state: FolderState,
    deferred: (u64, u64),
    upload_left: Option<u64>,
    cannot_sync: Vec<ItemId>,
}

/// The work budget of one round, in [`Clock`] time.
#[derive(Debug, Clone, Copy)]
struct Budget {
    /// When the round's budget ends.
    until: i64,
    /// The whole budget of the round.
    slice: i64,
}

impl Budget {
    /// When a phase that starts at `now` has to stop: at the end of the round's budget, but
    /// never before a quarter of the budget has passed in the phase itself, so a round whose
    /// scan and plan already took the budget still moves the transfer on instead of doing one
    /// object per round.
    fn phase_until(self, now: i64) -> i64 {
        self.until.max(now.saturating_add(self.slice / 4))
    }
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

/// The bytes and files of one hash batch: the scan checks the round's work budget between
/// batches ([`FolderSettings::work_budget_ms`]). 64 MiB take well under a second on a usual
/// disk; a single larger file is a batch of its own and is not split.
const HASH_BATCH_BYTES: u64 = 64 * 1024 * 1024;
const HASH_BATCH_FILES: usize = 32;

/// How long an upload waits for an answer of the workers before it looks at its deadline and at
/// waiting commands again ([`FolderSettings::interrupt`]): a command is taken within about this
/// long even while every upload hangs on a slow server.
const UPLOAD_WAIT_SLICE: std::time::Duration = std::time::Duration::from_millis(50);

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
    /// The clock, for the round's work budget.
    clock: &'a dyn Clock,
    /// When this apply run stops starting new downloads (the round's work budget).
    until: Option<i64>,
    /// Commands waiting for the engine thread: with a budget, no new download starts then.
    interrupt: &'a Interrupt,
    /// A download was left for the next round, by the byte bound or the budget.
    cut: bool,
    /// Where the chunks come from ([`crate::download`]).
    lane: &'a mut FetchLane,
    /// Downloads in parts under way: chunks in the part file of each content.
    partials: &'a mut BTreeMap<ContentKey, PartialDownload>,
    /// Where written bytes are reported, for live progress.
    progress: &'a crate::progress::Progress,
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

    /// Whether the round's budget is spent or a command waits ([`FolderSync::spent`]).
    fn spent(&self) -> bool {
        self.until
            .is_some_and(|u| self.clock.now_ms() >= u || self.interrupt.pending())
    }

    /// Chunk `id` of `expected` plaintext bytes, fetched through the lane and opened. With
    /// `may_stop`, the wait for it gives way to the budget and to waiting commands: the fetch
    /// goes on in the lane and the file waits for the next round ([`Self::cut`]).
    fn fetch_plain(
        &mut self,
        id: &ObjectId,
        expected: u64,
        may_stop: bool,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, ActionError> {
        let (until, clock, interrupt) = (self.until, self.clock, self.interrupt);
        let stop =
            move || may_stop && until.is_some_and(|u| clock.now_ms() >= u || interrupt.pending());
        let blob = match self.lane.take(id, expected, &mut *self.server, &stop) {
            Fetched::Blob(blob) => blob,
            Fetched::Stopped => {
                self.cut = true;
                return Err(ActionError::Unavailable);
            }
            Fetched::Failed => return Err(ActionError::Unavailable),
        };
        self.downloaded = self.downloaded.saturating_add(blob.len() as u64);
        let plain = self
            .crypto
            .open(id, ObjectType::Chunk, &blob)
            .map_err(|_| ActionError::Unavailable)?;
        if plain.len() as u64 != expected {
            return Err(ActionError::Unavailable);
        }
        Ok(plain)
    }

    /// Keeps `state` as the download in parts of `content`, giving up the oldest other one
    /// beyond [`MAX_PARTIAL_DOWNLOADS`] (its part file goes as well).
    fn note_partial(&mut self, content: ContentKey, state: PartialDownload) {
        self.partials.insert(content, state);
        while self.partials.len() > MAX_PARTIAL_DOWNLOADS {
            let Some(other) = self.partials.keys().find(|k| **k != content).copied() else {
                break;
            };
            if let Some(gone) = self.partials.remove(&other) {
                let _ = self.fs.partial_remove(&gone.part.name);
            }
        }
    }

    /// Gives up the download in parts of `content`: its part file goes, the next attempt starts
    /// from the first chunk.
    fn drop_partial(&mut self, content: &ContentKey, part: &PartialFile) {
        self.partials.remove(content);
        let _ = self.fs.partial_remove(&part.name);
    }

    /// Writes a file of several chunks into its part file from the chunk its state reached on,
    /// chunk by chunk, and puts it in place once whole. It stops between two chunks once the
    /// budget is spent or a command waits, keeping what is written for the next round. Before
    /// the file lands, its whole content is read back through the handle it lands with and
    /// compared with the digests of what was written (security review M1): a part file that
    /// another program or the disk changed meanwhile is dropped and the download starts over,
    /// and nothing lands. The file itself appears only whole, by one rename, as with
    /// [`FileSystem::write_atomic`].
    fn write_in_parts(
        &mut self,
        item: &ItemId,
        path: &[String],
        version: &FileVersion,
        expect: Option<&FileVersion>,
        chunks: &[ObjectId],
    ) -> Result<(), ActionError> {
        let size = version.size;
        let content = version.content;
        let count = chunks.len() as u64;
        let mut state = self
            .partials
            .remove(&content)
            .filter(|s| s.chunks <= count && s.digests.len() as u64 == s.chunks)
            .unwrap_or_else(|| PartialDownload::new(&content));
        let done = state.chunks;
        // How often each chunk is still to come, so a repeated one is kept until its last use.
        let mut left: BTreeMap<ObjectId, u64> = BTreeMap::new();
        for id in chunks
            .iter()
            .skip(usize::try_from(done).unwrap_or(usize::MAX))
        {
            *left.entry(*id).or_default() += 1;
        }
        let mut cache: BTreeMap<ObjectId, zeroize::Zeroizing<Vec<u8>>> = BTreeMap::new();
        let mut cached = 0u64;
        for index in done..count {
            if index > done && self.spent() {
                self.note_partial(content, state);
                self.cut = true;
                return Err(ActionError::Unavailable);
            }
            let Some(id) = chunks.get(usize::try_from(index).unwrap_or(usize::MAX)) else {
                return Err(ActionError::Unavailable);
            };
            let remaining = left.get_mut(id).map_or(0, |n| {
                *n = n.saturating_sub(1);
                *n
            });
            let plain = match cache.remove(id) {
                Some(p) => {
                    cached = cached.saturating_sub(p.len() as u64);
                    p
                }
                None => match self.fetch_plain(id, chunk_len(size, index), true) {
                    Ok(p) => p,
                    Err(e) => {
                        self.note_partial(content, state);
                        return Err(e);
                    }
                },
            };
            let offset = index.saturating_mul(hangar_drive_protocol::object::CHUNK_SIZE);
            match self.fs.partial_write(&mut state.part, offset, &plain) {
                Ok(()) => {}
                // The part file is not what was written (it went missing or was replaced):
                // from the start.
                Err(FsError::Changed) => {
                    self.drop_partial(&content, &state.part);
                    return Err(ActionError::Unavailable);
                }
                Err(e) => {
                    self.note_partial(content, state);
                    return Err(action_error(e));
                }
            }
            state.digests.push(digest(&plain));
            state.chunks = index + 1;
            self.progress.moved(plain.len() as u64);
            if remaining > 0 && cached.saturating_add(plain.len() as u64) <= CHUNK_CACHE_BYTES {
                cached += plain.len() as u64;
                cache.insert(*id, plain);
            }
        }
        // The check reads the whole file once more. Only a waiting command stops it (not the
        // round's budget, which a large file would always outlast); it runs again in full next
        // time, since the file may change while nobody looks.
        let interrupt = self.interrupt;
        let budgeted = self.until.is_some();
        let mut stopped = false;
        let mut mismatch = false;
        let known = self.file_ids.get(item).copied();
        let result = {
            let digests = &state.digests;
            let mut check = |reader: &mut dyn std::io::Read| -> Result<(), FsError> {
                let mut buf = vec![0u8; hangar_drive_protocol::object::CHUNK_SIZE as usize];
                for (index, want) in digests.iter().enumerate() {
                    if budgeted && index > 0 && interrupt.pending() {
                        stopped = true;
                        return Err(FsError::Io("the check gave way to a command".into()));
                    }
                    let len = usize::try_from(chunk_len(size, index as u64)).unwrap_or(0);
                    let part = buf.get_mut(..len).ok_or(FsError::Changed)?;
                    if reader.read_exact(part).is_err() || digest(part) != *want {
                        mismatch = true;
                        return Err(FsError::Changed);
                    }
                }
                let mut extra = [0u8; 1];
                if digests.len() as u64 != count || reader.read(&mut extra).unwrap_or(1) != 0 {
                    mismatch = true;
                    return Err(FsError::Changed);
                }
                Ok(())
            };
            self.fs.partial_finish(
                &state.part,
                path,
                version.mtime_ms,
                version.executable,
                expect.map(|e| expect_of(e, known)),
                &mut check,
            )
        };
        match result {
            Ok(stat) => {
                if let Some(id) = stat.file_id {
                    self.file_ids.insert(*item, id);
                    self.dirty.insert(*item, Some(id));
                }
                Ok(())
            }
            Err(_) if stopped => {
                self.note_partial(content, state);
                self.cut = true;
                Err(ActionError::Unavailable)
            }
            // Not what was written, gone, or not the file created then: nothing lands, the
            // download starts over.
            Err(_) if mismatch => {
                self.drop_partial(&content, &state.part);
                Err(ActionError::Unavailable)
            }
            Err(FsError::Io(e)) => {
                self.drop_partial(&content, &state.part);
                Err(ActionError::Io(e))
            }
            // The target changed or is locked: the whole content stays in the part file, and
            // the next attempt checks it again and puts it in place.
            Err(e) => {
                self.note_partial(content, state);
                Err(action_error(e))
            }
        }
    }
}

/// A download in parts under way ([`FileSystem::partial_write`]): its part file, the chunks
/// written into it and the digest of each, which the finish checks the whole file against.
#[derive(Debug, Clone)]
struct PartialDownload {
    part: PartialFile,
    chunks: u64,
    digests: Vec<[u8; 32]>,
}

impl PartialDownload {
    fn new(content: &ContentKey) -> Self {
        Self {
            part: PartialFile {
                name: partial_name(content),
                file_id: None,
            },
            chunks: 0,
            digests: Vec::new(),
        }
    }
}

/// SHA-256 of a chunk's plaintext as it went into a part file.
fn digest(plain: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    sha2::Sha256::digest(plain).into()
}

/// The plaintext length of chunk `index` of a file of `size` bytes.
fn chunk_len(size: u64, index: u64) -> u64 {
    size.saturating_sub(index.saturating_mul(hangar_drive_protocol::object::CHUNK_SIZE))
        .min(hangar_drive_protocol::object::CHUNK_SIZE)
}

/// The name of the part file of a download in parts: its content key in hex.
fn partial_name(content: &ContentKey) -> String {
    content.0.iter().map(|b| format!("{b:02x}")).collect()
}

/// Downloads in parts a folder keeps at once; the executor writes one file at a time, so one
/// more covers a file it went past and comes back to.
const MAX_PARTIAL_DOWNLOADS: usize = 2;

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
        // The run was cut (budget, a waiting command): no other download starts in it, so the
        // files still to come do not each wait for their content.
        if self.cut {
            return Err(ActionError::Unavailable);
        }
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
        let count = list.chunks.len() as u64;
        // A file of more than one chunk arrives in parts where the root keeps them, so a large
        // file goes on where it stopped instead of holding the round for its whole length.
        let in_parts = count > 1 && self.fs.partial_supported();
        let done = if in_parts {
            self.partials
                .get(&version.content)
                .map_or(0, |s| s.chunks)
                .min(count)
        } else {
            0
        };
        let written = done.saturating_mul(hangar_drive_protocol::object::CHUNK_SIZE);
        // Checked before anything is fetched: a manifest may name the same chunk up to its
        // limit, so the file can be far larger than what the server stores and the quota
        // counts. Without room the file waits (the caller backs off) and nothing is written.
        if !room_for(
            size.saturating_sub(written),
            self.fs.free_bytes(),
            self.fs.volume_bytes(),
        ) {
            return Err(ActionError::DiskFull);
        }
        // At least one file per run, so every round moves the download on.
        let over_bytes = self.downloaded.saturating_add(size) > ROUND_DOWNLOAD_BYTES;
        if self.downloaded > 0 && (over_bytes || self.spent()) {
            self.cut = true;
            return Err(ActionError::Unavailable);
        }
        if in_parts {
            return self.write_in_parts(item, path, version, expect, &list.chunks);
        }
        // A file of one chunk: fetched first, so the wait for it gives way to the budget and to
        // waiting commands, then written in one go.
        let single = match list.chunks.first() {
            Some(id) if count == 1 => Some(self.fetch_plain(id, size, true)?),
            _ => None,
        };
        // How often each chunk is still to come, so a repeated one is kept until its last use.
        let mut left: BTreeMap<ObjectId, u64> = BTreeMap::new();
        for id in &list.chunks {
            *left.entry(*id).or_default() += 1;
        }
        let mut failure: Option<ActionError> = None;
        let known = self.file_ids.get(item).copied();
        let fs = self.fs;
        let mut fill = |out: &mut dyn std::io::Write| -> Result<(), FsError> {
            if let Some(plain) = &single {
                out.write_all(plain)
                    .map_err(|e| FsError::Io(e.to_string()))?;
                return Ok(());
            }
            // Several chunks on a root without parts: the whole file within this write.
            let mut written = 0u64;
            let mut cache: BTreeMap<ObjectId, zeroize::Zeroizing<Vec<u8>>> = BTreeMap::new();
            let mut cached = 0u64;
            for (index, id) in list.chunks.iter().enumerate() {
                let remaining = left.get_mut(id).map_or(0, |n| {
                    *n = n.saturating_sub(1);
                    *n
                });
                let expected = chunk_len(size, index as u64);
                let plain = match cache.remove(id) {
                    Some(p) => {
                        cached = cached.saturating_sub(p.len() as u64);
                        p
                    }
                    None => match self.fetch_plain(id, expected, false) {
                        Ok(p) => p,
                        Err(e) => {
                            failure = Some(e);
                            return Err(FsError::Io("content unavailable".into()));
                        }
                    },
                };
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
        let result = fs.write_atomic(
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
                if single.is_some() {
                    self.progress.moved(size);
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
    /// The round's work budget is spent part way through an upload. Nothing was committed;
    /// what went up stays on the server (uploads without a commit are kept for a day) and the
    /// next round's missing-objects query skips it.
    Yielded,
    /// Everything is uploaded, but the commit waits ([`FolderSettings::publish_interval_ms`],
    /// [`FolderSettings::commit_allowance`]) until [`FolderSync::hold_until`].
    Held,
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
            local_known: false,
            applied_timeline: 0,
            budget: None,
            upload_left: None,
            deferred: BTreeMap::new(),
            partial_hashes: BTreeMap::new(),
            recheck: BTreeSet::new(),
            jobs: Vec::new(),
            fetch: None,
            partial_downloads: BTreeMap::new(),
            known_present: BTreeSet::new(),
            pending: None,
            round_seq: 0,
            upload_until: None,
            last_stage_ms: None,
            pull_due: true,
            quiet: false,
            in_round: false,
            saved_meta: None,
            hashed_in_scan: false,
            publish_tokens: PUBLISH_BURST,
            publish_filled_ms: None,
            hold_until: None,
            gated: false,
            commits_left: None,
            commits_sent: 0,
            round_commits: 0,
            cut: false,
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
        let local = Tree::from_nodes(stored.local);
        let saved_meta = Some(stored.meta.clone());
        Ok(Some(Self {
            folder,
            remote: Tree::from_nodes(stored.remote),
            synced: Tree::from_nodes(stored.synced),
            file_ids: stored.file_ids.into_iter().collect(),
            file_ids_dirty: BTreeMap::new(),
            view,
            scan_scope: ScanScope::Full,
            too_large_at: None,
            last_action: None,
            rehash: BTreeSet::new(),
            local_known: !local.is_empty(),
            local,
            applied_timeline: meta.timeline.len(),
            meta,
            budget: None,
            upload_left: None,
            deferred: BTreeMap::new(),
            partial_hashes: BTreeMap::new(),
            recheck: BTreeSet::new(),
            jobs: Vec::new(),
            fetch: None,
            partial_downloads: BTreeMap::new(),
            known_present: BTreeSet::new(),
            pending: None,
            round_seq: 0,
            upload_until: None,
            last_stage_ms: None,
            pull_due: true,
            quiet: false,
            in_round: false,
            saved_meta,
            hashed_in_scan: false,
            publish_tokens: PUBLISH_BURST,
            publish_filled_ms: None,
            hold_until: None,
            gated: false,
            commits_left: None,
            commits_sent: 0,
            round_commits: 0,
            cut: false,
        }))
    }

    fn save(&mut self, store: &mut dyn Store) -> Result<(), SyncError> {
        self.meta.chain = self.view.chain().iter().map(ChainRec::from).collect();
        self.meta.marks = self.view.marks().iter().map(|(k, v)| (*k, *v)).collect();
        self.meta.discarded = self.view.discarded().iter().copied().collect();
        let meta = serde_json::to_vec(&self.meta).map_err(|e| SyncError::Corrupt(e.to_string()))?;
        let mut batch = SaveBatch {
            remote: self.remote.take_delta(),
            synced: self.synced.take_delta(),
            local: self.local.take_delta(),
            file_ids: std::mem::take(&mut self.file_ids_dirty)
                .into_iter()
                .collect(),
            meta: None,
        };
        let meta_changed = self.saved_meta.as_deref() != Some(meta.as_slice());
        let rows = [&batch.remote, &batch.synced, &batch.local]
            .iter()
            .any(|d| !d.upsert.is_empty() || !d.remove.is_empty())
            || !batch.file_ids.is_empty();
        // A round saves after every step; most of them change nothing in an idle folder, and
        // an unchanged state is not written again (finding F of the second performance review).
        if !meta_changed && !rows {
            return Ok(());
        }
        if meta_changed {
            batch.meta = Some(meta.clone());
        }
        store.save_folder(&self.folder, &batch)?;
        if meta_changed {
            self.saved_meta = Some(meta);
        }
        // A change stored outside a round is the person's action (a decision, a restore, a
        // pause): the next round plans again and is not skipped.
        if !self.in_round {
            self.quiet = false;
            self.pending = None;
        }
        Ok(())
    }

    /// Stores the folder's state now.
    pub(crate) fn save_state(&mut self, store: &mut dyn Store) -> Result<(), SyncError> {
        self.save(store)
    }

    /// Shrinks the folder's caches in the local index to what this device still uses (security
    /// review, MEDIUM 3; the engine calls it with the hourly scan): before, every plaintext,
    /// object ID and chunk list ever seen stayed until the folder was removed. Kept are
    ///
    /// - the object IDs of the remote and the local tree, found by encoding them against the
    ///   cache (nothing is uploaded), so the next publish seals no unchanged node again;
    /// - the plaintexts and object IDs of the nodes and manifests reachable from the remote
    ///   root, the last fully synced head and every commit of the timeline seen within
    ///   [`HISTORY_CACHE_MS`], so the history opens without the network as before;
    /// - the chunk lists of every file of the three trees, which a download, the next
    ///   publish and the scan need, and which cannot all be fetched again (local contents).
    ///
    /// What goes is a cache: a restore of an older commit fetches its nodes and manifests
    /// from the server again, and the chunk lists come with them. A tree that does not encode
    /// (a chunk list missing already) leaves everything as it is.
    pub fn prune_cache(&self, cx: &mut Ctx<'_>) -> Result<u64, SyncError> {
        let now = cx.clock.now_ms();
        let chain_generation = self.view.frontier().map(|f| f.generation);
        let crypto = cx.account.folder_crypto(&self.folder, chain_generation)?;
        let mut objects = BTreeSet::new();
        for tree in [&self.remote, &self.local] {
            match codec::encode(tree, &crypto, cx.store, cx.entropy) {
                Ok(encoded) => objects.extend(encoded.reachable),
                Err(CodecError::UnknownContent) => return Ok(0),
                Err(e) => return Err(e.into()),
            }
        }
        let roots: Vec<ObjectId> = self
            .meta
            .remote_root
            .into_iter()
            .chain(self.meta.sync_base.map(|b| b.root))
            .chain(
                self.meta
                    .timeline
                    .iter()
                    .filter(|t| now.saturating_sub(t.seen_at_ms) < HISTORY_CACHE_MS)
                    .map(|t| t.root),
            )
            .collect();
        objects.extend(codec::cached_reachable(&roots, &self.folder, cx.store)?);
        let contents: BTreeSet<ContentKey> = [&self.remote, &self.synced, &self.local]
            .into_iter()
            .flat_map(|t| {
                t.iter()
                    .filter_map(|(_, n)| n.kind.file().map(|v| v.content))
            })
            .collect();
        Ok(cx.store.retain_cache(&self.folder, &objects, &contents)?)
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

    /// The bytes of the folder's files on this disk as the local tree holds them, so the window
    /// can show a size without walking the disk again; None until the tree shows the disk.
    pub fn local_bytes(&self) -> Option<u64> {
        self.local_known.then(|| self.local.file_bytes())
    }

    /// The files of the folder on this disk and their bytes, in one pass: the local tree plus
    /// the new files the last scan left unhashed at its budget ([`Self::deferred`]), so the
    /// numbers do not jump during a large first scan. None until the tree shows the disk.
    pub fn local_stats(&self) -> Option<(u64, u64)> {
        if !self.local_known {
            return None;
        }
        let (files, bytes) = self.local.file_stats();
        let (waiting, waiting_bytes) = self.deferred();
        Some((
            files.saturating_add(waiting),
            bytes.saturating_add(waiting_bytes),
        ))
    }

    /// The verified chain.
    pub fn view(&self) -> &FolderView {
        &self.view
    }

    /// The explicit state.
    pub fn state(&self) -> FolderState {
        self.meta.state
    }

    /// Paths the watcher reported as changed (below the root); the next scan reads them. Past
    /// [`crate::watch::MAX_CHANGED_PATHS`] (changes that pile up while rounds wait) the next
    /// scan reads everything instead.
    pub fn note_changes(&mut self, paths: impl IntoIterator<Item = Vec<String>>) {
        if let ScanScope::Paths(set) = &mut self.scan_scope {
            set.extend(paths);
            if set.len() > crate::watch::MAX_CHANGED_PATHS {
                self.scan_scope = ScanScope::Full;
            }
        }
    }

    /// The next scan reads every directory (hourly, or after the watcher lost events).
    pub fn request_full_scan(&mut self) {
        self.scan_scope = ScanScope::Full;
    }

    /// The next round pulls the server's commits (with [`FolderSettings::pull_on_demand`]).
    pub fn request_pull(&mut self) {
        self.pull_due = true;
    }

    /// The change feed reports `sequence` as the folder's head on the server: the next round
    /// pulls unless that is the head this device already has (its own commit, say). A sequence
    /// below this device's is pulled as well, so an older state is noticed.
    pub fn note_remote_head(&mut self, sequence: u64) {
        if self.view.frontier().map(|f| f.sequence) != Some(sequence) {
            self.pull_due = true;
        }
    }

    /// Whether a round now has anything to do. A folder whose last round ended in sync, with no
    /// change on disk reported since, no head on the server to pull, nothing waiting (hashes,
    /// an upload, a repair) and nothing stored by the person since, is skipped by the engine
    /// (finding F of the second performance review). The root marker is still read every time
    /// (one small read), since no watcher reports its loss and a round stops the folder then. A
    /// paused or stopped folder's round does nothing either, except a folder stopped as too
    /// large that may try again.
    pub fn wants_round(&self, fs: &dyn FileSystem, now: i64) -> bool {
        // A held commit waits for its time; a head to pull, or files still waiting for their
        // hash, come in between (the scan goes on while the commit waits).
        if self.hold_until.is_some_and(|at| now < at)
            && !self.pull_due
            && self.deferred.is_empty()
            && self.recheck.is_empty()
        {
            return false;
        }
        match self.meta.state {
            FolderState::Active => {
                !self.quiet
                    || self.pull_due
                    || self.meta.full_next
                    || self.pending.is_some()
                    || !self.deferred.is_empty()
                    || !self.recheck.is_empty()
                    || !self.rehash.is_empty()
                    || !matches!(&self.scan_scope, ScanScope::Paths(p) if p.is_empty())
                    || !self.marker_ok(fs)
            }
            FolderState::Stopped(StopReason::LocalTooLarge) => self.retry_too_large(now),
            _ => false,
        }
    }

    /// The commit calls the last round sent, also when it failed, for the engine's commit
    /// budget of the device.
    pub fn round_commits(&self) -> u32 {
        self.round_commits
    }

    /// When a held publish of this folder is due ([`RoundReport::held_until`]).
    pub fn hold_until(&self) -> Option<i64> {
        self.hold_until
    }

    /// Whether the folder is active and its last round ended in sync with nothing changed
    /// since: a skipped round of it counts as in sync.
    pub fn quiet(&self) -> bool {
        self.meta.state == FolderState::Active && self.quiet
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
            self.meta.approved.extend(held);
        }
        // A decision starts the long window again.
        self.meta.long_deletes.clear();
        self.save(store)?;
        Ok(n)
    }

    /// The files among the held incoming deletes (the number the question shows).
    pub fn incoming_held_files(&self) -> usize {
        self.meta
            .incoming_held
            .iter()
            .filter(|id| self.synced.get(id).is_some_and(|n| !n.is_dir()))
            .count()
    }

    /// "Delete here too" for the held incoming deletes: exactly the held items pass the guard,
    /// and only when `revision` is the state the person was shown; deletes held since ask
    /// again. Returns the files approved.
    pub fn approve_incoming(
        &mut self,
        revision: u64,
        store: &mut dyn Store,
    ) -> Result<usize, SyncError> {
        if revision != self.meta.incoming_revision {
            return Err(SyncError::Invalid("the held deletes changed"));
        }
        let n = self.incoming_held_files();
        let held = std::mem::take(&mut self.meta.incoming_held);
        self.meta.incoming_approved.extend(held);
        self.meta.incoming_devices.clear();
        // A decision starts the long window again.
        self.meta.recent_incoming.clear();
        self.save(store)?;
        Ok(n)
    }

    /// "Restore on all devices" for the held incoming deletes: a new commit on the current head
    /// puts every held item that is still gone back at its place, from this device's synced
    /// tree (the files are still on this disk, so their content can be uploaded again). An
    /// item that is back already stays as it is. Returns the files that came back.
    pub fn restore_incoming(&mut self, cx: &mut Ctx<'_>) -> Result<u64, SyncError> {
        self.pull(cx)?;
        let date = date_label(cx.clock.now_ms(), cx.settings.tz_offset_minutes);
        let base = self.synced.clone();
        let (files, dirs): (Vec<ItemId>, Vec<ItemId>) = self
            .meta
            .incoming_held
            .iter()
            .filter(|id| base.contains(id))
            .partition(|id| base.get(id).is_some_and(|n| !n.is_dir()));
        // A directory comes back with its first file, an empty one on its own. One whose
        // entries moved elsewhere stays gone: grafting its subtree would bring them twice.
        let empty_dirs: Vec<ItemId> = dirs
            .into_iter()
            .filter(|id| base.children(id).next().is_none())
            .collect();
        let mut tree = self.remote.clone();
        for item in files.iter().chain(empty_dirs.iter()) {
            if tree.contains(item) {
                continue;
            }
            let mut ids = EntropyIds::new(cx.entropy);
            tree = graft(&tree, &base, item, &cx.settings.words, &date, &mut ids)?.0;
            ids.check()?;
        }
        let back = tree
            .iter()
            .filter(|(id, n)| !n.is_dir() && !self.remote.contains(id))
            .count() as u64;
        if tree != self.remote {
            self.publish_tree(cx, tree)?;
            // Brought back from a question, not an action with its own undo.
            self.last_action = None;
        }
        self.meta.incoming_held.clear();
        self.meta.incoming_devices.clear();
        self.meta.recent_incoming.clear();
        self.save(cx.store)?;
        Ok(back)
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

    /// One round of the control loop (module docs). With a work budget
    /// ([`FolderSettings::work_budget_ms`]) the round may stop early at a clean point:
    /// between hash batches, between two object uploads before the commit, or between two
    /// downloaded files. Then [`RoundReport::more`] is set and the next round carries on from
    /// what is stored and what the server already holds; nothing is committed half.
    pub fn round(&mut self, cx: &mut Ctx<'_>) -> Result<RoundReport, SyncError> {
        self.round_with(cx, cx.settings.work_budget_ms, true)
    }

    /// [`Self::round`] with the budget `budget_ms` (`None`: to its end).
    fn round_with(
        &mut self,
        cx: &mut Ctx<'_>,
        budget_ms: Option<i64>,
        gated: bool,
    ) -> Result<RoundReport, SyncError> {
        let now = cx.clock.now_ms();
        self.budget = budget_ms.map(|ms| {
            let slice = ms.max(1);
            Budget {
                until: now.saturating_add(slice),
                slice,
            }
        });
        self.cut = false;
        self.round_seq = self.round_seq.wrapping_add(1);
        self.upload_until = None;
        self.in_round = true;
        self.gated = gated;
        self.commits_left = if gated {
            cx.settings.commit_allowance
        } else {
            None
        };
        self.commits_sent = 0;
        let result = self.round_inner(cx);
        self.gated = false;
        self.commits_left = None;
        self.round_commits = std::mem::take(&mut self.commits_sent);
        self.in_round = false;
        self.budget = None;
        let more = std::mem::take(&mut self.cut);
        match result {
            Ok(mut report) => {
                report.more |= more;
                // Files waiting for their hash, or a round cut short, are not in sync yet.
                report.in_sync &= !report.more && self.deferred.is_empty();
                if !report.more {
                    self.upload_left = None;
                }
                self.quiet = report.in_sync;
                report.commits = self.round_commits;
                report.held_until = self.hold_until;
                Ok(report)
            }
            Err(e) => {
                self.upload_left = None;
                self.quiet = false;
                self.pull_due = true;
                Err(e)
            }
        }
    }

    /// Bytes the current upload still has to send, while one is under way or waits for the
    /// next round ([`FolderSettings::work_budget_ms`]); `None` when no upload is pending.
    pub fn upload_left(&self) -> Option<u64> {
        self.upload_left
    }

    /// The key of the window's numbers of this folder ([`SummaryKey`]).
    pub fn summary_key(&self) -> SummaryKey {
        SummaryKey {
            trees: (
                self.local.edition(),
                self.synced.edition(),
                self.remote.edition(),
            ),
            local_known: self.local_known,
            state: self.meta.state,
            deferred: self.deferred(),
            upload_left: self.upload_left,
            cannot_sync: self.meta.cannot_sync.keys().copied().collect(),
        }
    }

    /// New files the last scan left unhashed at its budget: how many and their bytes. They are
    /// not in the local tree yet, so without them a large first scan reads as up to date.
    pub fn deferred(&self) -> (u64, u64) {
        let bytes = self
            .deferred
            .values()
            .fold(0u64, |s, b| s.saturating_add(*b));
        (self.deferred.len() as u64, bytes)
    }

    /// Whether the round's budget is spent at `until`, or a command waits for the engine
    /// thread ([`FolderSettings::interrupt`]); a round without a budget never is.
    fn spent(cx: &Ctx<'_>, until: Option<i64>) -> bool {
        until.is_some_and(|u| cx.clock.now_ms() >= u || cx.settings.interrupt.pending())
    }

    fn round_inner(&mut self, cx: &mut Ctx<'_>) -> Result<RoundReport, SyncError> {
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
        // With pulls on demand, a round pulls only when the change feed named a new head (or
        // at start, after an error, hourly); a missed feed entry is caught by the hourly pull.
        if !cx.settings.pull_on_demand || self.pull_due {
            match self.pull(cx) {
                Ok(n) => {
                    report.pulled = n;
                    self.pull_due = false;
                }
                Err(e) if e.is_offline() => {
                    report.offline = true;
                    return Ok(report);
                }
                Err(e) => return self.stop_on(e, cx.store),
            }
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
        if self.meta.full_next
            && self.meta.state == FolderState::Active
            && self.commits_left != Some(0)
        {
            match self.repair(cx) {
                Ok(()) => report.published = true,
                Err(PublishFailure::Error(e)) if e.is_offline() => {
                    report.offline = true;
                    self.save(cx.store)?;
                    return Ok(report);
                }
                // `more` comes from the upload's cut (`self.cut`), which a stalled upload does
                // not set.
                Err(PublishFailure::Yielded) => {
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
        // The publish the last round's budget cut, while nothing it was planned from changed:
        // its upload goes on without a new plan, encoding and ask (finding A).
        let mut resumed = self.take_pending(cx);
        self.hold_until = None;
        for _ in 0..attempts {
            let (p, mut encoded) = match resumed.take() {
                Some(pending) => (pending.plan, pending.encoded),
                None => (self.plan_round(cx, &mut report)?, None),
            };
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
            match self.publish(cx, &p, &mut encoded) {
                Ok(()) => {
                    report.published = true;
                    self.note_deletes(cx.clock.now_ms(), &p.local_deletes);
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
                // Stopped at the budget before the commit: the next round goes on with this
                // plan, its encoding and its upload's queue while nothing changed, and plans,
                // encodes and asks again otherwise; it uploads nothing twice. `more` comes from
                // the upload's cut (`self.cut`), which a stalled upload does not set.
                Err(PublishFailure::Yielded) => {
                    self.keep_pending(cx, p, encoded);
                    self.save(cx.store)?;
                    return Ok(report);
                }
                // Uploaded, but the commit is not due yet: the round ends without `more` and
                // not in sync, nothing of the plan reaches the disk, and the next round at
                // `hold_until` commits the kept plan (MEDIUM 1).
                Err(PublishFailure::Held) => {
                    self.keep_pending(cx, p, encoded);
                    self.save(cx.store)?;
                    return Ok(report);
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

    /// Records local deletes that went out, for the windows of the mass delete guard.
    fn note_deletes(&mut self, now: i64, deletes: &[ItemId]) {
        let counted = deletes
            .iter()
            .filter(|id| !self.meta.approved.contains(id))
            .count() as u64;
        if counted > 0 {
            self.meta.recent_deletes.push((now, counted));
        }
        let old = self.old_files(deletes.iter().filter(|id| !self.meta.approved.contains(id)));
        if old > 0 {
            self.meta.long_deletes.push((now, old));
        }
    }

    /// Local deletes this device propagated within the window before `now`; older records go.
    fn recent_deletes(&mut self, now: i64) -> u64 {
        window_sum(&mut self.meta.recent_deletes, now, DELETE_WINDOW_MS)
    }

    /// The files among `items` that the synced tree holds and that did not just arrive: what
    /// the guards count.
    fn old_files<'a>(&self, items: impl Iterator<Item = &'a ItemId>) -> u64 {
        items
            .filter(|id| {
                self.synced.get(id).is_some_and(|n| !n.is_dir())
                    && !self.meta.fresh_files.contains_key(id)
            })
            .count() as u64
    }

    /// The folder's size the guards take a share of (security review M3): the fewest files the
    /// synced tree held over the long window, now included, plus the deletes carried out within
    /// it (which took files away from that count). Files added just before a delete raise the
    /// count only after the fewest of the day, so they do not dilute it. Also keeps this hour's
    /// fewest files, once the folder was fully synced.
    fn files_before(&mut self, now: i64) -> u64 {
        let count = self.synced.count_files() as u64;
        let minimums = &mut self.meta.file_minimums;
        minimums.retain(|(at, _)| (now - at).abs() < LONG_DELETE_WINDOW_MS);
        if self.meta.sync_base.is_some() {
            let hour = now - now.rem_euclid(FILE_COUNT_STEP_MS);
            match minimums.iter_mut().find(|(at, _)| *at == hour) {
                Some((_, fewest)) => *fewest = (*fewest).min(count),
                None => minimums.push((hour, count)),
            }
        }
        let fewest = minimums
            .iter()
            .map(|(_, n)| *n)
            .chain([count])
            .min()
            .unwrap_or(count);
        let carried =
            window_sum(&mut self.meta.recent_incoming, now, LONG_DELETE_WINDOW_MS).saturating_add(
                window_sum(&mut self.meta.long_deletes, now, LONG_DELETE_WINDOW_MS),
            );
        fewest.saturating_add(carried)
    }

    /// Remembers the files that came into the synced tree in this round (`arriving`, files of
    /// the plan the base lacked), when the folder was fully synced before; forgets the ones
    /// past the long window or gone from the base, and the oldest past [`FRESH_FILES_CAP`].
    fn note_fresh(&mut self, now: i64, arriving: &[ItemId], baseline: bool) {
        let synced = &self.synced;
        let fresh = &mut self.meta.fresh_files;
        if baseline {
            for id in arriving.iter().filter(|id| synced.contains(id)) {
                fresh.entry(*id).or_insert(now);
            }
        }
        fresh.retain(|id, at| synced.contains(id) && (now - *at).abs() < LONG_DELETE_WINDOW_MS);
        if fresh.len() > FRESH_FILES_CAP {
            let mut by_age: Vec<(i64, ItemId)> = fresh.iter().map(|(id, at)| (*at, *id)).collect();
            by_age.sort_unstable();
            for (_, id) in by_age.iter().take(fresh.len() - FRESH_FILES_CAP) {
                fresh.remove(id);
            }
        }
    }

    /// The guard for deletes another device made (ADR 0001, amendment "incoming mass deletes";
    /// security review, LOW 4). An incoming delete is an item of the base and of the disk that
    /// the server's tree and the plan no longer have; moves keep their item and are none. Once
    /// the incoming file deletes of the window reach the threshold ([`hold_deletes`]), or while
    /// a question is open, the new ones are held: the executor leaves them (and the deleted
    /// directories above them) on the disk and in the synced tree, so everything else of the
    /// folder keeps syncing. A local change to a held file makes the plan keep it (the merge
    /// rules), so it leaves the question by itself.
    fn guard_incoming(&mut self, now: i64, files: u64, own: DeviceId, p: &mut Plan) {
        let (synced, remote) = (&self.synced, &self.remote);
        let incoming: BTreeSet<ItemId> = p
            .disk
            .ids()
            .filter(|id| synced.contains(id) && !remote.contains(id) && !p.merged.contains(id))
            .copied()
            .collect();
        self.meta.incoming_held.retain(|id| incoming.contains(id));
        self.meta
            .incoming_approved
            .retain(|id| incoming.contains(id));
        if self.meta.incoming_held.is_empty() {
            self.meta.incoming_devices.clear();
        }
        let new: Vec<ItemId> = incoming
            .iter()
            .filter(|id| {
                !self.meta.incoming_approved.contains(id) && !self.meta.incoming_held.contains(id)
            })
            .copied()
            .collect();
        if !new.is_empty() {
            let asking = !self.meta.incoming_held.is_empty();
            let recent = window_sum(&mut self.meta.recent_incoming, now, LONG_DELETE_WINDOW_MS);
            let deleted = self.old_files(new.iter());
            if asking || (deleted > 0 && hold_deletes(deleted.saturating_add(recent), files)) {
                self.meta.incoming_held.extend(new);
                self.meta.incoming_revision = self.meta.incoming_revision.saturating_add(1);
                let writers = self
                    .meta
                    .timeline
                    .get(self.applied_timeline..)
                    .unwrap_or_default()
                    .iter()
                    .filter(|t| !t.side && t.device != own)
                    .map(|t| t.device)
                    .collect::<Vec<_>>();
                self.meta.incoming_devices.extend(writers);
            }
        }
        for id in &self.meta.incoming_held {
            p.skip.insert(*id);
            let mut at = p.disk.get(id).map(|n| n.parent);
            while let Some(parent) = at {
                if parent == ROOT || !incoming.contains(&parent) || !p.skip.insert(parent) {
                    break;
                }
                at = p.disk.get(&parent).map(|n| n.parent);
            }
        }
    }

    fn plan_round(
        &mut self,
        cx: &mut Ctx<'_>,
        report: &mut RoundReport,
    ) -> Result<Plan, SyncError> {
        let now = cx.clock.now_ms();
        let delay = cx.settings.delete_delay_ms;
        // A held delete whose item is back on the disk (or gone from the base) is no question
        // any more.
        let (synced, local) = (&self.synced, &self.local);
        self.meta
            .held
            .retain(|id| synced.contains(id) && !local.contains(id));
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
        let mut ids = EntropyIds::new(cx.entropy);
        let mut p = plan(
            PlanInput {
                remote: &self.remote,
                synced: &self.synced,
                local: &self.local,
                delayed: &delayed,
                restore: &restore,
            },
            &labels,
            &mut ids,
        );
        ids.check()?;
        // The guard (security review, LOW 1): deletes the person approved pass; the others are
        // held while a question is open, or when they reach the threshold together with what
        // this device propagated within the window.
        let unapproved: Vec<ItemId> = p
            .local_deletes
            .iter()
            .filter(|id| !self.meta.approved.contains(id))
            .copied()
            .collect();
        let asking = !self.meta.held.is_empty();
        let recent = self.recent_deletes(now);
        let threshold = cx.settings.mass_delete_threshold as u64;
        let files = self.files_before(now);
        // The long window (security review M3): the old files this device deleted since the
        // last decision, by the share rule of the incoming guard and never below the set
        // threshold.
        let old = self.old_files(unapproved.iter());
        let long =
            window_sum(&mut self.meta.long_deletes, now, LONG_DELETE_WINDOW_MS).saturating_add(old);
        let slow = old > 0 && long >= threshold && hold_deletes(long, files);
        if !unapproved.is_empty()
            && (asking || slow || (unapproved.len() as u64).saturating_add(recent) >= threshold)
        {
            self.meta.held.extend(unapproved);
            report.held = self.meta.held.iter().copied().collect();
            let delayed: BTreeSet<ItemId> = delayed.union(&self.meta.held).copied().collect();
            let mut ids = EntropyIds::new(cx.entropy);
            p = plan(
                PlanInput {
                    remote: &self.remote,
                    synced: &self.synced,
                    local: &self.local,
                    delayed: &delayed,
                    restore: &restore,
                },
                &labels,
                &mut ids,
            );
            ids.check()?;
        }
        self.guard_incoming(now, files, *cx.account.device(), &mut p);
        report.copies.extend(p.copies.iter().copied());
        Ok(p)
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
        // Nothing to read: no path reported since the last scan and nothing left waiting. The
        // walk would take every directory from the index and build the same tree again, which
        // costs a pass over the whole folder in every round of a long upload.
        let nothing_reported = matches!(&self.scan_scope, ScanScope::Paths(p) if p.is_empty());
        if nothing_reported
            && self.local_known
            && self.deferred.is_empty()
            && self.recheck.is_empty()
            && self.rehash.is_empty()
        {
            self.note_local_deletes(cx.clock.now_ms());
            return Ok(());
        }
        self.expect_directories(cx.fs);
        self.recover_parked(cx.fs)?;
        let reader = cx.account.folder_reader(&self.folder)?;
        let newest = reader.writable_generation();
        let tolerance = cx.fs.mtime_tolerance_ms();
        let exec_supported = cx.fs.exec_supported();
        // 1. Walk: list every directory in a full scan; in a partial one only the directories
        // the watcher named (with their ancestors) and new ones, and take the rest from the
        // index.
        // Files the last scan left unhashed at its budget are listed again here, and hashed
        // first below.
        let waited: BTreeSet<Vec<String>> = self
            .deferred
            .keys()
            .chain(self.recheck.iter())
            .cloned()
            .collect();
        self.hashed_in_scan = false;
        let deferred = std::mem::take(&mut self.deferred);
        let recheck = std::mem::take(&mut self.recheck);
        let relist =
            match std::mem::replace(&mut self.scan_scope, ScanScope::Paths(BTreeSet::new())) {
                ScanScope::Full => None,
                ScanScope::Paths(paths) => {
                    let mut set = BTreeSet::new();
                    for path in paths.into_iter().chain(deferred.into_keys()).chain(recheck) {
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
        // Every lookup of the scan goes through indexes of the names, built once per scan
        // (security review of the scan, HIGH 1); the remote one only when a new file needs it.
        let local_index = NameIndex::new(&self.local);
        let remote_index = std::cell::OnceCell::new();
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
                    local_index
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
            let at_path = local_index
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
        // Per job: whether the budget may leave it for the next scan. A file the local tree
        // knows keeps its known version meanwhile; a new file stays out of the tree, which only
        // delays its upload. A file the synced or the remote tree knows (by item or, for a
        // join, by path) is always hashed: leaving it out would read as a local delete.
        let mut deferrable: Vec<bool> = Vec::new();
        for (item, path, stat) in &items {
            if stat.kind != EntryType::File {
                continue;
            }
            let prev = self.local.get(item).and_then(|n| n.kind.file()).copied();
            // A remote file at the same path does not keep a new file from waiting: the remote
            // tree may be older than the next pull, so `apply_plan` leaves every remote item at
            // a waiting path alone until the file is hashed (security review of the budget,
            // H1).
            let may_wait =
                prev.is_some() || (!self.synced.contains(item) && !self.remote.contains(item));
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
                        pausable: may_wait,
                        resume: self.partial_hashes.get(path).cloned(),
                    });
                    job_items.push((*item, prev, *stat));
                    deferrable.push(may_wait);
                    continue;
                }
            }
            let generation = prev
                .and_then(|v| cx.store.chunk_list(&self.folder, &v.content).ok().flatten())
                .and_then(|l| l.generation)
                .or_else(|| {
                    // A join: the remote item at the same path.
                    remote_index
                        .get_or_init(|| NameIndex::new(&self.remote))
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
                pausable: may_wait,
                resume: self.partial_hashes.get(path).cloned(),
            });
            job_items.push((*item, prev, *stat));
            deferrable.push(may_wait);
        }

        // Files that waited since an earlier scan go first: in path order a folder that keeps
        // changing (a log, a database) would fill the first batch, the only one a spent budget
        // still hashes, in every scan, and the files that wait would starve (LOW 3).
        if !waited.is_empty() {
            let mut order: Vec<usize> = (0..jobs.len()).collect();
            order.sort_by_key(|i| !waited.contains(&jobs[*i].path));
            jobs = order.iter().map(|i| jobs[*i].clone()).collect();
            job_items = order.iter().map(|i| job_items[*i]).collect();
            deferrable = order.iter().map(|i| deferrable[*i]).collect();
        }
        self.hashed_in_scan = !jobs.is_empty();

        // 4. Hash, in parallel with backpressure, in batches so the round's work budget is
        // checked between them. `None`: left for the next scan.
        let until = self.budget.map(|b| b.phase_until(cx.clock.now_ms()));
        let threads = cx.settings.hash_threads;
        // A large file stops between two chunks at the budget or for a waiting command, checked
        // by the hashing threads themselves in wall time ([`ChunkError::Paused`]).
        let stop = {
            let interrupt = cx.settings.interrupt.clone();
            let deadline = until.map(|u| {
                let left = u.saturating_sub(cx.clock.now_ms()).max(0);
                std::time::Instant::now()
                    + std::time::Duration::from_millis(u64::try_from(left).unwrap_or(0))
            });
            move || deadline.is_some_and(|d| std::time::Instant::now() >= d || interrupt.pending())
        };
        let paths: BTreeSet<&Vec<String>> = jobs.iter().map(|j| &j.path).collect();
        self.partial_hashes.retain(|path, _| paths.contains(path));
        let mut results: Vec<Option<Result<crate::chunker::Hashed, ChunkError>>> =
            Vec::with_capacity(jobs.len());
        let mut start = 0;
        while start < jobs.len() {
            let mut end = start;
            let mut bytes = 0u64;
            while end < jobs.len()
                && (end == start || (bytes < HASH_BATCH_BYTES && end - start < HASH_BATCH_FILES))
            {
                bytes = bytes.saturating_add(job_items[end].2.size);
                end += 1;
            }
            let batch = hash_many(cx.fs, &jobs[start..end], reader.all_keys(), threads, &stop);
            let mut paused = false;
            for (index, result) in (start..end).zip(batch) {
                let path = &jobs[index].path;
                match result {
                    // Left for the next scan, which goes on from these chunks.
                    Err(ChunkError::Paused(partial)) => {
                        paused = true;
                        let (_, prev, stat) = &job_items[index];
                        if prev.is_some() {
                            self.recheck.insert(path.clone());
                        } else {
                            self.deferred.insert(path.clone(), stat.size);
                        }
                        self.partial_hashes.insert(path.clone(), *partial);
                        results.push(None);
                    }
                    other => {
                        self.partial_hashes.remove(path);
                        results.push(Some(other));
                    }
                }
            }
            start = end;
            if paused && start == jobs.len() {
                self.cut = true;
            }
            if start < jobs.len() && (paused || Self::spent(cx, until)) {
                let must: Vec<HashJob> = (start..jobs.len())
                    .filter(|i| !deferrable[*i])
                    .map(|i| jobs[i].clone())
                    .collect();
                let mut hashed =
                    hash_many(cx.fs, &must, reader.all_keys(), threads, &|| false).into_iter();
                for (index, (job, may_wait)) in
                    jobs[start..].iter().zip(&deferrable[start..]).enumerate()
                {
                    if *may_wait {
                        let (_, prev, stat) = &job_items[start + index];
                        if prev.is_some() {
                            self.recheck.insert(job.path.clone());
                        } else {
                            self.deferred.insert(job.path.clone(), stat.size);
                        }
                        results.push(None);
                    } else {
                        results.push(hashed.next());
                    }
                }
                self.cut = true;
                break;
            }
        }
        let mut rehash: Vec<usize> = Vec::new();
        for (index, ((item, prev, stat), result)) in job_items.iter().zip(results).enumerate() {
            let Some(result) = result else {
                // Left for the next scan: the known version stays meanwhile, and an unchanged
                // file that waits for a new hash stays marked for it.
                if let Some(v) = prev {
                    versions.insert(*item, *v);
                    if rehash_contents.contains(&v.content) {
                        self.rehash.insert(v.content);
                    }
                }
                continue;
            };
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
            let job = HashJob::whole(jobs[index].path.clone(), newest);
            if let Some(Ok(hashed)) =
                hash_many(cx.fs, &[job], reader.all_keys(), 1, &|| false).pop()
            {
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
            if let Some(dir_id) = local_index.lookup(dir) {
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
        self.note_local_deletes(cx.clock.now_ms());
        self.local_known = true;
        Ok(())
    }

    /// Local deletes: remembers when each was first seen.
    fn note_local_deletes(&mut self, now: i64) {
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
    }

    // -- Pull -------------------------------------------------------------------------------

    fn pull(&mut self, cx: &mut Ctx<'_>) -> Result<usize, SyncError> {
        // A commit ahead of this device's log or of an unknown generation, or a stored pull of
        // another log: the account is read again and the pull begins again, once.
        let mut refreshed = false;
        let verdict = loop {
            match self.pull_delta(cx, PullMode::Check { persist: true }) {
                Ok(v) => break v,
                Err(e) if !refreshed && needs_refresh(&e) => {
                    refreshed = true;
                    cx.account.refresh(cx.server, cx.keychain, cx.store)?;
                }
                Err(e) => return Err(e),
            }
        };
        let pulled = match verdict {
            PullVerdict::Accepted(pulled) => pulled,
            PullVerdict::RemovedSigner(refusal) => {
                // Only after this real refusal does this device look at the delta without the
                // removed signer rule, and it writes no barrier on its own: the heads it would
                // let in go to the person (security review H1).
                let permit =
                    BarrierPermit::takeover(cx.account.state(), cx.account.device(), &refusal)
                        .ok_or(SyncError::Chain(
                            hangar_drive_crypto::commit::ChainError::RemovedSigner,
                        ))?;
                let before = match self.pull_delta(cx, PullMode::BeforeBarrier(&permit))? {
                    PullVerdict::Accepted(before) => before,
                    PullVerdict::RemovedSigner(_) => {
                        return Err(SyncError::Chain(
                            hangar_drive_crypto::commit::ChainError::RemovedSigner,
                        ))
                    }
                };
                self.meta.removed_heads = before.removed_heads.iter().map(Into::into).collect();
                self.meta.state = FolderState::Stopped(StopReason::RemovedHeads);
                return Ok(0);
            }
        };
        let Some(head) = pulled.last_head.clone() else {
            return Ok(0);
        };
        let reader = cx.account.folder_reader(&self.folder)?;
        let decoded = if pulled.tree_limit {
            // A head on the way is beyond the limits: its delta could not be checked, and the
            // folder stops as for a head beyond the limits (HIGH 1 of the follow-up review).
            Err(codec::CodecError::Limit)
        } else {
            codec::decode(&head.commit.root, &reader, cx.store, cx.server)
        };
        let n = pulled.heads;
        let tree = match decoded {
            Ok(tree) => tree,
            Err(codec::CodecError::Limit) => {
                // The commits verified, so they are the folder's chain and its history; only
                // the head's tree stays out (security review M3). The remote tree keeps the last
                // one taken in, and the folder waits for a restore, which carries a full delta.
                self.meta.timeline.extend(pulled.timeline);
                self.meta.full_next = true;
                self.view = pulled.view;
                self.meta.remote_root = Some(head.commit.root);
                self.meta.frontier_wire = Some(Blob(head.wire.clone()));
                self.meta.sync_base = None;
                self.meta.state = FolderState::Stopped(StopReason::TreeLimit);
                return Ok(n);
            }
            Err(e) => return Err(e.into()),
        };
        self.meta.timeline.extend(pulled.timeline);
        self.meta.full_next |= pulled.unchecked;
        self.view = pulled.view;
        self.set_remote(tree);
        self.meta.remote_root = Some(head.commit.root);
        self.meta.frontier_wire = Some(Blob(head.wire.clone()));
        Ok(n)
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

    fn newest(&self, cx: &Ctx<'_>) -> Result<Generation, SyncError> {
        cx.account
            .newest_generation(&self.folder)
            .ok_or(SyncError::NotSetUp("no key ring for the folder"))
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

    /// When a gated round may commit its publish, if not now: the folder's bucket of
    /// [`PUBLISH_BURST`] commits refills by one per [`FolderSettings::publish_interval_ms`], and
    /// every commit waits while the device's allowance is used up.
    fn publish_hold(&mut self, cx: &Ctx<'_>) -> Option<i64> {
        if !self.gated {
            return None;
        }
        let now = cx.clock.now_ms();
        let interval = cx.settings.publish_interval_ms;
        if self.commits_left == Some(0) {
            return Some(now.saturating_add(interval.max(1_000)));
        }
        if interval <= 0 {
            return None;
        }
        if let Some(at) = self.publish_filled_ms {
            if now < at {
                // The clock went back: count from now instead of holding until it caught up.
                self.publish_filled_ms = Some(now);
            } else {
                let steps = (now - at) / interval;
                if steps > 0 {
                    let gained = u32::try_from(steps).unwrap_or(u32::MAX);
                    self.publish_tokens = self
                        .publish_tokens
                        .saturating_add(gained)
                        .min(PUBLISH_BURST);
                    self.publish_filled_ms = if self.publish_tokens >= PUBLISH_BURST {
                        None
                    } else {
                        Some(at.saturating_add(steps.saturating_mul(interval)))
                    };
                }
            }
        }
        if self.publish_tokens > 0 {
            return None;
        }
        Some(
            self.publish_filled_ms
                .unwrap_or(now)
                .saturating_add(interval),
        )
    }

    /// What a pending publish is valid for now ([`PendingKey`]).
    fn pending_key(&self, cx: &Ctx<'_>) -> PendingKey {
        PendingKey {
            trees: (
                self.local.edition(),
                self.synced.edition(),
                self.remote.edition(),
            ),
            frontier: self.view.frontier().map(|f| f.commit),
            remote_root: self.meta.remote_root,
            generation: cx.account.newest_generation(&self.folder).map(|g| g.0),
        }
    }

    /// The publish the last round's budget cut, when nothing it was planned from changed since.
    fn take_pending(&mut self, cx: &Ctx<'_>) -> Option<PendingPublish> {
        let pending = self.pending.take()?;
        (pending.key == self.pending_key(cx)).then_some(pending)
    }

    /// Keeps a publish the budget cut for the next round, keyed by the state after this round
    /// (which includes its own intermediate commits).
    fn keep_pending(&mut self, cx: &Ctx<'_>, plan: Plan, encoded: Option<Encoded>) {
        self.pending = Some(PendingPublish {
            key: self.pending_key(cx),
            plan,
            encoded,
        });
    }

    /// When the upload phase of the running round ends: at the round's budget, but never before
    /// a quarter of the folder's share, and at least [`UPLOAD_FLOOR_MS`], has passed in the
    /// phase, so a round whose scan took the budget, or a folder with a small share of a pass,
    /// still moves its upload on. Fixed once per round: the uploads of a publish, its stages and
    /// its side commit share it.
    fn upload_deadline(&mut self, cx: &Ctx<'_>) -> Option<i64> {
        let budget = self.budget?;
        let floor = (budget.slice / 4).max(UPLOAD_FLOOR_MS.min(budget.slice));
        let now = cx.clock.now_ms();
        Some(
            *self
                .upload_until
                .get_or_insert_with(|| budget.until.max(now.saturating_add(floor))),
        )
    }

    /// Asks the server which of `ids` it lacks, in queries of the protocol's size.
    fn ask_missing(
        cx: &mut Ctx<'_>,
        folder: &FolderId,
        ids: &[ObjectId],
    ) -> Result<Vec<ObjectId>, NetError> {
        let mut missing = Vec::new();
        for batch in ids.chunks(hangar_drive_protocol::api::MAX_MISSING_QUERY) {
            missing.extend(cx.server.missing_objects(folder, batch)?);
        }
        Ok(missing)
    }

    /// A digest of an upload's candidates, to tell whether a kept job was made for them.
    fn candidates_digest(candidates: &BTreeSet<ObjectId>) -> [u8; 32] {
        use sha2::Digest;
        let mut hash = sha2::Sha256::new();
        for id in candidates {
            hash.update(id.as_bytes());
        }
        hash.finalize().into()
    }

    /// The objects of `missing` in read order with their sizes, where each chunk lives on
    /// disk, and their bytes (finding H: chunks by path and chunk index, so a file is read from
    /// its start to its end, not in the order of the IDs). Chunks the disk cannot produce come
    /// first, so a changed disk ends the upload before anything else is sent; sealed nodes and
    /// manifests come last.
    #[allow(clippy::type_complexity)]
    fn queue_for(
        encoded: &Encoded,
        disk: &Tree,
        missing: &[ObjectId],
    ) -> (
        Vec<ObjectId>,
        BTreeMap<ObjectId, u64>,
        BTreeMap<ObjectId, (Vec<String>, u64, ContentKey)>,
        u64,
    ) {
        let wanted: BTreeSet<ObjectId> = missing.iter().copied().collect();
        let mut sources: BTreeMap<ObjectId, (Vec<String>, u64, ContentKey)> = BTreeMap::new();
        let mut sizes: BTreeMap<ObjectId, u64> = BTreeMap::new();
        for (item, node) in disk.iter() {
            let Some(v) = node.kind.file() else {
                continue;
            };
            let Some(chunks) = encoded.chunks.get(&v.content) else {
                continue;
            };
            if !chunks
                .iter()
                .any(|c| wanted.contains(c) && !sources.contains_key(c))
            {
                continue;
            }
            let Some(path) = disk.path(item) else {
                continue;
            };
            for (index, chunk) in chunks.iter().enumerate() {
                if !wanted.contains(chunk) || sources.contains_key(chunk) {
                    continue;
                }
                let start =
                    (index as u64).saturating_mul(hangar_drive_protocol::object::CHUNK_SIZE);
                sizes.insert(
                    *chunk,
                    v.size
                        .saturating_sub(start)
                        .min(hangar_drive_protocol::object::CHUNK_SIZE),
                );
                sources.insert(*chunk, (path.clone(), index as u64, v.content));
            }
        }
        let mut unknown = Vec::new();
        let mut chunks: Vec<(&Vec<String>, u64, ObjectId)> = Vec::new();
        let mut sealed = Vec::new();
        for id in &wanted {
            if let Some(blob) = encoded.sealed.get(id) {
                sizes.insert(*id, blob.len() as u64);
                sealed.push(*id);
            } else if let Some((path, index, _)) = sources.get(id) {
                chunks.push((path, *index, *id));
            } else {
                unknown.push(*id);
            }
        }
        chunks.sort();
        let order: Vec<ObjectId> = unknown
            .into_iter()
            .chain(chunks.into_iter().map(|(_, _, id)| id))
            .chain(sealed)
            .collect();
        let left = order
            .iter()
            .map(|id| sizes.get(id).copied().unwrap_or(0))
            .fold(0u64, u64::saturating_add);
        (order, sizes, sources, left)
    }

    /// Puts `ids` back at the front of the job's queue, in read order.
    fn requeue(job: &mut UploadJob, encoded: &Encoded, disk: &Tree, ids: &[ObjectId]) {
        let queued: BTreeSet<ObjectId> = job.queue.iter().copied().collect();
        let ids: Vec<ObjectId> = ids
            .iter()
            .filter(|id| !queued.contains(id))
            .copied()
            .collect();
        let (order, sizes, sources, left) = Self::queue_for(encoded, disk, &ids);
        job.sizes.extend(sizes);
        job.sources.extend(sources);
        job.left = job.left.saturating_add(left);
        for id in order.into_iter().rev() {
            job.queue.push_front(id);
        }
    }

    /// Ends the transfer threads of a folder that does not run a round now (paused, stopped,
    /// nothing to do): upload lanes take nothing new and their workers end once their request
    /// is answered, while the answers stay for the next round to book. Nothing is lost.
    pub fn release_transfers(&mut self) {
        for job in &mut self.jobs {
            if let Some(lane) = &mut job.flight {
                lane.close();
            }
        }
        // Fetched chunks not written yet are fetched again when the folder runs.
        self.fetch = None;
        // A hash in parts goes on only within a run of the folder (security review M3).
        self.partial_hashes.clear();
    }

    /// Removes every part file of a download in parts of this folder from `fs` (security
    /// review N1): the engine calls it before it lets the folder go (stopped, removed, the
    /// device signed out) or gives it another root.
    pub fn discard_partials(&mut self, fs: &dyn FileSystem) {
        for (_, gone) in std::mem::take(&mut self.partial_downloads) {
            let _ = fs.partial_remove(&gone.part.name);
        }
        self.fetch = None;
    }

    /// Part files of downloads in parts this folder keeps, for tests.
    pub fn partial_download_count(&self) -> usize {
        self.partial_downloads.len()
    }

    /// Worker threads of this folder's upload lanes that still take objects, for tests.
    pub fn open_transfer_lanes(&self) -> usize {
        self.jobs
            .iter()
            .filter(|j| j.flight.as_ref().is_some_and(|l| !l.closed()))
            .count()
            + usize::from(self.fetch.as_ref().is_some_and(FetchLane::parallel))
    }

    /// Keeps a job for later rounds; the oldest beyond [`MAX_UPLOAD_JOBS`] goes.
    fn store_job(&mut self, job: UploadJob) {
        self.jobs.push(job);
        if self.jobs.len() > MAX_UPLOAD_JOBS {
            self.jobs.remove(0);
        }
    }

    /// Uploads every object of `encoded` among `candidates` the server lacks: sealed nodes and
    /// manifests, and chunks read from the disk. A chunk that does not seal to its ID marks its
    /// content for the next scan to hash again ([`FolderSync::rehash`]).
    fn upload(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        encoded: &Encoded,
        candidates: &BTreeSet<ObjectId>,
        disk: &Tree,
    ) -> Result<(), PublishFailure> {
        self.upload_part(cx, crypto, encoded, candidates, disk, false)
            .map(|_| ())
    }

    /// [`Self::upload`], kept across rounds in an [`UploadJob`]: the server is asked once which
    /// candidates it lacks, a later round goes on with the queue (after asking whether the
    /// server kept what the last round sent), and before the upload reports done the server is
    /// asked about every candidate again unless that ask was in this round, since it deletes
    /// uploads no commit names after a day. With `stage`, it stops with
    /// [`UploadStep::StageDue`] once enough went up for an intermediate commit.
    fn upload_part(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        encoded: &Encoded,
        candidates: &BTreeSet<ObjectId>,
        disk: &Tree,
        stage: bool,
    ) -> Result<UploadStep, PublishFailure> {
        let generation = crypto.writable_generation().0;
        let digest = Self::candidates_digest(candidates);
        let kept = self
            .jobs
            .iter()
            .position(|j| j.root == encoded.root && j.generation == generation);
        let mut job = match kept {
            Some(index) => {
                let mut job = self.jobs.remove(index);
                if job.candidates != digest {
                    // The parent moved on (an intermediate commit): what is no candidate any
                    // more is on the server already, and a new candidate is found by the ask
                    // before the upload reports done.
                    job.queue.retain(|id| candidates.contains(id));
                    // Objects still in flight are booked when they land, so they stay counted.
                    let in_flight = job.flight.as_ref().map_or(&[][..], |l| l.in_flight_ids());
                    job.left = job
                        .queue
                        .iter()
                        .chain(in_flight)
                        .map(|id| job.sizes.get(id).copied().unwrap_or(0))
                        .fold(0u64, u64::saturating_add);
                    job.candidates = digest;
                    job.asked_round = 0;
                }
                job
            }
            None => {
                // Objects an upload under way already found on the server, or sent, are not
                // asked about again now; the ask before the commit covers them.
                let ask: Vec<ObjectId> = candidates
                    .iter()
                    .filter(|id| !self.known_present.contains(id))
                    .copied()
                    .collect();
                let carried = ask.len() < candidates.len();
                let missing = Self::ask_missing(cx, &self.folder, &ask)?;
                let lacking: BTreeSet<ObjectId> = missing.iter().copied().collect();
                self.known_present
                    .extend(ask.iter().filter(|id| !lacking.contains(id)).copied());
                let (order, sizes, sources, left) = Self::queue_for(encoded, disk, &missing);
                UploadJob {
                    root: encoded.root,
                    generation,
                    candidates: digest,
                    queue: order.into(),
                    sizes,
                    sources,
                    left,
                    sent: Vec::new(),
                    sent_round: self.round_seq,
                    since_stage: (0, 0),
                    asked_round: if carried { 0 } else { self.round_seq },
                    stalled: false,
                    flight: None,
                }
            }
        };
        // Uploads of other plans take nothing new while this one runs: their workers end once
        // their request is answered, and the answers stay for a round that takes that job up
        // again, so at most one lane per folder keeps threads waiting.
        for other in &mut self.jobs {
            if let Some(lane) = &mut other.flight {
                lane.close();
            }
        }
        let result = self.run_job(cx, crypto, encoded, candidates, disk, stage, &mut job);
        match &result {
            // The disk changed: the next scan and plan start a new upload.
            Err(PublishFailure::LocalChanged) => {}
            _ => self.store_job(job),
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn run_job(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        encoded: &Encoded,
        candidates: &BTreeSet<ObjectId>,
        disk: &Tree,
        stage: bool,
        job: &mut UploadJob,
    ) -> Result<UploadStep, PublishFailure> {
        // Did the server keep what the last round sent? One that lists it as missing again
        // keeps nothing (a hostile or broken server): it is sent again, but the upload's cuts
        // no longer ask for an immediate next round (security review of the budget, L2).
        if job.sent_round != self.round_seq && !job.sent.is_empty() {
            let lost = Self::ask_missing(cx, &self.folder, &job.sent)?;
            job.sent.clear();
            job.stalled = !lost.is_empty();
            for id in &lost {
                self.known_present.remove(id);
            }
            Self::requeue(job, encoded, disk, &lost);
        }
        let until = self.upload_deadline(cx);
        self.upload_left = Some(job.left);
        let width = cx
            .settings
            .upload_workers
            .clamp(1, crate::upload::MAX_UPLOAD_WORKERS);
        let folder = self.folder;
        // Objects a former round left in flight are booked by this one; otherwise a new lane.
        // Worker threads pay off only with more than one object to send.
        let carried = match job.flight.take() {
            // A lane closed while the folder did not run: its last answers are booked first,
            // then a new lane with workers of its own takes over.
            Some(mut closed) if closed.closed() => {
                let mut stop: Option<Stop> = None;
                let mut unsealable: Vec<ObjectId> = Vec::new();
                loop {
                    match closed.next(Some(UPLOAD_WAIT_SLICE)) {
                        Next::Done(done) => {
                            self.collect(cx, job, &mut closed, done, &mut stop, &mut unsealable)
                        }
                        Next::Waiting if Self::spent(cx, until) => {
                            job.flight = Some(closed);
                            Stop::halt(&mut stop, Stop::Yield);
                            let stop = stop.unwrap_or(Stop::Yield);
                            return self.finish(cx, crypto, job, stop, &unsealable);
                        }
                        Next::Waiting => {}
                        Next::Empty => break,
                    }
                }
                if let Some(stop) = stop {
                    return self.finish(cx, crypto, job, stop, &unsealable);
                }
                None
            }
            other => other,
        };
        let mut lane = match carried {
            Some(lane) => lane,
            None => {
                let uploader = if width > 1 && job.queue.len() > 1 {
                    cx.server.uploader()?
                } else {
                    None
                };
                match uploader {
                    // No more workers than objects to send: a small upload starts few threads.
                    Some(uploader) => Lane::workers(width.min(job.queue.len()), uploader, folder),
                    None => Lane::inline(folder),
                }
            }
        };
        let fs: &dyn FileSystem = cx.fs;
        let keys = crypto.writable().ok();
        let result = std::thread::scope(|scope| {
            // The round's sealing threads borrow the disk and the keys; they end with the scope,
            // once what was handed to them is sealed. The workers that send are not scoped.
            let sealers = lane.sealers(scope, fs, keys);
            self.dispatch(
                cx,
                crypto,
                encoded,
                candidates,
                disk,
                stage,
                job,
                until,
                &mut lane,
                sealers.as_ref(),
            )
        });
        // What is still in flight stays with the job; an empty lane drops and ends its workers.
        if lane.in_flight() > 0 {
            job.flight = Some(lane);
        }
        cx.server.settle_uploads();
        result
    }

    /// The upload loop of [`Self::run_job`] (module [`crate::upload`]): dispatches objects in
    /// the queue's order while the lane has room, books every result as it comes, and stops
    /// dispatching at the first reason to stop (done, a stage due, the deadline, a changed disk,
    /// an error). It waits for the answers in flight in slices of [`UPLOAD_WAIT_SLICE`] and
    /// books each as one upload at a time did (`sent` for the next round's check,
    /// `known_present`, the bytes left and the stage counters); once the deadline passes or a
    /// command waits, it returns without the answers still out, which stay in the lane for the
    /// next round, so a slow server never holds the engine thread.
    #[allow(clippy::too_many_arguments)]
    fn dispatch(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        encoded: &Encoded,
        candidates: &BTreeSet<ObjectId>,
        disk: &Tree,
        stage: bool,
        job: &mut UploadJob,
        until: Option<i64>,
        lane: &mut Lane,
        sealers: Option<&Sealers>,
    ) -> Result<UploadStep, PublishFailure> {
        let mut dispatched = 0usize;
        let mut stop: Option<Stop> = None;
        let mut unsealable: Vec<ObjectId> = Vec::new();
        loop {
            if stop.is_none() {
                stop = self.fill(
                    cx,
                    crypto,
                    encoded,
                    candidates,
                    disk,
                    stage,
                    job,
                    until,
                    lane,
                    sealers,
                    &mut dispatched,
                );
            }
            match lane.next(Some(UPLOAD_WAIT_SLICE)) {
                Next::Done(done) => self.collect(cx, job, lane, done, &mut stop, &mut unsealable),
                Next::Waiting => {
                    if Self::spent(cx, until) {
                        // The answers still out stay in the lane; a stage waits for them in a
                        // later round, a failure or changed disk is reported now.
                        Stop::halt(&mut stop, Stop::Yield);
                        let stop = stop.unwrap_or(Stop::Yield);
                        return self.finish(cx, crypto, job, stop, &unsealable);
                    }
                }
                Next::Empty => {
                    // `fill` either dispatched or named a reason to stop; nothing else empties
                    // the lane, so a missing reason is a broken invariant, reported as an error.
                    let stop = stop.unwrap_or(Stop::Error(PublishFailure::Error(
                        SyncError::Invalid("the upload stopped without a reason"),
                    )));
                    return self.finish(cx, crypto, job, stop, &unsealable);
                }
            }
        }
    }

    /// Dispatches objects while the lane has room; returns why it stopped dispatching for good,
    /// or `None` while it waits for objects in flight.
    #[allow(clippy::too_many_arguments)]
    fn fill(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        encoded: &Encoded,
        candidates: &BTreeSet<ObjectId>,
        disk: &Tree,
        stage: bool,
        job: &mut UploadJob,
        until: Option<i64>,
        lane: &mut Lane,
        sealers: Option<&Sealers>,
        dispatched: &mut usize,
    ) -> Option<Stop> {
        while lane.in_flight() < lane.width() {
            if job.queue.is_empty() {
                // The ask before the upload reports done waits for every answer, so it sees
                // what is still in flight as sent.
                if lane.in_flight() > 0 {
                    return None;
                }
                if job.asked_round != self.round_seq {
                    let all: Vec<ObjectId> = candidates.iter().copied().collect();
                    let missing = match Self::ask_missing(cx, &self.folder, &all) {
                        Ok(missing) => missing,
                        Err(e) => return Some(Stop::Error(e.into())),
                    };
                    job.asked_round = self.round_seq;
                    if !missing.is_empty() {
                        for id in &missing {
                            self.known_present.remove(id);
                        }
                        Self::requeue(job, encoded, disk, &missing);
                        self.upload_left = Some(job.left);
                        continue;
                    }
                }
                return Some(Stop::Done);
            }
            if stage && self.stage_due(cx, job) {
                return Some(Stop::Stage);
            }
            // Checked before each object but the first, so every round moves the upload on.
            if *dispatched > 0 && Self::spent(cx, until) {
                return Some(Stop::Yield);
            }
            let id = job.queue.pop_front()?;
            let payload = if let Some(blob) = encoded.sealed.get(&id) {
                Payload::Sealed(Bytes::copy_from_slice(blob))
            } else {
                let Some((path, index, _)) = job.sources.get(&id) else {
                    // A chunk this device cannot produce: the disk changed, scan again.
                    return Some(Stop::Changed);
                };
                if let Err(e) = crypto.writable() {
                    job.queue.push_front(id);
                    return Some(Stop::Error(SyncError::from(e).into()));
                }
                let nonce = match draw_nonce(cx.entropy) {
                    Ok(nonce) => nonce,
                    Err(e) => {
                        job.queue.push_front(id);
                        return Some(Stop::Error(SyncError::from(e).into()));
                    }
                };
                Payload::Chunk {
                    path: path.clone(),
                    index: *index,
                    nonce,
                }
            };
            lane.submit(
                Work { id, payload },
                sealers,
                cx.fs,
                crypto.writable().ok(),
                &mut *cx.server,
            );
            *dispatched += 1;
        }
        None
    }

    /// Books one result of the lane.
    fn collect(
        &mut self,
        cx: &mut Ctx<'_>,
        job: &mut UploadJob,
        lane: &mut Lane,
        done: Done,
        stop: &mut Option<Stop>,
        unsealable: &mut Vec<ObjectId>,
    ) {
        let id = done.id;
        let (blob, mut error) = match done.outcome {
            Outcome::Sent => {
                self.book_sent(cx, job, id);
                return;
            }
            Outcome::Unsealable => {
                unsealable.push(id);
                Stop::halt(stop, Stop::Changed);
                return;
            }
            Outcome::Failed { blob, error } => (blob, error),
        };
        if error.code() == Some(ErrorCode::Unauthorized) && !blob.is_empty() {
            // The session ran out under a worker, which never signs in: this connection signs
            // in again, which renews the token for the workers as well.
            match cx.server.put_object(&self.folder, &id, &blob) {
                Ok(_) => {
                    self.book_sent(cx, job, id);
                    return;
                }
                Err(e) => error = e,
            }
        }
        job.queue.push_front(id);
        // The client already waited as `Retry-After` asked. Still refused: other uploads of the
        // account hold the server's slots (another device, a folder of the account), so this
        // upload goes on with one object less at once instead of failing the round; one object
        // at a time that is still refused is an error as before.
        if error.code() == Some(ErrorCode::RateLimited) && lane.narrow() {
            return;
        }
        Stop::halt(stop, Stop::Error(error.into()));
    }

    /// Books an object the server now holds, as one upload at a time did.
    fn book_sent(&mut self, cx: &Ctx<'_>, job: &mut UploadJob, id: ObjectId) {
        let size = job.sizes.get(&id).copied().unwrap_or(0);
        cx.settings.progress.moved(size);
        job.left = job.left.saturating_sub(size);
        job.since_stage.0 = job.since_stage.0.saturating_add(size);
        job.since_stage.1 = job.since_stage.1.saturating_add(1);
        if job.sent_round != self.round_seq {
            job.sent.clear();
            job.sent_round = self.round_seq;
        }
        job.sent.push(id);
        self.known_present.insert(id);
        self.upload_left = Some(job.left);
    }

    /// The result of an upload loop that stopped with nothing in flight.
    fn finish(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        job: &mut UploadJob,
        stop: Stop,
        unsealable: &[ObjectId],
    ) -> Result<UploadStep, PublishFailure> {
        match stop {
            Stop::Done => {
                self.upload_left = None;
                Ok(UploadStep::Done)
            }
            Stop::Stage => Ok(UploadStep::StageDue(job.queue.iter().copied().collect())),
            Stop::Yield => {
                // A stalled upload waits for the loop's pause instead of running without one.
                self.cut |= !job.stalled;
                Err(PublishFailure::Yielded)
            }
            Stop::Changed => {
                let queued: Vec<ObjectId> =
                    unsealable.iter().chain(job.queue.iter()).copied().collect();
                for id in unsealable {
                    if let Some((_, _, content)) = job.sources.get(id) {
                        let content = *content;
                        self.mark_rehash(cx, crypto, content, &queued, &job.sources)?;
                    }
                }
                Err(PublishFailure::LocalChanged)
            }
            Stop::Error(e) => Err(e),
        }
    }

    /// Whether the upload sent enough since its last intermediate commit for the next one, and
    /// the last one is long enough ago.
    fn stage_due(&self, cx: &Ctx<'_>, job: &UploadJob) -> bool {
        let volume = job.since_stage.0 >= cx.settings.stage_bytes
            || job.since_stage.1 >= cx.settings.stage_objects;
        let now = cx.clock.now_ms();
        // An intermediate commit leaves at least one commit of the device's allowance for the
        // final one.
        volume
            && self.commits_left.is_none_or(|n| n >= 2)
            && self
                .last_stage_ms
                .is_none_or(|at| !(0..cx.settings.stage_interval_ms).contains(&(now - at)))
    }

    /// Uploads what the plan's tree adds to `parent`, committing the files complete so far
    /// whenever enough went up ([`FolderSettings::stage_bytes`], finding C): each intermediate
    /// commit is the server's tree plus whole files whose every chunk is on the server, with the
    /// directories they need ([`stage_ready`]); a file still uploading never shows. Other devices
    /// see a large first upload grow, and what went up is named by a commit long before the
    /// server's collection would delete it. `parent` follows each intermediate commit.
    fn upload_in_stages(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        p: &Plan,
        encoded: &Encoded,
        parent: &mut BTreeSet<ObjectId>,
    ) -> Result<(), PublishFailure> {
        let limit = delta_limit(cx.settings.max_delta_ids);
        loop {
            let added: BTreeSet<ObjectId> = encoded.reachable.difference(parent).copied().collect();
            let queued = match self.upload_part(cx, crypto, encoded, &added, &p.disk, true)? {
                UploadStep::Done => return Ok(()),
                UploadStep::StageDue(queued) => queued,
            };
            let ready = |content: &ContentKey| {
                encoded
                    .chunks
                    .get(content)
                    .is_some_and(|chunks| chunks.iter().all(|c| !queued.contains(c)))
            };
            let before = self.view.frontier().map(|f| f.commit);
            if let Some(stage) = stage_ready(&self.remote, &p.merged, encoded, limit / 2, &ready) {
                self.publish_stage(cx, crypto, &stage, &p.disk)?;
                self.last_stage_ms = Some(cx.clock.now_ms());
                // The disk held the head before fully, and the stage adds whole files from the
                // disk: the disk holds the stage as well, so the final commit needs no side
                // commit on the older head. A folder never fully synced keeps no base.
                if self
                    .meta
                    .sync_base
                    .is_some_and(|b| Some(b.entry.commit) == before)
                {
                    if let (Some(frontier), Some(root)) =
                        (self.view.frontier(), self.meta.remote_root)
                    {
                        self.meta.sync_base = Some(SyncBase {
                            entry: ChainRec::from(frontier),
                            root,
                        });
                    }
                }
                self.save(cx.store)?;
                *parent = self.reachable_of(self.meta.remote_root, crypto, cx)?;
                // The stage's own upload is done; only this publish's job is kept.
                let root = encoded.root;
                self.jobs.retain(|j| j.root == root);
            }
            // Nothing complete to commit yet (one large file still going up): the next stage
            // comes after the next volume.
            if let Some(job) = self.jobs.iter_mut().find(|j| j.root == encoded.root) {
                job.since_stage = (0, 0);
            }
        }
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

    /// Publishes the plan's tree. `slot` holds its encoding: one a cut round kept, or `None` to
    /// encode now; it keeps the encoding afterwards for a round that is cut again.
    fn publish(
        &mut self,
        cx: &mut Ctx<'_>,
        p: &Plan,
        slot: &mut Option<Encoded>,
    ) -> Result<(), PublishFailure> {
        let chain_generation = self.view.frontier().map(|f| f.generation);
        let crypto = cx.account.folder_crypto(&self.folder, chain_generation)?;
        let mut encoded = match slot.take() {
            Some(encoded) => encoded,
            None => codec::encode(&p.merged, &crypto, cx.store, cx.entropy)?,
        };
        let result = self.publish_encoded(cx, &crypto, p, &mut encoded);
        *slot = Some(encoded);
        if result.is_ok() && self.gated {
            self.publish_tokens = self.publish_tokens.saturating_sub(1);
            self.publish_filled_ms.get_or_insert(cx.clock.now_ms());
        }
        if result.is_ok() {
            // Everything is committed: the uploads' state starts afresh with the next change.
            self.jobs.clear();
            self.known_present.clear();
        }
        result
    }

    fn publish_encoded(
        &mut self,
        cx: &mut Ctx<'_>,
        crypto: &FolderCrypto,
        p: &Plan,
        encoded: &mut Encoded,
    ) -> Result<(), PublishFailure> {
        let limit = delta_limit(cx.settings.max_delta_ids);
        let mut parent = self.reachable_of(self.meta.remote_root, crypto, cx)?;
        // Too many changes for one commit, as a diff and as the full set: publish valid
        // intermediate trees first, each the server's tree plus whole new files and their new
        // directories (open point B). Half the limit for the new objects leaves room for the
        // old versions a stage drops.
        while !fits_one_commit(&parent, &encoded.reachable, limit) {
            let Some(stage) = stage_tree(&self.remote, &p.merged, encoded, limit / 2) else {
                return Err(SyncError::Invalid("too many changes for one commit").into());
            };
            self.publish_stage(cx, crypto, &stage, &p.disk)?;
            *encoded = codec::encode(&p.merged, crypto, cx.store, cx.entropy)?;
            parent = self.reachable_of(self.meta.remote_root, crypto, cx)?;
        }
        // A large upload goes out with intermediate commits of the files complete so far, before
        // the side commit and the commit of the whole tree (finding C).
        self.upload_in_stages(cx, crypto, p, encoded, &mut parent)?;
        if let Some(due) = self.publish_hold(cx) {
            self.hold_until = Some(due);
            return Err(PublishFailure::Held);
        }

        // A side commit when the server moved on since the last fully synced head.
        let frontier = self.view.frontier().copied();
        let side_base = self
            .meta
            .sync_base
            .filter(|b| frontier.is_some_and(|f| f.commit != b.entry.commit));
        let mut side: Option<(SignedCommit, ReferenceDelta)> = None;
        if let (Some(base), Some(_)) = (side_base, frontier) {
            if let Ok(side_enc) = codec::encode(&p.disk, crypto, cx.store, cx.entropy) {
                let base_reach = self.reachable_of(Some(base.root), crypto, cx)?;
                // A side commit's delta is always a diff against its base. One that would not
                // fit one commit is left out: the merge commit alone loses nothing, as with an
                // expired base.
                if let Some((side_delta, side_digest)) =
                    diff_delta(&base_reach, &side_enc.reachable, limit)
                {
                    let side_added: BTreeSet<ObjectId> = side_delta.added.iter().copied().collect();
                    self.upload(cx, crypto, &side_enc, &side_added, &p.disk)?;
                    codec::remember_uploaded(&side_enc, &self.folder, cx.store)
                        .map_err(SyncError::from)?;
                    let content = self.content(cx, crypto, side_enc.root, side_digest)?;
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
            crypto,
            &p.merged,
            encoded,
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
        // Every call counts against the server's limit, also one it refuses.
        self.commits_sent = self.commits_sent.saturating_add(1);
        if let Some(left) = &mut self.commits_left {
            *left = left.saturating_sub(1);
        }
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
        // A remote item at the path of a new file that waits for its hash is left alone this
        // round: written now it would meet the file on disk (`Exists`) and stay in the
        // cannot-sync list for good, or come back as a needless conflict copy. Once the file is
        // hashed the merge sees both (security review of the budget, H1).
        if !self.deferred.is_empty() {
            let key = |path: &[String]| -> Vec<String> {
                path.iter()
                    .map(|n| hangar_drive_protocol::name::case_key(n))
                    .collect()
            };
            let waiting: BTreeSet<Vec<String>> = self.deferred.keys().map(|p| key(p)).collect();
            let at_waiting: Vec<ItemId> = p
                .merged
                .iter()
                .filter(|(id, _)| !p.disk.contains(id))
                .filter(|(id, _)| {
                    p.merged
                        .path(id)
                        .is_some_and(|path| waiting.contains(&key(&path)))
                })
                .map(|(id, _)| *id)
                .collect();
            for id in at_waiting {
                skip.extend(p.merged.subtree(&id));
                // Next round at once only while the scan moves on (LOW 3).
                report.more |= self.hashed_in_scan;
            }
        }
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
        // Files the base lacks that this round may bring in: once synced, they count as just
        // arrived for the long window (security review M3), unless the folder was never fully
        // synced (a first download or "download again" is no baseline).
        let baseline = self.meta.sync_base.is_some();
        let arriving: Vec<ItemId> = if baseline {
            p.merged
                .iter()
                .filter(|(id, n)| !n.is_dir() && !self.synced.contains(id))
                .map(|(id, _)| *id)
                .collect()
        } else {
            Vec::new()
        };
        let mut work = p.disk;
        // What the executor will write, in its order (item ID), for the lane to fetch ahead:
        // the chunks of files whose content the disk lacks, up to a few windows ahead.
        let mut ahead: Vec<(ObjectId, u64)> = Vec::new();
        let mut planned = 0u64;
        for (id, node) in p.merged.iter() {
            if planned >= 4 * FETCH_WINDOW_BYTES {
                break;
            }
            let Some(v) = node.kind.file() else {
                continue;
            };
            if skip.contains(id)
                || work
                    .get(id)
                    .and_then(|n| n.kind.file())
                    .is_some_and(|w| w.content == v.content)
            {
                continue;
            }
            let Ok(Some(list)) = cx.store.chunk_list(&self.folder, &v.content) else {
                continue;
            };
            let first = self
                .partial_downloads
                .get(&v.content)
                .map_or(0, |s| s.chunks);
            // The bound holds per chunk, so one large file cannot plan far past it.
            for (index, chunk) in list.chunks.iter().enumerate() {
                if planned >= 4 * FETCH_WINDOW_BYTES {
                    break;
                }
                if (index as u64) < first {
                    continue;
                }
                let bytes = chunk_len(v.size, index as u64);
                ahead.push((*chunk, bytes));
                planned = planned.saturating_add(bytes);
            }
        }
        // Part files of contents the plan no longer brings in go (security review N1): the
        // plaintext of a file another device replaced or deleted stays on no disk.
        let wanted: BTreeSet<ContentKey> = p
            .merged
            .iter()
            .filter_map(|(id, node)| {
                let v = node.kind.file()?;
                let on_disk = work.get(id).and_then(|n| n.kind.file()).map(|w| w.content);
                (on_disk != Some(v.content)).then_some(v.content)
            })
            .collect();
        let stale: Vec<ContentKey> = self
            .partial_downloads
            .keys()
            .filter(|k| !wanted.contains(k))
            .copied()
            .collect();
        for content in stale {
            if let Some(gone) = self.partial_downloads.remove(&content) {
                let _ = cx.fs.partial_remove(&gone.part.name);
            }
        }
        // Worker threads pay off only with more than one object to fetch.
        let mut lane = match self.fetch.take() {
            Some(lane) => lane,
            None if ahead.len() > 1 => match cx.server.fetcher()? {
                Some(fetcher) => FetchLane::workers(
                    DOWNLOAD_WORKERS,
                    fetcher,
                    self.folder,
                    cx.settings.fetch_budget.clone(),
                ),
                None => FetchLane::inline(self.folder),
            },
            None => FetchLane::inline(self.folder),
        };
        lane.ahead(ahead);
        let mut disk = FsDisk {
            fs: cx.fs,
            server: &mut *cx.server,
            store: &*cx.store,
            crypto: &reader,
            file_ids: &mut self.file_ids,
            dirty: &mut self.file_ids_dirty,
            downloaded: 0,
            clock: cx.clock,
            until: self.budget.map(|b| b.phase_until(now)),
            interrupt: &cx.settings.interrupt,
            cut: false,
            lane: &mut lane,
            partials: &mut self.partial_downloads,
            progress: &cx.settings.progress,
        };
        let result = apply(&p.merged, &mut work, &mut self.synced, &skip, &mut disk);
        let cut = disk.cut;
        if cut {
            report.more = true;
        }
        // Chunks in flight or fetched ahead stay for the next round of a cut run; a finished
        // run drops the lane, which ends its workers.
        if cut && !lane.idle() {
            self.fetch = Some(lane);
        }
        report.applied = result.done.len();
        // Incoming file deletes carried out, for the window of the incoming guard.
        let carried = result
            .done
            .iter()
            .filter(|id| {
                before.get(id).is_some_and(|n| !n.is_dir())
                    && !p.merged.contains(id)
                    && !self.meta.incoming_approved.contains(id)
                    && !self.meta.fresh_files.contains_key(id)
            })
            .count() as u64;
        if carried > 0 {
            self.meta.recent_incoming.push((now, carried));
        }
        self.note_fresh(now, &arriving, baseline);
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
        // An approved delete that went out, or whose item is back, leaves the approval.
        let (synced, local) = (&self.synced, &self.local);
        self.meta
            .approved
            .retain(|id| synced.contains(id) && !local.contains(id));
        // An approved incoming delete that was carried out leaves the approval.
        self.meta
            .incoming_approved
            .retain(|id| synced.contains(id) && local.contains(id));
        self.applied_timeline = self.meta.timeline.len();
        Ok(())
    }

    // -- Person's actions -------------------------------------------------------------------

    /// Publishes `tree` as a normal commit on the current head: the restore of ADR 0001,
    /// section 5 ("a restore is a commit"). Local changes are merged in the next round.
    pub fn publish_tree(&mut self, cx: &mut Ctx<'_>, tree: Tree) -> Result<(), SyncError> {
        let change = UndoState::between(&self.remote, &tree);
        // What the person's own action removes is their decision: the incoming guard lets it
        // pass on this device (other devices ask).
        let dropped: Vec<ItemId> = self
            .remote
            .ids()
            .filter(|id| !tree.contains(id))
            .copied()
            .collect();
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
        // A person's publish asks the server afresh, as a new round does.
        self.round_seq = self.round_seq.wrapping_add(1);
        match self.publish(cx, &p, &mut None) {
            Ok(()) => {
                self.last_action = Some(change);
                if !dropped.is_empty() {
                    self.meta.incoming_approved.extend(dropped);
                    self.save(cx.store)?;
                }
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
            // A person's action runs outside a round, without a budget, so it never yields.
            Err(PublishFailure::Yielded) => Err(SyncError::Invalid("the upload was cut off")),
            // Not gated either.
            Err(PublishFailure::Held) => Err(SyncError::Invalid("the commit was held")),
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
        let mut ids = EntropyIds::new(cx.entropy);
        let (tree, name) = graft(
            &self.remote,
            &old,
            item,
            &cx.settings.words,
            &date,
            &mut ids,
        )?;
        ids.check()?;
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
            let mut ids = EntropyIds::new(cx.entropy);
            tree = graft(&tree, &old, item, &cx.settings.words, &date, &mut ids)?.0;
            ids.check()?;
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
        // A whole round: the undo must come after every local change, so no budget cuts it.
        // The person's undo is not held by the interval or the allowance.
        let report = self.round_with(cx, None, false)?;
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
        self.meta.approved.clear();
        self.meta.recent_deletes.clear();
        self.meta.incoming_held.clear();
        self.meta.incoming_devices.clear();
        self.meta.incoming_approved.clear();
        self.meta.recent_incoming.clear();
        self.meta.long_deletes.clear();
        self.meta.file_minimums.clear();
        self.meta.fresh_files.clear();
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
        let mut ids = EntropyIds::new(cx.entropy);
        let merged = crate::merge::merge3(&base_tree, &remote, &self.local, &labels, &mut ids);
        ids.check()?;
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
        taken: Option<Vec<TimelineRec>>,
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
        if let Some(records) = taken {
            // The heads the barrier covers, so "Undo a device" finds them (N2).
            self.meta.timeline.extend(records);
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

    /// The frontier's signed commit, if it is stored.
    pub fn frontier_commit(&self) -> Option<SignedCommit> {
        self.meta
            .frontier_wire
            .as_ref()
            .and_then(|w| SignedCommit::decode(w.as_bytes()).ok())
    }

    /// Takes a pulled delta, checked with every rule, as the new verified state (the removal
    /// job after its barrier check).
    pub(crate) fn take_outcome(
        &mut self,
        cx: &mut Ctx<'_>,
        pulled: Pulled,
    ) -> Result<(), SyncError> {
        self.meta.timeline.extend(pulled.timeline);
        self.meta.full_next |= pulled.unchecked;
        if let Some(head) = &pulled.last_head {
            let reader = cx.account.folder_reader(&self.folder)?;
            let tree = codec::decode(&head.commit.root, &reader, cx.store, cx.server)?;
            self.set_remote(tree);
            self.meta.remote_root = Some(head.commit.root);
            self.meta.frontier_wire = Some(Blob(head.wire.clone()));
        }
        self.view = pulled.view;
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

/// Whether a refused pull may pass once the account is read again: a commit names a log head
/// or a generation this device does not know yet, or the device log changed under a stored
/// pull.
fn needs_refresh(e: &SyncError) -> bool {
    use hangar_drive_crypto::commit::{ChainError, CommitError};
    matches!(
        e,
        SyncError::Commit(CommitError::AheadOfLog { .. })
            | SyncError::Chain(ChainError::Commit(CommitError::AheadOfLog { .. }))
            | SyncError::Chain(ChainError::UnknownGeneration(_))
            | SyncError::Chain(ChainError::LogChanged)
    )
}

/// The IDs one commit's delta may list: the setting, at least 1 and at most
/// `hangar_drive_protocol::api::MAX_REFERENCE_DELTA_IDS`.
/// The sum of `records` within `window` before `now`; older records go.
fn window_sum(records: &mut Vec<(i64, u64)>, now: i64, window: i64) -> u64 {
    // A record from the future (the clock went back) counts until it is a window ahead.
    records.retain(|(at, _)| (now - at).abs() < window);
    records.iter().map(|(_, n)| *n).sum()
}

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

/// A tree as [`DeltaWalk::goto`] reached it.
#[derive(Debug, Clone)]
enum Seen {
    /// Readable: the move to it from where the set was (`None` when the move failed and the
    /// tree was read alone), and the set's manifests and chunks before the move.
    Set {
        moved: Option<codec::Transition>,
        manifests_before: u64,
        chunks_before: u64,
    },
    /// An object the server no longer holds.
    Gone,
    /// Beyond the limits of a folder.
    Limit,
}

impl Seen {
    /// Manifests and chunks the move dropped, against those before it. A full delta counts
    /// chunks only: a barrier or a repair seals manifests again, which renames them without
    /// dropping a file, while the chunks of a dropped file go in every case.
    fn drops(&self, full: bool) -> DropCount {
        let Seen::Set {
            moved: Some(moved),
            manifests_before,
            chunks_before,
        } = self
        else {
            return DropCount {
                dropped: 0,
                before: 0,
            };
        };
        let (mut dropped, mut before) = (moved.dropped_chunks, *chunks_before);
        if !full {
            dropped += moved.dropped_manifests;
            before += manifests_before;
        }
        DropCount { dropped, before }
    }
}

impl codec::Transition {
    /// The diff digest of this move, as `DeltaDigest::diff` of the two sets gives it.
    fn digest(&self) -> DeltaDigest {
        DeltaDigest::of(false, &self.added, &self.dropped).unwrap_or(DeltaDigest {
            full: false,
            hash: [0; 32],
        })
    }
}

/// The counted reachable set of [`FolderSync::verify_tree_deltas`] with the roots found
/// unreadable, which are not read again.
#[derive(Debug, Default)]
struct DeltaWalk {
    state: codec::ReachState,
    unreadable: BTreeMap<ObjectId, Seen>,
}

impl DeltaWalk {
    /// Moves the set to the tree of `target` (`None`: the empty tree).
    fn goto(
        &mut self,
        target: Option<ObjectId>,
        crypto: &FolderCrypto,
        cx: &mut Ctx<'_>,
    ) -> Result<Seen, SyncError> {
        if let Some(known) = target.and_then(|root| self.unreadable.get(&root)) {
            return Ok(known.clone());
        }
        let (manifests_before, chunks_before) = (self.state.manifests(), self.state.chunks());
        let from_elsewhere = !self.state.is_empty();
        let mut graph = codec::StoreGraph {
            crypto,
            store: &mut *cx.store,
            server: &mut *cx.server,
        };
        let mut result = self.state.goto(target, &mut graph).map(Some);
        // A move also reads the old tree's dropped nodes (from the cache); a failure there is
        // not the target's. The set is empty after any failure, so one more try reads the
        // target alone and finds out; that read is no move from the old tree, which counts as
        // unreadable then, as a full read of it would have found.
        if from_elsewhere && result.is_err() {
            result = self.state.goto(target, &mut graph).map(|_| None);
        }
        let seen = match result {
            Ok(moved) => {
                return Ok(Seen::Set {
                    moved,
                    manifests_before,
                    chunks_before,
                })
            }
            Err(CodecError::Limit) => Seen::Limit,
            Err(CodecError::Net(NetError::Server(body))) if body.code == ErrorCode::NotFound => {
                Seen::Gone
            }
            Err(e) => return Err(e.into()),
        };
        if let Some(root) = target {
            self.unreadable.insert(root, seen.clone());
        }
        Ok(seen)
    }

    /// The full digest of the set.
    fn full_digest(&self) -> DeltaDigest {
        let all: Vec<ObjectId> = self.state.ids().copied().collect();
        DeltaDigest::of(true, &all, &[]).unwrap_or(DeltaDigest {
            full: true,
            hash: [0; 32],
        })
    }
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

/// One intermediate commit of a large upload (finding C of the second performance review): the
/// server's tree `remote` plus the files of `target` whose content is `ready` (every chunk on the
/// server) and that `remote` lacks or holds with other content, in path order, each with the
/// directories it needs, until their objects reach `budget`. Like [`stage_tree`], every stage is
/// a whole tree: no file without its content, no item without its parents, no name twice in a
/// directory; moves, renames, deletes and directories without a new file wait for the commit of
/// `target` itself. Unlike [`stage_tree`] it walks the tree once instead of copying it for every
/// file, since it runs every few hundred MiB of a first upload of any size; a name that
/// collides with one in the directory by any of its keys (a broader test than a collision)
/// waits for that commit too.
///
/// `None` when no file is ready or nothing fits the budget.
pub fn stage_ready(
    remote: &Tree,
    target: &Tree,
    encoded: &Encoded,
    budget: usize,
    ready: &dyn Fn(&ContentKey) -> bool,
) -> Option<Tree> {
    use hangar_drive_protocol::name::{case_key, fold_key, upper_key};
    let keys = |name: &str| -> [String; 4] {
        [
            name.to_owned(),
            case_key(name),
            fold_key(name),
            upper_key(name),
        ]
    };
    let mut stage = remote.clone();
    // The root's directory node changes with the first staged file.
    let mut spent = 1usize;
    let mut staged = 0usize;
    // Directories whose node this stage already changes, each counted once.
    let mut touched: BTreeSet<ItemId> = BTreeSet::new();
    // The name keys of the entries of each directory that takes a new entry, built once.
    let mut taken: BTreeMap<ItemId, BTreeSet<String>> = BTreeMap::new();
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
    let mut files: Vec<(Vec<String>, ItemId)> = target
        .iter()
        .filter(|(id, n)| {
            n.kind.file().is_some_and(|v| ready(&v.content))
                && remote.get(id).is_none_or(|old| old.kind != n.kind)
        })
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
            Some(old) if old.is_dir() => continue,
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
                let mut chain: Vec<(ItemId, Node)> = Vec::new();
                let mut at = node.parent;
                while at != ROOT && !stage.contains(&at) {
                    let Some(dir) = target.get(&at) else {
                        break;
                    };
                    chain.push((at, dir.clone()));
                    at = dir.parent;
                }
                if at != ROOT && !stage.get(&at).is_some_and(Node::is_dir) {
                    continue;
                }
                // Only the topmost new entry joins an existing directory; the ones below it
                // go into directories this stage creates.
                let top_name = chain.last().map_or(&node.name, |(_, dir)| &dir.name);
                let names = taken.entry(at).or_insert_with(|| {
                    stage
                        .children(&at)
                        .filter_map(|c| stage.get(c))
                        .flat_map(|n| keys(&n.name))
                        .collect()
                });
                let top_keys = keys(top_name);
                if top_keys.iter().any(|k| names.contains(k)) {
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
                names.extend(top_keys);
                for (dir_id, dir) in chain.into_iter().rev() {
                    stage.insert(dir_id, dir);
                    touched.insert(dir_id);
                }
                stage.insert(id, node.clone());
                touched.extend(above);
                spent += extra;
            }
        }
        staged += 1;
    }
    if staged == 0 || stage.check().is_err() {
        return None;
    }
    Some(stage)
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

#[cfg(test)]
mod tests {
    use super::*;

    struct Broken;

    impl Entropy for Broken {
        fn fill(&mut self, _: &mut [u8]) -> Result<(), hangar_drive_crypto::EntropyError> {
            Err(hangar_drive_crypto::EntropyError)
        }
    }

    /// A failing generator gives distinct IDs for the rest of the run and the run is refused,
    /// never two items under one constant ID (security review, info).
    #[test]
    fn a_failing_generator_gives_distinct_ids_and_an_error() {
        let mut broken = Broken;
        let mut ids = EntropyIds::new(&mut broken);
        let a = ids.new_item_id();
        let b = ids.new_item_id();
        assert_ne!(a, b);
        assert!(matches!(ids.check(), Err(SyncError::Entropy(_))));
    }

    /// Metadata stored before the incoming guard existed still loads, with no question open.
    #[test]
    fn metadata_without_the_incoming_guard_fields_loads() {
        let mut stored = serde_json::to_value(FolderMeta {
            name: "Docs".into(),
            ..FolderMeta::default()
        })
        .unwrap();
        let fields = stored.as_object_mut().unwrap();
        for key in [
            "incoming_held",
            "incoming_revision",
            "incoming_devices",
            "incoming_approved",
            "recent_incoming",
            "long_deletes",
            "file_minimums",
            "fresh_files",
        ] {
            assert!(fields.remove(key).is_some(), "{key}");
        }
        let meta: FolderMeta = serde_json::from_value(stored).unwrap();
        assert_eq!(meta.name, "Docs");
        assert!(meta.incoming_held.is_empty() && meta.incoming_approved.is_empty());
        assert_eq!(meta.incoming_revision, 0);
        assert!(meta.incoming_devices.is_empty() && meta.recent_incoming.is_empty());
        assert!(meta.long_deletes.is_empty() && meta.file_minimums.is_empty());
        assert!(meta.fresh_files.is_empty());
    }
}
