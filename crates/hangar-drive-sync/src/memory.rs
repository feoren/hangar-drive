//! In-memory implementations of every port, for the seeded simulation and the tests.
//!
//! - [`MemFs`]: a sync root with exact or case-insensitive names, file IDs, locked files and
//!   operations a simulated person performs.
//! - [`MemServer`]: the server API over one shared [`ServerState`], with the server's checks
//!   from `hangar-drive-crypto` (log batches, commit signatures, compare-and-swap, side commits,
//!   reference deltas) and fault injection (offline, lost replies, small pages, refused commits,
//!   a server key other than the pinned one).
//! - [`MemStore`]: the local index; clones share the data, so a "restarted" device reads what
//!   the previous instance wrote.
//! - [`ManualClock`], [`SeededRandom`], [`MemKeychain`].
//!
//! Everything is deterministic given the seed.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::Mutex;

use hangar_drive_crypto::commit::SignedCommit;
use hangar_drive_crypto::devicelog::AccountState;
use hangar_drive_crypto::{Entropy, EntropyError};
use hangar_drive_protocol::api::{
    ChallengeResponse, CommitRequest, CommitResponse, CommitRole, CreateAccountRequest,
    CreateAccountResponse, DeltaCommit, DeltaPage, ErrorBody, ErrorCode, FeedChange, FeedEntry,
    FeedPage, LogAppendRequest, LogAppendResponse, LogPage, PairingRequest, RecordKey, RecordPut,
    RecordResponse, SessionResponse, UploadResponse, WrappedKeyResponse,
};
use hangar_drive_protocol::ids::{
    AccountId, Blob, Challenge, CommitId, DeviceId, Epoch, FolderId, ItemId, ObjectId, PairingId,
    ServerId, SessionToken, Signature,
};
use hangar_drive_protocol::name::case_key;
use zeroize::Zeroizing;

use crate::ports::{
    ChunkList, Clock, EntryType, Expect, FileSystem, FsError, Keychain, KeychainError, ListEntry,
    NetError, SaveBatch, ServerApi, Stat, Store, StoreError, StoredFolder,
};
use crate::tree::{ContentKey, Node, TreeDelta};

// ------------------------------------------------------------------------------------------
// Clock and randomness
// ------------------------------------------------------------------------------------------

/// A clock the test moves by hand. Clones share the time.
#[derive(Debug, Clone, Default)]
pub struct ManualClock(Rc<RefCell<i64>>);

impl ManualClock {
    /// A clock at `now_ms`.
    pub fn at(now_ms: i64) -> Self {
        Self(Rc::new(RefCell::new(now_ms)))
    }

    /// Moves the clock forward.
    pub fn advance(&self, ms: i64) {
        *self.0.borrow_mut() += ms;
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        *self.0.borrow()
    }
}

/// A deterministic generator (SplitMix64) for the simulation. Never for real keys.
#[derive(Debug, Clone)]
pub struct SeededRandom(u64);

impl SeededRandom {
    /// A generator from `seed`.
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    /// The next 64 bits.
    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number below `n` (0 for `n == 0`).
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            0
        } else {
            self.next_u64() % n
        }
    }

    /// True with probability `percent` / 100.
    pub fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

impl Entropy for SeededRandom {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

/// A keychain in memory.
#[derive(Debug, Default, Clone)]
pub struct MemKeychain(BTreeMap<String, Vec<u8>>);

impl Keychain for MemKeychain {
    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        Ok(self.0.get(key).map(|v| Zeroizing::new(v.clone())))
    }
    fn store(&mut self, key: &str, secret: &[u8]) -> Result<(), KeychainError> {
        self.0.insert(key.to_owned(), secret.to_vec());
        Ok(())
    }
    fn delete(&mut self, key: &str) -> Result<(), KeychainError> {
        self.0.remove(key);
        Ok(())
    }
}

impl MemKeychain {
    /// The names stored, for tests that check what is left (security review L1).
    pub fn keys(&self) -> Vec<String> {
        self.0.keys().cloned().collect()
    }
}

/// A [`MemKeychain`] a test keeps a handle to while an engine owns the port.
#[derive(Debug, Default, Clone)]
pub struct SharedKeychain(Rc<RefCell<MemKeychain>>);

impl SharedKeychain {
    /// The names stored now.
    pub fn keys(&self) -> Vec<String> {
        self.0.borrow().keys()
    }
}

impl Keychain for SharedKeychain {
    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError> {
        self.0.borrow().load(key)
    }
    fn store(&mut self, key: &str, secret: &[u8]) -> Result<(), KeychainError> {
        self.0.borrow_mut().store(key, secret)
    }
    fn delete(&mut self, key: &str) -> Result<(), KeychainError> {
        self.0.borrow_mut().delete(key)
    }
}

// ------------------------------------------------------------------------------------------
// File system
// ------------------------------------------------------------------------------------------

/// The wall clock of simulated people: every write of a person gets a later modification time
/// than every write before it, on every device, as with a real clock. (The local index trusts
/// size, mtime and file ID, ADR 0001, section 3; a clock that gave two different writes of the
/// same size the same mtime would defeat it, on real disks as here.)
static USER_CLOCK: std::sync::atomic::AtomicI64 =
    std::sync::atomic::AtomicI64::new(1_700_000_000_000);

fn user_now() -> i64 {
    USER_CLOCK.fetch_add(1_001, std::sync::atomic::Ordering::Relaxed) + 1_001
}

#[derive(Debug, Clone)]
struct MemEntry {
    name: String,
    dir: bool,
    data: Vec<u8>,
    mtime_ms: i64,
    file_id: u128,
    executable: bool,
}

#[derive(Debug, Default)]
struct MemFsState {
    /// Keyed by the normalized path.
    entries: BTreeMap<Vec<String>, MemEntry>,
    next_id: u128,
    tick: i64,
    locked: BTreeSet<Vec<String>>,
    full: bool,
    /// Paths changed since the last [`MemFs::take_events`], as a watcher would report them.
    events: Vec<Vec<String>>,
}

/// A sync root in memory (module docs).
#[derive(Debug)]
pub struct MemFs {
    state: Mutex<MemFsState>,
    case_insensitive: bool,
}

impl MemFs {
    /// An empty root. `case_insensitive` behaves like NTFS and APFS by default.
    pub fn new(case_insensitive: bool) -> Self {
        Self {
            state: Mutex::new(MemFsState {
                tick: 1_700_000_000_000,
                ..MemFsState::default()
            }),
            case_insensitive,
        }
    }

    fn key(&self, path: &[String]) -> Vec<String> {
        if self.case_insensitive {
            path.iter().map(|n| case_key(n)).collect()
        } else {
            path.to_vec()
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MemFsState> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// The paths changed since the last call, like the events of a file system watcher.
    pub fn take_events(&self) -> Vec<Vec<String>> {
        std::mem::take(&mut self.lock().events)
    }

    fn event(&self, path: &[String]) {
        self.lock().events.push(path.to_vec());
    }

    fn parent_ok(&self, s: &MemFsState, path: &[String]) -> bool {
        match path.split_last() {
            None => false,
            Some((_, [])) => true,
            Some((_, parent)) => s.entries.get(&self.key(parent)).is_some_and(|e| e.dir),
        }
    }

    // -- What a simulated person does -----------------------------------------------------

    /// Writes a file (creates or overwrites), like an editor. Fails if the parent is missing or
    /// the path is a directory.
    pub fn user_write(&self, path: &[String], data: &[u8]) -> bool {
        let ok = self.user_write_inner(path, data);
        if ok {
            self.event(path);
        }
        ok
    }

    fn user_write_inner(&self, path: &[String], data: &[u8]) -> bool {
        let mut s = self.lock();
        if !self.parent_ok(&s, path) || s.locked.contains(&self.key(path)) {
            return false;
        }
        let tick = user_now();
        let key = self.key(path);
        match s.entries.get_mut(&key) {
            Some(e) if e.dir => false,
            Some(e) => {
                e.data = data.to_vec();
                e.mtime_ms = tick;
                true
            }
            None => {
                s.next_id += 1;
                let file_id = s.next_id;
                s.entries.insert(
                    key,
                    MemEntry {
                        name: path.last().cloned().unwrap_or_default(),
                        dir: false,
                        data: data.to_vec(),
                        mtime_ms: tick,
                        file_id,
                        executable: false,
                    },
                );
                true
            }
        }
    }

    /// Creates a directory.
    pub fn user_mkdir(&self, path: &[String]) -> bool {
        self.create_dir(path).is_ok()
    }

    /// Renames or moves an entry with everything below it.
    pub fn user_rename(&self, from: &[String], to: &[String]) -> bool {
        self.rename(from, to).is_ok()
    }

    /// Deletes a file or a directory with everything below it.
    pub fn user_delete(&self, path: &[String]) -> bool {
        let mut s = self.lock();
        let key = self.key(path);
        if !s.entries.contains_key(&key) {
            return false;
        }
        s.entries.retain(|k, _| !k.starts_with(&key));
        s.events.push(path.to_vec());
        true
    }

    /// Locks or unlocks a file, like a program holding it open without sharing.
    pub fn set_locked(&self, path: &[String], locked: bool) {
        let mut s = self.lock();
        let key = self.key(path);
        if locked {
            s.locked.insert(key);
        } else {
            s.locked.remove(&key);
        }
    }

    /// Makes every write fail with [`FsError::DiskFull`].
    pub fn set_full(&self, full: bool) {
        self.lock().full = full;
    }

    /// Every file and directory with its content, by the actual path (for the invariants).
    /// Entries under the reserved directory are left out.
    pub fn snapshot(&self) -> BTreeMap<Vec<String>, Option<Vec<u8>>> {
        let s = self.lock();
        let mut out = BTreeMap::new();
        for key in s.entries.keys() {
            if key.first().is_some_and(|n| {
                n.eq_ignore_ascii_case(hangar_drive_protocol::name::RESERVED_ROOT_DIR)
            }) {
                continue;
            }
            // Rebuild the actual path from the names of each prefix.
            let mut actual = Vec::new();
            for len in 1..=key.len() {
                if let Some(e) = s.entries.get(&key[..len]) {
                    actual.push(e.name.clone());
                }
            }
            if let Some(e) = s.entries.get(key) {
                out.insert(actual, (!e.dir).then(|| e.data.clone()));
            }
        }
        out
    }

    /// The content of a file.
    pub fn read_all(&self, path: &[String]) -> Option<Vec<u8>> {
        let s = self.lock();
        s.entries
            .get(&self.key(path))
            .filter(|e| !e.dir)
            .map(|e| e.data.clone())
    }

    fn stat_of(e: &MemEntry) -> Stat {
        Stat {
            kind: if e.dir {
                EntryType::Directory
            } else {
                EntryType::File
            },
            size: if e.dir { 0 } else { e.data.len() as u64 },
            mtime_ms: e.mtime_ms,
            file_id: Some(e.file_id),
            executable: e.executable,
        }
    }

    fn matches(e: &MemEntry, expect: Expect) -> bool {
        !e.dir && e.data.len() as u64 == expect.size && e.mtime_ms == expect.mtime_ms
    }
}

impl FileSystem for MemFs {
    fn stat(&self, path: &[String]) -> Result<Option<Stat>, FsError> {
        let s = self.lock();
        Ok(s.entries.get(&self.key(path)).map(Self::stat_of))
    }

    fn list(&self, path: &[String]) -> Result<Vec<ListEntry>, FsError> {
        let s = self.lock();
        let key = self.key(path);
        if !path.is_empty() && !s.entries.get(&key).is_some_and(|e| e.dir) {
            return Err(FsError::NotFound);
        }
        Ok(s.entries
            .iter()
            .filter(|(k, _)| k.len() == key.len() + 1 && k.starts_with(&key))
            .map(|(_, e)| ListEntry {
                name: Some(e.name.clone()),
                display: e.name.clone(),
                stat: Self::stat_of(e),
            })
            .collect())
    }

    fn read_at(&self, path: &[String], offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let s = self.lock();
        let key = self.key(path);
        if s.locked.contains(&key) {
            return Err(FsError::Locked);
        }
        let e = s
            .entries
            .get(&key)
            .filter(|e| !e.dir)
            .ok_or(FsError::NotFound)?;
        let start = usize::try_from(offset).map_err(|_| FsError::Io("offset".into()))?;
        if start >= e.data.len() {
            return Ok(0);
        }
        let n = buf.len().min(e.data.len() - start);
        buf[..n].copy_from_slice(&e.data[start..start + n]);
        Ok(n)
    }

    fn create_dir(&self, path: &[String]) -> Result<(), FsError> {
        let mut s = self.lock();
        if !self.parent_ok(&s, path) {
            return Err(FsError::NotFound);
        }
        let key = self.key(path);
        if s.entries.contains_key(&key) {
            return Err(FsError::Exists);
        }
        s.next_id += 1;
        s.tick += 1;
        let (file_id, tick) = (s.next_id, s.tick);
        s.entries.insert(
            key,
            MemEntry {
                name: path.last().cloned().unwrap_or_default(),
                dir: true,
                data: Vec::new(),
                mtime_ms: tick,
                file_id,
                executable: false,
            },
        );
        s.events.push(path.to_vec());
        Ok(())
    }

    fn write_atomic(
        &self,
        path: &[String],
        fill: &mut dyn FnMut(&mut dyn std::io::Write) -> Result<(), FsError>,
        mtime_ms: i64,
        executable: bool,
        replace: Option<Expect>,
    ) -> Result<Stat, FsError> {
        let mut data = Vec::new();
        fill(&mut data)?;
        let mut s = self.lock();
        if s.full {
            return Err(FsError::DiskFull);
        }
        if !self.parent_ok(&s, path) {
            return Err(FsError::NotFound);
        }
        let key = self.key(path);
        if s.locked.contains(&key) {
            return Err(FsError::Locked);
        }
        let file_id = match (s.entries.get(&key), replace) {
            (Some(_), None) => return Err(FsError::Exists),
            (None, Some(_)) => return Err(FsError::Changed),
            (Some(e), Some(expect)) if !Self::matches(e, expect) => return Err(FsError::Changed),
            // An atomic rename over the target gives the file the temporary file's ID.
            _ => {
                s.next_id += 1;
                s.next_id
            }
        };
        let entry = MemEntry {
            name: path.last().cloned().unwrap_or_default(),
            dir: false,
            data,
            mtime_ms,
            file_id,
            executable,
        };
        let stat = Self::stat_of(&entry);
        s.entries.insert(key, entry);
        s.events.push(path.to_vec());
        Ok(stat)
    }

    fn rename(&self, from: &[String], to: &[String]) -> Result<(), FsError> {
        let mut s = self.lock();
        let (fk, tk) = (self.key(from), self.key(to));
        if !s.entries.contains_key(&fk) {
            return Err(FsError::NotFound);
        }
        if !self.parent_ok(&s, to) {
            return Err(FsError::NotFound);
        }
        if tk.starts_with(&fk) && tk != fk {
            return Err(FsError::Io("cannot move a directory into itself".into()));
        }
        if s.entries.contains_key(&tk) && tk != fk {
            return Err(FsError::Exists);
        }
        if s.locked.iter().any(|l| l.starts_with(&fk)) {
            return Err(FsError::Locked);
        }
        let moved: Vec<(Vec<String>, MemEntry)> = s
            .entries
            .iter()
            .filter(|(k, _)| k.starts_with(&fk))
            .map(|(k, e)| (k.clone(), e.clone()))
            .collect();
        for (k, _) in &moved {
            s.entries.remove(k);
        }
        for (k, mut e) in moved {
            let mut nk = tk.clone();
            nk.extend_from_slice(&k[fk.len()..]);
            if k == fk {
                e.name = to.last().cloned().unwrap_or_default();
            }
            s.entries.insert(nk, e);
        }
        s.events.push(from.to_vec());
        s.events.push(to.to_vec());
        Ok(())
    }

    fn remove_file(&self, path: &[String], expect: Expect) -> Result<(), FsError> {
        let mut s = self.lock();
        let key = self.key(path);
        if s.locked.contains(&key) {
            return Err(FsError::Locked);
        }
        match s.entries.get(&key) {
            None => Err(FsError::NotFound),
            Some(e) if !Self::matches(e, expect) => Err(FsError::Changed),
            Some(_) => {
                s.entries.remove(&key);
                s.events.push(path.to_vec());
                Ok(())
            }
        }
    }

    fn remove_dir(&self, path: &[String]) -> Result<(), FsError> {
        let mut s = self.lock();
        let key = self.key(path);
        if !s.entries.get(&key).is_some_and(|e| e.dir) {
            return Err(FsError::NotFound);
        }
        if s.entries
            .keys()
            .any(|k| k.len() > key.len() && k.starts_with(&key))
        {
            return Err(FsError::NotEmpty);
        }
        s.entries.remove(&key);
        s.events.push(path.to_vec());
        Ok(())
    }

    fn set_meta(
        &self,
        path: &[String],
        mtime_ms: i64,
        executable: bool,
        expect: Expect,
    ) -> Result<(), FsError> {
        let mut s = self.lock();
        let key = self.key(path);
        match s.entries.get_mut(&key) {
            None => Err(FsError::NotFound),
            Some(e) if !Self::matches(e, expect) => Err(FsError::Changed),
            Some(e) => {
                e.mtime_ms = mtime_ms;
                e.executable = executable;
                s.events.push(path.to_vec());
                Ok(())
            }
        }
    }
}

// ------------------------------------------------------------------------------------------
// Store
// ------------------------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct MemFolderRows {
    remote: BTreeMap<ItemId, Node>,
    synced: BTreeMap<ItemId, Node>,
    local: BTreeMap<ItemId, Node>,
    file_ids: BTreeMap<ItemId, u128>,
    meta: Vec<u8>,
}

#[derive(Debug, Default)]
struct MemStoreInner {
    folders: BTreeMap<FolderId, MemFolderRows>,
    chunks: BTreeMap<(FolderId, ContentKey), ChunkList>,
    objects: BTreeMap<(FolderId, [u8; 32]), ObjectId>,
    plaintexts: BTreeMap<(FolderId, ObjectId), Vec<u8>>,
    account: BTreeMap<String, Vec<u8>>,
    saves: u64,
}

/// The local index in memory; clones share it (module docs).
#[derive(Debug, Default, Clone)]
pub struct MemStore(Rc<RefCell<MemStoreInner>>);

impl MemStore {
    /// An empty index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of folder saves so far.
    pub fn saves(&self) -> u64 {
        self.0.borrow().saves
    }
}

fn apply_delta(rows: &mut BTreeMap<ItemId, Node>, delta: &TreeDelta) {
    for id in &delta.remove {
        rows.remove(id);
    }
    for (id, node) in &delta.upsert {
        rows.insert(*id, node.clone());
    }
}

impl Store for MemStore {
    fn folders(&self) -> Result<Vec<FolderId>, StoreError> {
        Ok(self.0.borrow().folders.keys().copied().collect())
    }

    fn load_folder(&self, folder: &FolderId) -> Result<Option<StoredFolder>, StoreError> {
        Ok(self.0.borrow().folders.get(folder).map(|f| StoredFolder {
            remote: f.remote.iter().map(|(k, v)| (*k, v.clone())).collect(),
            synced: f.synced.iter().map(|(k, v)| (*k, v.clone())).collect(),
            local: f.local.iter().map(|(k, v)| (*k, v.clone())).collect(),
            file_ids: f.file_ids.iter().map(|(k, v)| (*k, *v)).collect(),
            meta: f.meta.clone(),
        }))
    }

    fn save_folder(&mut self, folder: &FolderId, batch: &SaveBatch) -> Result<(), StoreError> {
        let mut inner = self.0.borrow_mut();
        inner.saves += 1;
        let rows = inner.folders.entry(*folder).or_default();
        apply_delta(&mut rows.remote, &batch.remote);
        apply_delta(&mut rows.synced, &batch.synced);
        apply_delta(&mut rows.local, &batch.local);
        for (id, file_id) in &batch.file_ids {
            match file_id {
                Some(f) => rows.file_ids.insert(*id, *f),
                None => rows.file_ids.remove(id),
            };
        }
        if let Some(meta) = &batch.meta {
            rows.meta = meta.clone();
        }
        Ok(())
    }

    fn delete_folder(&mut self, folder: &FolderId) -> Result<(), StoreError> {
        let mut inner = self.0.borrow_mut();
        inner.folders.remove(folder);
        inner.chunks.retain(|(f, _), _| f != folder);
        inner.objects.retain(|(f, _), _| f != folder);
        inner.plaintexts.retain(|(f, _), _| f != folder);
        Ok(())
    }

    fn chunk_list(
        &self,
        folder: &FolderId,
        content: &ContentKey,
    ) -> Result<Option<ChunkList>, StoreError> {
        Ok(self.0.borrow().chunks.get(&(*folder, *content)).cloned())
    }

    fn put_chunk_list(
        &mut self,
        folder: &FolderId,
        content: &ContentKey,
        list: &ChunkList,
    ) -> Result<(), StoreError> {
        self.0
            .borrow_mut()
            .chunks
            .insert((*folder, *content), list.clone());
        Ok(())
    }

    fn object_for(
        &self,
        folder: &FolderId,
        digest: &[u8; 32],
    ) -> Result<Option<ObjectId>, StoreError> {
        Ok(self.0.borrow().objects.get(&(*folder, *digest)).copied())
    }

    fn put_object_for(
        &mut self,
        folder: &FolderId,
        digest: &[u8; 32],
        id: &ObjectId,
    ) -> Result<(), StoreError> {
        self.0.borrow_mut().objects.insert((*folder, *digest), *id);
        Ok(())
    }

    fn plaintext(&self, folder: &FolderId, id: &ObjectId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.0.borrow().plaintexts.get(&(*folder, *id)).cloned())
    }

    fn put_plaintext(
        &mut self,
        folder: &FolderId,
        id: &ObjectId,
        plaintext: &[u8],
    ) -> Result<(), StoreError> {
        self.0
            .borrow_mut()
            .plaintexts
            .insert((*folder, *id), plaintext.to_vec());
        Ok(())
    }

    fn account_value(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.0.borrow().account.get(key).cloned())
    }

    fn put_account_value(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError> {
        self.0
            .borrow_mut()
            .account
            .insert(key.to_owned(), value.to_vec());
        Ok(())
    }

    fn delete_account_value(&mut self, key: &str) -> Result<(), StoreError> {
        self.0.borrow_mut().account.remove(key);
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------
// Server
// ------------------------------------------------------------------------------------------

#[derive(Debug, Default, Clone)]
struct MemFolder {
    objects: BTreeMap<ObjectId, Vec<u8>>,
    commits: Vec<DeltaCommit>,
    head: Option<CommitId>,
    heads: BTreeSet<CommitId>,
    sequence: u64,
    retired: bool,
    marks: BTreeMap<DeviceId, u64>,
}

/// The state of the in-memory server, shared by every device's [`MemServer`].
#[derive(Debug)]
pub struct ServerState {
    /// While false, every call fails with [`NetError::Unreachable`].
    pub online: bool,
    /// The next commit call is applied but its reply is lost.
    pub lose_next_commit_reply: bool,
    /// Commits per delta page (small pages test paging).
    pub page_size: usize,
    /// Answer "base expired" to every side commit.
    pub expire_bases: bool,
    /// While set, every commit is refused with this code (a used up upload budget, say).
    pub refuse_commits: Option<ErrorCode>,
    /// The SPKI pin of the key the server presents. A connection pinned to another key fails
    /// every call with [`NetError::PinMismatch`] and reports this one as seen (ADR 0001,
    /// section 6, "Pin rotation"); `None` presents whatever a connection pinned.
    pub presented_pin: Option<[u8; 32]>,
    /// While set, a device the log removed gets `device_removed` on every call, with the log
    /// from the length it last named up to its removal, as the real server answers its proof
    /// (security review H2). Off by default, so tests can let a removed device read on.
    pub refuse_removed: bool,
    server: ServerId,
    account: Option<AccountId>,
    log: Vec<Vec<u8>>,
    state: Option<AccountState>,
    wraps: BTreeMap<(u32, DeviceId), Vec<u8>>,
    records: BTreeMap<RecordKey, (u64, Vec<u8>)>,
    feed: Vec<FeedEntry>,
    sequence: u64,
    folders: BTreeMap<FolderId, MemFolder>,
    pairing: BTreeMap<PairingId, Option<PairingRequest>>,
    /// Calls served, for the tests.
    pub calls: u64,
}

impl ServerState {
    fn new() -> Self {
        Self {
            online: true,
            lose_next_commit_reply: false,
            page_size: hangar_drive_protocol::api::MAX_DELTA_PAGE,
            expire_bases: false,
            refuse_commits: None,
            presented_pin: None,
            refuse_removed: false,
            server: ServerId::from_bytes([0x5e; 16]),
            account: None,
            log: Vec::new(),
            state: None,
            wraps: BTreeMap::new(),
            records: BTreeMap::new(),
            feed: Vec::new(),
            sequence: 0,
            folders: BTreeMap::new(),
            pairing: BTreeMap::new(),
            calls: 0,
        }
    }

    fn push_feed(&mut self, change: FeedChange) {
        self.sequence += 1;
        self.feed.push(FeedEntry {
            sequence: self.sequence,
            change,
        });
    }

    /// The current head of a folder.
    pub fn head(&self, folder: &FolderId) -> Option<CommitId> {
        self.folders.get(folder).and_then(|f| f.head)
    }

    /// The folder's sequence.
    pub fn folder_sequence(&self, folder: &FolderId) -> u64 {
        self.folders.get(folder).map_or(0, |f| f.sequence)
    }

    /// The verified device log.
    pub fn account_state(&self) -> Option<&AccountState> {
        self.state.as_ref()
    }

    /// Every stored object of a folder.
    pub fn object_count(&self, folder: &FolderId) -> usize {
        self.folders.get(folder).map_or(0, |f| f.objects.len())
    }

    /// The wire bytes of the current head commit.
    pub fn head_commit(&self, folder: &FolderId) -> Option<Vec<u8>> {
        let f = self.folders.get(folder)?;
        f.commits
            .iter()
            .rev()
            .find(|c| c.role == CommitRole::Head)
            .map(|c| c.commit.0.clone())
    }

    /// The stored commits of a folder, for a test that plays a malicious server.
    pub fn folder_commits(&self, folder: &FolderId) -> Vec<DeltaCommit> {
        self.folders
            .get(folder)
            .map(|f| f.commits.clone())
            .unwrap_or_default()
    }

    /// Replaces the commits of a folder: a malicious server that shows another history (for
    /// example one without a barrier commit). Objects stay.
    pub fn set_folder_commits(&mut self, folder: &FolderId, commits: Vec<DeltaCommit>) {
        let f = self.folders.entry(*folder).or_default();
        f.sequence = commits.last().map_or(0, |c| c.sequence);
        f.head = commits
            .iter()
            .rev()
            .find(|c| c.role == CommitRole::Head)
            .and_then(|c| SignedCommit::decode(c.commit.as_bytes()).ok())
            .map(|c| c.id);
        f.commits = commits;
    }

    /// Rewinds a folder to its state after `sequence` (an operator restoring an old backup).
    pub fn rewind_folder(&mut self, folder: &FolderId, sequence: u64) {
        if let Some(f) = self.folders.get_mut(folder) {
            f.commits.retain(|c| c.sequence <= sequence);
            f.sequence = sequence;
            f.head = f
                .commits
                .iter()
                .rev()
                .find(|c| c.role == CommitRole::Head)
                .and_then(|c| SignedCommit::decode(c.commit.as_bytes()).ok())
                .map(|c| c.id);
            let seq = self.sequence + 1;
            self.sequence = seq;
            self.feed.push(FeedEntry {
                sequence: seq,
                change: FeedChange::FolderHead {
                    folder: *folder,
                    sequence,
                },
            });
        }
    }
}

/// One device's connection to the shared [`ServerState`].
#[derive(Debug, Clone)]
pub struct MemServer {
    shared: Rc<RefCell<ServerState>>,
    device: DeviceId,
    pin: Option<[u8; 32]>,
    known_log_length: Option<u64>,
}

impl MemServer {
    /// A new server.
    pub fn new_shared() -> Rc<RefCell<ServerState>> {
        Rc::new(RefCell::new(ServerState::new()))
    }

    /// The connection of `device`.
    pub fn connect(shared: &Rc<RefCell<ServerState>>, device: DeviceId) -> Self {
        Self::connect_pinned(shared, device, None)
    }

    /// The connection of `device` pinned to the server key `pin` (none: any key).
    pub fn connect_pinned(
        shared: &Rc<RefCell<ServerState>>,
        device: DeviceId,
        pin: Option<[u8; 32]>,
    ) -> Self {
        Self {
            shared: Rc::clone(shared),
            device,
            pin,
            known_log_length: None,
        }
    }

    /// The presented key, when it is not the one this connection pinned.
    fn other_key(&self, s: &ServerState) -> Option<[u8; 32]> {
        match (self.pin, s.presented_pin) {
            (Some(pinned), Some(presented)) if pinned != presented => Some(presented),
            _ => None,
        }
    }

    /// The shared state.
    pub fn state(&self) -> std::cell::RefMut<'_, ServerState> {
        self.shared.borrow_mut()
    }

    fn enter(&self) -> Result<std::cell::RefMut<'_, ServerState>, NetError> {
        let mut s = self.shared.borrow_mut();
        s.calls += 1;
        if !s.online {
            return Err(NetError::Unreachable);
        }
        if self.other_key(&s).is_some() {
            return Err(NetError::PinMismatch);
        }
        if s.refuse_removed {
            let removed_at = s
                .state
                .as_ref()
                .and_then(|state| state.device(&self.device))
                .and_then(|d| d.removed_at);
            if let Some(removed_at) = removed_at {
                let log = self
                    .known_log_length
                    .filter(|after| *after < removed_at)
                    .map(|after| {
                        let start = usize::try_from(after).unwrap_or(usize::MAX);
                        let end = usize::try_from(removed_at).unwrap_or(usize::MAX);
                        LogPage {
                            first_index: after + 1,
                            entries: s
                                .log
                                .get(start..end.min(s.log.len()))
                                .unwrap_or_default()
                                .iter()
                                .take(hangar_drive_protocol::api::MAX_LOG_PAGE)
                                .map(|e| Blob(e.clone()))
                                .collect(),
                            length: s.log.len() as u64,
                        }
                    });
                return Err(NetError::DeviceRemoved(log));
            }
        }
        Ok(s)
    }
}

fn refuse(code: ErrorCode) -> NetError {
    NetError::Server(ErrorBody::new(code))
}

impl ServerApi for MemServer {
    fn create_account(
        &mut self,
        request: &CreateAccountRequest,
    ) -> Result<CreateAccountResponse, NetError> {
        // Without a session the sender is the device that issued entry 1.
        if let Ok(entry) =
            hangar_drive_crypto::devicelog::LogEntry::decode(request.genesis.as_bytes())
        {
            self.device = entry.issuer;
        }
        let mut s = self.enter()?;
        if s.account.is_some() {
            return Err(refuse(ErrorCode::AlreadyExists));
        }
        let mut state = AccountState::new(request.account);
        state
            .admit_genesis(request.genesis.as_bytes(), &self.device)
            .map_err(|_| refuse(ErrorCode::LogEntryRefused))?;
        s.account = Some(request.account);
        s.log.push(request.genesis.0.clone());
        s.state = Some(state);
        s.push_feed(FeedChange::DeviceLog { length: 1 });
        Ok(CreateAccountResponse { server: s.server })
    }

    fn challenge(
        &mut self,
        _account: &AccountId,
        _device: &DeviceId,
    ) -> Result<ChallengeResponse, NetError> {
        let s = self.enter()?;
        Ok(ChallengeResponse {
            server: s.server,
            challenge: Challenge::from_bytes([7; 32]),
            expires_in_secs: 60,
        })
    }

    fn proof(
        &mut self,
        _account: &AccountId,
        _device: &DeviceId,
        _challenge: &Challenge,
        _signature: &Signature,
    ) -> Result<SessionResponse, NetError> {
        let _s = self.enter()?;
        Ok(SessionResponse {
            token: SessionToken::from_bytes([1; 32]),
            expires_in_secs: 3600,
        })
    }

    fn log(&mut self, after: u64) -> Result<LogPage, NetError> {
        let s = self.enter()?;
        let start = usize::try_from(after)
            .unwrap_or(usize::MAX)
            .min(s.log.len());
        let entries: Vec<Blob> = s.log[start..]
            .iter()
            .take(hangar_drive_protocol::api::MAX_LOG_PAGE)
            .map(|e| Blob(e.clone()))
            .collect();
        Ok(LogPage {
            first_index: after + 1,
            entries,
            length: s.log.len() as u64,
        })
    }

    fn append_log(&mut self, request: &LogAppendRequest) -> Result<LogAppendResponse, NetError> {
        let mut s = self.enter()?;
        request
            .validate()
            .map_err(|_| refuse(ErrorCode::BadRequest))?;
        let state = s.state.clone().ok_or(refuse(ErrorCode::NotFound))?;
        let batch = state
            .admit_batch(request.entries.iter().map(|e| e.as_bytes()), &self.device)
            .map_err(|_| refuse(ErrorCode::LogEntryRefused))?;
        let fits = hangar_drive_crypto::epoch::append_wraps_fit(
            &batch,
            request.wraps.iter().map(|w| (&w.device, w.data.as_bytes())),
            request
                .device_wrap
                .as_ref()
                .map(|w| (&w.device, w.data.as_bytes())),
        );
        if !fits {
            return Err(refuse(ErrorCode::LogEntryRefused));
        }
        let epoch = batch.state.current_epoch().map(|e| e.epoch.0);
        for w in &request.wraps {
            if let Some(epoch) = epoch {
                s.wraps.insert((epoch, w.device), w.data.0.clone());
            }
        }
        if let (Some(w), Some(epoch)) = (&request.device_wrap, epoch) {
            s.wraps.insert((epoch, w.device), w.data.0.clone());
        }
        for e in &request.entries {
            s.log.push(e.0.clone());
        }
        let head = batch.state.head().ok_or(refuse(ErrorCode::Internal))?;
        let rotated = matches!(
            batch.shape,
            hangar_drive_crypto::devicelog::BatchShape::Rotation { .. }
        );
        s.state = Some(batch.state);
        let length = s.log.len() as u64;
        s.push_feed(FeedChange::DeviceLog { length });
        if let (true, Some(epoch)) = (rotated, epoch) {
            s.push_feed(FeedChange::Epoch {
                epoch: Epoch(epoch),
            });
        }
        Ok(LogAppendResponse { head })
    }

    fn epoch_key(&mut self, epoch: Epoch) -> Result<WrappedKeyResponse, NetError> {
        let s = self.enter()?;
        let data = s
            .wraps
            .get(&(epoch.0, self.device))
            .cloned()
            .ok_or(refuse(ErrorCode::NotFound))?;
        Ok(WrappedKeyResponse {
            epoch,
            data: Blob(data),
        })
    }

    fn record(&mut self, key: &RecordKey) -> Result<Option<RecordResponse>, NetError> {
        let s = self.enter()?;
        Ok(s.records.get(key).map(|(version, data)| RecordResponse {
            key: *key,
            version: *version,
            data: Blob(data.clone()),
        }))
    }

    fn put_record(&mut self, key: &RecordKey, put: &RecordPut) -> Result<(), NetError> {
        let mut s = self.enter()?;
        let current = s.records.get(key).map_or(0, |(v, _)| *v);
        if put.version != current + 1 {
            return Err(refuse(ErrorCode::RecordVersion));
        }
        s.records.insert(*key, (put.version, put.data.0.clone()));
        s.push_feed(FeedChange::Record {
            key: *key,
            version: put.version,
        });
        Ok(())
    }

    fn feed(&mut self, after: u64) -> Result<FeedPage, NetError> {
        let s = self.enter()?;
        let entries: Vec<FeedEntry> = s
            .feed
            .iter()
            .filter(|e| e.sequence > after)
            .take(hangar_drive_protocol::api::MAX_FEED_PAGE)
            .cloned()
            .collect();
        let more = s.feed.iter().filter(|e| e.sequence > after).count() > entries.len();
        Ok(FeedPage {
            entries,
            sequence: s.sequence,
            more,
        })
    }

    fn reserve_pairing(
        &mut self,
        id: &PairingId,
    ) -> Result<hangar_drive_protocol::api::PairingReservation, NetError> {
        let mut s = self.enter()?;
        let open = s.pairing.values().filter(|slot| slot.is_none()).count();
        if open >= hangar_drive_protocol::api::MAX_OPEN_PAIRINGS && !s.pairing.contains_key(id) {
            return Err(refuse(ErrorCode::RateLimited));
        }
        s.pairing.entry(*id).or_insert(None);
        Ok(hangar_drive_protocol::api::PairingReservation {
            expires_in_secs: 600,
        })
    }

    fn post_pairing(&mut self, id: &PairingId, request: &PairingRequest) -> Result<(), NetError> {
        let mut s = self.enter()?;
        request
            .validate()
            .map_err(|_| refuse(ErrorCode::BadRequest))?;
        match s.pairing.get_mut(id) {
            Some(slot @ None) => {
                *slot = Some(request.clone());
                Ok(())
            }
            Some(Some(_)) => Err(refuse(ErrorCode::AlreadyExists)),
            None => Err(refuse(ErrorCode::NotFound)),
        }
    }

    fn get_pairing(&mut self, id: &PairingId) -> Result<Option<PairingRequest>, NetError> {
        let s = self.enter()?;
        match s.pairing.get(id) {
            Some(slot) => Ok(slot.clone()),
            None => Err(refuse(ErrorCode::NotFound)),
        }
    }

    fn close_pairing(&mut self, id: &PairingId) -> Result<(), NetError> {
        let mut s = self.enter()?;
        s.pairing.remove(id);
        Ok(())
    }

    fn missing_objects(
        &mut self,
        folder: &FolderId,
        ids: &[ObjectId],
    ) -> Result<Vec<ObjectId>, NetError> {
        let s = self.enter()?;
        let f = s.folders.get(folder);
        Ok(ids
            .iter()
            .filter(|id| !f.is_some_and(|f| f.objects.contains_key(id)))
            .copied()
            .collect())
    }

    fn put_object(
        &mut self,
        folder: &FolderId,
        id: &ObjectId,
        blob: &[u8],
    ) -> Result<UploadResponse, NetError> {
        let mut s = self.enter()?;
        if hangar_drive_crypto::object::object_header(blob).is_none() {
            return Err(refuse(ErrorCode::BadRequest));
        }
        let f = s.folders.entry(*folder).or_default();
        let stored = !f.objects.contains_key(id);
        f.objects.entry(*id).or_insert_with(|| blob.to_vec());
        Ok(UploadResponse { stored })
    }

    fn get_object(&mut self, folder: &FolderId, id: &ObjectId) -> Result<Vec<u8>, NetError> {
        let s = self.enter()?;
        s.folders
            .get(folder)
            .and_then(|f| f.objects.get(id))
            .cloned()
            .ok_or(refuse(ErrorCode::NotFound))
    }

    fn commit(
        &mut self,
        folder: &FolderId,
        request: &CommitRequest,
    ) -> Result<CommitResponse, NetError> {
        let mut s = self.enter()?;
        request
            .validate()
            .map_err(|_| refuse(ErrorCode::BadRequest))?;
        let state = s.state.clone().ok_or(refuse(ErrorCode::NotFound))?;
        let expire_bases = s.expire_bases;
        if let Some(code) = s.refuse_commits {
            return Err(refuse(code));
        }
        let f = s.folders.entry(*folder).or_default();
        if f.retired {
            return Err(refuse(ErrorCode::FolderRetired));
        }
        if request.expected_head != f.head {
            return Err(NetError::Server(ErrorBody {
                code: ErrorCode::HeadMoved,
                current_head: f.head,
                missing: Vec::new(),
                removal_log: None,
            }));
        }
        let head = SignedCommit::decode(request.head.commit.as_bytes())
            .map_err(|_| refuse(ErrorCode::CommitRefused))?;
        head.verify_for_server(&state, folder)
            .map_err(|_| refuse(ErrorCode::CommitRefused))?;
        let c = &head.commit;
        if c.side || c.parents.first().copied() != f.head {
            return Err(refuse(ErrorCode::CommitRefused));
        }
        let side = match &request.side {
            None => {
                if c.parents.len() > 1 {
                    return Err(refuse(ErrorCode::CommitRefused));
                }
                None
            }
            Some(upload) => {
                let side = SignedCommit::decode(upload.commit.as_bytes())
                    .map_err(|_| refuse(ErrorCode::CommitRefused))?;
                side.verify_for_server(&state, folder)
                    .map_err(|_| refuse(ErrorCode::CommitRefused))?;
                let sc = &side.commit;
                let base_known = sc.parents.first().is_some_and(|p| f.heads.contains(p));
                if !sc.side
                    || c.parents.get(1) != Some(&side.id)
                    || sc.device != c.device
                    || sc.counter >= c.counter
                    || !base_known
                {
                    return Err(refuse(ErrorCode::CommitRefused));
                }
                if expire_bases {
                    return Err(refuse(ErrorCode::BaseExpired));
                }
                Some((side, upload))
            }
        };
        let mark = f.marks.get(&c.device).copied().unwrap_or(0);
        let lowest = side.as_ref().map_or(c.counter, |(s, _)| s.commit.counter);
        if lowest <= mark {
            return Err(refuse(ErrorCode::CommitRefused));
        }
        let mut missing: Vec<ObjectId> = request
            .head
            .delta
            .added
            .iter()
            .chain(side.iter().flat_map(|(_, u)| u.delta.added.iter()))
            .filter(|id| !f.objects.contains_key(id))
            .copied()
            .collect();
        if !f.objects.contains_key(&c.root) {
            missing.push(c.root);
        }
        if !missing.is_empty() {
            missing.truncate(64);
            return Err(NetError::Server(ErrorBody {
                code: ErrorCode::MissingObjects,
                current_head: None,
                missing,
                removal_log: None,
            }));
        }
        f.sequence += 1;
        let sequence = f.sequence;
        if let Some((side, _)) = &side {
            f.commits.push(DeltaCommit {
                sequence,
                role: CommitRole::Side,
                commit: Blob(side.wire.clone()),
            });
        }
        f.commits.push(DeltaCommit {
            sequence,
            role: CommitRole::Head,
            commit: Blob(head.wire.clone()),
        });
        f.head = Some(head.id);
        f.heads.insert(head.id);
        f.marks.insert(c.device, c.counter);
        s.push_feed(FeedChange::FolderHead {
            folder: *folder,
            sequence,
        });
        if s.lose_next_commit_reply {
            s.lose_next_commit_reply = false;
            return Err(NetError::Unreachable);
        }
        Ok(CommitResponse {
            head: head.id,
            sequence,
        })
    }

    fn commits(&mut self, folder: &FolderId, after: u64) -> Result<DeltaPage, NetError> {
        let s = self.enter()?;
        let page = s.page_size.max(1);
        let Some(f) = s.folders.get(folder) else {
            return Ok(DeltaPage {
                commits: Vec::new(),
                sequence: 0,
                more: false,
            });
        };
        // Whole calls only: a page never splits a head from its side commit.
        let mut commits = Vec::new();
        let mut calls = BTreeSet::new();
        for c in f.commits.iter().filter(|c| c.sequence > after) {
            if !calls.contains(&c.sequence) && calls.len() == page {
                break;
            }
            calls.insert(c.sequence);
            commits.push(c.clone());
        }
        let last = commits.last().map_or(after, |c| c.sequence);
        Ok(DeltaPage {
            more: last < f.sequence,
            commits,
            sequence: f.sequence,
        })
    }

    fn retire(&mut self, folder: &FolderId) -> Result<(), NetError> {
        let mut s = self.enter()?;
        s.folders.entry(*folder).or_default().retired = true;
        s.push_feed(FeedChange::FolderRetired { folder: *folder });
        Ok(())
    }

    fn bring_back(&mut self, folder: &FolderId) -> Result<(), NetError> {
        let mut s = self.enter()?;
        let f = s
            .folders
            .get_mut(folder)
            .filter(|f| f.retired)
            .ok_or(refuse(ErrorCode::BadRequest))?;
        f.retired = false;
        // ADR 0001, section 3: undoing a retirement is announced as a new folder.
        s.push_feed(FeedChange::FolderCreated { folder: *folder });
        Ok(())
    }

    fn seen_pin(&self) -> Option<[u8; 32]> {
        self.other_key(&self.shared.borrow())
    }

    fn set_known_log_length(&mut self, length: u64) {
        self.known_log_length = Some(length);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn case_insensitive_fs_refuses_a_second_spelling() {
        let fs = MemFs::new(true);
        assert!(fs.user_write(&p(&["a.txt"]), b"1"));
        let r = fs.write_atomic(&p(&["A.TXT"]), &mut |_| Ok(()), 0, false, None);
        assert_eq!(r, Err(FsError::Exists));
        let fs = MemFs::new(false);
        assert!(fs.user_write(&p(&["a.txt"]), b"1"));
        assert!(fs
            .write_atomic(&p(&["A.TXT"]), &mut |_| Ok(()), 0, false, None)
            .is_ok());
    }

    #[test]
    fn renames_keep_file_ids_and_move_subtrees() {
        let fs = MemFs::new(true);
        assert!(fs.user_mkdir(&p(&["d"])));
        assert!(fs.user_write(&p(&["d", "x"]), b"abc"));
        let before = fs.stat(&p(&["d", "x"])).unwrap().unwrap();
        assert!(fs.user_rename(&p(&["d"]), &p(&["e"])));
        let after = fs.stat(&p(&["e", "x"])).unwrap().unwrap();
        assert_eq!(before.file_id, after.file_id);
        assert_eq!(fs.read_all(&p(&["e", "x"])).unwrap(), b"abc");
    }

    #[test]
    fn seeded_random_is_deterministic() {
        let mut a = SeededRandom::new(5);
        let mut b = SeededRandom::new(5);
        assert_eq!(a.next_u64(), b.next_u64());
        let mut buf = [0u8; 13];
        a.fill(&mut buf).unwrap();
        assert_ne!(buf, [0; 13]);
    }
}
