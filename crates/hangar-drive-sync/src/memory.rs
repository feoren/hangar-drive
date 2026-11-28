//! In-memory implementations of every port, for the seeded simulation and the tests.
//!
//! - [`MemFs`]: a sync root with exact or case-insensitive names, file IDs, locked files and
//!   operations a simulated person performs.
//! - [`MemServer`]: the server API over one shared [`ServerState`], with the server's checks
//!   from `hangar-drive-crypto` (log batches, commit signatures, compare-and-swap, side commits,
//!   reference deltas) and fault injection (offline, lost replies, small pages, refused commits,
//!   a server key other than the pinned one). With [`ServerState::enable_parallel_uploads`] it
//!   also hands out an uploader for worker threads ([`MemUploads`]), off by default so the
//!   seeded simulation and the tests that watch the order of uploads stay on one thread.
//! - [`MemStore`]: the local index; clones share the data, so a "restarted" device reads what
//!   the previous instance wrote.
//! - [`ManualClock`], [`SeededRandom`], [`MemKeychain`].
//!
//! Everything is deterministic given the seed.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

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
    NetError, ObjectUploader, PartialCheck, PartialFile, SaveBatch, ServerApi, Stat, Store,
    StoreError, StoredFolder,
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

/// A clock the test moves by hand that can cross threads (the engine thread, the hashing
/// workers); [`WorkCost`] moves it as work is done. Clones share the time.
#[derive(Debug, Clone, Default)]
pub struct SharedClock(Arc<AtomicI64>);

impl SharedClock {
    /// A clock at `now_ms`.
    pub fn at(now_ms: i64) -> Self {
        Self(Arc::new(AtomicI64::new(now_ms)))
    }

    /// Moves the clock forward.
    pub fn advance(&self, ms: i64) {
        self.0.fetch_add(ms, Ordering::SeqCst);
    }

    /// A cost that moves this clock by `ms` per unit of work and sleeps `sleep` in real time.
    pub fn cost(&self, ms: i64, sleep: std::time::Duration) -> WorkCost {
        WorkCost {
            clock: self.clone(),
            ms,
            sleep,
        }
    }
}

impl Clock for SharedClock {
    fn now_ms(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// What one unit of work (an object upload, a file read) costs in a test: time on a
/// [`SharedClock`], which a work budget sees, and optionally real time, so a test can watch the
/// engine thread while it works.
#[derive(Debug, Clone)]
pub struct WorkCost {
    /// The clock the cost moves.
    pub clock: SharedClock,
    /// Milliseconds per unit.
    pub ms: i64,
    /// Real time per unit.
    pub sleep: std::time::Duration,
}

impl WorkCost {
    fn pay(&self) {
        self.clock.advance(self.ms);
        if !self.sleep.is_zero() {
            std::thread::sleep(self.sleep);
        }
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
    /// What [`FileSystem::free_bytes`] reports; `None` like a platform that cannot tell. A
    /// write takes its bytes off and a remove gives them back, as on a disk.
    free: Option<u64>,
    /// What [`FileSystem::volume_bytes`] reports.
    volume: Option<u64>,
    /// Paths changed since the last [`MemFs::take_events`], as a watcher would report them.
    events: Vec<Vec<String>>,
    /// Bytes read from files so far ([`MemFs::bytes_read`]).
    bytes_read: u64,
    /// The part files of downloads in parts ([`FileSystem::partial_write`]) with their file
    /// IDs, by name.
    partials: BTreeMap<String, (Vec<u8>, u128)>,
}

/// A sync root in memory (module docs).
#[derive(Debug)]
pub struct MemFs {
    state: Mutex<MemFsState>,
    case_insensitive: bool,
    /// What each read costs ([`MemFs::set_read_cost`]).
    read_cost: Mutex<Option<WorkCost>>,
    /// Rung on every change a simulated person makes, like the real watcher's callback.
    waker: Mutex<Option<crate::watch::Waker>>,
}

impl MemFs {
    /// Bytes read from files so far, for tests that count how often a file is read.
    pub fn bytes_read(&self) -> u64 {
        self.lock().bytes_read
    }

    /// The part files of downloads in parts and their lengths, for tests.
    pub fn partial_files(&self) -> Vec<(String, u64)> {
        self.lock()
            .partials
            .iter()
            .map(|(name, (data, _))| (name.clone(), data.len() as u64))
            .collect()
    }

    /// Changes one byte of a part file, keeping its length and file ID (another program or a
    /// disk error), for tests.
    pub fn tamper_partial(&self, name: &str) {
        if let Some((data, _)) = self.lock().partials.get_mut(name) {
            if let Some(last) = data.last_mut() {
                *last ^= 0xff;
            }
        }
    }

    /// Changes a file in place, keeping its size, modification time and file ID (a writer that
    /// keeps its time stamp, a mapped file), for tests.
    pub fn overwrite_in_place(&self, path: &[String], data: &[u8]) {
        let key = self.key(path);
        if let Some(entry) = self.lock().entries.get_mut(&key) {
            entry.data = data.to_vec();
        }
    }

    /// Cuts a part file to `len` bytes, keeping its file ID, for tests.
    pub fn truncate_partial(&self, name: &str, len: usize) {
        if let Some((data, _)) = self.lock().partials.get_mut(name) {
            data.truncate(len);
        }
    }

    /// An empty root. `case_insensitive` behaves like NTFS and APFS by default.
    pub fn new(case_insensitive: bool) -> Self {
        Self {
            state: Mutex::new(MemFsState {
                tick: 1_700_000_000_000,
                // Plenty of room on a volume of unknown size: a download needs a known free
                // space (LOW 4 of the follow-up review).
                free: Some(1 << 40),
                ..MemFsState::default()
            }),
            case_insensitive,
            read_cost: Mutex::new(None),
            waker: Mutex::new(None),
        }
    }

    /// Rings `waker` on every later change a simulated person makes (the engine's wake-up).
    pub fn set_user_waker(&self, waker: crate::watch::Waker) {
        match self.waker.lock() {
            Ok(mut guard) => *guard = Some(waker),
            Err(poisoned) => *poisoned.into_inner() = Some(waker),
        }
    }

    fn ring(&self) {
        let waker = match self.waker.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    /// Makes every read of file content cost `cost` (hashing and sealing read the files).
    pub fn set_read_cost(&self, cost: Option<WorkCost>) {
        match self.read_cost.lock() {
            Ok(mut guard) => *guard = cost,
            Err(poisoned) => *poisoned.into_inner() = cost,
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
            self.ring();
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
        let ok = self.create_dir(path).is_ok();
        if ok {
            self.ring();
        }
        ok
    }

    /// Renames or moves an entry with everything below it.
    pub fn user_rename(&self, from: &[String], to: &[String]) -> bool {
        let ok = self.rename(from, to).is_ok();
        if ok {
            self.ring();
        }
        ok
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
        drop(s);
        self.ring();
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

    /// Sets the free space the root reports (`None`: unknown; the default is 1 TiB).
    pub fn set_free_bytes(&self, free: Option<u64>) {
        self.lock().free = free;
    }

    /// Sets the volume size the root reports (`None`: unknown, the default).
    pub fn set_volume_bytes(&self, volume: Option<u64>) {
        self.lock().volume = volume;
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
        let cost = match self.read_cost.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        if let Some(cost) = cost {
            cost.pay();
        }
        let mut s = self.lock();
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
        s.bytes_read = s.bytes_read.saturating_add(n as u64);
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
        let written = entry.data.len() as u64;
        if let Some(old) = s.entries.insert(key, entry) {
            s.free = s.free.map(|f| f.saturating_add(old.data.len() as u64));
        }
        s.free = s.free.map(|f| f.saturating_sub(written));
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
                if let Some(old) = s.entries.remove(&key) {
                    s.free = s.free.map(|f| f.saturating_add(old.data.len() as u64));
                }
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

    fn free_bytes(&self) -> Option<u64> {
        self.lock().free
    }

    fn volume_bytes(&self) -> Option<u64> {
        self.lock().volume
    }

    fn partial_supported(&self) -> bool {
        true
    }

    fn partial_write(
        &self,
        part: &mut PartialFile,
        offset: u64,
        data: &[u8],
    ) -> Result<(), FsError> {
        let mut s = self.lock();
        if s.full {
            return Err(FsError::DiskFull);
        }
        if offset == 0 {
            s.next_id += 1;
            let id = s.next_id;
            s.partials.insert(part.name.clone(), (data.to_vec(), id));
            part.file_id = Some(id);
            return Ok(());
        }
        match s.partials.get_mut(&part.name) {
            Some((bytes, id)) if bytes.len() as u64 == offset && Some(*id) == part.file_id => {
                bytes.extend_from_slice(data);
                Ok(())
            }
            _ => Err(FsError::Changed),
        }
    }

    fn partial_finish(
        &self,
        part: &PartialFile,
        path: &[String],
        mtime_ms: i64,
        executable: bool,
        replace: Option<Expect>,
        check: PartialCheck<'_>,
    ) -> Result<Stat, FsError> {
        let (data, id) = self
            .lock()
            .partials
            .get(&part.name)
            .cloned()
            .ok_or_else(|| FsError::Io("the part file is gone".into()))?;
        if Some(id) != part.file_id {
            return Err(FsError::Io("the part file is not the one written".into()));
        }
        check(&mut data.as_slice())?;
        let result = self.write_atomic(
            path,
            &mut |w| w.write_all(&data).map_err(|e| FsError::Io(e.to_string())),
            mtime_ms,
            executable,
            replace,
        );
        if result.is_ok() {
            self.lock().partials.remove(&part.name);
        }
        result
    }

    fn change_stamp(&self, path: &[String]) -> Option<u64> {
        use std::hash::{Hash, Hasher};
        let s = self.lock();
        let e = s.entries.get(&self.key(path))?;
        // What a status change time tracks: any change of the content or the metadata.
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        (&e.data, e.mtime_ms, e.executable, e.file_id).hash(&mut hasher);
        Some(hasher.finish())
    }

    fn partial_remove(&self, name: &str) -> Result<(), FsError> {
        self.lock().partials.remove(name);
        Ok(())
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

    /// Rows of the caches (plaintexts, object IDs, chunk lists) of all folders.
    pub fn cache_rows(&self) -> (usize, usize, usize) {
        let inner = self.0.borrow();
        (
            inner.plaintexts.len(),
            inner.objects.len(),
            inner.chunks.len(),
        )
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
        // A pull of the folder stored between pages goes with it, as in the SQLite index.
        let pull = format!("pull/{}", folder.to_hex());
        inner
            .account
            .retain(|k, _| k != &pull && !k.starts_with(&format!("{pull}/")));
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

    fn retain_cache(
        &mut self,
        folder: &FolderId,
        objects: &BTreeSet<ObjectId>,
        contents: &BTreeSet<ContentKey>,
    ) -> Result<u64, StoreError> {
        let mut inner = self.0.borrow_mut();
        let before = inner.plaintexts.len() + inner.objects.len() + inner.chunks.len();
        inner
            .plaintexts
            .retain(|(f, id), _| f != folder || objects.contains(id));
        inner
            .objects
            .retain(|(f, _), id| f != folder || objects.contains(id));
        inner
            .chunks
            .retain(|(f, c), _| f != folder || contents.contains(c));
        let after = inner.plaintexts.len() + inner.objects.len() + inner.chunks.len();
        Ok((before - after) as u64)
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
    /// The live set the reference deltas declared, as the real server keeps it.
    live: BTreeSet<ObjectId>,
    /// The live set after each head, so a side commit's diff is checked against its base as the
    /// real server does.
    live_at: BTreeMap<CommitId, BTreeSet<ObjectId>>,
}

/// The state of the in-memory server, shared by every device's [`MemServer`].
#[derive(Debug)]
pub struct ServerState {
    /// While false, every call fails with [`NetError::Unreachable`].
    pub online: bool,
    /// The next commit call is applied but its reply is lost.
    pub lose_next_commit_reply: bool,
    /// The next log append is applied but its reply is lost.
    pub lose_next_append_reply: bool,
    /// The next log append is lost on its way: not applied, and the call fails as offline.
    pub drop_next_append: bool,
    /// The next log append is applied, then the server goes offline before it answers (the
    /// app ends, or the connection drops, right after the append).
    pub offline_after_next_append: bool,
    /// Commits per delta page (small pages test paging).
    pub page_size: usize,
    /// Delta pages served so far, for the tests.
    pub delta_pages: u64,
    /// When set, this many more delta pages are served, then the connection fails (a pull
    /// cut off midway).
    pub delta_pages_left: Option<u64>,
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
    /// The server time it stamps on accepted calls and reports in the delta pull (`None`: no
    /// time, like a commit whose time expired).
    pub server_time_ms: Option<u64>,
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
    /// Reads of the account feed served, for the tests.
    pub feed_calls: u64,
    /// How often `get_object` served each object, for the tests.
    pub object_gets: BTreeMap<ObjectId, u64>,
    /// How often `put_object` was called for each object, for the tests.
    pub object_puts: BTreeMap<ObjectId, u64>,
    /// Every `put_object` in the order it came, for the tests.
    pub put_log: Vec<ObjectId>,
    /// `missing_objects` calls and the IDs they asked about, for the tests.
    pub missing_queries: u64,
    /// See [`Self::missing_queries`].
    pub missing_ids: u64,
    /// What each `put_object` costs, for tests of the work budget.
    pub put_cost: Option<WorkCost>,
    /// What each `get_object` costs, for tests of the work budget.
    pub get_cost: Option<WorkCost>,
    /// While set, `put_object` answers "stored" but keeps nothing, so `missing_objects` keeps
    /// listing the objects (a hostile or broken server).
    pub forget_puts: bool,
    /// Uploads from worker threads ([`Self::enable_parallel_uploads`]); `None`: every upload
    /// goes through [`MemServer`]'s `put_object` on the engine thread.
    pub parallel_uploads: Option<Arc<MemUploads>>,
    /// Downloads from worker threads ([`Self::enable_parallel_downloads`]); `None`: every
    /// download goes through [`MemServer`]'s `get_object` on the engine thread.
    pub parallel_downloads: Option<Arc<MemDownloads>>,
}

/// The uploads of [`MemUploader`]s, shared between worker threads and the [`ServerState`],
/// which takes in what landed at its next call ([`ServerState::settle_uploads`]).
#[derive(Debug, Default)]
pub struct MemUploads(Mutex<MemUploadState>);

impl MemUploads {
    /// The state, for the tests to set faults and read counters.
    pub fn lock(&self) -> std::sync::MutexGuard<'_, MemUploadState> {
        // Counters only; one written by a thread that panicked is still whole.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Faults and counters of the parallel uploads of the in-memory server.
#[derive(Debug, Default)]
pub struct MemUploadState {
    /// Real time each upload takes, so the uploads of the workers overlap.
    pub delay: std::time::Duration,
    /// After this many accepted uploads, every further one fails as unreachable.
    pub fail_after: Option<u64>,
    /// The next this many uploads answer `rate_limited` (a busy upload slot).
    pub rate_limited: u64,
    /// The next this many uploads answer `unauthorized` (an expired session).
    pub unauthorized: u64,
    /// Uploads accepted so far.
    pub accepted: u64,
    /// Uploads answered `rate_limited` so far.
    pub refused: u64,
    /// The most uploads in flight at once.
    pub max_in_flight: usize,
    in_flight: usize,
    landed: Vec<(FolderId, ObjectId, Vec<u8>)>,
}

/// The downloads of [`MemFetcher`]s: a copy of the server's objects that worker threads can
/// read, kept current whenever a fetcher is handed out ([`ServerState::enable_parallel_downloads`]).
#[derive(Debug, Default)]
pub struct MemDownloads(Mutex<MemDownloadState>);

impl MemDownloads {
    /// The state, for the tests to set faults and read counters.
    pub fn lock(&self) -> std::sync::MutexGuard<'_, MemDownloadState> {
        // Counters only; one written by a thread that panicked is still whole.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Faults and counters of the parallel downloads of the in-memory server.
#[derive(Debug, Default)]
pub struct MemDownloadState {
    /// Real time each download takes, so the downloads of the workers overlap.
    pub delay: std::time::Duration,
    /// The next this many downloads answer `rate_limited`.
    pub rate_limited: u64,
    /// Downloads served so far, by object.
    pub fetched: BTreeMap<ObjectId, u64>,
    /// The most downloads in flight at once.
    pub max_in_flight: usize,
    in_flight: usize,
    objects: BTreeMap<(FolderId, ObjectId), Vec<u8>>,
}

/// A fetcher of the in-memory server for worker threads ([`ServerState::parallel_downloads`]).
#[derive(Debug)]
struct MemFetcher {
    downloads: Arc<MemDownloads>,
    cost: Option<WorkCost>,
}

impl crate::ports::ObjectFetcher for MemFetcher {
    fn get_object(&self, folder: &FolderId, id: &ObjectId) -> Result<Vec<u8>, NetError> {
        let (verdict, delay) = {
            let mut s = self.downloads.lock();
            s.in_flight += 1;
            s.max_in_flight = s.max_in_flight.max(s.in_flight);
            let verdict = if s.rate_limited > 0 {
                s.rate_limited -= 1;
                Err(refuse(ErrorCode::RateLimited))
            } else {
                *s.fetched.entry(*id).or_default() += 1;
                s.objects
                    .get(&(*folder, *id))
                    .cloned()
                    .ok_or(refuse(ErrorCode::NotFound))
            };
            (verdict, s.delay)
        };
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        if let Some(cost) = &self.cost {
            cost.pay();
        }
        self.downloads.lock().in_flight -= 1;
        verdict
    }
}

/// An uploader of the in-memory server for worker threads ([`ServerState::parallel_uploads`]).
#[derive(Debug)]
struct MemUploader {
    uploads: Arc<MemUploads>,
    cost: Option<WorkCost>,
}

impl ObjectUploader for MemUploader {
    fn put_object(
        &self,
        folder: &FolderId,
        id: &ObjectId,
        blob: bytes::Bytes,
    ) -> Result<UploadResponse, NetError> {
        let (verdict, delay) = {
            let mut s = self.uploads.lock();
            s.in_flight += 1;
            s.max_in_flight = s.max_in_flight.max(s.in_flight);
            let verdict = if s.unauthorized > 0 {
                s.unauthorized -= 1;
                Err(refuse(ErrorCode::Unauthorized))
            } else if s.rate_limited > 0 {
                s.rate_limited -= 1;
                s.refused += 1;
                Err(refuse(ErrorCode::RateLimited))
            } else if s.fail_after.is_some_and(|n| s.accepted >= n) {
                Err(NetError::Unreachable)
            } else if hangar_drive_crypto::object::object_header(&blob).is_none() {
                Err(refuse(ErrorCode::BadRequest))
            } else {
                s.accepted += 1;
                Ok(())
            };
            (verdict, s.delay)
        };
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        if let Some(cost) = &self.cost {
            cost.pay();
        }
        let mut s = self.uploads.lock();
        s.in_flight -= 1;
        verdict?;
        s.landed.push((*folder, *id, blob.to_vec()));
        Ok(UploadResponse { stored: true })
    }
}

impl ServerState {
    /// A record as stored (version and sealed bytes), for tests.
    pub fn stored_record(&self, key: &RecordKey) -> Option<(u64, Vec<u8>)> {
        self.records.get(key).cloned()
    }

    /// Puts a record back as it was stored earlier: a server that shows a device another
    /// version than it keeps, or rewinds a record, for tests.
    pub fn set_stored_record(&mut self, key: RecordKey, version: u64, data: Vec<u8>) {
        self.records.insert(key, (version, data));
    }

    fn new() -> Self {
        Self {
            online: true,
            lose_next_commit_reply: false,
            lose_next_append_reply: false,
            drop_next_append: false,
            offline_after_next_append: false,
            page_size: hangar_drive_protocol::api::MAX_DELTA_PAGE,
            delta_pages: 0,
            delta_pages_left: None,
            expire_bases: false,
            refuse_commits: None,
            presented_pin: None,
            refuse_removed: false,
            server_time_ms: None,
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
            feed_calls: 0,
            object_gets: BTreeMap::new(),
            object_puts: BTreeMap::new(),
            put_log: Vec::new(),
            missing_queries: 0,
            missing_ids: 0,
            put_cost: None,
            get_cost: None,
            forget_puts: false,
            parallel_uploads: None,
            parallel_downloads: None,
        }
    }

    /// Hands out fetchers for worker threads from now on; returns their shared state.
    pub fn enable_parallel_downloads(&mut self) -> Arc<MemDownloads> {
        Arc::clone(
            self.parallel_downloads
                .get_or_insert_with(|| Arc::new(MemDownloads::default())),
        )
    }

    /// Copies the objects for the fetchers of worker threads.
    fn mirror_downloads(&self) {
        let Some(downloads) = &self.parallel_downloads else {
            return;
        };
        let mut d = downloads.lock();
        for (folder, f) in &self.folders {
            for (id, blob) in &f.objects {
                d.objects
                    .entry((*folder, *id))
                    .or_insert_with(|| blob.clone());
            }
        }
    }

    /// Hands out uploaders for worker threads from now on; returns their shared state.
    pub fn enable_parallel_uploads(&mut self) -> Arc<MemUploads> {
        Arc::clone(
            self.parallel_uploads
                .get_or_insert_with(|| Arc::new(MemUploads::default())),
        )
    }

    /// Takes in what the uploaders of worker threads sent, as `put_object` would have.
    pub fn settle_uploads(&mut self) {
        let Some(uploads) = self.parallel_uploads.clone() else {
            return;
        };
        let landed = std::mem::take(&mut uploads.lock().landed);
        for (folder, id, blob) in landed {
            *self.object_puts.entry(id).or_default() += 1;
            self.put_log.push(id);
            if self.forget_puts {
                continue;
            }
            self.folders
                .entry(folder)
                .or_default()
                .objects
                .entry(id)
                .or_insert(blob);
        }
    }

    fn push_feed(&mut self, change: FeedChange) {
        self.sequence += 1;
        self.feed.push(FeedEntry {
            sequence: self.sequence,
            change,
        });
    }

    /// Puts a notice into the change feed, as the real server does after an anomaly pin or a
    /// budget, quota or disk condition (this server detects none of them itself).
    pub fn push_notice(&mut self, notice: hangar_drive_protocol::api::Notice) {
        self.push_feed(FeedChange::Notice { notice });
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

    /// The live set of a folder: what the heads' reference deltas declared reachable.
    pub fn live_set(&self, folder: &FolderId) -> BTreeSet<ObjectId> {
        self.folders
            .get(folder)
            .map(|f| f.live.clone())
            .unwrap_or_default()
    }

    /// Replaces the live set of a folder: a server view another device broke before the
    /// reference deltas were bound to the tree, or a test of the repair.
    pub fn set_live(&mut self, folder: &FolderId, live: BTreeSet<ObjectId>) {
        self.folders.entry(*folder).or_default().live = live;
    }

    /// Deletes objects of a folder, as the collection does with objects no retained tree
    /// declares.
    pub fn delete_objects(&mut self, folder: &FolderId, ids: &BTreeSet<ObjectId>) {
        if let Some(f) = self.folders.get_mut(folder) {
            f.objects.retain(|id, _| !ids.contains(id));
        }
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
        let mut s = self.shared.borrow_mut();
        s.settle_uploads();
        s
    }

    fn enter(&self) -> Result<std::cell::RefMut<'_, ServerState>, NetError> {
        let mut s = self.shared.borrow_mut();
        s.settle_uploads();
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
        if std::mem::take(&mut s.drop_next_append) {
            return Err(NetError::Unreachable);
        }
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
        let recovery = matches!(
            batch.shape,
            hangar_drive_crypto::devicelog::BatchShape::Recovery { .. }
        );
        for w in &request.wraps {
            if let Some(epoch) = epoch {
                s.wraps.insert((epoch, w.device), w.data.0.clone());
            }
        }
        // The added device's wrap is of the epoch before the batch; a recovery rotates after
        // the add, so its wrap belongs to the epoch the log had before it (as the server keeps
        // it).
        let device_epoch = if recovery {
            state.current_epoch().map(|e| e.epoch.0)
        } else {
            epoch
        };
        if let (Some(w), Some(epoch)) = (&request.device_wrap, device_epoch) {
            s.wraps.insert((epoch, w.device), w.data.0.clone());
        }
        for e in &request.entries {
            s.log.push(e.0.clone());
        }
        let head = batch.state.head().ok_or(refuse(ErrorCode::Internal))?;
        let rotated = recovery
            || matches!(
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
        if std::mem::take(&mut s.offline_after_next_append) {
            s.online = false;
            return Err(NetError::Unreachable);
        }
        if std::mem::take(&mut s.lose_next_append_reply) {
            return Err(NetError::Unreachable);
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
        let mut s = self.enter()?;
        s.feed_calls += 1;
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
        let mut s = self.enter()?;
        s.missing_queries += 1;
        s.missing_ids += ids.len() as u64;
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
        let cost = self.shared.borrow().put_cost.clone();
        if let Some(cost) = cost {
            cost.pay();
        }
        let mut s = self.enter()?;
        *s.object_puts.entry(*id).or_default() += 1;
        s.put_log.push(*id);
        if hangar_drive_crypto::object::object_header(blob).is_none() {
            return Err(refuse(ErrorCode::BadRequest));
        }
        if s.forget_puts {
            return Ok(UploadResponse { stored: true });
        }
        let f = s.folders.entry(*folder).or_default();
        let stored = !f.objects.contains_key(id);
        f.objects.entry(*id).or_insert_with(|| blob.to_vec());
        Ok(UploadResponse { stored })
    }

    fn uploader(&mut self) -> Result<Option<Arc<dyn ObjectUploader>>, NetError> {
        // Without parallel uploads this is no call to the server, so tests that count calls
        // see the same numbers as before.
        if self.shared.borrow().parallel_uploads.is_none() {
            return Ok(None);
        }
        let s = self.enter()?;
        Ok(s.parallel_uploads.as_ref().map(|uploads| {
            Arc::new(MemUploader {
                uploads: Arc::clone(uploads),
                cost: s.put_cost.clone(),
            }) as Arc<dyn ObjectUploader>
        }))
    }

    fn settle_uploads(&mut self) {
        self.shared.borrow_mut().settle_uploads();
    }

    fn fetcher(&mut self) -> Result<Option<Arc<dyn crate::ports::ObjectFetcher>>, NetError> {
        // Without parallel downloads this is no call to the server, so tests that count calls
        // see the same numbers as before.
        if self.shared.borrow().parallel_downloads.is_none() {
            return Ok(None);
        }
        let s = self.enter()?;
        s.mirror_downloads();
        Ok(s.parallel_downloads.as_ref().map(|downloads| {
            Arc::new(MemFetcher {
                downloads: Arc::clone(downloads),
                cost: s.get_cost.clone(),
            }) as Arc<dyn crate::ports::ObjectFetcher>
        }))
    }

    fn get_object(&mut self, folder: &FolderId, id: &ObjectId) -> Result<Vec<u8>, NetError> {
        let cost = self.shared.borrow().get_cost.clone();
        if let Some(cost) = cost {
            cost.pay();
        }
        let mut s = self.enter()?;
        *s.object_gets.entry(*id).or_default() += 1;
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
        let server_ms = s.server_time_ms;
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
                ..ErrorBody::new(ErrorCode::HeadMoved)
            }));
        }
        let head = SignedCommit::decode(request.head.commit.as_bytes())
            .map_err(|_| refuse(ErrorCode::CommitRefused))?;
        head.verify_for_server(&state, folder)
            .map_err(|_| refuse(ErrorCode::CommitRefused))?;
        head.check_delta(&request.head.delta.added, &request.head.delta.dropped)
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
                side.check_delta(&upload.delta.added, &upload.delta.dropped)
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
                missing,
                ..ErrorBody::new(ErrorCode::MissingObjects)
            }));
        }
        // The side commit's diff against the live set of its base.
        if let Some((sc, upload)) = &side {
            let base = sc.commit.parents.first().and_then(|p| f.live_at.get(p));
            let empty = BTreeSet::new();
            let base = base.unwrap_or(&empty);
            let mut off: Vec<ObjectId> = upload
                .delta
                .added
                .iter()
                .filter(|id| base.contains(id))
                .chain(upload.delta.dropped.iter().filter(|id| !base.contains(id)))
                .copied()
                .collect();
            if !off.is_empty() {
                off.truncate(64);
                return Err(NetError::Server(ErrorBody {
                    missing: off,
                    ..ErrorBody::new(ErrorCode::DeltaMismatch)
                }));
            }
        }
        // The head's delta against the live set, as the real server checks it: a full delta
        // replaces the set and must hold its root; a diff must fit the set and leave the root
        // live.
        let delta = &request.head.delta;
        let live = if c.delta.full {
            if delta.added.binary_search(&c.root).is_err() {
                return Err(refuse(ErrorCode::CommitRefused));
            }
            delta.added.iter().copied().collect()
        } else {
            let mut off: Vec<ObjectId> = delta
                .added
                .iter()
                .filter(|id| f.live.contains(id))
                .chain(delta.dropped.iter().filter(|id| !f.live.contains(id)))
                .copied()
                .collect();
            let mut live = f.live.clone();
            live.extend(delta.added.iter().copied());
            for id in &delta.dropped {
                live.remove(id);
            }
            if !live.contains(&c.root) {
                off.push(c.root);
            }
            if !off.is_empty() {
                off.truncate(64);
                return Err(NetError::Server(ErrorBody {
                    missing: off,
                    ..ErrorBody::new(ErrorCode::DeltaMismatch)
                }));
            }
            live
        };
        f.live_at.insert(head.id, live.clone());
        f.live = live;
        f.sequence += 1;
        let sequence = f.sequence;
        if let Some((side, _)) = &side {
            f.commits.push(DeltaCommit {
                sequence,
                role: CommitRole::Side,
                commit: Blob(side.wire.clone()),
                server_ms,
            });
        }
        f.commits.push(DeltaCommit {
            sequence,
            role: CommitRole::Head,
            commit: Blob(head.wire.clone()),
            server_ms,
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
        let mut s = self.enter()?;
        match s.delta_pages_left {
            Some(0) => return Err(NetError::Unreachable),
            Some(n) => s.delta_pages_left = Some(n - 1),
            None => {}
        }
        s.delta_pages += 1;
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
