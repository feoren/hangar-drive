//! The traits behind which the sync core keeps file system, network, storage, clock,
//! randomness and keychain (ADR 0001, section 3: one deterministic control loop with every
//! effect behind a trait, so the seeded simulation can replace all of them).
//!
//! Real implementations: [`crate::localfs::LocalFs`], [`crate::http::HttpServer`],
//! [`crate::index::SqliteStore`], [`SystemClock`], [`OsRandom`]. In-memory ones for tests and
//! the simulation: `crate::memory` (feature `test-support`). The keychain is the app's (the OS keychain through Tauri);
//! this crate only defines the trait and an in-memory version.

use hangar_drive_crypto::{Entropy, EntropyError};
use hangar_drive_protocol::api::{
    ChallengeResponse, CommitRequest, CommitResponse, DeltaPage, ErrorBody, ErrorCode, FeedPage,
    LogAppendRequest, LogAppendResponse, LogPage, PairingRequest, RecordKey, RecordPut,
    RecordResponse, SessionResponse, UploadResponse, WrappedKeyResponse,
};
use hangar_drive_protocol::ids::{
    AccountId, Challenge, DeviceId, Epoch, FolderId, ItemId, ObjectId, PairingId, Signature,
};
use zeroize::Zeroizing;

use crate::tree::{ContentKey, TreeDelta};

// ------------------------------------------------------------------------------------------
// Clock and randomness
// ------------------------------------------------------------------------------------------

/// Wall clock time in milliseconds since the Unix epoch (UTC).
pub trait Clock {
    /// Now.
    fn now_ms(&self) -> i64;
}

/// The system clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
            .unwrap_or(0)
    }
}

/// Randomness: the crypto crate's [`Entropy`]. Item IDs, nonces and secrets come from it.
pub trait Random: Entropy {}

impl<T: Entropy> Random for T {}

/// The operating system's random number generator.
pub type OsRandom = hangar_drive_crypto::OsEntropy;

/// A random item ID that is never [`crate::tree::ROOT`].
pub fn random_item_id(random: &mut dyn Entropy) -> Result<ItemId, EntropyError> {
    loop {
        let mut bytes = [0u8; 16];
        random.fill(&mut bytes)?;
        let id = ItemId::from_bytes(bytes);
        if id != crate::tree::ROOT {
            return Ok(id);
        }
    }
}

// ------------------------------------------------------------------------------------------
// Keychain
// ------------------------------------------------------------------------------------------

/// Why the keychain failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeychainError {
    /// The OS keychain refused or is not available.
    #[error("the keychain is not available: {0}")]
    Unavailable(String),
}

/// The OS keychain: the device identity and the epoch secrets live only here (project rule:
/// secrets exclusively in the OS keychain).
pub trait Keychain {
    /// The secret under `key`.
    fn load(&self, key: &str) -> Result<Option<Zeroizing<Vec<u8>>>, KeychainError>;
    /// Stores a secret under `key`.
    fn store(&mut self, key: &str, secret: &[u8]) -> Result<(), KeychainError>;
    /// Deletes the secret under `key`.
    fn delete(&mut self, key: &str) -> Result<(), KeychainError>;
}

// ------------------------------------------------------------------------------------------
// File system
// ------------------------------------------------------------------------------------------

/// What an entry on disk is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryType {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link: never synced, never followed.
    Symlink,
    /// A junction, mount point or other reparse point, or a cloud placeholder: never synced.
    Reparse,
    /// A file with the Windows system attribute: never synced.
    System,
    /// A FIFO, socket or device node: never synced.
    Other,
}

/// Metadata of one entry, read without following links.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stat {
    /// What it is.
    pub kind: EntryType,
    /// Bytes (0 for a directory).
    pub size: u64,
    /// Modification time, milliseconds since the Unix epoch.
    pub mtime_ms: i64,
    /// NTFS file index or inode: kept by a move.
    pub file_id: Option<u128>,
    /// The owner's execute bit (always false on Windows).
    pub executable: bool,
}

/// One entry of a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListEntry {
    /// The name, or `None` if it is not valid UTF-8 (possible on Linux): such an entry is never
    /// synced and is shown as "cannot sync on this device".
    pub name: Option<String>,
    /// The raw name for display when it is not UTF-8.
    pub display: String,
    /// Its metadata.
    pub stat: Stat,
}

/// Why a file system call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FsError {
    /// No such entry.
    #[error("not found")]
    NotFound,
    /// The name is taken.
    #[error("already exists")]
    Exists,
    /// Open in another program (sharing or lock violation).
    #[error("locked by another program")]
    Locked,
    /// A directory to remove is not empty.
    #[error("the directory is not empty")]
    NotEmpty,
    /// The disk holds something other than expected (precondition of a replace or delete).
    #[error("the entry changed")]
    Changed,
    /// This device cannot hold the name (Windows rules) or the entry.
    #[error("cannot sync on this device: {0}")]
    CannotSync(String),
    /// No space left.
    #[error("the disk is full")]
    DiskFull,
    /// No permission.
    #[error("permission denied")]
    Denied,
    /// Another error, with the OS message.
    #[error("i/o error: {0}")]
    Io(String),
}

/// What a replace or delete expects to find on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Expect {
    /// Bytes.
    pub size: u64,
    /// Modification time.
    pub mtime_ms: i64,
    /// The file ID the index knows, if any: a file saved under the same name by another
    /// program (a new file ID with the same size and time) is not the expected one (security
    /// review L3).
    pub file_id: Option<u128>,
}

/// A sync root on disk. Paths are lists of names below the root; the implementation checks
/// every name before it builds a platform path from it (ADR 0001, section 7).
pub trait FileSystem: Sync {
    /// Metadata of an entry, `None` if it does not exist.
    fn stat(&self, path: &[String]) -> Result<Option<Stat>, FsError>;
    /// The entries of a directory.
    fn list(&self, path: &[String]) -> Result<Vec<ListEntry>, FsError>;
    /// Reads up to `buf.len()` bytes at `offset`; 0 at the end.
    fn read_at(&self, path: &[String], offset: u64, buf: &mut [u8]) -> Result<usize, FsError>;
    /// Creates a directory; [`FsError::Exists`] if the name is taken.
    fn create_dir(&self, path: &[String]) -> Result<(), FsError>;
    /// Writes a file atomically: `fill` writes the content into a temporary file in the
    /// reserved directory, which is then renamed over the target. With `replace`, the target
    /// must still match it; without, the target name must be free ([`FsError::Exists`]).
    fn write_atomic(
        &self,
        path: &[String],
        fill: &mut dyn FnMut(&mut dyn std::io::Write) -> Result<(), FsError>,
        mtime_ms: i64,
        executable: bool,
        replace: Option<Expect>,
    ) -> Result<Stat, FsError>;
    /// Renames without replacing an existing target.
    fn rename(&self, from: &[String], to: &[String]) -> Result<(), FsError>;
    /// Deletes a file that still matches `expect`.
    fn remove_file(&self, path: &[String], expect: Expect) -> Result<(), FsError>;
    /// Takes away a file that still matches `expect` because another device deleted it: to
    /// the system's recycle bin, or to the quarantine of item `item` (security review M2). The
    /// default deletes it.
    fn trash_file(
        &self,
        item: &ItemId,
        path: &[String],
        expect: Expect,
    ) -> Result<crate::trash::Trashed, FsError> {
        let _ = item;
        self.remove_file(path, expect)
            .map(|()| crate::trash::Trashed::RecycleBin)
    }
    /// The file IDs the index knows for directories below the root, by path; every operation
    /// compares the directories on its way with them (security review L1). The default keeps
    /// nothing.
    fn expect_directories(&self, ids: Vec<(Vec<String>, u128)>) {
        let _ = ids;
    }
    /// Deletes an empty directory.
    fn remove_dir(&self, path: &[String]) -> Result<(), FsError>;
    /// Sets modification time and execute flag of a file that still matches `expect`.
    fn set_meta(
        &self,
        path: &[String],
        mtime_ms: i64,
        executable: bool,
        expect: Expect,
    ) -> Result<(), FsError>;
    /// The tolerance for comparing modification times: 2 s on FAT and exFAT, else 0.
    fn mtime_tolerance_ms(&self) -> i64 {
        0
    }
    /// Whether the file system reports and keeps the execute bit (not on Windows, where the
    /// flag of the synced tree is kept).
    fn exec_supported(&self) -> bool {
        true
    }
    /// Periodic upkeep of the sync root's reserved directory at `now_ms` (Unix ms), called with
    /// the hourly full scan: quarantined files past their days go (security review, info), not
    /// only when the root is opened.
    fn housekeeping(&self, _now_ms: i64) {}
    /// Free bytes for this user on the volume of the sync root, `None` when the platform cannot
    /// tell. A download checks it before it writes anything (security review M2 of the
    /// download path: a manifest may name far more bytes than the server stores).
    fn free_bytes(&self) -> Option<u64> {
        None
    }
    /// The size of the volume of the sync root, `None` when the platform cannot tell. The
    /// free space a download leaves scales with it (LOW 4 of the follow-up review).
    fn volume_bytes(&self) -> Option<u64> {
        None
    }
}

impl<T: FileSystem + Send + ?Sized> FileSystem for std::sync::Arc<T> {
    fn stat(&self, path: &[String]) -> Result<Option<Stat>, FsError> {
        (**self).stat(path)
    }
    fn list(&self, path: &[String]) -> Result<Vec<ListEntry>, FsError> {
        (**self).list(path)
    }
    fn read_at(&self, path: &[String], offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        (**self).read_at(path, offset, buf)
    }
    fn create_dir(&self, path: &[String]) -> Result<(), FsError> {
        (**self).create_dir(path)
    }
    fn write_atomic(
        &self,
        path: &[String],
        fill: &mut dyn FnMut(&mut dyn std::io::Write) -> Result<(), FsError>,
        mtime_ms: i64,
        executable: bool,
        replace: Option<Expect>,
    ) -> Result<Stat, FsError> {
        (**self).write_atomic(path, fill, mtime_ms, executable, replace)
    }
    fn rename(&self, from: &[String], to: &[String]) -> Result<(), FsError> {
        (**self).rename(from, to)
    }
    fn remove_file(&self, path: &[String], expect: Expect) -> Result<(), FsError> {
        (**self).remove_file(path, expect)
    }
    fn trash_file(
        &self,
        item: &ItemId,
        path: &[String],
        expect: Expect,
    ) -> Result<crate::trash::Trashed, FsError> {
        (**self).trash_file(item, path, expect)
    }
    fn expect_directories(&self, ids: Vec<(Vec<String>, u128)>) {
        (**self).expect_directories(ids)
    }
    fn remove_dir(&self, path: &[String]) -> Result<(), FsError> {
        (**self).remove_dir(path)
    }
    fn set_meta(
        &self,
        path: &[String],
        mtime_ms: i64,
        executable: bool,
        expect: Expect,
    ) -> Result<(), FsError> {
        (**self).set_meta(path, mtime_ms, executable, expect)
    }
    fn mtime_tolerance_ms(&self) -> i64 {
        (**self).mtime_tolerance_ms()
    }
    fn exec_supported(&self) -> bool {
        (**self).exec_supported()
    }
    fn housekeeping(&self, now_ms: i64) {
        (**self).housekeeping(now_ms)
    }
    fn free_bytes(&self) -> Option<u64> {
        (**self).free_bytes()
    }
    fn volume_bytes(&self) -> Option<u64> {
        (**self).volume_bytes()
    }
}

/// The file system of a folder that has no sync root on this device. Jobs that only work on
/// the folder's chain (the barriers of a device removal) take it; every call fails, so a change
/// that starts to touch the disk on that path shows as an error instead of writing nowhere.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoLocalRoot;

impl NoLocalRoot {
    fn refuse<T>() -> Result<T, FsError> {
        Err(FsError::Io(
            "the folder has no sync root on this device".into(),
        ))
    }
}

impl FileSystem for NoLocalRoot {
    fn stat(&self, _: &[String]) -> Result<Option<Stat>, FsError> {
        Self::refuse()
    }
    fn list(&self, _: &[String]) -> Result<Vec<ListEntry>, FsError> {
        Self::refuse()
    }
    fn read_at(&self, _: &[String], _: u64, _: &mut [u8]) -> Result<usize, FsError> {
        Self::refuse()
    }
    fn create_dir(&self, _: &[String]) -> Result<(), FsError> {
        Self::refuse()
    }
    fn write_atomic(
        &self,
        _: &[String],
        _: &mut dyn FnMut(&mut dyn std::io::Write) -> Result<(), FsError>,
        _: i64,
        _: bool,
        _: Option<Expect>,
    ) -> Result<Stat, FsError> {
        Self::refuse()
    }
    fn rename(&self, _: &[String], _: &[String]) -> Result<(), FsError> {
        Self::refuse()
    }
    fn remove_file(&self, _: &[String], _: Expect) -> Result<(), FsError> {
        Self::refuse()
    }
    fn trash_file(
        &self,
        _: &ItemId,
        _: &[String],
        _: Expect,
    ) -> Result<crate::trash::Trashed, FsError> {
        Self::refuse()
    }
    fn remove_dir(&self, _: &[String]) -> Result<(), FsError> {
        Self::refuse()
    }
    fn set_meta(&self, _: &[String], _: i64, _: bool, _: Expect) -> Result<(), FsError> {
        Self::refuse()
    }
}

// ------------------------------------------------------------------------------------------
// Server API
// ------------------------------------------------------------------------------------------

/// Why a server call failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    /// The server refused with one of its error codes.
    #[error("the server refused: {0:?}")]
    Server(ErrorBody),
    /// No connection, a timeout or a reset; retried with backoff.
    #[error("the server is not reachable")]
    Unreachable,
    /// The server's TLS key does not match the pin (ADR 0001, section 6). Nothing was sent.
    #[error("the server identifies itself differently than usual")]
    PinMismatch,
    /// TLS failed otherwise (no valid certificate).
    #[error("the connection is not secure: {0}")]
    Tls(String),
    /// The server's answer does not follow the protocol.
    #[error("the server's answer does not follow the protocol: {0}")]
    Protocol(String),
    /// The server speaks another protocol version.
    #[error("the server needs another version of the app")]
    Version,
    /// The server answered this device's own sign-in proof with `device_removed` (security
    /// review H2). Only the answer to the proof call means this; the same code on any other
    /// route is a [`NetError::Protocol`] error, because only a proof made with this device's
    /// key tells the server which device asks. It carries the device log from the head this
    /// device named up to the removal, when the server sent it; the engine forgets the account
    /// only when those entries continue its own verified log with a valid removal of this
    /// device, never on the code alone (`engine`, "reported removed").
    #[error("the server says this device was removed")]
    DeviceRemoved(Option<LogPage>),
}

impl NetError {
    /// The server's error code, if it refused.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            NetError::Server(body) => Some(body.code),
            NetError::DeviceRemoved(_) => Some(ErrorCode::DeviceRemoved),
            _ => None,
        }
    }

    /// Whether a retry later may succeed.
    pub fn is_transient(&self) -> bool {
        match self {
            NetError::Unreachable => true,
            NetError::Server(body) => matches!(
                body.code,
                ErrorCode::RateLimited | ErrorCode::Internal | ErrorCode::Unknown
            ),
            _ => false,
        }
    }
}

/// The server API of `hangar-drive-protocol::api`, one method per call. The session (token,
/// renewal by a new proof) is the implementation's concern.
pub trait ServerApi {
    /// `POST /accounts`.
    fn create_account(
        &mut self,
        request: &hangar_drive_protocol::api::CreateAccountRequest,
    ) -> Result<hangar_drive_protocol::api::CreateAccountResponse, NetError>;
    /// `POST /session/challenge`.
    fn challenge(
        &mut self,
        account: &AccountId,
        device: &DeviceId,
    ) -> Result<ChallengeResponse, NetError>;
    /// `POST /session/proof`.
    fn proof(
        &mut self,
        account: &AccountId,
        device: &DeviceId,
        challenge: &Challenge,
        signature: &Signature,
    ) -> Result<SessionResponse, NetError>;
    /// `GET /account/log?after=N`.
    fn log(&mut self, after: u64) -> Result<LogPage, NetError>;
    /// `POST /account/log`.
    fn append_log(&mut self, request: &LogAppendRequest) -> Result<LogAppendResponse, NetError>;
    /// `GET /account/epochs/{epoch}/key`.
    fn epoch_key(&mut self, epoch: Epoch) -> Result<WrappedKeyResponse, NetError>;
    /// `GET /account/records/...`; `None` if there is none.
    fn record(&mut self, key: &RecordKey) -> Result<Option<RecordResponse>, NetError>;
    /// `PUT /account/records/...`.
    fn put_record(&mut self, key: &RecordKey, put: &RecordPut) -> Result<(), NetError>;
    /// `GET /account/feed?after=N`.
    fn feed(&mut self, after: u64) -> Result<FeedPage, NetError>;
    /// `PUT /pairing/{id}` (the inviting device, with its session): reserves the slot before
    /// the offer is shown; the server allows a few open slots per account, and the new device
    /// may only answer a reserved one.
    fn reserve_pairing(
        &mut self,
        id: &PairingId,
    ) -> Result<hangar_drive_protocol::api::PairingReservation, NetError>;
    /// `POST /pairing/{id}` (the new device, without a session).
    fn post_pairing(&mut self, id: &PairingId, request: &PairingRequest) -> Result<(), NetError>;
    /// `GET /pairing/{id}` (the inviting device); `None` while nobody answered.
    fn get_pairing(&mut self, id: &PairingId) -> Result<Option<PairingRequest>, NetError>;
    /// `DELETE /pairing/{id}` (the inviting device, once the person answered): the request
    /// leaves the server. Closing a slot that is gone is no error.
    fn close_pairing(&mut self, id: &PairingId) -> Result<(), NetError>;
    /// `POST /folders/{folder}/objects/missing`.
    fn missing_objects(
        &mut self,
        folder: &FolderId,
        ids: &[ObjectId],
    ) -> Result<Vec<ObjectId>, NetError>;
    /// `PUT /folders/{folder}/objects/{id}`.
    fn put_object(
        &mut self,
        folder: &FolderId,
        id: &ObjectId,
        blob: &[u8],
    ) -> Result<UploadResponse, NetError>;
    /// `GET /folders/{folder}/objects/{id}`.
    fn get_object(&mut self, folder: &FolderId, id: &ObjectId) -> Result<Vec<u8>, NetError>;
    /// `POST /folders/{folder}/commit`.
    fn commit(
        &mut self,
        folder: &FolderId,
        request: &CommitRequest,
    ) -> Result<CommitResponse, NetError>;
    /// `GET /folders/{folder}/commits?after=N`.
    fn commits(&mut self, folder: &FolderId, after: u64) -> Result<DeltaPage, NetError>;
    /// `POST /folders/{folder}/retire`.
    fn retire(&mut self, folder: &FolderId) -> Result<(), NetError>;
    /// `DELETE /folders/{folder}/retire`: brings a retired folder back within the retention
    /// window (ADR 0001, section 3, "Folder list").
    fn bring_back(&mut self, folder: &FolderId) -> Result<(), NetError>;
    /// The SPKI pin of the key the server presented when the last call ended with
    /// [`NetError::PinMismatch`], so the person can compare its server key number with the
    /// server CLI (ADR 0001, section 6, "Pin rotation"). Learnt from the aborted handshake; it is
    /// never trusted until the person confirmed it. `None` when no mismatch was seen.
    fn seen_pin(&self) -> Option<[u8; 32]> {
        None
    }
    /// The length of the device log this device verified, sent with the next sign-in proof
    /// (`ProofRequest::log_length`), so a server that answers "removed" sends the log from there
    /// (security review H2). Implementations without sessions ignore it.
    fn set_known_log_length(&mut self, _length: u64) {}
}

// ------------------------------------------------------------------------------------------
// Storage (the local index)
// ------------------------------------------------------------------------------------------

/// Why the local index failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    /// The database failed.
    #[error("the local index failed: {0}")]
    Db(String),
    /// A stored value does not decode.
    #[error("the local index holds an invalid value: {0}")]
    Corrupt(String),
}

/// The chunk IDs of one content, and the generation they were sealed under if known.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkList {
    /// The generation of the chunks (known after an upload or a download).
    pub generation: Option<u32>,
    /// The chunk IDs in file order.
    pub chunks: Vec<ObjectId>,
}

/// The persisted state of one folder: its trees, the file IDs of the local tree and the
/// folder's metadata as JSON (the verified chain, cursor, journal).
#[derive(Debug, Clone, Default)]
pub struct StoredFolder {
    /// The remote tree.
    pub remote: Vec<(ItemId, crate::tree::Node)>,
    /// The synced tree.
    pub synced: Vec<(ItemId, crate::tree::Node)>,
    /// The local tree.
    pub local: Vec<(ItemId, crate::tree::Node)>,
    /// File IDs of local items.
    pub file_ids: Vec<(ItemId, u128)>,
    /// The folder's metadata ([`crate::folder::FolderMeta`] as JSON).
    pub meta: Vec<u8>,
}

/// One atomic write of a folder's state.
#[derive(Debug, Clone, Default)]
pub struct SaveBatch {
    /// Changed rows of the remote tree.
    pub remote: TreeDelta,
    /// Changed rows of the synced tree.
    pub synced: TreeDelta,
    /// Changed rows of the local tree.
    pub local: TreeDelta,
    /// File IDs set or cleared.
    pub file_ids: Vec<(ItemId, Option<u128>)>,
    /// New metadata, if it changed.
    pub meta: Option<Vec<u8>>,
}

/// The local index (ADR 0001, section 3): lives in the platform's config directory, never in
/// the sync folder.
pub trait Store {
    /// Folder IDs with stored state.
    fn folders(&self) -> Result<Vec<FolderId>, StoreError>;
    /// A folder's stored state.
    fn load_folder(&self, folder: &FolderId) -> Result<Option<StoredFolder>, StoreError>;
    /// Writes a batch atomically.
    fn save_folder(&mut self, folder: &FolderId, batch: &SaveBatch) -> Result<(), StoreError>;
    /// Deletes a folder's state.
    fn delete_folder(&mut self, folder: &FolderId) -> Result<(), StoreError>;
    /// The chunk list of a content in a folder.
    fn chunk_list(
        &self,
        folder: &FolderId,
        content: &ContentKey,
    ) -> Result<Option<ChunkList>, StoreError>;
    /// Stores a chunk list.
    fn put_chunk_list(
        &mut self,
        folder: &FolderId,
        content: &ContentKey,
        list: &ChunkList,
    ) -> Result<(), StoreError>;
    /// The object ID known for a plaintext digest (object type and SHA-256 of the plaintext).
    fn object_for(
        &self,
        folder: &FolderId,
        digest: &[u8; 32],
    ) -> Result<Option<ObjectId>, StoreError>;
    /// Remembers an object ID for a plaintext digest.
    fn put_object_for(
        &mut self,
        folder: &FolderId,
        digest: &[u8; 32],
        id: &ObjectId,
    ) -> Result<(), StoreError>;
    /// The cached plaintext of a directory node or manifest.
    fn plaintext(&self, folder: &FolderId, id: &ObjectId) -> Result<Option<Vec<u8>>, StoreError>;
    /// Caches a plaintext.
    fn put_plaintext(
        &mut self,
        folder: &FolderId,
        id: &ObjectId,
        plaintext: &[u8],
    ) -> Result<(), StoreError>;
    /// A value of the account state (JSON), for example the verified log and the counter.
    fn account_value(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError>;
    /// Stores a value of the account state.
    fn put_account_value(&mut self, key: &str, value: &[u8]) -> Result<(), StoreError>;
    /// Deletes a value of the account state; deleting what is not there is not an error.
    fn delete_account_value(&mut self, key: &str) -> Result<(), StoreError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Zeros(u8);

    impl Entropy for Zeros {
        fn fill(&mut self, buf: &mut [u8]) -> Result<(), EntropyError> {
            // First call all zeros, then ones.
            buf.fill(self.0);
            self.0 = 1;
            Ok(())
        }
    }

    #[test]
    fn random_item_ids_skip_the_root_id() {
        let id = random_item_id(&mut Zeros(0)).unwrap();
        assert_eq!(id, ItemId::from_bytes([1; 16]));
    }

    #[test]
    fn transient_errors() {
        assert!(NetError::Unreachable.is_transient());
        assert!(!NetError::PinMismatch.is_transient());
        assert!(NetError::Server(ErrorBody::new(ErrorCode::RateLimited)).is_transient());
        assert!(!NetError::Server(ErrorBody::new(ErrorCode::HeadMoved)).is_transient());
    }
}
