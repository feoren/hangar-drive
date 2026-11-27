//! Folder key rings (record kind `folder-keys`) and the folder list (record kind `folders`).
//!
//! # Folder key ring
//!
//! Folder keys are random and independent of account epochs, so an epoch rotation re-seals one
//! small ring per folder and re-encrypts no content. The ring holds every generation of the
//! folder, oldest first; generation `g` counts from 1 without gaps (after the notes key ring of
//! the sister project's `hangar-team-crypto`, `src/notes.rs`, MIT, same owner).
//!
//! ```text
//! ring = 0x01 || folder id (16) || count (u16)
//!        || count x ( generation (u32) || created at log index (u64) || FK (32) ), oldest first
//! ```
//!
//! `created at log index` is the device log head index of the device that made the
//! generation, at the moment it made it: at least 1, never decreasing along the ring, and never
//! above the log head the ring's record names. It binds a generation to the log state it was
//! made in, so a device can tell whether a removed device may know it (freshness below).
//!
//! A newer ring must extend the one a device holds: every older generation with the same key
//! and index ([`FolderKeyRing::extends`]), so a server cannot swap an old key under a valid
//! newer version.
//!
//! # Freshness (ADR 0001, section 3, "Record freshness")
//!
//! The replay guard refuses only versions older than one this device accepted. It cannot tell
//! a device that a newer version exists. So a device commits to a folder only
//! ([`writable_generation`]):
//!
//! - with a ring sealed under the **newest epoch** of its verified account log,
//! - while no rotation is due in that log,
//! - with a newest generation created at or after the log's **last removal**
//!   ([`AccountState::last_removal_index`]): a generation made before it may be known to the
//!   removed device,
//! - and never under a generation below the newest one on the first-parent chain it verified.
//!
//! Every removal rotates the epoch and the removing device re-seals every account record with
//! a new generation in every ring ([`reseal_after_removal`]), so an old ring is caught as soon
//! as the device knows the log.
//!
//! # Folder list
//!
//! ```text
//! list  = 0x01 || count (u32) || count x ( folder id (16) || field(name, UTF-8) ), sorted by folder id
//! ```
//!
//! A name is 1 to [`MAX_FOLDER_NAME_LEN`] bytes and passes
//! [`hangar_drive_protocol::name::check_display_name`] (no control, format or bidirectional
//! control characters, a visible character, no white space at either edge). The server sees
//! only folder IDs.

use std::fmt;

use hangar_drive_protocol::api::{RecordKey, RecordKind};
use hangar_drive_protocol::ids::{DeviceId, Epoch, FolderId, Generation, LogHead};
use hangar_drive_protocol::name::check_display_name;
use thiserror::Error;
use zeroize::Zeroizing;

use crate::device_names::DeviceNameList;
use crate::devicelog::AccountState;
use crate::encoding::{constant_time_eq, Reader, Writer};
use crate::entropy::{Entropy, EntropyError};
use crate::epoch::{AccountSecret, WrapError};
use crate::identity::DeviceIdentity;
use crate::record::{OpenError, OpenedRecord, RecordCipher, SealError};

const RING_VERSION: u8 = 1;
const LIST_VERSION: u8 = 1;
const RING_HEADER_LEN: usize = 1 + 16 + 2;
const RING_ENTRY_LEN: usize = 4 + 8 + 32;
/// Generations one ring may hold (one per device removal, about 180 KB at the limit).
pub const MAX_GENERATIONS: usize = 4096;
/// Folders one account may list.
pub const MAX_FOLDERS: usize = 1024;
/// Bytes of a folder name.
pub const MAX_FOLDER_NAME_LEN: usize = 255;

/// Why a ring or list was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FolderKeysError {
    /// Not a ring or list of this format.
    #[error("the folder key ring or folder list is malformed")]
    Malformed,
    /// A format version this crate does not know.
    #[error("format version {0} is not supported")]
    Version(u8),
    /// The ring belongs to another folder than its record.
    #[error("the ring belongs to another folder")]
    FolderMismatch,
    /// Generations not exactly 1, 2, ..., count, or creation indexes that are 0, go back or lie
    /// beyond the record's log head.
    #[error("the ring's generations are not consecutive from 1 or not in log order")]
    Generations,
    /// Re-sealing needs a log whose newest epoch follows its last removal.
    #[error("the account log has no rotation after its last removal yet")]
    NotRotated,
    /// A record version would overflow.
    #[error("the record version cannot grow")]
    VersionOverflow,
    /// No account key for the newest epoch.
    #[error(transparent)]
    Key(#[from] WrapError),
    /// Above the limits.
    #[error("too many generations or folders")]
    TooLarge,
    /// The newer ring drops or changes an older generation.
    #[error("the newer ring does not keep every older key")]
    NotExtending,
    /// An invalid folder name.
    #[error("a folder name is empty, too long or has control characters")]
    Name,
    /// Folder IDs unsorted or repeated.
    #[error("the folder list is not sorted by folder id")]
    Unsorted,
    /// No randomness.
    #[error(transparent)]
    Entropy(#[from] EntropyError),
    /// Sealing failed.
    #[error(transparent)]
    Seal(#[from] SealError),
    /// Opening failed.
    #[error(transparent)]
    Open(#[from] OpenError),
}

/// One folder key generation `FK_f,g`. Wiped on drop, never printed.
#[derive(Clone)]
pub struct FolderKey(Zeroizing<[u8; 32]>);

impl fmt::Debug for FolderKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FolderKey(..)")
    }
}

impl FolderKey {
    /// A key of these bytes.
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> Self {
        Self(bytes)
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn generate(entropy: &mut impl Entropy) -> Result<Self, EntropyError> {
        let mut key = Zeroizing::new([0u8; 32]);
        entropy.fill(key.as_mut())?;
        Ok(Self(key))
    }
}

/// One generation of a ring: its key and the log index it was created at.
#[derive(Clone)]
struct RingKey {
    created_at: u64,
    key: FolderKey,
}

/// A folder's keys, every generation.
#[derive(Clone)]
pub struct FolderKeyRing {
    folder: FolderId,
    keys: Vec<RingKey>,
}

impl fmt::Debug for FolderKeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FolderKeyRing")
            .field("folder", &self.folder)
            .field("generations", &self.keys.len())
            .field("newest_created_at", &self.newest_created_at())
            .finish()
    }
}

impl FolderKeyRing {
    /// A new folder's ring with generation 1, made at the creating device's verified log head
    /// index `created_at`.
    pub fn new(
        folder: FolderId,
        created_at: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Self, FolderKeysError> {
        if created_at == 0 {
            return Err(FolderKeysError::Generations);
        }
        Ok(Self {
            folder,
            keys: vec![RingKey {
                created_at,
                key: FolderKey::generate(entropy)?,
            }],
        })
    }

    /// The folder.
    pub fn folder(&self) -> &FolderId {
        &self.folder
    }

    /// Adds the next generation (after a device removal), made at the device's verified log
    /// head index `created_at`, and returns it.
    pub fn add_generation(
        &mut self,
        created_at: u64,
        entropy: &mut impl Entropy,
    ) -> Result<Generation, FolderKeysError> {
        if self.keys.len() >= MAX_GENERATIONS {
            return Err(FolderKeysError::TooLarge);
        }
        if created_at < self.newest_created_at() {
            return Err(FolderKeysError::Generations);
        }
        self.keys.push(RingKey {
            created_at,
            key: FolderKey::generate(entropy)?,
        });
        Ok(self.newest_generation())
    }

    /// The newest generation, which new objects use.
    pub fn newest_generation(&self) -> Generation {
        Generation(u32::try_from(self.keys.len()).unwrap_or(u32::MAX))
    }

    /// The log index the newest generation was created at.
    pub fn newest_created_at(&self) -> u64 {
        self.keys.last().map_or(0, |k| k.created_at)
    }

    /// The log index generation `g` was created at.
    pub fn created_at(&self, generation: Generation) -> Option<u64> {
        let at = usize::try_from(generation.0.checked_sub(1)?).ok()?;
        self.keys.get(at).map(|k| k.created_at)
    }

    /// The key of generation `g`.
    pub fn get(&self, generation: Generation) -> Option<&FolderKey> {
        let at = usize::try_from(generation.0.checked_sub(1)?).ok()?;
        self.keys.get(at).map(|k| &k.key)
    }

    /// Whether this ring keeps every generation of `older` with the same key and index.
    pub fn extends(&self, older: &FolderKeyRing) -> bool {
        self.folder == older.folder
            && self.keys.len() >= older.keys.len()
            && self.keys.iter().zip(&older.keys).all(|(a, b)| {
                a.created_at == b.created_at && constant_time_eq(a.key.bytes(), b.key.bytes())
            })
    }

    /// The ring's plaintext (module docs), wiped on drop.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut w = Writer::with_capacity(RING_HEADER_LEN + RING_ENTRY_LEN * self.keys.len());
        w.u8(RING_VERSION)
            .raw(self.folder.as_bytes())
            .u16(u16::try_from(self.keys.len()).unwrap_or(u16::MAX));
        for (i, key) in self.keys.iter().enumerate() {
            w.u32(u32::try_from(i + 1).unwrap_or(u32::MAX))
                .u64(key.created_at)
                .raw(key.key.bytes());
        }
        Zeroizing::new(w.into_bytes())
    }

    /// Reads a ring of `folder` strictly.
    pub fn decode(bytes: &[u8], folder: &FolderId) -> Result<Self, FolderKeysError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().ok_or(FolderKeysError::Malformed)?;
        if version != RING_VERSION {
            return Err(FolderKeysError::Version(version));
        }
        let id = FolderId::from_bytes(r.raw().ok_or(FolderKeysError::Malformed)?);
        if id != *folder {
            return Err(FolderKeysError::FolderMismatch);
        }
        let count = usize::from(r.u16().ok_or(FolderKeysError::Malformed)?);
        if count == 0 {
            return Err(FolderKeysError::Generations);
        }
        if count > MAX_GENERATIONS {
            return Err(FolderKeysError::TooLarge);
        }
        if r.remaining() != count * RING_ENTRY_LEN {
            return Err(FolderKeysError::Malformed);
        }
        let mut keys: Vec<RingKey> = Vec::with_capacity(count);
        for expected in 1..=count {
            let generation = r.u32().ok_or(FolderKeysError::Malformed)?;
            if usize::try_from(generation).ok() != Some(expected) {
                return Err(FolderKeysError::Generations);
            }
            let created_at = r.u64().ok_or(FolderKeysError::Malformed)?;
            if created_at == 0 || keys.last().is_some_and(|k| created_at < k.created_at) {
                return Err(FolderKeysError::Generations);
            }
            let mut key = Zeroizing::new([0u8; 32]);
            key.copy_from_slice(r.raw_slice(32).ok_or(FolderKeysError::Malformed)?);
            keys.push(RingKey {
                created_at,
                key: FolderKey(key),
            });
        }
        r.finish().ok_or(FolderKeysError::Malformed)?;
        Ok(Self { folder: id, keys })
    }
}

/// A ring opened from its record: the ring with the epoch, version and writer of the record.
#[derive(Debug)]
pub struct OpenedRing {
    /// The ring.
    pub ring: FolderKeyRing,
    /// The epoch it was sealed under.
    pub epoch: Epoch,
    /// The record version.
    pub version: u64,
    /// The writing device.
    pub sender: DeviceId,
    /// The record, for the [`crate::record::RecordGuard`].
    pub record: OpenedRecord,
}

fn ring_key(folder: FolderId) -> RecordKey {
    RecordKey {
        kind: RecordKind::FolderKeys,
        folder: Some(folder),
    }
}

/// Seals `ring` as `version` of its `folder-keys` record.
#[allow(clippy::too_many_arguments)]
pub fn seal_ring(
    cipher: &RecordCipher,
    ring: &FolderKeyRing,
    version: u64,
    identity: &DeviceIdentity,
    sender: &DeviceId,
    head: &LogHead,
    entropy: &mut impl Entropy,
) -> Result<Vec<u8>, FolderKeysError> {
    Ok(cipher.seal(
        &ring_key(ring.folder),
        version,
        identity,
        sender,
        head,
        &ring.encode(),
        entropy,
    )?)
}

/// Opens the `folder-keys` record of `folder`, served as `version`.
pub fn open_ring(
    cipher: &RecordCipher,
    state: &AccountState,
    folder: &FolderId,
    version: u64,
    data: &[u8],
) -> Result<OpenedRing, FolderKeysError> {
    let record = cipher.open(state, &ring_key(*folder), version, data)?;
    let ring = FolderKeyRing::decode(&record.plaintext, folder)?;
    // No generation can be made at a log head after the one its writer sealed the ring at.
    if ring.newest_created_at() > record.head.index {
        return Err(FolderKeysError::Generations);
    }
    Ok(OpenedRing {
        ring,
        epoch: record.epoch,
        version: record.version,
        sender: record.sender,
        record,
    })
}

/// Why a device may not commit to a folder with this ring yet.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum FreshnessError {
    /// The verified log has no epoch yet.
    #[error("the account has no epoch yet")]
    NoEpoch,
    /// A removal waits for its rotation.
    #[error("a rotation is due; the folder waits for it")]
    RotationDue,
    /// The ring was sealed under an older epoch than the log's newest: fetch the newer ring.
    #[error(
        "the folder key ring was sealed under epoch {ring}, the account is at epoch {current}"
    )]
    StaleEpoch {
        /// The ring's epoch.
        ring: u32,
        /// The log's newest epoch.
        current: u32,
    },
    /// The ring's newest generation is below one the verified chain already used.
    #[error("the folder key ring stops at generation {ring}, the folder already uses {chain}")]
    StaleGeneration {
        /// The ring's newest generation.
        ring: u32,
        /// The newest generation on the verified chain.
        chain: u32,
    },
    /// The ring's newest generation was made before the log's last removal, so the removed
    /// device may know it: fetch the ring the removing device re-sealed.
    #[error(
        "the folder key ring's newest generation dates from log entry {created_at}, before the removal at {removal}"
    )]
    GenerationBeforeRemoval {
        /// The log index the newest generation was made at.
        created_at: u64,
        /// The log index of the last removal.
        removal: u64,
    },
}

/// The generation a device may write new objects and commits under, or why it may not commit
/// yet (module docs). `chain_generation` is the newest generation on the first-parent chain the
/// device verified (`None` for a folder without commits).
pub fn writable_generation(
    state: &AccountState,
    ring: &OpenedRing,
    chain_generation: Option<Generation>,
) -> Result<Generation, FreshnessError> {
    let current = state.current_epoch().ok_or(FreshnessError::NoEpoch)?;
    if state.rotation_due() {
        return Err(FreshnessError::RotationDue);
    }
    if ring.epoch != current.epoch {
        return Err(FreshnessError::StaleEpoch {
            ring: ring.epoch.0,
            current: current.epoch.0,
        });
    }
    let newest = ring.ring.newest_generation();
    let created_at = ring.ring.newest_created_at();
    if created_at < state.last_removal_index() {
        return Err(FreshnessError::GenerationBeforeRemoval {
            created_at,
            removal: state.last_removal_index(),
        });
    }
    if let Some(chain) = chain_generation {
        if newest < chain {
            return Err(FreshnessError::StaleGeneration {
                ring: newest.0,
                chain: chain.0,
            });
        }
    }
    Ok(newest)
}

/// One synced folder of the account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderEntry {
    /// The folder.
    pub folder: FolderId,
    /// Its name, shown in the app.
    pub name: String,
}

/// The account's folder list (module docs).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FolderList {
    folders: Vec<FolderEntry>,
}

fn valid_folder_name(name: &str) -> bool {
    check_display_name(name, MAX_FOLDER_NAME_LEN).is_ok()
}

impl FolderList {
    /// A list of these folders in any order.
    pub fn new(mut folders: Vec<FolderEntry>) -> Result<Self, FolderKeysError> {
        folders.sort_by_key(|f| f.folder);
        let list = Self { folders };
        list.check()?;
        Ok(list)
    }

    fn check(&self) -> Result<(), FolderKeysError> {
        if self.folders.len() > MAX_FOLDERS {
            return Err(FolderKeysError::TooLarge);
        }
        if self.folders.windows(2).any(|w| w[0].folder >= w[1].folder) {
            return Err(FolderKeysError::Unsorted);
        }
        if !self.folders.iter().all(|f| valid_folder_name(&f.name)) {
            return Err(FolderKeysError::Name);
        }
        Ok(())
    }

    /// The folders, sorted by ID.
    pub fn folders(&self) -> &[FolderEntry] {
        &self.folders
    }

    /// The list's plaintext.
    pub fn encode(&self) -> Result<Vec<u8>, FolderKeysError> {
        self.check()?;
        let mut w = Writer::new();
        w.u8(LIST_VERSION)
            .u32(u32::try_from(self.folders.len()).map_err(|_| FolderKeysError::TooLarge)?);
        for entry in &self.folders {
            w.raw(entry.folder.as_bytes()).field(entry.name.as_bytes());
        }
        Ok(w.into_bytes())
    }

    /// Reads a list strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self, FolderKeysError> {
        let mut r = Reader::new(bytes);
        let version = r.u8().ok_or(FolderKeysError::Malformed)?;
        if version != LIST_VERSION {
            return Err(FolderKeysError::Version(version));
        }
        let count = usize::try_from(r.u32().ok_or(FolderKeysError::Malformed)?)
            .map_err(|_| FolderKeysError::TooLarge)?;
        if count > MAX_FOLDERS {
            return Err(FolderKeysError::TooLarge);
        }
        let mut folders = Vec::with_capacity(count);
        for _ in 0..count {
            let folder = FolderId::from_bytes(r.raw().ok_or(FolderKeysError::Malformed)?);
            let name = r.field().ok_or(FolderKeysError::Malformed)?;
            let name = std::str::from_utf8(name).map_err(|_| FolderKeysError::Name)?;
            folders.push(FolderEntry {
                folder,
                name: name.to_owned(),
            });
        }
        r.finish().ok_or(FolderKeysError::Malformed)?;
        let list = Self { folders };
        list.check()?;
        Ok(list)
    }
}

fn folders_key() -> RecordKey {
    RecordKey {
        kind: RecordKind::Folders,
        folder: None,
    }
}

/// Seals `list` as `version` of the account's `folders` record.
#[allow(clippy::too_many_arguments)]
pub fn seal_folder_list(
    cipher: &RecordCipher,
    list: &FolderList,
    version: u64,
    identity: &DeviceIdentity,
    sender: &DeviceId,
    head: &LogHead,
    entropy: &mut impl Entropy,
) -> Result<Vec<u8>, FolderKeysError> {
    Ok(cipher.seal(
        &folders_key(),
        version,
        identity,
        sender,
        head,
        &list.encode()?,
        entropy,
    )?)
}

/// Opens the `folders` record served as `version`; the record is for the
/// [`crate::record::RecordGuard`].
pub fn open_folder_list(
    cipher: &RecordCipher,
    state: &AccountState,
    version: u64,
    data: &[u8],
) -> Result<(FolderList, OpenedRecord), FolderKeysError> {
    let record = cipher.open(state, &folders_key(), version, data)?;
    let list = FolderList::decode(&record.plaintext)?;
    Ok((list, record))
}

/// A record re-sealed after a removal, to store with `PUT` as `version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResealedRecord {
    /// Which record.
    pub key: RecordKey,
    /// Its new version: one above the version the device accepted last.
    pub version: u64,
    /// The sealed record.
    pub data: Vec<u8>,
}

/// The account records the removing device holds, each with the version the server holds for
/// it, the one the device last read or wrote; the re-seal stores that version plus one (compare
/// and swap). Under the new epoch the replay guard orders by epoch first
/// ([`crate::record::RecordGuard`]), so the version need not exceed a mark of an older epoch.
#[derive(Debug)]
pub struct AccountRecords<'a> {
    /// Every folder key ring; each gets a new generation.
    pub rings: &'a mut [(FolderKeyRing, u64)],
    /// The folder list, if the account has one.
    pub folders: Option<(&'a FolderList, u64)>,
    /// The device names, if the account has them; the caller has dropped the removed devices.
    pub device_names: Option<(&'a DeviceNameList, u64)>,
}

/// After a removal and its rotation were accepted (`state` is the verified log after them,
/// `secret` the new epoch's secret): adds a generation, created at the log head, to every
/// ring and re-seals every ring, the folder list and the device names under the new epoch, as
/// the removing device must (ADR 0001, section 4). A record of a removed device no longer opens
/// ([`crate::record`]), and a generation the removed device knew is no longer writable
/// ([`writable_generation`]). The rings in `records` take their new generation only if every
/// record was sealed.
pub fn reseal_after_removal(
    state: &AccountState,
    secret: &AccountSecret,
    identity: &DeviceIdentity,
    sender: &DeviceId,
    records: AccountRecords<'_>,
    entropy: &mut impl Entropy,
) -> Result<Vec<ResealedRecord>, FolderKeysError> {
    let epoch = state.current_epoch().ok_or(FolderKeysError::NotRotated)?;
    if state.rotation_due() || epoch.index < state.last_removal_index() {
        return Err(FolderKeysError::NotRotated);
    }
    let head = state.head().ok_or(FolderKeysError::NotRotated)?;
    let cipher = RecordCipher::for_epoch(state, secret, epoch.epoch)?;
    let next = |version: u64| {
        version
            .checked_add(1)
            .ok_or(FolderKeysError::VersionOverflow)
    };
    let mut out = Vec::with_capacity(records.rings.len() + 2);
    let mut new_rings = Vec::with_capacity(records.rings.len());
    for (ring, version) in records.rings.iter() {
        let mut ring = ring.clone();
        ring.add_generation(head.index, entropy)?;
        let version = next(*version)?;
        let data = seal_ring(&cipher, &ring, version, identity, sender, &head, entropy)?;
        out.push(ResealedRecord {
            key: ring_key(ring.folder),
            version,
            data,
        });
        new_rings.push(ring);
    }
    if let Some((list, version)) = records.folders {
        let version = next(version)?;
        let data = seal_folder_list(&cipher, list, version, identity, sender, &head, entropy)?;
        out.push(ResealedRecord {
            key: folders_key(),
            version,
            data,
        });
    }
    if let Some((names, version)) = records.device_names {
        let version = next(version)?;
        let data = crate::device_names::seal_device_names(
            &cipher, names, version, identity, sender, &head, entropy,
        )?;
        out.push(ResealedRecord {
            key: crate::device_names::device_names_key(),
            version,
            data,
        });
    }
    for ((ring, version), new) in records.rings.iter_mut().zip(new_rings) {
        *ring = new;
        *version = version.saturating_add(1);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devicelog::EntryKind;
    use crate::entropy::{FixedEntropy, OsEntropy};
    use crate::epoch::rotate;
    use crate::record::tests::setup;

    const FOLDER: FolderId = FolderId::from_bytes([3; 16]);

    #[test]
    fn ring_generations_round_trip_and_extend() {
        let mut ring = FolderKeyRing::new(FOLDER, 1, &mut OsEntropy).unwrap();
        assert_eq!(ring.newest_generation(), Generation(1));
        let old = ring.clone();
        assert_eq!(
            ring.add_generation(2, &mut OsEntropy).unwrap(),
            Generation(2)
        );
        assert!(ring.get(Generation(0)).is_none() && ring.get(Generation(3)).is_none());
        let bytes = ring.encode();
        assert_eq!(bytes.len(), 19 + 88);
        let back = FolderKeyRing::decode(&bytes, &FOLDER).unwrap();
        assert!(back.extends(&ring) && ring.extends(&back));
        assert!(ring.extends(&old));
        assert!(!old.extends(&ring));
        let swapped = FolderKeyRing::new(FOLDER, 1, &mut OsEntropy).unwrap();
        assert!(!ring.extends(&swapped));
        assert_eq!(
            format!("{:?}", ring.get(Generation(1)).unwrap()),
            "FolderKey(..)"
        );
        assert!(!format!("{ring:?}").contains("Zeroizing"));
    }

    #[test]
    fn ring_decoding_is_strict() {
        let mut ring = FolderKeyRing::new(FOLDER, 1, &mut FixedEntropy::counting(0, 32)).unwrap();
        ring.add_generation(2, &mut FixedEntropy::counting(32, 32))
            .unwrap();
        let bytes = ring.encode().to_vec();
        assert_eq!(
            FolderKeyRing::decode(&bytes, &FolderId::from_bytes([4; 16])).unwrap_err(),
            FolderKeysError::FolderMismatch
        );
        // Reordered generations.
        let mut swapped = bytes[..19].to_vec();
        swapped.extend_from_slice(&bytes[19 + 44..]);
        swapped.extend_from_slice(&bytes[19..19 + 44]);
        assert_eq!(
            FolderKeyRing::decode(&swapped, &FOLDER).unwrap_err(),
            FolderKeysError::Generations
        );
        // Truncated, extended, empty, other version.
        for cut in 0..bytes.len() {
            assert!(FolderKeyRing::decode(&bytes[..cut], &FOLDER).is_err());
        }
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(
            FolderKeyRing::decode(&longer, &FOLDER).unwrap_err(),
            FolderKeysError::Malformed
        );
        let mut empty = bytes[..17].to_vec();
        empty.extend_from_slice(&[0, 0]);
        assert_eq!(
            FolderKeyRing::decode(&empty, &FOLDER).unwrap_err(),
            FolderKeysError::Generations
        );
        let mut v2 = bytes;
        v2[0] = 2;
        assert_eq!(
            FolderKeyRing::decode(&v2, &FOLDER).unwrap_err(),
            FolderKeysError::Version(2)
        );
    }

    #[test]
    fn ring_record_round_trip() {
        let s = setup();
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        let ring = FolderKeyRing::new(FOLDER, 1, &mut OsEntropy).unwrap();
        let head = s.state.head().unwrap();
        let data = seal_ring(
            &cipher,
            &ring,
            1,
            &s.a.identity,
            &s.a.id,
            &head,
            &mut OsEntropy,
        )
        .unwrap();
        let opened = open_ring(&cipher, &s.state, &FOLDER, 1, &data).unwrap();
        assert!(opened.ring.extends(&ring));
        assert_eq!(opened.epoch, Epoch(1));
        // Served for another folder: refused by the record's context.
        assert!(open_ring(&cipher, &s.state, &FolderId::from_bytes([4; 16]), 1, &data).is_err());
    }

    #[test]
    fn freshness_requires_the_newest_epoch_and_generation() {
        let mut s = setup();
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        let mut ring = FolderKeyRing::new(FOLDER, 1, &mut OsEntropy).unwrap();
        let head = s.state.head().unwrap();
        let data = seal_ring(
            &cipher,
            &ring,
            1,
            &s.a.identity,
            &s.a.id,
            &head,
            &mut OsEntropy,
        )
        .unwrap();
        let opened = open_ring(&cipher, &s.state, &FOLDER, 1, &data).unwrap();
        assert_eq!(
            writable_generation(&s.state, &opened, None),
            Ok(Generation(1))
        );
        assert_eq!(
            writable_generation(&s.state, &opened, Some(Generation(1))),
            Ok(Generation(1))
        );
        assert_eq!(
            writable_generation(&s.state, &opened, Some(Generation(2))),
            Err(FreshnessError::StaleGeneration { ring: 1, chain: 2 })
        );

        // A removal: no commit until the rotation.
        let entry = s
            .state
            .next_entry(&s.a.identity, s.a.id, 0, EntryKind::RemoveDevice(s.b.id))
            .unwrap();
        s.state.apply(&entry).unwrap();
        assert_eq!(
            writable_generation(&s.state, &opened, None),
            Err(FreshnessError::RotationDue)
        );
        // After the rotation the old ring (epoch 1) is stale, even though it opens.
        let rotation = rotate(&s.state, &s.a.identity, s.a.id, 0, &mut OsEntropy).unwrap();
        s.state.apply(&rotation.entry).unwrap();
        assert_eq!(
            writable_generation(&s.state, &opened, None),
            Err(FreshnessError::StaleEpoch {
                ring: 1,
                current: 2
            })
        );
        let cipher2 = RecordCipher::for_epoch(&s.state, &rotation.secret, Epoch(2)).unwrap();
        // The old ring re-sealed under epoch 2 without a new generation, or with one dated
        // before the removal: the removed device may know its newest key.
        for created_at in [None, Some(3)] {
            let mut old = ring.clone();
            if let Some(at) = created_at {
                old.add_generation(at, &mut OsEntropy).unwrap();
            }
            let data = seal_ring(
                &cipher2,
                &old,
                2,
                &s.a.identity,
                &s.a.id,
                &s.state.head().unwrap(),
                &mut OsEntropy,
            )
            .unwrap();
            let resealed = open_ring(&cipher2, &s.state, &FOLDER, 2, &data).unwrap();
            assert_eq!(
                writable_generation(&s.state, &resealed, None),
                Err(FreshnessError::GenerationBeforeRemoval {
                    created_at: created_at.unwrap_or(1),
                    removal: 4
                })
            );
        }
        // The removing device re-seals the ring with a new generation made after the removal.
        ring.add_generation(s.state.len(), &mut OsEntropy).unwrap();
        let data = seal_ring(
            &cipher2,
            &ring,
            2,
            &s.a.identity,
            &s.a.id,
            &s.state.head().unwrap(),
            &mut OsEntropy,
        )
        .unwrap();
        let fresh = open_ring(&cipher2, &s.state, &FOLDER, 2, &data).unwrap();
        assert!(fresh.ring.extends(&opened.ring));
        assert_eq!(
            writable_generation(&s.state, &fresh, Some(Generation(1))),
            Ok(Generation(2))
        );
    }

    #[test]
    fn creation_indexes_are_checked() {
        let mut ring = FolderKeyRing::new(FOLDER, 3, &mut OsEntropy).unwrap();
        assert!(FolderKeyRing::new(FOLDER, 0, &mut OsEntropy).is_err());
        assert_eq!(
            ring.add_generation(2, &mut OsEntropy),
            Err(FolderKeysError::Generations),
            "never back in the log"
        );
        ring.add_generation(3, &mut OsEntropy).unwrap();
        ring.add_generation(9, &mut OsEntropy).unwrap();
        assert_eq!(ring.created_at(Generation(2)), Some(3));
        assert_eq!(ring.newest_created_at(), 9);
        let bytes = ring.encode().to_vec();
        assert_eq!(
            FolderKeyRing::decode(&bytes, &FOLDER)
                .unwrap()
                .newest_created_at(),
            9
        );
        // A decreasing or zero index on the wire.
        for (at, value) in [(19 + 44 + 4, 2u64), (19 + 4, 0)] {
            let mut bad = bytes.clone();
            bad[at..at + 8].copy_from_slice(&value.to_be_bytes());
            assert_eq!(
                FolderKeyRing::decode(&bad, &FOLDER).unwrap_err(),
                FolderKeysError::Generations
            );
        }
        // A changed index breaks `extends`.
        let mut moved = bytes.clone();
        moved[19 + 4..19 + 12].copy_from_slice(&1u64.to_be_bytes());
        let moved = FolderKeyRing::decode(&moved, &FOLDER).unwrap();
        assert!(!moved.extends(&ring));
        // A generation dated after the log head the record names does not open.
        let s = setup();
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        let head = s.state.head().unwrap();
        let mut ahead = FolderKeyRing::new(FOLDER, head.index, &mut OsEntropy).unwrap();
        ahead
            .add_generation(head.index + 1, &mut OsEntropy)
            .unwrap();
        let data = seal_ring(
            &cipher,
            &ahead,
            1,
            &s.a.identity,
            &s.a.id,
            &head,
            &mut OsEntropy,
        )
        .unwrap();
        assert_eq!(
            open_ring(&cipher, &s.state, &FOLDER, 1, &data).unwrap_err(),
            FolderKeysError::Generations
        );
    }

    #[test]
    fn the_removing_device_reseals_every_record() {
        let mut s = setup();
        let cipher1 = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        let head = s.state.head().unwrap();
        let other = FolderId::from_bytes([4; 16]);
        let mut rings = vec![
            (
                FolderKeyRing::new(FOLDER, head.index, &mut OsEntropy).unwrap(),
                1u64,
            ),
            (
                FolderKeyRing::new(other, head.index, &mut OsEntropy).unwrap(),
                7u64,
            ),
        ];
        let before = rings[0].0.clone();
        let list = FolderList::new(vec![
            FolderEntry {
                folder: FOLDER,
                name: "Photos".into(),
            },
            FolderEntry {
                folder: other,
                name: "Work".into(),
            },
        ])
        .unwrap();
        let names = DeviceNameList::new(vec![crate::device_names::DeviceName {
            device: s.a.id,
            name: "Desktop".into(),
        }])
        .unwrap();
        // b wrote the folder list before its removal.
        let by_b = seal_folder_list(
            &cipher1,
            &list,
            2,
            &s.b.identity,
            &s.b.id,
            &head,
            &mut OsEntropy,
        )
        .unwrap();
        assert!(open_folder_list(&cipher1, &s.state, 2, &by_b).is_ok());

        // Re-sealing before the rotation is refused.
        let removal = crate::epoch::remove_devices(
            &s.state,
            &s.a.identity,
            s.a.id,
            0,
            &[s.b.id],
            &mut OsEntropy,
        )
        .unwrap();
        let mut half = s.state.clone();
        half.apply(&removal.entries[0]).unwrap();
        let records =
            |rings: &mut [(FolderKeyRing, u64)]| -> Result<Vec<ResealedRecord>, FolderKeysError> {
                reseal_after_removal(
                    &half,
                    &removal.rotation.secret,
                    &s.a.identity,
                    &s.a.id,
                    AccountRecords {
                        rings,
                        folders: None,
                        device_names: None,
                    },
                    &mut OsEntropy,
                )
            };
        assert_eq!(
            records(&mut rings).unwrap_err(),
            FolderKeysError::NotRotated
        );
        assert_eq!(rings[0].0.newest_generation(), Generation(1), "unchanged");

        s.state = removal.state;
        assert_eq!(
            open_folder_list(&cipher1, &s.state, 2, &by_b).unwrap_err(),
            FolderKeysError::Open(OpenError::SenderNotValid),
            "the removed device's record no longer opens"
        );
        let resealed = reseal_after_removal(
            &s.state,
            &removal.rotation.secret,
            &s.a.identity,
            &s.a.id,
            AccountRecords {
                rings: &mut rings,
                folders: Some((&list, 2)),
                device_names: Some((&names, 5)),
            },
            &mut OsEntropy,
        )
        .unwrap();
        assert_eq!(resealed.len(), 4);
        assert_eq!(
            resealed
                .iter()
                .map(|r| (r.key.kind, r.version))
                .collect::<Vec<_>>(),
            vec![
                (RecordKind::FolderKeys, 2),
                (RecordKind::FolderKeys, 8),
                (RecordKind::Folders, 3),
                (RecordKind::DeviceNames, 6)
            ]
        );
        assert_eq!(rings[0].1, 2);
        let cipher2 =
            RecordCipher::for_epoch(&s.state, &removal.rotation.secret, Epoch(2)).unwrap();
        let ring = open_ring(&cipher2, &s.state, &FOLDER, 2, &resealed[0].data).unwrap();
        assert!(ring.ring.extends(&before));
        assert_eq!(ring.ring.newest_generation(), Generation(2));
        assert_eq!(ring.ring.newest_created_at(), s.state.len());
        assert_eq!(
            writable_generation(&s.state, &ring, Some(Generation(1))),
            Ok(Generation(2))
        );
        assert_eq!(
            open_folder_list(&cipher2, &s.state, 3, &resealed[2].data)
                .unwrap()
                .0,
            list
        );
        let (opened, _) =
            crate::device_names::open_device_names(&cipher2, &s.state, 6, &resealed[3].data)
                .unwrap();
        assert_eq!(opened, names);
    }

    #[test]
    fn folder_list_round_trip_and_rules() {
        let a = FolderEntry {
            folder: FolderId::from_bytes([2; 16]),
            name: "Photos".into(),
        };
        let b = FolderEntry {
            folder: FolderId::from_bytes([1; 16]),
            name: "Videos".into(),
        };
        let list = FolderList::new(vec![a.clone(), b.clone()]).unwrap();
        assert_eq!(list.folders()[0], b);
        let bytes = list.encode().unwrap();
        assert_eq!(FolderList::decode(&bytes).unwrap(), list);
        assert_eq!(
            FolderList::new(vec![a.clone(), a.clone()]),
            Err(FolderKeysError::Unsorted)
        );
        let bad = FolderEntry {
            name: "a\nb".into(),
            ..a.clone()
        };
        assert_eq!(FolderList::new(vec![bad]), Err(FolderKeysError::Name));
        let empty_name = FolderEntry {
            name: String::new(),
            ..a.clone()
        };
        assert_eq!(
            FolderList::new(vec![empty_name]),
            Err(FolderKeysError::Name)
        );
        // Swapped order on the wire.
        let entry_len = (bytes.len() - 5) / 2;
        let mut swapped = bytes[..5].to_vec();
        swapped.extend_from_slice(&bytes[5 + entry_len..]);
        swapped.extend_from_slice(&bytes[5..5 + entry_len]);
        assert_eq!(FolderList::decode(&swapped), Err(FolderKeysError::Unsorted));
        let mut longer = bytes.clone();
        longer.push(0);
        assert_eq!(FolderList::decode(&longer), Err(FolderKeysError::Malformed));
        assert_eq!(
            FolderList::new(vec![]).unwrap().encode().unwrap(),
            vec![1, 0, 0, 0, 0]
        );
    }
}
