//! The account's device log: which devices belong to the account, with which public keys, and
//! which epoch secrets it uses. Signed, hash-chained plaintext with one member (the account's
//! owner). Clients accept a key only when this log vouches for it; the server runs the same
//! verifier ([`AccountState::admit_batch`]) before it stores an entry, and no secret is needed for it.
//!
//! Built after the membership log of the sister project's `hangar-team-crypto`
//! (`src/memberlog.rs`, MIT, same owner), reduced to one member: no member entries and no
//! roles, which stay reserved for sharing in a later version.
//!
//! # Entry format (version 1)
//!
//! ```text
//! entry  = body || Ed25519 signature of the issuing device over body (64 bytes)
//! body   = field("hangar-drive/v1/device-log-entry") || field(version = 1) || field(account)
//!          || field(index, u64) || field(prev hash, 32 bytes or empty for index 1)
//!          || field(issued_at, u64 ms) || field(issuer device) || field(tag, u8) || kind fields
//! device = field(device id) || field(sign key) || field(kem key) || field(recovery: 0 or 1)
//!          || field(proof of possession, 64 bytes; see `crate::identity`)
//! hash   = SHA-256( field("hangar-drive/v1/device-log") || field(index, u64)
//!                   || field(prev hash or empty) || field(entry) )
//! ```
//!
//! | Tag | Kind | Fields |
//! | --- | --- | --- |
//! | 1 | create | field(count, u32) then count devices (the issuer among them) |
//! | 2 | add device | device |
//! | 3 | remove device | field(device id) |
//! | 4 | rotate epoch | field(epoch, u32), then field(commitment, 32 bytes) |
//!
//! The body names the account, its own index and its predecessor's hash: a validly signed entry
//! fits only one position of one account's log. Decoding is strict: re-encoding must give the
//! same bytes.
//!
//! # Rules
//!
//! - Entry 1 creates the account: it lists the issuing device, which must not be a recovery
//!   device, and at most [`MAX_DEVICES_PER_ENTRY`] devices. Every later entry that creates is
//!   refused.
//! - Every later entry is issued by a current device of the log.
//! - A recovery device issues only add device, and only for a regular (not recovery) device:
//!   the one step it takes when the person recovers on a new installation.
//! - No device removes itself; a recovery device removes nothing.
//! - A device ID and a public key are accepted once per account and never again, even after
//!   the device was removed. Signing keys must be valid points of large order, X25519 keys
//!   canonical and of large order, and every listed device carries its proof of possession.
//! - At most [`MAX_DEVICES`] current devices, recovery devices included, so every rotation
//!   wraps to a bounded set.
//! - **Rotation is immediate:** a removal makes a rotation due, and while one is due the log
//!   accepts only further removals and the rotate epoch entry (ADR 0001, section 4: "rotate
//!   immediately after every removal"). No epoch is skipped meanwhile, and no device is added,
//!   with one exception: a recovery device may add exactly one regular device while a rotation
//!   is due. A log in which every regular device was lost with a rotation due would otherwise be
//!   stuck, because a recovery device may not rotate. The rotation stays due, and the new device
//!   makes it.
//! - **Atomic appends (server):** the server admits one append call as a batch
//!   ([`AccountState::admit_batch`]) of exactly one of two shapes: removals followed by their
//!   rotation, or one added device. The state after the batch must have no rotation due, except
//!   after the recovery device's one added device above. A removal therefore never reaches the
//!   server's log without its rotation.
//! - Epochs count from 1 without gaps.
//! - A log has at most [`MAX_LOG_ENTRIES`] entries; the last [`RESERVED_LOG_ENTRIES`] places take
//!   only removals and rotate epoch entries, the very last only a rotate epoch entry, so a stolen
//!   device can always still be removed and the key changed.
//! - `issued_at` is the issuer's clock, informational only; the order is the log's.
//!
//! A refused entry changes nothing (fail closed): [`AccountState::apply`] checks everything
//! before it records anything, and the caller stops trusting a log that delivered one.

use std::collections::{BTreeMap, BTreeSet};

use hangar_drive_protocol::ids::{
    AccountId, DeviceId, Epoch, LogHash, LogHead, PublicKey, Signature,
};
use thiserror::Error;

use crate::encoding::{sha256_framed, Reader, Writer};
use crate::epoch::EpochCommitment;
use crate::identity::{
    is_valid_kem_key, is_valid_sign_key, log_safety_number, verify, verify_proof, DeviceIdentity,
    DevicePublicKeys, SafetyNumber,
};

const LABEL_ENTRY: &[u8] = b"hangar-drive/v1/device-log-entry";
const LABEL_CHAIN: &[u8] = b"hangar-drive/v1/device-log";
/// The format version of new entries.
pub const ENTRY_VERSION: u8 = 1;
/// Current devices an account may have, recovery devices included.
pub const MAX_DEVICES: usize = 64;
/// Devices the create entry may list.
pub const MAX_DEVICES_PER_ENTRY: usize = 8;
/// The most entries an account's log may have. Every device verifies the whole log; 8192
/// entries are a few thousand device lifecycles.
pub const MAX_LOG_ENTRIES: u64 = 8_192;
/// The last places of [`MAX_LOG_ENTRIES`], which only removals and rotations take.
pub const RESERVED_LOG_ENTRIES: u64 = 64;
const SIGNATURE_LEN: usize = 64;

const TAG_CREATE: u8 = 1;
const TAG_ADD_DEVICE: u8 = 2;
const TAG_REMOVE_DEVICE: u8 = 3;
const TAG_ROTATE: u8 = 4;

/// Why a device log entry was refused. The log stops at a refused entry.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LogError {
    /// Not an entry of this format (encoding, field sizes, unknown tag, trailing bytes).
    #[error("the device log entry is malformed")]
    Malformed,
    /// An entry format version this crate does not know.
    #[error("device log entry version {0} is not supported")]
    Version(u8),
    /// The signed body names another account.
    #[error("the device log entry belongs to another account")]
    AccountMismatch,
    /// The signed body names another index than its position.
    #[error("the device log entry was signed for another position")]
    IndexMismatch,
    /// The signed body names another predecessor than the verified one.
    #[error("the device log entry was signed after another entry")]
    PrevMismatch,
    /// The first entry does not create the account.
    #[error("the device log does not start by creating the account")]
    NotCreated,
    /// A later entry tries to create the account again.
    #[error("the account was already created")]
    AlreadyCreated,
    /// The issuing device is not a current device of the log.
    #[error("the device log does not vouch for the issuing device")]
    UnknownIssuer,
    /// Server side: the entry is signed by another device than the session's.
    #[error("the device log entry is not issued by the sending device")]
    NotSender,
    /// The signature does not verify with the issuing device's key.
    #[error("the device log entry's signature does not verify")]
    Signature,
    /// The issuer may not make this change (recovery device, self removal).
    #[error("the issuer may not make this change")]
    Forbidden,
    /// The entry names a device that is not current.
    #[error("the device is not a current device of the account")]
    UnknownDevice,
    /// The device ID was used before in this account.
    #[error("the device id was used before")]
    DeviceExists,
    /// A public key was used before in this account.
    #[error("a public key was used before")]
    KeyReused,
    /// A public key no device may hold.
    #[error("a public key is not valid")]
    InvalidKey,
    /// A proof of possession does not verify.
    #[error("a proof of possession does not verify")]
    Proof,
    /// More devices than allowed.
    #[error("the account has too many devices")]
    TooManyDevices,
    /// A rotation is due; only removals and the rotation are accepted.
    #[error("a rotation is due after a removal")]
    RotationDue,
    /// The rotation does not name the next epoch.
    #[error("the rotation does not name the next epoch")]
    EpochGap,
    /// The log reached [`MAX_LOG_ENTRIES`].
    #[error("the device log is full")]
    LogFull,
    /// The reserved last places take only removals and rotations.
    #[error("the last places of the device log are reserved for removals and rotations")]
    Reserved,
    /// The log does not contain the pinned anchor.
    #[error("the device log does not extend the pinned anchor")]
    AnchorMismatch,
    /// Server side: an append is neither removals with their rotation nor one added device.
    #[error("an append must hold removals with their rotation, or one added device")]
    BatchShape,
    /// Server side: the append would leave a rotation due.
    #[error("the append leaves a rotation due")]
    RotationLeftDue,
}

/// A device as an entry lists it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogDevice {
    /// The device ID.
    pub id: DeviceId,
    /// Its public keys.
    pub keys: DevicePublicKeys,
    /// The offline device derived from a recovery code.
    pub recovery: bool,
    /// Its proof of possession.
    pub proof: Signature,
}

impl LogDevice {
    /// The entry for `identity` as `device` of `account`, with its own proof.
    pub fn of(
        identity: &DeviceIdentity,
        account: &AccountId,
        device: DeviceId,
        recovery: bool,
    ) -> Self {
        Self {
            id: device,
            keys: identity.public_keys(),
            recovery,
            proof: identity.prove(account, &device, recovery),
        }
    }

    fn write(&self, w: &mut Writer) {
        w.field(self.id.as_bytes())
            .field(self.keys.sign.as_bytes())
            .field(self.keys.kem.as_bytes())
            .field_u8(u8::from(self.recovery))
            .field(self.proof.as_bytes());
    }

    fn read(r: &mut Reader<'_>) -> Option<Self> {
        let id = DeviceId::from_bytes(r.field_fixed()?);
        let sign = PublicKey::from_bytes(r.field_fixed()?);
        let kem = PublicKey::from_bytes(r.field_fixed()?);
        let recovery = match r.field_u8()? {
            0 => false,
            1 => true,
            _ => return None,
        };
        let proof = Signature::from_bytes(r.field_fixed()?);
        Some(Self {
            id,
            keys: DevicePublicKeys { sign, kem },
            recovery,
            proof,
        })
    }
}

/// What an entry does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryKind {
    /// Entry 1: the account and its first devices.
    Create {
        /// The devices, the issuer among them.
        devices: Vec<LogDevice>,
    },
    /// A new device.
    AddDevice(LogDevice),
    /// A device leaves; a rotation becomes due.
    RemoveDevice(DeviceId),
    /// A new epoch secret, committed to.
    Rotate {
        /// The new epoch.
        epoch: Epoch,
        /// Its commitment.
        commitment: EpochCommitment,
    },
}

/// One decoded entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// The account.
    pub account: AccountId,
    /// Position, from 1.
    pub index: u64,
    /// Hash of the entry before; `None` only for index 1.
    pub prev: Option<LogHash>,
    /// The issuer's clock, informational only.
    pub issued_at_ms: u64,
    /// The issuing device.
    pub issuer: DeviceId,
    /// What it does.
    pub kind: EntryKind,
    /// The issuer's signature over the body.
    pub signature: Signature,
}

impl LogEntry {
    fn body(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(LABEL_ENTRY)
            .field_u8(ENTRY_VERSION)
            .field(self.account.as_bytes())
            .field_u64(self.index)
            .field(self.prev.as_ref().map_or(&[][..], |p| p.as_bytes()))
            .field_u64(self.issued_at_ms)
            .field(self.issuer.as_bytes());
        match &self.kind {
            EntryKind::Create { devices } => {
                w.field_u8(TAG_CREATE)
                    .field_u32(u32::try_from(devices.len()).unwrap_or(u32::MAX));
                for device in devices {
                    device.write(&mut w);
                }
            }
            EntryKind::AddDevice(device) => {
                w.field_u8(TAG_ADD_DEVICE);
                device.write(&mut w);
            }
            EntryKind::RemoveDevice(device) => {
                w.field_u8(TAG_REMOVE_DEVICE).field(device.as_bytes());
            }
            EntryKind::Rotate { epoch, commitment } => {
                w.field_u8(TAG_ROTATE)
                    .field_u32(epoch.0)
                    .field(&commitment.0);
            }
        }
        w.into_bytes()
    }

    /// The entry's bytes: body and signature.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = self.body();
        bytes.extend_from_slice(self.signature.as_bytes());
        bytes
    }

    /// Reads an entry strictly (module docs). Checks no signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, LogError> {
        let body_len = bytes
            .len()
            .checked_sub(SIGNATURE_LEN)
            .ok_or(LogError::Malformed)?;
        let (body, signature) = bytes.split_at(body_len);
        let signature = Signature::from_slice(signature).ok_or(LogError::Malformed)?;
        let mut r = Reader::new(body);
        if r.field() != Some(LABEL_ENTRY) {
            return Err(LogError::Malformed);
        }
        let version = r.field_u8().ok_or(LogError::Malformed)?;
        if version != ENTRY_VERSION {
            return Err(LogError::Version(version));
        }
        let entry = Self::read_rest(&mut r, signature).ok_or(LogError::Malformed)?;
        r.finish().ok_or(LogError::Malformed)?;
        if entry.encode() != bytes {
            return Err(LogError::Malformed);
        }
        Ok(entry)
    }

    fn read_rest(r: &mut Reader<'_>, signature: Signature) -> Option<Self> {
        let account = AccountId::from_bytes(r.field_fixed()?);
        let index = r.field_u64()?;
        let prev = match r.field()? {
            [] => None,
            hash => Some(LogHash::from_slice(hash)?),
        };
        let issued_at_ms = r.field_u64()?;
        let issuer = DeviceId::from_bytes(r.field_fixed()?);
        let kind = match r.field_u8()? {
            TAG_CREATE => {
                let count = usize::try_from(r.field_u32()?).ok()?;
                if count > MAX_DEVICES_PER_ENTRY {
                    return None;
                }
                let mut devices = Vec::with_capacity(count);
                for _ in 0..count {
                    devices.push(LogDevice::read(r)?);
                }
                EntryKind::Create { devices }
            }
            TAG_ADD_DEVICE => EntryKind::AddDevice(LogDevice::read(r)?),
            TAG_REMOVE_DEVICE => EntryKind::RemoveDevice(DeviceId::from_bytes(r.field_fixed()?)),
            TAG_ROTATE => EntryKind::Rotate {
                epoch: Epoch(r.field_u32()?),
                commitment: EpochCommitment(r.field_fixed()?),
            },
            _ => return None,
        };
        Some(Self {
            account,
            index,
            prev,
            issued_at_ms,
            issuer,
            kind,
            signature,
        })
    }
}

/// The chain hash of the entry at `index` (module docs).
pub fn entry_hash(index: u64, prev: Option<&LogHash>, entry: &[u8]) -> LogHash {
    LogHash::from_bytes(sha256_framed(&[
        LABEL_CHAIN,
        &index.to_be_bytes(),
        prev.map_or(&[][..], |p| p.as_bytes()),
        entry,
    ]))
}

/// A device the log has listed, with the index range in which its keys are valid.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceRecord {
    /// The device ID.
    pub id: DeviceId,
    /// Its public keys.
    pub keys: DevicePublicKeys,
    /// A recovery device.
    pub recovery: bool,
    /// Index of the entry that listed it.
    pub added_at: u64,
    /// Index of the entry that removed it.
    pub removed_at: Option<u64>,
}

impl DeviceRecord {
    /// Whether the log vouched for this device at log head `index`: listed at or before it and
    /// not removed at or before it.
    pub fn valid_at(&self, index: u64) -> bool {
        self.added_at <= index && self.removed_at.is_none_or(|removed| index < removed)
    }

    /// Not removed.
    pub fn is_current(&self) -> bool {
        self.removed_at.is_none()
    }
}

/// An epoch as the log records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochRecord {
    /// The epoch.
    pub epoch: Epoch,
    /// The commitment to its secret.
    pub commitment: EpochCommitment,
    /// Index of its rotate entry.
    pub index: u64,
    /// Hash of its rotate entry, bound into the account key.
    pub hash: LogHash,
}

/// What one admitted append batch did ([`AccountState::admit_batch`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchShape {
    /// Removals (possibly none) and the rotation to `epoch`.
    Rotation {
        /// The removed devices, in order.
        removed: Vec<DeviceId>,
        /// The new epoch.
        epoch: Epoch,
    },
    /// One added device.
    AddDevice {
        /// The new device.
        device: DeviceId,
    },
}

/// An append the server may store: the state after it and its shape.
#[derive(Debug, Clone)]
pub struct AdmittedBatch {
    /// The verified state after the batch.
    pub state: AccountState,
    /// What the batch did.
    pub shape: BatchShape,
}

/// The verified state of an account's device log.
#[derive(Debug, Clone)]
pub struct AccountState {
    account: AccountId,
    hashes: Vec<LogHash>,
    devices: BTreeMap<DeviceId, DeviceRecord>,
    epochs: Vec<EpochRecord>,
    rotation_due: bool,
    /// A recovery device added its one device while the rotation is due.
    recovery_added_while_due: bool,
    last_removal: u64,
    last_removal_issuer: Option<DeviceId>,
    used_keys: BTreeSet<[u8; 32]>,
}

impl AccountState {
    /// An empty log of `account`; its first entry must create it.
    pub fn new(account: AccountId) -> Self {
        Self {
            account,
            hashes: Vec::new(),
            devices: BTreeMap::new(),
            epochs: Vec::new(),
            rotation_due: false,
            recovery_added_while_due: false,
            last_removal: 0,
            last_removal_issuer: None,
            used_keys: BTreeSet::new(),
        }
    }

    /// Verifies a whole log from entry 1.
    pub fn from_entries<'a>(
        account: AccountId,
        entries: impl IntoIterator<Item = &'a [u8]>,
    ) -> Result<Self, LogError> {
        let mut state = Self::new(account);
        for entry in entries {
            state.apply(entry)?;
        }
        Ok(state)
    }

    /// The account.
    pub fn account(&self) -> &AccountId {
        &self.account
    }

    /// Entries verified.
    pub fn len(&self) -> u64 {
        self.hashes.len() as u64
    }

    /// No entry yet.
    pub fn is_empty(&self) -> bool {
        self.hashes.is_empty()
    }

    /// The newest verified entry.
    pub fn head(&self) -> Option<LogHead> {
        self.hashes.last().map(|hash| LogHead {
            index: self.len(),
            hash: *hash,
        })
    }

    /// The hash of entry `index` (from 1).
    pub fn hash_at(&self, index: u64) -> Option<&LogHash> {
        let at = usize::try_from(index.checked_sub(1)?).ok()?;
        self.hashes.get(at)
    }

    /// Whether this log contains `head` (same hash at that index).
    pub fn contains(&self, head: &LogHead) -> bool {
        self.hash_at(head.index) == Some(&head.hash)
    }

    /// Refuses a log that does not contain the pinned anchor (pairing head or own history).
    pub fn check_anchor(&self, anchor: &LogHead) -> Result<(), LogError> {
        if self.contains(anchor) {
            Ok(())
        } else {
            Err(LogError::AnchorMismatch)
        }
    }

    /// Every device the log ever listed.
    pub fn device(&self, id: &DeviceId) -> Option<&DeviceRecord> {
        self.devices.get(id)
    }

    /// The current devices, recovery devices included: the recipients of a rotation.
    pub fn current_devices(&self) -> impl Iterator<Item = &DeviceRecord> {
        self.devices.values().filter(|d| d.is_current())
    }

    /// The device that may sign commits and records at log head `index`: valid there and not a
    /// recovery device.
    pub fn signer_at(&self, id: &DeviceId, index: u64) -> Option<&DeviceRecord> {
        self.devices
            .get(id)
            .filter(|d| d.valid_at(index) && !d.recovery)
    }

    /// The record of `epoch`.
    pub fn epoch(&self, epoch: Epoch) -> Option<&EpochRecord> {
        let at = usize::try_from(epoch.0.checked_sub(1)?).ok()?;
        self.epochs.get(at)
    }

    /// The newest epoch.
    pub fn current_epoch(&self) -> Option<&EpochRecord> {
        self.epochs.last()
    }

    /// A removal waits for its rotation.
    pub fn rotation_due(&self) -> bool {
        self.rotation_due
    }

    /// The index of the newest remove device entry, 0 if the log has none. A folder key
    /// generation created before it may be known to a removed device
    /// ([`crate::folder_keys::writable_generation`]).
    pub fn last_removal_index(&self) -> u64 {
        self.last_removal
    }

    /// The device that issued the newest remove device entry, `None` if the log has none.
    pub fn last_removal_issuer(&self) -> Option<&DeviceId> {
        self.last_removal_issuer.as_ref()
    }

    /// The device that removed `device`, if the entries `first_index, first_index + 1, ...`
    /// continue this verified log (the first one at the index after its head, chained to its
    /// head's hash) and one of them is a valid removal of `device` (security review H2). Every
    /// entry goes through [`AccountState::apply`] on a copy, so a forged signature, an entry
    /// of another account, a chain that does not start at this head and an issuer the log does
    /// not allow are all `None`; `self` is not changed. Entries after the removal are not read.
    pub fn removal_in<'a>(
        &self,
        first_index: u64,
        entries: impl IntoIterator<Item = &'a [u8]>,
        device: &DeviceId,
    ) -> Option<DeviceId> {
        if self.is_empty() || first_index != self.len() + 1 {
            return None;
        }
        if !self
            .devices
            .get(device)
            .is_some_and(DeviceRecord::is_current)
        {
            return None;
        }
        let mut state = self.clone();
        for entry in entries {
            state.apply(entry).ok()?;
            if state.device(device).is_some_and(|d| !d.is_current()) {
                return state.last_removal_issuer().copied();
            }
        }
        None
    }

    /// The log safety number at the head.
    pub fn safety_number(&self) -> Option<SafetyNumber> {
        Some(log_safety_number(&self.account, &self.head()?))
    }

    /// Verifies and records the next entry (client side).
    pub fn apply(&mut self, entry: &[u8]) -> Result<LogHead, LogError> {
        self.apply_checked(entry, None)
    }

    /// Server side, for account creation only: [`AccountState::apply`] of entry 1 plus the rule
    /// that the device named in the request issued it. Every later append goes through
    /// [`AccountState::admit_batch`].
    pub fn admit_genesis(&mut self, entry: &[u8], sender: &DeviceId) -> Result<LogHead, LogError> {
        if !self.is_empty() {
            return Err(LogError::AlreadyCreated);
        }
        self.apply_checked(entry, Some(sender))
    }

    /// Server side: verifies one append call's entries as a batch issued by the session's
    /// device `sender` (module docs, "Atomic appends") and returns the state after it, which the
    /// server stores in the same transaction as the entries. `self` is not changed; a refused
    /// batch stores nothing. The caller then checks the wrapped keys with
    /// [`crate::epoch::append_wraps_fit`].
    pub fn admit_batch<'a>(
        &self,
        entries: impl IntoIterator<Item = &'a [u8]>,
        sender: &DeviceId,
    ) -> Result<AdmittedBatch, LogError> {
        let entries: Vec<&[u8]> = entries.into_iter().collect();
        let kinds = entries
            .iter()
            .map(|e| LogEntry::decode(e).map(|entry| entry.kind))
            .collect::<Result<Vec<_>, _>>()?;
        let shape = match kinds.as_slice() {
            [EntryKind::AddDevice(device)] => BatchShape::AddDevice { device: device.id },
            [removals @ .., EntryKind::Rotate { epoch, .. }] => {
                let removed = removals
                    .iter()
                    .map(|kind| match kind {
                        EntryKind::RemoveDevice(id) => Ok(*id),
                        _ => Err(LogError::BatchShape),
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                BatchShape::Rotation {
                    removed,
                    epoch: *epoch,
                }
            }
            _ => return Err(LogError::BatchShape),
        };
        if self.is_empty() {
            return Err(LogError::NotCreated);
        }
        let mut state = self.clone();
        for entry in &entries {
            state.apply_checked(entry, Some(sender))?;
        }
        // Only the recovery device's one added device may leave the rotation due that it found.
        let recovery_add = matches!(shape, BatchShape::AddDevice { .. }) && self.rotation_due;
        if state.rotation_due && !recovery_add {
            return Err(LogError::RotationLeftDue);
        }
        Ok(AdmittedBatch { state, shape })
    }

    /// Builds, signs and verifies the next entry issued by `identity` as `issuer`. The entry is
    /// not applied; the caller sends it and applies it once the server accepted it.
    pub fn next_entry(
        &self,
        identity: &DeviceIdentity,
        issuer: DeviceId,
        issued_at_ms: u64,
        kind: EntryKind,
    ) -> Result<Vec<u8>, LogError> {
        let mut entry = LogEntry {
            account: self.account,
            index: self.len() + 1,
            prev: self.hashes.last().copied(),
            issued_at_ms,
            issuer,
            kind,
            signature: Signature::from_bytes([0; 64]),
        };
        entry.signature = Signature::from_bytes(identity.sign(&entry.body()));
        let bytes = entry.encode();
        self.check(&bytes, None)?;
        Ok(bytes)
    }

    fn apply_checked(
        &mut self,
        bytes: &[u8],
        sender: Option<&DeviceId>,
    ) -> Result<LogHead, LogError> {
        let (change, head) = self.check(bytes, sender)?;
        self.record(change, head.index, head.hash);
        Ok(head)
    }

    /// Every rule for the next entry, without recording it.
    fn check(
        &self,
        bytes: &[u8],
        sender: Option<&DeviceId>,
    ) -> Result<(Change, LogHead), LogError> {
        let entry = LogEntry::decode(bytes)?;
        if entry.account != self.account {
            return Err(LogError::AccountMismatch);
        }
        let index = self.len() + 1;
        if entry.index != index {
            return Err(LogError::IndexMismatch);
        }
        if entry.prev.as_ref() != self.hashes.last() {
            return Err(LogError::PrevMismatch);
        }
        if sender.is_some_and(|s| *s != entry.issuer) {
            return Err(LogError::NotSender);
        }
        if index > MAX_LOG_ENTRIES {
            return Err(LogError::LogFull);
        }
        let reserved = index > MAX_LOG_ENTRIES - RESERVED_LOG_ENTRIES;
        let body_len = bytes.len() - SIGNATURE_LEN;
        let body = &bytes[..body_len];

        let change = if index == 1 {
            self.check_create(&entry, body)?
        } else {
            self.check_later(&entry, body, index, reserved)?
        };
        let hash = entry_hash(index, self.hashes.last(), bytes);
        Ok((change, LogHead { index, hash }))
    }

    fn check_new_device(
        &self,
        device: &LogDevice,
        seen: &BTreeSet<[u8; 32]>,
    ) -> Result<(), LogError> {
        if self.devices.contains_key(&device.id) {
            return Err(LogError::DeviceExists);
        }
        if !is_valid_sign_key(&device.keys.sign) || !is_valid_kem_key(&device.keys.kem) {
            return Err(LogError::InvalidKey);
        }
        for key in [device.keys.sign.as_bytes(), device.keys.kem.as_bytes()] {
            if self.used_keys.contains(key) || seen.contains(key) {
                return Err(LogError::KeyReused);
            }
        }
        if !verify_proof(
            &self.account,
            &device.id,
            &device.keys,
            device.recovery,
            &device.proof,
        ) {
            return Err(LogError::Proof);
        }
        Ok(())
    }

    fn check_create(&self, entry: &LogEntry, body: &[u8]) -> Result<Change, LogError> {
        let EntryKind::Create { devices } = &entry.kind else {
            return Err(LogError::NotCreated);
        };
        if devices.is_empty() || devices.len() > MAX_DEVICES_PER_ENTRY {
            return Err(LogError::Malformed);
        }
        let mut seen = BTreeSet::new();
        let mut ids = BTreeSet::new();
        for device in devices {
            if !ids.insert(device.id) {
                return Err(LogError::DeviceExists);
            }
            self.check_new_device(device, &seen)?;
            seen.insert(*device.keys.sign.as_bytes());
            seen.insert(*device.keys.kem.as_bytes());
        }
        let issuer = devices
            .iter()
            .find(|d| d.id == entry.issuer)
            .ok_or(LogError::UnknownIssuer)?;
        if issuer.recovery {
            return Err(LogError::Forbidden);
        }
        if !verify(&issuer.keys.sign, body, entry.signature.as_bytes()) {
            return Err(LogError::Signature);
        }
        Ok(Change::Add(devices.clone(), false))
    }

    fn check_later(
        &self,
        entry: &LogEntry,
        body: &[u8],
        index: u64,
        reserved: bool,
    ) -> Result<Change, LogError> {
        let issuer = self
            .devices
            .get(&entry.issuer)
            .filter(|d| d.is_current())
            .ok_or(LogError::UnknownIssuer)?;
        if !verify(&issuer.keys.sign, body, entry.signature.as_bytes()) {
            return Err(LogError::Signature);
        }
        let is_rotation = matches!(entry.kind, EntryKind::Rotate { .. });
        let is_removal = matches!(entry.kind, EntryKind::RemoveDevice(_));
        if index == MAX_LOG_ENTRIES && !is_rotation {
            return Err(LogError::Reserved);
        }
        if reserved && !is_rotation && !is_removal {
            return Err(LogError::Reserved);
        }
        // The one exception while a rotation is due (module docs): the recovery device adds one
        // regular device, which then removes and rotates.
        let recovery_add = issuer.recovery
            && !self.recovery_added_while_due
            && matches!(&entry.kind, EntryKind::AddDevice(d) if !d.recovery);
        if self.rotation_due && !is_rotation && !is_removal && !recovery_add {
            return Err(LogError::RotationDue);
        }
        match &entry.kind {
            EntryKind::Create { .. } => Err(LogError::AlreadyCreated),
            EntryKind::AddDevice(device) => {
                if issuer.recovery && device.recovery {
                    return Err(LogError::Forbidden);
                }
                if self.current_devices().count() >= MAX_DEVICES {
                    return Err(LogError::TooManyDevices);
                }
                self.check_new_device(device, &BTreeSet::new())?;
                Ok(Change::Add(
                    vec![*device],
                    self.rotation_due && issuer.recovery,
                ))
            }
            EntryKind::RemoveDevice(target) => {
                if issuer.recovery || *target == entry.issuer {
                    return Err(LogError::Forbidden);
                }
                if !self
                    .devices
                    .get(target)
                    .is_some_and(DeviceRecord::is_current)
                {
                    return Err(LogError::UnknownDevice);
                }
                Ok(Change::Remove(*target, entry.issuer))
            }
            EntryKind::Rotate { epoch, commitment } => {
                if issuer.recovery {
                    return Err(LogError::Forbidden);
                }
                let next = u32::try_from(self.epochs.len())
                    .ok()
                    .and_then(|n| n.checked_add(1))
                    .ok_or(LogError::EpochGap)?;
                if epoch.0 != next {
                    return Err(LogError::EpochGap);
                }
                Ok(Change::Rotate(*epoch, *commitment))
            }
        }
    }

    fn record(&mut self, change: Change, index: u64, hash: LogHash) {
        match change {
            Change::Add(devices, recovery_while_due) => {
                self.recovery_added_while_due |= recovery_while_due;
                for device in devices {
                    self.used_keys.insert(*device.keys.sign.as_bytes());
                    self.used_keys.insert(*device.keys.kem.as_bytes());
                    self.devices.insert(
                        device.id,
                        DeviceRecord {
                            id: device.id,
                            keys: device.keys,
                            recovery: device.recovery,
                            added_at: index,
                            removed_at: None,
                        },
                    );
                }
            }
            Change::Remove(target, issuer) => {
                if let Some(record) = self.devices.get_mut(&target) {
                    record.removed_at = Some(index);
                }
                self.last_removal = index;
                self.last_removal_issuer = Some(issuer);
                self.rotation_due = true;
            }
            Change::Rotate(epoch, commitment) => {
                self.epochs.push(EpochRecord {
                    epoch,
                    commitment,
                    index,
                    hash,
                });
                self.rotation_due = false;
                self.recovery_added_while_due = false;
            }
        }
        self.hashes.push(hash);
    }
}

/// What a checked entry changes.
enum Change {
    /// The devices, and whether a recovery device added them while a rotation is due.
    Add(Vec<LogDevice>, bool),
    Remove(DeviceId, DeviceId),
    Rotate(Epoch, EpochCommitment),
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::entropy::OsEntropy;

    pub(crate) struct Dev {
        pub(crate) id: DeviceId,
        pub(crate) identity: DeviceIdentity,
    }

    pub(crate) fn dev(n: u8) -> Dev {
        Dev {
            id: DeviceId::from_bytes([n; 16]),
            identity: DeviceIdentity::generate(&mut OsEntropy).expect("rng"),
        }
    }

    pub(crate) const ACCOUNT: AccountId = AccountId::from_bytes([0xac; 16]);

    pub(crate) fn created(first: &Dev) -> AccountState {
        let mut state = AccountState::new(ACCOUNT);
        let entry = state
            .next_entry(
                &first.identity,
                first.id,
                1,
                EntryKind::Create {
                    devices: vec![LogDevice::of(&first.identity, &ACCOUNT, first.id, false)],
                },
            )
            .expect("create");
        state.apply(&entry).expect("apply");
        state
    }

    fn add(
        state: &mut AccountState,
        issuer: &Dev,
        new: &Dev,
        recovery: bool,
    ) -> Result<LogHead, LogError> {
        let entry = state.next_entry(
            &issuer.identity,
            issuer.id,
            2,
            EntryKind::AddDevice(LogDevice::of(&new.identity, &ACCOUNT, new.id, recovery)),
        )?;
        state.apply(&entry)
    }

    fn rotate(state: &mut AccountState, issuer: &Dev) -> Result<LogHead, LogError> {
        let epoch = Epoch(state.current_epoch().map_or(1, |e| e.epoch.0 + 1));
        let entry = state.next_entry(
            &issuer.identity,
            issuer.id,
            3,
            EntryKind::Rotate {
                epoch,
                commitment: EpochCommitment([7; 32]),
            },
        )?;
        state.apply(&entry)
    }

    fn remove(
        state: &mut AccountState,
        issuer: &Dev,
        target: DeviceId,
    ) -> Result<LogHead, LogError> {
        let entry = state.next_entry(
            &issuer.identity,
            issuer.id,
            4,
            EntryKind::RemoveDevice(target),
        )?;
        state.apply(&entry)
    }

    /// A rotation to epoch 1, the kind the forged-entry tests sign.
    fn rotate_kind() -> EntryKind {
        EntryKind::Rotate {
            epoch: Epoch(1),
            commitment: EpochCommitment([1; 32]),
        }
    }

    /// Signs an entry without the builder's own check, for forged cases.
    fn sign_raw(identity: &DeviceIdentity, mut entry: LogEntry) -> Vec<u8> {
        entry.signature = Signature::from_bytes(identity.sign(&entry.body()));
        entry.encode()
    }

    fn raw_entry(state: &AccountState, issuer: DeviceId, kind: EntryKind) -> LogEntry {
        LogEntry {
            account: ACCOUNT,
            index: state.len() + 1,
            prev: state.head().map(|h| h.hash),
            issued_at_ms: 0,
            issuer,
            kind,
            signature: Signature::from_bytes([0; 64]),
        }
    }

    // Security review H2: the removal a server shows a removed device must continue the
    // device's own verified log and be a valid entry; nothing else counts.
    fn entries(t: &[Vec<u8>]) -> Vec<&[u8]> {
        t.iter().map(Vec::as_slice).collect()
    }

    #[test]
    fn a_removal_counts_only_from_the_own_head() {
        let a = dev(1);
        let b = dev(2);
        let mut server = created(&a);
        add(&mut server, &a, &b, false).unwrap();
        // B's view: everything up to its own addition.
        let view = server.clone();
        let from = view.len() + 1;
        let mut tail = Vec::new();
        let rot = server
            .next_entry(&a.identity, a.id, 5, rotate_kind())
            .unwrap();
        server.apply(&rot).unwrap();
        tail.push(rot);
        let removal = server
            .next_entry(&a.identity, a.id, 6, EntryKind::RemoveDevice(b.id))
            .unwrap();
        server.apply(&removal).unwrap();
        tail.push(removal.clone());

        assert_eq!(view.removal_in(from, entries(&tail), &b.id), Some(a.id));
        assert_eq!(view.len(), from - 1, "the view is not changed");
        // Not for another device, and not without the removal.
        assert_eq!(view.removal_in(from, entries(&tail), &a.id), None);
        assert_eq!(view.removal_in(from, entries(&tail[..1]), &b.id), None);
        assert_eq!(view.removal_in(from, entries(&[]), &b.id), None);
        // A chain that does not start at the own head: a gap, or a wrong first index.
        assert_eq!(view.removal_in(from + 1, entries(&tail[1..]), &b.id), None);
        assert_eq!(view.removal_in(from, entries(&tail[1..]), &b.id), None);
        assert_eq!(view.removal_in(from - 1, entries(&tail), &b.id), None);
        // A forged signature, and a removal signed by a key the log does not list.
        let mut forged = removal.clone();
        let last = forged.len() - 1;
        forged[last] ^= 1;
        assert_eq!(
            view.removal_in(from, entries(&[tail[0].clone(), forged]), &b.id),
            None
        );
        let stranger = dev(9);
        let mut before = view.clone();
        before.apply(&tail[0]).unwrap();
        let fake = sign_raw(
            &stranger.identity,
            raw_entry(&before, a.id, EntryKind::RemoveDevice(b.id)),
        );
        assert_eq!(
            view.removal_in(from, entries(&[tail[0].clone(), fake]), &b.id),
            None
        );
    }

    #[test]
    fn full_lifecycle_add_rotate_remove_rotate() {
        let a = dev(1);
        let b = dev(2);
        let r = dev(3);
        let mut state = created(&a);
        assert_eq!(state.len(), 1);
        rotate(&mut state, &a).unwrap();
        add(&mut state, &a, &b, false).unwrap();
        add(&mut state, &a, &r, true).unwrap();
        assert_eq!(state.current_devices().count(), 3);
        assert!(state.signer_at(&b.id, 3).is_some());
        assert!(state.signer_at(&b.id, 2).is_none(), "not yet listed at 2");
        assert!(state.signer_at(&r.id, 4).is_none(), "recovery never signs");
        remove(&mut state, &a, b.id).unwrap();
        assert!(state.rotation_due());
        assert!(
            state.signer_at(&b.id, 4).is_some(),
            "valid before its removal"
        );
        assert!(state.signer_at(&b.id, 5).is_none());
        rotate(&mut state, &a).unwrap();
        assert!(!state.rotation_due());
        assert_eq!(state.current_epoch().unwrap().epoch, Epoch(2));
        assert_eq!(state.current_epoch().unwrap().index, 6);
        assert_eq!(state.epoch(Epoch(1)).unwrap().index, 2);
        assert!(state.epoch(Epoch(3)).is_none() && state.epoch(Epoch(0)).is_none());

        // A second device verifying the same entries from scratch reaches the same head.
        let head = state.head().unwrap();
        assert!(state.contains(&head));
        assert!(state.safety_number().is_some());
    }

    #[test]
    fn rebuilding_from_entries_and_anchor() {
        let a = dev(1);
        let b = dev(2);
        let mut state = AccountState::new(ACCOUNT);
        let mut entries = Vec::new();
        let create = state
            .next_entry(
                &a.identity,
                a.id,
                1,
                EntryKind::Create {
                    devices: vec![LogDevice::of(&a.identity, &ACCOUNT, a.id, false)],
                },
            )
            .unwrap();
        state.apply(&create).unwrap();
        entries.push(create);
        let anchor = state.head().unwrap();
        let entry = state
            .next_entry(
                &a.identity,
                a.id,
                2,
                EntryKind::AddDevice(LogDevice::of(&b.identity, &ACCOUNT, b.id, false)),
            )
            .unwrap();
        state.apply(&entry).unwrap();
        entries.push(entry);
        let rebuilt =
            AccountState::from_entries(ACCOUNT, entries.iter().map(Vec::as_slice)).unwrap();
        assert_eq!(rebuilt.head(), state.head());
        assert_eq!(rebuilt.check_anchor(&anchor), Ok(()));
        let forged = LogHead {
            index: 1,
            hash: LogHash::from_bytes([0; 32]),
        };
        assert_eq!(rebuilt.check_anchor(&forged), Err(LogError::AnchorMismatch));
        let beyond = LogHead { index: 9, ..anchor };
        assert_eq!(rebuilt.check_anchor(&beyond), Err(LogError::AnchorMismatch));
    }

    #[test]
    fn first_entry_must_create_with_a_regular_issuer() {
        let a = dev(1);
        let state = AccountState::new(ACCOUNT);
        let entry = sign_raw(
            &a.identity,
            raw_entry(&state, a.id, EntryKind::RemoveDevice(a.id)),
        );
        assert_eq!(state.clone().apply(&entry), Err(LogError::NotCreated));
        let recovery = EntryKind::Create {
            devices: vec![LogDevice::of(&a.identity, &ACCOUNT, a.id, true)],
        };
        let entry = sign_raw(&a.identity, raw_entry(&state, a.id, recovery));
        assert_eq!(state.clone().apply(&entry), Err(LogError::Forbidden));
        let b = dev(2);
        let unlisted = EntryKind::Create {
            devices: vec![LogDevice::of(&b.identity, &ACCOUNT, b.id, false)],
        };
        let entry = sign_raw(&a.identity, raw_entry(&state, a.id, unlisted));
        assert_eq!(state.clone().apply(&entry), Err(LogError::UnknownIssuer));
        let empty = sign_raw(
            &a.identity,
            raw_entry(&state, a.id, EntryKind::Create { devices: vec![] }),
        );
        assert_eq!(state.clone().apply(&empty), Err(LogError::Malformed));
    }

    #[test]
    fn later_create_is_refused() {
        let a = dev(1);
        let state = created(&a);
        let b = dev(2);
        let entry = sign_raw(
            &a.identity,
            raw_entry(
                &state,
                a.id,
                EntryKind::Create {
                    devices: vec![LogDevice::of(&b.identity, &ACCOUNT, b.id, false)],
                },
            ),
        );
        assert_eq!(state.clone().apply(&entry), Err(LogError::AlreadyCreated));
    }

    #[test]
    fn forged_moved_and_reordered_entries_are_refused() {
        let a = dev(1);
        let b = dev(2);
        let mut state = created(&a);
        let entry = state
            .next_entry(
                &a.identity,
                a.id,
                2,
                EntryKind::AddDevice(LogDevice::of(&b.identity, &ACCOUNT, b.id, false)),
            )
            .unwrap();
        // Signed by a device the log does not list.
        let stranger = dev(9);
        let forged = sign_raw(&stranger.identity, raw_entry(&state, a.id, rotate_kind()));
        assert_eq!(state.clone().apply(&forged), Err(LogError::Signature));
        // A flipped byte anywhere.
        for at in [10, entry.len() / 2, entry.len() - 1] {
            let mut bad = entry.clone();
            bad[at] ^= 1;
            assert!(state.clone().apply(&bad).is_err(), "flip at {at}");
        }
        // Truncated.
        assert_eq!(
            state.clone().apply(&entry[..entry.len() - 1]),
            Err(LogError::Malformed)
        );
        assert_eq!(state.clone().apply(&entry[..10]), Err(LogError::Malformed));
        // Another account's log.
        let mut other = AccountState::new(AccountId::from_bytes([1; 16]));
        assert!(other.apply(&entry).is_err());
        // Applied twice (replay at the next index) and out of order.
        state.apply(&entry).unwrap();
        assert_eq!(state.clone().apply(&entry), Err(LogError::IndexMismatch));
        let mut wrong_prev = raw_entry(&state, a.id, rotate_kind());
        wrong_prev.prev = Some(LogHash::from_bytes([1; 32]));
        let wrong_prev = sign_raw(&a.identity, wrong_prev);
        assert_eq!(
            state.clone().apply(&wrong_prev),
            Err(LogError::PrevMismatch)
        );
    }

    #[test]
    fn server_admits_only_the_senders_entries() {
        let a = dev(1);
        let b = dev(2);
        let mut state = created(&a);
        let entry = state
            .next_entry(
                &a.identity,
                a.id,
                2,
                EntryKind::AddDevice(LogDevice::of(&b.identity, &ACCOUNT, b.id, false)),
            )
            .unwrap();
        assert_eq!(
            state.admit_batch([entry.as_slice()], &b.id).unwrap_err(),
            LogError::NotSender
        );
        let admitted = state.admit_batch([entry.as_slice()], &a.id).unwrap();
        assert_eq!(admitted.shape, BatchShape::AddDevice { device: b.id });
        assert_eq!(admitted.state.len(), 2);
        assert_eq!(state.len(), 1, "admit_batch changes nothing itself");
        state.apply(&entry).unwrap();
        assert_eq!(state.head(), admitted.state.head());
    }

    /// Builds the entries of `steps` one after the other on a copy of `state`.
    fn batch(state: &AccountState, steps: &[(&Dev, EntryKind)]) -> Vec<Vec<u8>> {
        let mut scratch = state.clone();
        steps
            .iter()
            .map(|(issuer, kind)| {
                let entry = scratch
                    .next_entry(&issuer.identity, issuer.id, 9, kind.clone())
                    .unwrap();
                scratch.apply(&entry).unwrap();
                entry
            })
            .collect()
    }

    fn slices(entries: &[Vec<u8>]) -> Vec<&[u8]> {
        entries.iter().map(Vec::as_slice).collect()
    }

    fn next_rotation(state: &AccountState) -> EntryKind {
        EntryKind::Rotate {
            epoch: Epoch(state.current_epoch().map_or(1, |e| e.epoch.0 + 1)),
            commitment: EpochCommitment([7; 32]),
        }
    }

    #[test]
    fn a_removal_is_admitted_only_together_with_its_rotation() {
        let a = dev(1);
        let b = dev(2);
        let c = dev(3);
        let mut state = created(&a);
        add(&mut state, &a, &b, false).unwrap();
        add(&mut state, &a, &c, false).unwrap();
        let rotate_kind = next_rotation(&state);

        let alone = batch(&state, &[(&a, EntryKind::RemoveDevice(b.id))]);
        assert_eq!(
            state.admit_batch(slices(&alone), &a.id).unwrap_err(),
            LogError::BatchShape
        );
        let both = batch(
            &state,
            &[
                (&a, EntryKind::RemoveDevice(b.id)),
                (&a, EntryKind::RemoveDevice(c.id)),
                (&a, rotate_kind.clone()),
            ],
        );
        let admitted = state.admit_batch(slices(&both), &a.id).unwrap();
        assert!(!admitted.state.rotation_due());
        assert_eq!(
            admitted.shape,
            BatchShape::Rotation {
                removed: vec![b.id, c.id],
                epoch: Epoch(1)
            }
        );
        assert_eq!(admitted.state.last_removal_index(), 5);
        assert_eq!(state.last_removal_index(), 0);
        // A plain rotation is a rotation batch without removals.
        let plain = batch(&state, &[(&a, rotate_kind.clone())]);
        assert!(state.admit_batch(slices(&plain), &a.id).is_ok());
        // Other shapes.
        let d = dev(4);
        let add_d = EntryKind::AddDevice(LogDevice::of(&d.identity, &ACCOUNT, d.id, false));
        let e = dev(5);
        let add_e = EntryKind::AddDevice(LogDevice::of(&e.identity, &ACCOUNT, e.id, false));
        for steps in [
            vec![(&a, add_d.clone()), (&a, add_e.clone())],
            vec![(&a, add_d.clone()), (&a, rotate_kind.clone())],
            vec![
                (&a, rotate_kind.clone()),
                (&a, EntryKind::RemoveDevice(b.id)),
            ],
        ] {
            let entries = batch(&state, &steps);
            assert_eq!(
                state.admit_batch(slices(&entries), &a.id).unwrap_err(),
                LogError::BatchShape
            );
        }
        assert_eq!(
            state.admit_batch(Vec::<&[u8]>::new(), &a.id).unwrap_err(),
            LogError::BatchShape
        );
        // A malformed entry refuses the whole batch.
        let mut broken = both.clone();
        broken[1][20] ^= 1;
        assert!(state.admit_batch(slices(&broken), &a.id).is_err());
    }

    #[test]
    fn genesis_is_admitted_on_its_own() {
        let a = dev(1);
        let mut empty = AccountState::new(ACCOUNT);
        let create = empty
            .next_entry(
                &a.identity,
                a.id,
                1,
                EntryKind::Create {
                    devices: vec![LogDevice::of(&a.identity, &ACCOUNT, a.id, false)],
                },
            )
            .unwrap();
        assert_eq!(
            empty.admit_batch([create.as_slice()], &a.id).unwrap_err(),
            LogError::BatchShape
        );
        assert_eq!(
            empty
                .clone()
                .admit_genesis(&create, &DeviceId::from_bytes([9; 16])),
            Err(LogError::NotSender)
        );
        empty.admit_genesis(&create, &a.id).unwrap();
        assert_eq!(
            empty.clone().admit_genesis(&create, &a.id),
            Err(LogError::AlreadyCreated)
        );
        let rotate = batch(&empty, &[(&a, next_rotation(&empty))]);
        assert!(AccountState::new(ACCOUNT)
            .admit_batch(slices(&rotate), &a.id)
            .is_err());
    }

    #[test]
    fn a_recovery_device_may_add_one_device_while_a_rotation_is_due() {
        // A log stuck with a rotation due (written by an older client entry by entry): the only
        // regular device a removed b and was then lost before it rotated.
        let a = dev(1);
        let b = dev(2);
        let r = dev(3);
        let n = dev(4);
        let m = dev(5);
        let mut state = created(&a);
        rotate(&mut state, &a).unwrap();
        add(&mut state, &a, &b, false).unwrap();
        add(&mut state, &a, &r, true).unwrap();
        remove(&mut state, &a, b.id).unwrap();
        assert!(state.rotation_due());

        // A regular device may not add one now, and the recovery device never a recovery device.
        assert_eq!(
            add(&mut state.clone(), &a, &n, false),
            Err(LogError::RotationDue)
        );
        assert_eq!(
            add(&mut state.clone(), &r, &n, true),
            Err(LogError::RotationDue),
            "the exception covers only a regular device"
        );
        let add_n = batch(
            &state,
            &[(
                &r,
                EntryKind::AddDevice(LogDevice::of(&n.identity, &ACCOUNT, n.id, false)),
            )],
        );
        let admitted = state.admit_batch(slices(&add_n), &r.id).unwrap();
        assert!(admitted.state.rotation_due(), "the rotation stays due");
        let mut state = admitted.state;
        // Exactly one.
        assert_eq!(
            add(&mut state.clone(), &r, &m, false),
            Err(LogError::RotationDue)
        );
        // The new device removes the lost device and the recovery device and rotates.
        let steps = [
            (&n, EntryKind::RemoveDevice(a.id)),
            (&n, EntryKind::RemoveDevice(r.id)),
            (&n, next_rotation(&state)),
        ];
        let entries = batch(&state, &steps);
        let admitted = state.admit_batch(slices(&entries), &n.id).unwrap();
        assert!(!admitted.state.rotation_due());
        state = admitted.state;
        assert_eq!(state.current_devices().count(), 1);
        // A recovery device added after the rotation may add again when nothing is due.
        let r2 = dev(6);
        add(&mut state, &n, &r2, true).unwrap();
        add(&mut state, &r2, &m, false).unwrap();
    }

    #[test]
    fn device_ids_and_keys_are_used_once() {
        let a = dev(1);
        let b = dev(2);
        let mut state = created(&a);
        add(&mut state, &a, &b, false).unwrap();
        remove(&mut state, &a, b.id).unwrap();
        rotate(&mut state, &a).unwrap();
        // The same id again, with new keys.
        let again = Dev {
            id: b.id,
            identity: DeviceIdentity::generate(&mut OsEntropy).unwrap(),
        };
        assert_eq!(
            add(&mut state, &a, &again, false),
            Err(LogError::DeviceExists)
        );
        // The same keys under a new id.
        let reused = Dev {
            id: DeviceId::from_bytes([5; 16]),
            identity: DeviceIdentity::import(&b.identity.export()).unwrap(),
        };
        assert_eq!(
            add(&mut state, &a, &reused, false),
            Err(LogError::KeyReused)
        );
    }

    #[test]
    fn bad_proofs_and_keys_are_refused() {
        let a = dev(1);
        let b = dev(2);
        let state = created(&a);
        let mut device = LogDevice::of(&b.identity, &ACCOUNT, b.id, false);
        device.proof = b.identity.prove(&ACCOUNT, &b.id, true);
        let entry = sign_raw(
            &a.identity,
            raw_entry(&state, a.id, EntryKind::AddDevice(device)),
        );
        assert_eq!(state.clone().apply(&entry), Err(LogError::Proof));
        let mut device = LogDevice::of(&b.identity, &ACCOUNT, b.id, false);
        device.keys.kem = PublicKey::from_bytes([0; 32]);
        let entry = sign_raw(
            &a.identity,
            raw_entry(&state, a.id, EntryKind::AddDevice(device)),
        );
        assert_eq!(state.clone().apply(&entry), Err(LogError::InvalidKey));
    }

    #[test]
    fn recovery_device_may_only_add_a_regular_device() {
        let a = dev(1);
        let r = dev(2);
        let n = dev(3);
        let mut state = created(&a);
        rotate(&mut state, &a).unwrap();
        add(&mut state, &a, &r, true).unwrap();
        assert_eq!(
            remove(&mut state.clone(), &r, a.id),
            Err(LogError::Forbidden)
        );
        assert_eq!(rotate(&mut state.clone(), &r), Err(LogError::Forbidden));
        assert_eq!(
            add(&mut state.clone(), &r, &n, true),
            Err(LogError::Forbidden)
        );
        add(&mut state, &r, &n, false).unwrap();
        // The new device removes the lost device and the used recovery device, then rotates.
        remove(&mut state, &n, a.id).unwrap();
        remove(&mut state, &n, r.id).unwrap();
        rotate(&mut state, &n).unwrap();
        assert_eq!(state.current_devices().count(), 1);
    }

    #[test]
    fn no_self_removal_and_no_removed_issuer() {
        let a = dev(1);
        let b = dev(2);
        let mut state = created(&a);
        add(&mut state, &a, &b, false).unwrap();
        assert_eq!(
            remove(&mut state.clone(), &a, a.id),
            Err(LogError::Forbidden)
        );
        assert_eq!(
            remove(&mut state.clone(), &a, DeviceId::from_bytes([9; 16])),
            Err(LogError::UnknownDevice)
        );
        remove(&mut state, &a, b.id).unwrap();
        assert_eq!(
            remove(&mut state.clone(), &a, b.id),
            Err(LogError::UnknownDevice)
        );
        // The removed device signs nothing any more.
        let entry = sign_raw(&b.identity, raw_entry(&state, b.id, rotate_kind()));
        assert_eq!(state.clone().apply(&entry), Err(LogError::UnknownIssuer));
    }

    #[test]
    fn rotation_is_immediate_after_a_removal() {
        let a = dev(1);
        let b = dev(2);
        let c = dev(3);
        let d = dev(4);
        let mut state = created(&a);
        add(&mut state, &a, &b, false).unwrap();
        add(&mut state, &a, &c, false).unwrap();
        remove(&mut state, &a, b.id).unwrap();
        assert_eq!(
            add(&mut state.clone(), &a, &d, false),
            Err(LogError::RotationDue)
        );
        // A second removal is allowed before the rotation.
        remove(&mut state, &a, c.id).unwrap();
        rotate(&mut state, &a).unwrap();
        add(&mut state, &a, &d, false).unwrap();
    }

    #[test]
    fn epochs_have_no_gaps() {
        let a = dev(1);
        let mut state = created(&a);
        let entry = state.next_entry(
            &a.identity,
            a.id,
            0,
            EntryKind::Rotate {
                epoch: Epoch(2),
                commitment: EpochCommitment([0; 32]),
            },
        );
        assert_eq!(entry, Err(LogError::EpochGap));
        rotate(&mut state, &a).unwrap();
        let again = sign_raw(&a.identity, raw_entry(&state, a.id, rotate_kind()));
        assert_eq!(state.clone().apply(&again), Err(LogError::EpochGap));
    }

    #[test]
    fn device_cap() {
        let a = dev(1);
        let mut state = created(&a);
        for n in 2..=MAX_DEVICES as u8 {
            add(&mut state, &a, &dev(n), false).unwrap();
        }
        assert_eq!(state.current_devices().count(), MAX_DEVICES);
        assert_eq!(
            add(&mut state, &a, &dev(200), false),
            Err(LogError::TooManyDevices)
        );
    }

    #[test]
    fn the_last_places_are_reserved() {
        let a = dev(1);
        let b = dev(2);
        let mut state = created(&a);
        add(&mut state, &a, &b, false).unwrap();
        while state.len() < MAX_LOG_ENTRIES - RESERVED_LOG_ENTRIES {
            rotate(&mut state, &a).unwrap();
        }
        assert_eq!(
            add(&mut state.clone(), &a, &dev(3), false),
            Err(LogError::Reserved)
        );
        remove(&mut state, &a, b.id).unwrap();
        while state.len() < MAX_LOG_ENTRIES - 1 {
            rotate(&mut state, &a).unwrap();
        }
        let c_entry = sign_raw(
            &a.identity,
            raw_entry(&state, a.id, EntryKind::RemoveDevice(b.id)),
        );
        assert_eq!(state.clone().apply(&c_entry), Err(LogError::Reserved));
        rotate(&mut state, &a).unwrap();
        assert_eq!(state.len(), MAX_LOG_ENTRIES);
        assert_eq!(rotate(&mut state, &a), Err(LogError::LogFull));
    }

    #[test]
    fn decoding_is_strict() {
        let a = dev(1);
        let state = created(&a);
        let entry = state
            .next_entry(&a.identity, a.id, 0, rotate_kind())
            .unwrap();
        let decoded = LogEntry::decode(&entry).unwrap();
        assert_eq!(decoded.encode(), entry);
        let mut longer = entry.clone();
        longer.insert(entry.len() - 64, 0);
        assert_eq!(LogEntry::decode(&longer), Err(LogError::Malformed));
        assert_eq!(LogEntry::decode(&[0; 10]), Err(LogError::Malformed));
        // Version byte at offset 4 + label + 4.
        let at = 4 + LABEL_ENTRY.len() + 4;
        let mut v2 = entry.clone();
        v2[at] = 2;
        assert_eq!(LogEntry::decode(&v2), Err(LogError::Version(2)));
    }
}
