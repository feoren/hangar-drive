//! Sealed account records (`folder-keys`, `folders`, `device-names`): encrypted with the epoch's
//! account seal key and signed by the writing device, with a version per record that the
//! [`RecordGuard`] never lets go back.
//!
//! Built after the sealed records of the sister project's `hangar-team-crypto`
//! (`src/record.rs`, MIT, same owner). Drive replaces the per-device counter with the record's
//! version, which the server advances by compare and swap and the feed announces.
//!
//! # Format (version 1)
//!
//! ```text
//! data = 0x01 || epoch (u32) || version (u64) || sender device (16) || head index (u64)
//!        || head hash (32) || nonce (24 random bytes) || XChaCha20-Poly1305(K_acct,e, nonce, plaintext, aad)
//!        || Ed25519 signature of the sender (64 bytes)
//! aad  = field("hangar-drive/v1/record") || field(0x01) || field(account) || field(epoch, u32)
//!        || field(kind label) || field(record id: folder id or empty) || field(version, u64)
//!        || field(sender device) || field(head index, u64) || field(head hash)
//! signed message = field("hangar-drive/v1/record-sig") || field(aad) || field(nonce) || field(ciphertext)
//! ```
//!
//! The associated data binds a record to account, epoch, kind, record ID, version and sender,
//! so the server can neither move it to another folder or kind nor present it as another
//! version. The signature stops a device from writing in another's name, which the shared key
//! alone would allow.
//!
//! # Opening, in order
//!
//! Format, the cipher's epoch, a head index this device verified ([`OpenError::AheadOfLog`]
//! otherwise: fetch the log), the sender valid and not a recovery device at that index **and a
//! current device of the verified log** (a removed device's records never open again, whatever
//! head they name; the removing device re-seals every record,
//! [`crate::folder_keys::reseal_after_removal`]), the head not before the epoch's rotation, the
//! signature, decryption, and only then the head's
//! hash ([`OpenError::Fork`]): only a record that is signed and sealed with the epoch's key can
//! report a fork. A forged record costs no decryption.
//!
//! # Replay guard
//!
//! [`RecordGuard`] keeps per record the highest version this device accepted and the digest of
//! its bytes. It refuses an older version ([`GuardError::Replay`]) and a different record under
//! the same version ([`GuardError::Equivocation`]). It cannot tell a device that a newer version
//! exists; the freshness rule for `folder-keys` is in [`crate::folder_keys`].

use std::collections::BTreeMap;
use std::fmt;

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use hangar_drive_protocol::api::RecordKey;
use hangar_drive_protocol::ids::{AccountId, DeviceId, Epoch, LogHash, LogHead};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::devicelog::AccountState;
use crate::encoding::{framed, sha256, Reader, Writer};
use crate::entropy::{Entropy, EntropyError};
use crate::epoch::{AccountKey, AccountSecret, WrapError};
use crate::identity::{verify, DeviceIdentity};

const LABEL_RECORD: &[u8] = b"hangar-drive/v1/record";
const LABEL_RECORD_SIG: &[u8] = b"hangar-drive/v1/record-sig";
const RECORD_VERSION: u8 = 1;
const HEADER_LEN: usize = 1 + 4 + 8 + 16 + 8 + 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const SIGNATURE_LEN: usize = 64;
/// Bytes a record adds to its plaintext.
pub const RECORD_OVERHEAD: usize = HEADER_LEN + NONCE_LEN + TAG_LEN + SIGNATURE_LEN;
/// The largest plaintext of a record.
pub const MAX_RECORD_PLAINTEXT: usize = 1 << 20;

/// Why a record was not sealed.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SealError {
    /// The plaintext is above [`MAX_RECORD_PLAINTEXT`].
    #[error("the record is too large")]
    TooLarge,
    /// Version 0: versions count from 1.
    #[error("record versions count from 1")]
    Version,
    /// No randomness for the nonce.
    #[error(transparent)]
    Entropy(#[from] EntropyError),
    /// The cipher refused (not expected).
    #[error("sealing failed")]
    Cipher,
}

/// Why a record did not open.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum OpenError {
    /// Not a record of this format.
    #[error("the sealed record is malformed")]
    Malformed,
    /// A record format version this crate does not know.
    #[error("sealed record format version {0} is not supported")]
    Format(u8),
    /// Sealed under another epoch than this cipher's.
    #[error("the record was sealed under epoch {got}, expected {expected}")]
    EpochMismatch {
        /// This cipher's epoch.
        expected: u32,
        /// The record's epoch.
        got: u32,
    },
    /// The signed version is not the one the server named for it.
    #[error("the record's version is not the one it was served as")]
    VersionMismatch,
    /// The sender saw a newer log than this device: fetch the log and open again.
    #[error("the record names log entry {index}, which this device has not verified yet")]
    AheadOfLog {
        /// The sender's head index.
        index: u64,
    },
    /// The log never listed the sender.
    #[error("the device log does not know the sender")]
    UnknownSender,
    /// The log did not vouch for the sender at the record's log head, or it is a recovery
    /// device, which signs no records.
    #[error("the sender may not sign records at the record's log head")]
    SenderNotValid,
    /// The record names a log head from before its epoch began.
    #[error("the record names a log head from before its epoch")]
    HeadBeforeEpoch,
    /// The signature does not verify over this context.
    #[error("the record's signature does not verify for this sender and context")]
    Signature,
    /// Signed, but the ciphertext does not open.
    #[error("the record does not decrypt")]
    Decrypt,
    /// The sender's log differs from this device's at `index`: the server shows the two
    /// devices different logs.
    #[error("the sender's device log differs from this device's at entry {index}")]
    Fork {
        /// The index known to differ.
        index: u64,
    },
}

/// The clear header of a record, read **without** any check: never a reason to trust anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecordHeader {
    /// The epoch it claims.
    pub epoch: Epoch,
    /// The version it claims.
    pub version: u64,
    /// The sender it claims.
    pub sender: DeviceId,
    /// The log head it claims.
    pub head: LogHead,
}

struct Parsed<'a> {
    header: RecordHeader,
    nonce: &'a [u8],
    ciphertext: &'a [u8],
    signature: [u8; SIGNATURE_LEN],
}

fn parse(data: &[u8]) -> Result<Parsed<'_>, OpenError> {
    let mut r = Reader::new(data);
    let version = r.u8().ok_or(OpenError::Malformed)?;
    if version != RECORD_VERSION {
        return Err(OpenError::Format(version));
    }
    if data.len() < RECORD_OVERHEAD {
        return Err(OpenError::Malformed);
    }
    let epoch = Epoch(r.u32().ok_or(OpenError::Malformed)?);
    let record_version = r.u64().ok_or(OpenError::Malformed)?;
    let sender = DeviceId::from_bytes(r.raw().ok_or(OpenError::Malformed)?);
    let index = r.u64().ok_or(OpenError::Malformed)?;
    let hash = LogHash::from_bytes(r.raw().ok_or(OpenError::Malformed)?);
    let nonce = r.raw_slice(NONCE_LEN).ok_or(OpenError::Malformed)?;
    let rest = r.remaining();
    let ciphertext = r
        .raw_slice(rest - SIGNATURE_LEN)
        .ok_or(OpenError::Malformed)?;
    let signature = r.raw::<SIGNATURE_LEN>().ok_or(OpenError::Malformed)?;
    Ok(Parsed {
        header: RecordHeader {
            epoch,
            version: record_version,
            sender,
            head: LogHead { index, hash },
        },
        nonce,
        ciphertext,
        signature,
    })
}

/// The clear header of a record (bookkeeping only; see [`RecordHeader`]).
pub fn record_header(data: &[u8]) -> Option<RecordHeader> {
    parse(data).ok().map(|p| p.header)
}

/// An opened record. `Debug` does not show the plaintext.
pub struct OpenedRecord {
    /// Which record.
    pub key: RecordKey,
    /// The epoch it was sealed under.
    pub epoch: Epoch,
    /// Its version.
    pub version: u64,
    /// The writing device.
    pub sender: DeviceId,
    /// The sender's log head.
    pub head: LogHead,
    /// SHA-256 of the sealed bytes, for the [`RecordGuard`].
    pub digest: [u8; 32],
    /// The plaintext, wiped on drop.
    pub plaintext: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for OpenedRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedRecord")
            .field("key", &self.key)
            .field("epoch", &self.epoch)
            .field("version", &self.version)
            .field("sender", &self.sender)
            .field("head", &self.head)
            .field("len", &self.plaintext.len())
            .finish()
    }
}

/// Seals and opens the records of one epoch.
#[derive(Debug)]
pub struct RecordCipher {
    key: AccountKey,
}

impl RecordCipher {
    /// The cipher of `epoch` as the verified log records it.
    pub fn for_epoch(
        state: &AccountState,
        secret: &AccountSecret,
        epoch: Epoch,
    ) -> Result<Self, WrapError> {
        Ok(Self {
            key: AccountKey::for_epoch(state, secret, epoch)?,
        })
    }

    /// The cipher of an account key derived elsewhere.
    pub fn new(key: AccountKey) -> Self {
        Self { key }
    }

    /// The epoch.
    pub fn epoch(&self) -> Epoch {
        self.key.epoch()
    }

    fn account(&self) -> &AccountId {
        self.key.account()
    }

    fn aad(&self, key: &RecordKey, version: u64, sender: &DeviceId, head: &LogHead) -> Vec<u8> {
        let mut w = Writer::new();
        w.field(LABEL_RECORD)
            .field_u8(RECORD_VERSION)
            .field(self.account().as_bytes())
            .field_u32(self.epoch().0)
            .field(key.kind.label().as_bytes())
            .field(&key.id_bytes())
            .field_u64(version)
            .field(sender.as_bytes())
            .field_u64(head.index)
            .field(head.hash.as_bytes());
        w.into_bytes()
    }

    fn cipher(&self) -> Option<XChaCha20Poly1305> {
        XChaCha20Poly1305::new_from_slice(self.key.bytes()).ok()
    }

    /// Seals `plaintext` as `version` of record `key`, written by `sender` (whose keys
    /// `identity` holds) at its newest verified log head `head`.
    #[allow(clippy::too_many_arguments)]
    pub fn seal(
        &self,
        key: &RecordKey,
        version: u64,
        identity: &DeviceIdentity,
        sender: &DeviceId,
        head: &LogHead,
        plaintext: &[u8],
        entropy: &mut impl Entropy,
    ) -> Result<Vec<u8>, SealError> {
        if plaintext.len() > MAX_RECORD_PLAINTEXT {
            return Err(SealError::TooLarge);
        }
        if version == 0 {
            return Err(SealError::Version);
        }
        let mut nonce = [0u8; NONCE_LEN];
        entropy.fill(&mut nonce)?;
        let aad = self.aad(key, version, sender, head);
        let ciphertext = self
            .cipher()
            .ok_or(SealError::Cipher)?
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad,
                },
            )
            .map_err(|_| SealError::Cipher)?;
        let signature = identity.sign(&framed(&[LABEL_RECORD_SIG, &aad, &nonce, &ciphertext]));
        let mut w = Writer::with_capacity(plaintext.len() + RECORD_OVERHEAD);
        w.u8(RECORD_VERSION)
            .u32(self.epoch().0)
            .u64(version)
            .raw(sender.as_bytes())
            .u64(head.index)
            .raw(head.hash.as_bytes())
            .raw(&nonce)
            .raw(&ciphertext)
            .raw(&signature);
        Ok(w.into_bytes())
    }

    /// Opens `data`, served as `version` of record `key`, against the verified log `state`
    /// (order: module docs).
    pub fn open(
        &self,
        state: &AccountState,
        key: &RecordKey,
        version: u64,
        data: &[u8],
    ) -> Result<OpenedRecord, OpenError> {
        let parsed = parse(data)?;
        let header = parsed.header;
        if header.epoch != self.epoch() {
            return Err(OpenError::EpochMismatch {
                expected: self.epoch().0,
                got: header.epoch.0,
            });
        }
        if header.version != version {
            return Err(OpenError::VersionMismatch);
        }
        if header.head.index == 0 || header.head.index > state.len() {
            return Err(OpenError::AheadOfLog {
                index: header.head.index,
            });
        }
        if state.device(&header.sender).is_none() {
            return Err(OpenError::UnknownSender);
        }
        // Valid at the head the record names is not enough: a removed device whose key leaked
        // could name a head from before its removal. The sender must be current now; every
        // removal is followed by the re-seal of all records by the removing device
        // (`crate::folder_keys::reseal_after_removal`).
        let signer = state
            .signer_at(&header.sender, header.head.index)
            .filter(|d| d.is_current())
            .ok_or(OpenError::SenderNotValid)?;
        let epoch_start =
            state
                .epoch(self.epoch())
                .map(|e| e.index)
                .ok_or(OpenError::EpochMismatch {
                    expected: self.epoch().0,
                    got: header.epoch.0,
                })?;
        if header.head.index < epoch_start {
            return Err(OpenError::HeadBeforeEpoch);
        }
        let aad = self.aad(key, header.version, &header.sender, &header.head);
        if !verify(
            &signer.keys.sign,
            &framed(&[LABEL_RECORD_SIG, &aad, parsed.nonce, parsed.ciphertext]),
            &parsed.signature,
        ) {
            return Err(OpenError::Signature);
        }
        let nonce: [u8; NONCE_LEN] = parsed.nonce.try_into().map_err(|_| OpenError::Malformed)?;
        let plaintext = self
            .cipher()
            .ok_or(OpenError::Decrypt)?
            .decrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| OpenError::Decrypt)?;
        let plaintext = Zeroizing::new(plaintext);
        if !state.contains(&header.head) {
            return Err(OpenError::Fork {
                index: header.head.index,
            });
        }
        Ok(OpenedRecord {
            key: *key,
            epoch: header.epoch,
            version: header.version,
            sender: header.sender,
            head: header.head,
            digest: sha256(data),
            plaintext,
        })
    }
}

/// Why the replay guard refused a record.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum GuardError {
    /// A version older than one this device accepted.
    #[error("record version {got} is older than the accepted version {accepted}")]
    Replay {
        /// The record's version.
        got: u64,
        /// The highest version accepted.
        accepted: u64,
    },
    /// Another record under a version this device accepted: two writers or a lying server.
    #[error("a different record was accepted under the same version")]
    Equivocation,
}

/// The highest accepted version per record (module docs). The app stores
/// [`RecordGuard::marks`] and resumes it after a restart.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RecordGuard {
    marks: BTreeMap<RecordKey, (u64, [u8; 32])>,
}

impl RecordGuard {
    /// An empty guard.
    pub fn new() -> Self {
        Self::default()
    }

    /// A guard with stored marks.
    pub fn resume(marks: BTreeMap<RecordKey, (u64, [u8; 32])>) -> Self {
        Self { marks }
    }

    /// The marks to store.
    pub fn marks(&self) -> &BTreeMap<RecordKey, (u64, [u8; 32])> {
        &self.marks
    }

    /// The highest version accepted for `key`.
    pub fn accepted(&self, key: &RecordKey) -> Option<u64> {
        self.marks.get(key).map(|(version, _)| *version)
    }

    /// Checks an opened record without recording it.
    pub fn check(&self, record: &OpenedRecord) -> Result<(), GuardError> {
        match self.marks.get(&record.key) {
            Some((accepted, _)) if record.version < *accepted => Err(GuardError::Replay {
                got: record.version,
                accepted: *accepted,
            }),
            Some((accepted, digest))
                if record.version == *accepted
                    && !crate::encoding::constant_time_eq(digest, &record.digest) =>
            {
                Err(GuardError::Equivocation)
            }
            _ => Ok(()),
        }
    }

    /// Checks and records an opened record. The same record again is accepted (idempotent).
    pub fn accept(&mut self, record: &OpenedRecord) -> Result<(), GuardError> {
        self.check(record)?;
        self.marks
            .insert(record.key, (record.version, record.digest));
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::devicelog::tests::{created, dev, Dev, ACCOUNT};
    use crate::devicelog::{EntryKind, LogDevice};
    use crate::entropy::OsEntropy;
    use crate::epoch::rotate;
    use hangar_drive_protocol::api::RecordKind;
    use hangar_drive_protocol::ids::FolderId;

    pub(crate) struct Setup {
        pub(crate) a: Dev,
        pub(crate) b: Dev,
        pub(crate) state: AccountState,
        pub(crate) secret: AccountSecret,
    }

    /// A account with devices a and b and epoch 1.
    pub(crate) fn setup() -> Setup {
        let a = dev(1);
        let b = dev(2);
        let mut state = created(&a);
        let entry = state
            .next_entry(
                &a.identity,
                a.id,
                0,
                EntryKind::AddDevice(LogDevice::of(&b.identity, &ACCOUNT, b.id, false)),
            )
            .unwrap();
        state.apply(&entry).unwrap();
        let rotation = rotate(&state, &a.identity, a.id, 0, &mut OsEntropy).unwrap();
        state.apply(&rotation.entry).unwrap();
        Setup {
            a,
            b,
            state,
            secret: rotation.secret,
        }
    }

    fn ring_key() -> RecordKey {
        RecordKey::new(RecordKind::FolderKeys, Some(FolderId::from_bytes([3; 16]))).unwrap()
    }

    fn sealed(s: &Setup, key: &RecordKey, version: u64, plaintext: &[u8]) -> Vec<u8> {
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        cipher
            .seal(
                key,
                version,
                &s.a.identity,
                &s.a.id,
                &s.state.head().unwrap(),
                plaintext,
                &mut OsEntropy,
            )
            .unwrap()
    }

    #[test]
    fn seal_open_round_trip() {
        let s = setup();
        let key = ring_key();
        let data = sealed(&s, &key, 1, b"ring");
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        let opened = cipher.open(&s.state, &key, 1, &data).unwrap();
        assert_eq!(opened.plaintext.as_slice(), b"ring");
        assert_eq!(opened.sender, s.a.id);
        assert_eq!(opened.version, 1);
        assert!(!format!("{opened:?}").contains("ring"));
        let header = record_header(&data).unwrap();
        assert_eq!(header.version, 1);
        assert_eq!(header.epoch, Epoch(1));
    }

    #[test]
    fn wrong_context_aad_does_not_open() {
        let s = setup();
        let key = ring_key();
        let data = sealed(&s, &key, 1, b"ring");
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        // Another folder or another kind: the signature binds the context.
        let other_folder =
            RecordKey::new(RecordKind::FolderKeys, Some(FolderId::from_bytes([4; 16]))).unwrap();
        assert_eq!(
            cipher.open(&s.state, &other_folder, 1, &data).unwrap_err(),
            OpenError::Signature
        );
        let other_kind = RecordKey::new(RecordKind::Folders, None).unwrap();
        assert_eq!(
            cipher.open(&s.state, &other_kind, 1, &data).unwrap_err(),
            OpenError::Signature
        );
        // Served as another version.
        assert_eq!(
            cipher.open(&s.state, &key, 2, &data).unwrap_err(),
            OpenError::VersionMismatch
        );
    }

    #[test]
    fn tampering_and_truncation_are_refused() {
        let s = setup();
        let key = ring_key();
        let data = sealed(&s, &key, 1, b"ring");
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        // The version in the header rewritten to match the served version: signature fails.
        let mut bumped = data.clone();
        bumped[5..13].copy_from_slice(&2u64.to_be_bytes());
        assert_eq!(
            cipher.open(&s.state, &key, 2, &bumped).unwrap_err(),
            OpenError::Signature
        );
        // The ciphertext.
        let mut flipped = data.clone();
        flipped[HEADER_LEN + NONCE_LEN] ^= 1;
        assert_eq!(
            cipher.open(&s.state, &key, 1, &flipped).unwrap_err(),
            OpenError::Signature
        );
        // The sender claims b: b's key does not verify a's signature.
        let mut sender = data.clone();
        sender[13..29].copy_from_slice(s.b.id.as_bytes());
        assert_eq!(
            cipher.open(&s.state, &key, 1, &sender).unwrap_err(),
            OpenError::Signature
        );
        for cut in [0, 1, RECORD_OVERHEAD - 1, data.len() - 1] {
            assert!(
                cipher.open(&s.state, &key, 1, &data[..cut]).is_err(),
                "cut {cut}"
            );
        }
        let mut v2 = data;
        v2[0] = 2;
        assert_eq!(
            cipher.open(&s.state, &key, 1, &v2).unwrap_err(),
            OpenError::Format(2)
        );
    }

    #[test]
    fn a_record_signed_with_the_epoch_key_but_another_key_does_not_decrypt() {
        let s = setup();
        let key = ring_key();
        // Sealed under a key derived from another secret, but labelled as epoch 1.
        let wrong = AccountKey::derive(
            &AccountSecret::generate(&mut OsEntropy).unwrap(),
            &ACCOUNT,
            Epoch(1),
            &s.state.epoch(Epoch(1)).unwrap().hash,
        )
        .unwrap();
        let data = RecordCipher::new(wrong)
            .seal(
                &key,
                1,
                &s.a.identity,
                &s.a.id,
                &s.state.head().unwrap(),
                b"x",
                &mut OsEntropy,
            )
            .unwrap();
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        assert_eq!(
            cipher.open(&s.state, &key, 1, &data).unwrap_err(),
            OpenError::Decrypt
        );
    }

    #[test]
    fn sender_and_head_rules() {
        let mut s = setup();
        let key = ring_key();
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        let head = s.state.head().unwrap();
        // A head this device has not verified.
        let ahead = LogHead {
            index: head.index + 1,
            hash: head.hash,
        };
        let data = cipher
            .seal(
                &key,
                1,
                &s.a.identity,
                &s.a.id,
                &ahead,
                b"x",
                &mut OsEntropy,
            )
            .unwrap();
        assert_eq!(
            cipher.open(&s.state, &key, 1, &data).unwrap_err(),
            OpenError::AheadOfLog { index: ahead.index }
        );
        // A head before the epoch began.
        let early = LogHead {
            index: 1,
            hash: *s.state.hash_at(1).unwrap(),
        };
        let data = cipher
            .seal(
                &key,
                1,
                &s.a.identity,
                &s.a.id,
                &early,
                b"x",
                &mut OsEntropy,
            )
            .unwrap();
        assert_eq!(
            cipher.open(&s.state, &key, 1, &data).unwrap_err(),
            OpenError::HeadBeforeEpoch
        );
        // Signed and sealed, but at a head whose hash differs: a fork.
        let forked = LogHead {
            index: head.index,
            hash: LogHash::from_bytes([9; 32]),
        };
        let data = cipher
            .seal(
                &key,
                1,
                &s.a.identity,
                &s.a.id,
                &forked,
                b"x",
                &mut OsEntropy,
            )
            .unwrap();
        assert_eq!(
            cipher.open(&s.state, &key, 1, &data).unwrap_err(),
            OpenError::Fork { index: head.index }
        );
        // An unknown sender.
        let stranger = dev(9);
        let data = cipher
            .seal(
                &key,
                1,
                &stranger.identity,
                &stranger.id,
                &head,
                b"x",
                &mut OsEntropy,
            )
            .unwrap();
        assert_eq!(
            cipher.open(&s.state, &key, 1, &data).unwrap_err(),
            OpenError::UnknownSender
        );
        // A removed sender, at a head after its removal.
        let entry = s
            .state
            .next_entry(&s.a.identity, s.a.id, 0, EntryKind::RemoveDevice(s.b.id))
            .unwrap();
        s.state.apply(&entry).unwrap();
        let after = s.state.head().unwrap();
        let data = cipher
            .seal(
                &key,
                1,
                &s.b.identity,
                &s.b.id,
                &after,
                b"x",
                &mut OsEntropy,
            )
            .unwrap();
        assert_eq!(
            cipher.open(&s.state, &key, 1, &data).unwrap_err(),
            OpenError::SenderNotValid
        );
        // Another epoch's cipher.
        let other = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        let mut data = sealed(&s, &key, 1, b"x");
        data[1..5].copy_from_slice(&2u32.to_be_bytes());
        assert_eq!(
            other.open(&s.state, &key, 1, &data).unwrap_err(),
            OpenError::EpochMismatch {
                expected: 1,
                got: 2
            }
        );
    }

    #[test]
    fn a_removed_sender_is_refused_even_at_a_head_before_its_removal() {
        let mut s = setup();
        let key = ring_key();
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        // b seals at the head before its removal, as a stolen key could after it.
        let before = s.state.head().unwrap();
        let data = cipher
            .seal(
                &key,
                1,
                &s.b.identity,
                &s.b.id,
                &before,
                b"x",
                &mut OsEntropy,
            )
            .unwrap();
        assert!(cipher.open(&s.state, &key, 1, &data).is_ok());
        let entry = s
            .state
            .next_entry(&s.a.identity, s.a.id, 0, EntryKind::RemoveDevice(s.b.id))
            .unwrap();
        s.state.apply(&entry).unwrap();
        assert_eq!(
            cipher.open(&s.state, &key, 1, &data).unwrap_err(),
            OpenError::SenderNotValid
        );
    }

    #[test]
    fn recovery_devices_sign_no_records() {
        let mut s = setup();
        let r = dev(7);
        let entry = s
            .state
            .next_entry(
                &s.a.identity,
                s.a.id,
                0,
                EntryKind::AddDevice(LogDevice::of(&r.identity, &ACCOUNT, r.id, true)),
            )
            .unwrap();
        s.state.apply(&entry).unwrap();
        let key = ring_key();
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        let data = cipher
            .seal(
                &key,
                1,
                &r.identity,
                &r.id,
                &s.state.head().unwrap(),
                b"x",
                &mut OsEntropy,
            )
            .unwrap();
        assert_eq!(
            cipher.open(&s.state, &key, 1, &data).unwrap_err(),
            OpenError::SenderNotValid
        );
    }

    #[test]
    fn seal_limits() {
        let s = setup();
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        let head = s.state.head().unwrap();
        let key = ring_key();
        assert_eq!(
            cipher.seal(&key, 0, &s.a.identity, &s.a.id, &head, b"x", &mut OsEntropy),
            Err(SealError::Version)
        );
        let big = vec![0u8; MAX_RECORD_PLAINTEXT + 1];
        assert_eq!(
            cipher.seal(&key, 1, &s.a.identity, &s.a.id, &head, &big, &mut OsEntropy),
            Err(SealError::TooLarge)
        );
    }

    #[test]
    fn replay_guard_never_goes_back() {
        let s = setup();
        let key = ring_key();
        let cipher = RecordCipher::for_epoch(&s.state, &s.secret, Epoch(1)).unwrap();
        let v1 = cipher
            .open(&s.state, &key, 1, &sealed(&s, &key, 1, b"one"))
            .unwrap();
        let v2 = cipher
            .open(&s.state, &key, 2, &sealed(&s, &key, 2, b"two"))
            .unwrap();
        let v2_other = cipher
            .open(&s.state, &key, 2, &sealed(&s, &key, 2, b"two'"))
            .unwrap();
        let mut guard = RecordGuard::new();
        guard.accept(&v1).unwrap();
        guard.accept(&v2).unwrap();
        assert_eq!(guard.accept(&v2), Ok(()), "the same record again");
        assert_eq!(
            guard.accept(&v1),
            Err(GuardError::Replay {
                got: 1,
                accepted: 2
            })
        );
        assert_eq!(guard.accept(&v2_other), Err(GuardError::Equivocation));
        assert_eq!(guard.accepted(&key), Some(2));
        let resumed = RecordGuard::resume(guard.marks().clone());
        assert_eq!(
            resumed.check(&v1),
            Err(GuardError::Replay {
                got: 1,
                accepted: 2
            })
        );
        // Another record key is independent.
        let other = RecordKey::new(RecordKind::Folders, None).unwrap();
        assert_eq!(resumed.accepted(&other), None);
    }
}
