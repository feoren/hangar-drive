//! Account key epochs: a random 256-bit [`AccountSecret`] per epoch, committed to in the signed
//! device log and wrapped with HPKE to every current device, recovery devices included. Drive
//! needs no history link: folder key rings are re-sealed under every new epoch and always hold
//! all generations.
//!
//! Built after the sister project's `hangar-team-crypto` (`src/epoch.rs`, `src/rotation.rs`,
//! MIT, same owner), with Drive's labels and context.
//!
//! # Commitment
//!
//! ```text
//! commitment = SHA-256( field("hangar-drive/v1/epoch-commitment") || field(account)
//!                       || field(epoch, u32) || field(secret) )
//! ```
//!
//! HPKE base mode does not authenticate the sender: anyone, the server included, can wrap some
//! secret to a device's public key. A device therefore accepts an unwrapped secret only when it
//! matches the commitment of that epoch in the verified device log.
//!
//! # Wrapped key (version 1, 81 bytes)
//!
//! ```text
//! 0x01 || enc (32 bytes, the ephemeral X25519 public key) || HPKE ciphertext of the secret (48 bytes)
//! info = field("hangar-drive/v1/wrap") || field(account) || field(epoch, u32) || field(recipient device)
//! ```
//!
//! HPKE (RFC 9180) mode base with DHKEM(X25519, HKDF-SHA256), HKDF-SHA256 and
//! ChaCha20Poly1305, empty associated data. A wrapped key moved to another account, epoch or
//! device does not open.
//!
//! # Account seal key
//!
//! ```text
//! K_acct,e = HKDF-SHA256(salt none, ikm = S_e,
//!                        info = field("hangar-drive/v1/account-seal") || field(account)
//!                               || field(e, u32) || field(rotation log hash))
//! ```
//!
//! `rotation log hash` is the hash of the epoch's rotate entry: a server that forks the log
//! gives the two sides different hashes, hence different keys from the same secret.
//!
//! # Wrapped keys of an append call
//!
//! - A rotation ([`rotate`], [`remove_devices`]) wraps the new secret to every device that is
//!   current after it, recovery devices included.
//! - An added device ([`add_device`]) gets exactly one wrap, of the current epoch, and no
//!   rotation happens. Records are sealed under the newest epoch and folder key rings hold every
//!   generation, so the current epoch is all a new device needs.
//! - A recovery ([`recover`]) carries both: the new device's wrap of the epoch before the batch
//!   (so it can open the records it re-seals) and the rotation's wraps to every device that is
//!   current after the batch.
//!
//! The server checks both with [`append_wraps_fit`] after the device log verifier admitted the
//! batch.

use std::fmt;

use hangar_drive_protocol::ids::{AccountId, DeviceId, Epoch, FolderId, LogHash, PublicKey};
use hpke::aead::ChaCha20Poly1305;
use hpke::kdf::HkdfSha256;
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::devicelog::{AccountState, AdmittedBatch, BatchShape, EntryKind, LogDevice, LogError};
use crate::encoding::{constant_time_eq, framed, hkdf, sha256_framed, Writer};
use crate::entropy::{Entropy, EntropyError, OneShotRng};
use crate::identity::{DeviceIdentity, KemPublicKey};

const LABEL_COMMITMENT: &[u8] = b"hangar-drive/v1/epoch-commitment";
const LABEL_WRAP: &[u8] = b"hangar-drive/v1/wrap";
const LABEL_ACCOUNT_SEAL: &[u8] = b"hangar-drive/v1/account-seal";

const WRAP_VERSION: u8 = 1;
const SECRET_LEN: usize = 32;
const TAG_LEN: usize = 16;
const ENC_LEN: usize = 32;
/// Bytes of a wrapped key.
pub const WRAPPED_KEY_LEN: usize = 1 + ENC_LEN + SECRET_LEN + TAG_LEN;
const _: () = assert!(WRAPPED_KEY_LEN == hangar_drive_protocol::api::WRAPPED_KEY_LEN);

/// Why a wrapped key did not give a secret, or no account key was set up.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WrapError {
    /// Not a wrapped key of this crate (length).
    #[error("not a wrapped account key")]
    Malformed,
    /// A format version this crate does not know.
    #[error("wrapped key format version {0} is not supported")]
    Version(u8),
    /// HPKE refused: wrapped for another device, account or epoch, or changed.
    #[error("the wrapped key does not open for this device, account and epoch")]
    Open,
    /// The secret opened but is not the one the device log committed to.
    #[error("the account key does not match the device log's commitment for epoch {0}")]
    Commitment(u32),
    /// The recipient's public key was refused by HPKE.
    #[error("the recipient's key cannot receive a wrapped key")]
    RecipientKey,
    /// The device log has no such epoch.
    #[error("the device log has no epoch {0}")]
    UnknownEpoch(u32),
    /// HPKE wanted other randomness than one ephemeral key.
    #[error("unexpected use of randomness while wrapping")]
    Rng,
    /// Key derivation failed (not expected).
    #[error("key derivation failed")]
    Derive,
    /// No randomness.
    #[error(transparent)]
    Entropy(#[from] EntropyError),
}

/// One epoch's 256-bit secret. Wiped on drop, never printed, compared in constant time.
#[derive(Clone)]
pub struct AccountSecret(Zeroizing<[u8; SECRET_LEN]>);

impl PartialEq for AccountSecret {
    fn eq(&self, other: &Self) -> bool {
        constant_time_eq(self.0.as_ref(), other.0.as_ref())
    }
}

impl Eq for AccountSecret {}

impl fmt::Debug for AccountSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccountSecret(..)")
    }
}

impl AccountSecret {
    /// A new random secret.
    pub fn generate(entropy: &mut impl Entropy) -> Result<Self, EntropyError> {
        let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
        entropy.fill(secret.as_mut())?;
        Ok(Self(secret))
    }

    /// A secret from the OS keychain (what [`AccountSecret::export`] gave).
    pub fn from_bytes(bytes: Zeroizing<[u8; SECRET_LEN]>) -> Self {
        Self(bytes)
    }

    /// The raw secret for the OS keychain.
    pub fn export(&self) -> Zeroizing<[u8; SECRET_LEN]> {
        self.0.clone()
    }

    /// What the device log records for this secret as `epoch` of `account`.
    pub fn commitment(&self, account: &AccountId, epoch: Epoch) -> EpochCommitment {
        EpochCommitment(sha256_framed(&[
            LABEL_COMMITMENT,
            account.as_bytes(),
            &epoch.0.to_be_bytes(),
            self.0.as_ref(),
        ]))
    }
}

/// The hash of an epoch's secret in the device log (module docs). Public.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct EpochCommitment(pub [u8; 32]);

impl EpochCommitment {
    /// Equality in constant time: one side is computed from a secret the caller holds.
    pub fn matches(&self, other: &EpochCommitment) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for EpochCommitment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EpochCommitment(")?;
        for byte in &self.0[..4] {
            write!(f, "{byte:02x}")?;
        }
        f.write_str("..)")
    }
}

/// The account seal key of one epoch (module docs), which seals the account records. Wiped on
/// drop, never printed.
pub struct AccountKey {
    account: AccountId,
    epoch: Epoch,
    key: Zeroizing<[u8; 32]>,
}

impl fmt::Debug for AccountKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccountKey")
            .field("account", &self.account)
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl AccountKey {
    /// Derives the key of `epoch` from its secret and the hash of its rotate entry, without
    /// checking the secret against the epoch's commitment. Crate-internal (security review,
    /// info): outside this crate a key comes only from [`AccountKey::for_epoch`], which takes
    /// both from the verified log and checks the commitment.
    pub(crate) fn derive(
        secret: &AccountSecret,
        account: &AccountId,
        epoch: Epoch,
        rotation: &LogHash,
    ) -> Result<Self, WrapError> {
        let mut info = Writer::new();
        info.field(LABEL_ACCOUNT_SEAL)
            .field(account.as_bytes())
            .field_u32(epoch.0)
            .field(rotation.as_bytes());
        let key = hkdf::<32>(secret.0.as_ref(), &info.into_bytes()).ok_or(WrapError::Derive)?;
        Ok(Self {
            account: *account,
            epoch,
            key,
        })
    }

    /// The key of `epoch` as the verified log records it: the secret must match the epoch's
    /// commitment, and the derivation binds the rotate entry's hash.
    pub fn for_epoch(
        state: &AccountState,
        secret: &AccountSecret,
        epoch: Epoch,
    ) -> Result<Self, WrapError> {
        let record = state.epoch(epoch).ok_or(WrapError::UnknownEpoch(epoch.0))?;
        if !secret
            .commitment(state.account(), epoch)
            .matches(&record.commitment)
        {
            return Err(WrapError::Commitment(epoch.0));
        }
        Self::derive(secret, state.account(), epoch, &record.hash)
    }

    /// The account.
    pub fn account(&self) -> &AccountId {
        &self.account
    }

    /// The epoch.
    pub fn epoch(&self) -> Epoch {
        self.epoch
    }

    pub(crate) fn bytes(&self) -> &[u8; 32] {
        &self.key
    }
}

fn wrap_info(account: &AccountId, epoch: Epoch, recipient: &DeviceId) -> Vec<u8> {
    framed(&[
        LABEL_WRAP,
        account.as_bytes(),
        &epoch.0.to_be_bytes(),
        recipient.as_bytes(),
    ])
}

/// Wraps `secret` (epoch `epoch` of `account`) to device `recipient` with X25519 key `kem`.
/// The caller takes `kem` from the verified device log, never from the server.
pub fn wrap(
    secret: &AccountSecret,
    account: &AccountId,
    epoch: Epoch,
    recipient: &DeviceId,
    kem: &PublicKey,
    entropy: &mut impl Entropy,
) -> Result<Vec<u8>, WrapError> {
    let recipient_key =
        KemPublicKey::from_bytes(kem.as_bytes()).map_err(|_| WrapError::RecipientKey)?;
    let mut rng = OneShotRng::draw(entropy)?;
    let (enc, ciphertext) =
        hpke::single_shot_seal_with_rng::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeS::Base,
            &recipient_key,
            &wrap_info(account, epoch, recipient),
            secret.0.as_ref(),
            b"",
            &mut rng,
        )
        .map_err(|_| WrapError::RecipientKey)?;
    if !rng.consumed_exactly_once() {
        return Err(WrapError::Rng);
    }
    let mut bytes = Vec::with_capacity(WRAPPED_KEY_LEN);
    bytes.push(WRAP_VERSION);
    bytes.extend_from_slice(enc.to_bytes().as_slice());
    bytes.extend_from_slice(&ciphertext);
    if bytes.len() != WRAPPED_KEY_LEN {
        return Err(WrapError::Malformed);
    }
    Ok(bytes)
}

/// Opens a wrapped key addressed to this device (`me`) for `epoch` and accepts it only if it
/// matches `commitment`, the epoch's commitment from the verified device log.
pub fn unwrap(
    identity: &DeviceIdentity,
    account: &AccountId,
    epoch: Epoch,
    me: &DeviceId,
    data: &[u8],
    commitment: &EpochCommitment,
) -> Result<AccountSecret, WrapError> {
    let (&version, rest) = data.split_first().ok_or(WrapError::Malformed)?;
    if version != WRAP_VERSION {
        return Err(WrapError::Version(version));
    }
    if rest.len() != WRAPPED_KEY_LEN - 1 {
        return Err(WrapError::Malformed);
    }
    let (enc, ciphertext) = rest.split_at(ENC_LEN);
    let enc = <X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(enc)
        .map_err(|_| WrapError::Malformed)?;
    let plain = Zeroizing::new(
        hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, X25519HkdfSha256>(
            &OpModeR::Base,
            identity.kem_private(),
            &enc,
            &wrap_info(account, epoch, me),
            ciphertext,
            b"",
        )
        .map_err(|_| WrapError::Open)?,
    );
    let mut secret = Zeroizing::new([0u8; SECRET_LEN]);
    if plain.len() != SECRET_LEN {
        return Err(WrapError::Malformed);
    }
    secret.copy_from_slice(&plain);
    let secret = AccountSecret(secret);
    if !secret.commitment(account, epoch).matches(commitment) {
        return Err(WrapError::Commitment(epoch.0));
    }
    Ok(secret)
}

/// Why no rotation was made.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RotateError {
    /// The device log refused the rotate entry.
    #[error(transparent)]
    Log(#[from] LogError),
    /// Wrapping to a device failed.
    #[error(transparent)]
    Wrap(#[from] WrapError),
    /// No randomness.
    #[error(transparent)]
    Entropy(#[from] EntropyError),
}

/// A new epoch: the signed rotate entry, the new secret and its wraps to every current device.
/// The app sends entry and wraps in one append call and keeps the secret only once the server
/// accepted both.
#[derive(Debug)]
pub struct Rotation {
    /// The rotate entry.
    pub entry: Vec<u8>,
    /// The new epoch.
    pub epoch: Epoch,
    /// Its secret.
    pub secret: AccountSecret,
    /// One wrapped key per current device of the log, recovery devices included.
    pub wraps: Vec<(DeviceId, Vec<u8>)>,
}

/// Makes the next epoch, issued by `identity` as `issuer`.
pub fn rotate(
    state: &AccountState,
    identity: &DeviceIdentity,
    issuer: DeviceId,
    issued_at_ms: u64,
    entropy: &mut impl Entropy,
) -> Result<Rotation, RotateError> {
    let next = state
        .current_epoch()
        .map_or(Some(1), |e| e.epoch.0.checked_add(1))
        .ok_or(LogError::EpochGap)?;
    let epoch = Epoch(next);
    let secret = AccountSecret::generate(entropy)?;
    let entry = state.next_entry(
        identity,
        issuer,
        issued_at_ms,
        EntryKind::Rotate {
            epoch,
            commitment: secret.commitment(state.account(), epoch),
        },
    )?;
    let mut wraps = Vec::new();
    for device in state.current_devices() {
        wraps.push((
            device.id,
            wrap(
                &secret,
                state.account(),
                epoch,
                &device.id,
                &device.keys.kem,
                entropy,
            )?,
        ));
    }
    Ok(Rotation {
        entry,
        epoch,
        secret,
        wraps,
    })
}

/// The removal of devices with the rotation that must follow it in the same append call
/// ([`crate::devicelog::AccountState::admit_batch`]).
#[derive(Debug)]
pub struct Removal {
    /// The remove device entries, then the rotate entry, in order.
    pub entries: Vec<Vec<u8>>,
    /// The rotation; its wraps go to the devices that stay.
    pub rotation: Rotation,
    /// The verified state after the batch, to apply once the server accepted it.
    pub state: AccountState,
    /// The proof that lets the removing device verify a folder delta without the removed
    /// signer rule, to write its barrier commits
    /// ([`crate::commit::FolderView::verify_delta_before_barrier`]; security review N2).
    pub permit: BarrierPermit,
}

/// Proof that a removal and its rotation are in the verified log and that the holder may write
/// the barrier commits after it (security review N2). Only [`remove_devices`] makes one for the
/// removing device, valid in every folder, and [`BarrierPermit::takeover`] for a current device
/// that completes the step of a removing device that went away (N1). A takeover permit is bound
/// to one folder and can only be made from a [`crate::commit::RemovedSignerRefusal`], the
/// result of a delta that [`crate::commit::FolderView::check_delta`] refused by the removed
/// signer rule, so no device verifies a delta without that rule unless it first failed with it
/// (security review H1). [`crate::commit::FolderView::verify_delta_before_barrier`] refuses a
/// permit for any other state or folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarrierPermit {
    account: AccountId,
    removal_index: u64,
    holder: DeviceId,
    folder: Option<FolderId>,
}

impl BarrierPermit {
    /// The permit of a current, regular device for the folder of `refusal`, when the removing
    /// device did not finish its barriers (N1). `None` if the refusal belongs to another account
    /// or another removal than the last one of `state`, while a rotation is due, or if `device`
    /// is not a current regular device.
    pub fn takeover(
        state: &AccountState,
        device: &DeviceId,
        refusal: &crate::commit::RemovedSignerRefusal,
    ) -> Option<Self> {
        let removal_index = state.last_removal_index();
        if removal_index == 0 || state.rotation_due() {
            return None;
        }
        if refusal.account() != state.account() || refusal.removal_index() != removal_index {
            return None;
        }
        if state.current_epoch()?.index < removal_index {
            return None;
        }
        state
            .device(device)
            .filter(|d| d.is_current() && !d.recovery)?;
        Some(Self {
            account: *state.account(),
            removal_index,
            holder: *device,
            folder: Some(*refusal.folder()),
        })
    }

    /// The permit of the device that issued the last removal of the verified log `state`, for
    /// a removal job it resumes after a crash or a lost answer (N1): the log entry it signed is
    /// the proof, so no other device can get this permit, which holds in every folder. `None`
    /// while a rotation is due or if `device` did not issue the last removal or is no longer a
    /// current regular device.
    pub fn of_own_removal(state: &AccountState, device: &DeviceId) -> Option<Self> {
        let removal_index = state.last_removal_index();
        if removal_index == 0 || state.rotation_due() || state.last_removal_issuer() != Some(device)
        {
            return None;
        }
        state
            .device(device)
            .filter(|d| d.is_current() && !d.recovery)?;
        Some(Self {
            account: *state.account(),
            removal_index,
            holder: *device,
            folder: None,
        })
    }

    /// Whether this permit covers the last removal of `state` and its holder is still a
    /// current regular device there.
    pub fn covers(&self, state: &AccountState) -> bool {
        self.removal_index > 0
            && self.account == *state.account()
            && self.removal_index == state.last_removal_index()
            && state
                .device(&self.holder)
                .is_some_and(|d| d.is_current() && !d.recovery)
    }

    /// Whether this permit may be used in `folder`: the removing device's permit in every
    /// folder, a takeover permit only in the folder whose delta was refused.
    pub fn allows_folder(&self, folder: &FolderId) -> bool {
        self.folder.is_none_or(|f| f == *folder)
    }

    /// The log index of the removal.
    pub fn removal_index(&self) -> u64 {
        self.removal_index
    }

    /// Whether this is a takeover permit (bound to one folder).
    pub fn is_takeover(&self) -> bool {
        self.folder.is_some()
    }
}

/// Builds the append call that removes `targets` and rotates at once, issued by `identity` as
/// `issuer`. After the server accepted it, the issuer re-seals every account record under the
/// new epoch ([`crate::folder_keys::reseal_after_removal`]) and writes a barrier commit per
/// folder ([`crate::commit::Commit::barrier`]).
pub fn remove_devices(
    state: &AccountState,
    identity: &DeviceIdentity,
    issuer: DeviceId,
    issued_at_ms: u64,
    targets: &[DeviceId],
    entropy: &mut impl Entropy,
) -> Result<Removal, RotateError> {
    let mut after = state.clone();
    let mut entries = Vec::with_capacity(targets.len() + 1);
    for target in targets {
        let entry = after.next_entry(
            identity,
            issuer,
            issued_at_ms,
            EntryKind::RemoveDevice(*target),
        )?;
        after.apply(&entry)?;
        entries.push(entry);
    }
    let rotation = rotate(&after, identity, issuer, issued_at_ms, entropy)?;
    after.apply(&rotation.entry)?;
    entries.push(rotation.entry.clone());
    let permit = BarrierPermit {
        account: *after.account(),
        removal_index: after.last_removal_index(),
        holder: issuer,
        folder: None,
    };
    Ok(Removal {
        entries,
        rotation,
        state: after,
        permit,
    })
}

/// An add device entry with the new device's wrapped key of the current epoch.
#[derive(Debug)]
pub struct Addition {
    /// The add device entry.
    pub entry: Vec<u8>,
    /// The wrapped secret of the current epoch for the new device; `None` while the account
    /// has no epoch.
    pub wrap: Option<Vec<u8>>,
}

/// Builds the append call that adds `device`, issued by `identity` as `issuer`. `current` is
/// the secret of the log's current epoch, which the issuer holds; adding does not rotate.
pub fn add_device(
    state: &AccountState,
    identity: &DeviceIdentity,
    issuer: DeviceId,
    issued_at_ms: u64,
    device: LogDevice,
    current: Option<&AccountSecret>,
    entropy: &mut impl Entropy,
) -> Result<Addition, RotateError> {
    let entry = state.next_entry(identity, issuer, issued_at_ms, EntryKind::AddDevice(device))?;
    let wrap = match (state.current_epoch(), current) {
        (None, _) => None,
        (Some(record), Some(secret)) => {
            if !secret
                .commitment(state.account(), record.epoch)
                .matches(&record.commitment)
            {
                return Err(WrapError::Commitment(record.epoch.0).into());
            }
            Some(wrap(
                secret,
                state.account(),
                record.epoch,
                &device.id,
                &device.keys.kem,
                entropy,
            )?)
        }
        (Some(record), None) => return Err(WrapError::UnknownEpoch(record.epoch.0).into()),
    };
    Ok(Addition { entry, wrap })
}

/// Server side: whether `data` can be the wrapped key of the current epoch for the device that
/// an add device batch just added. `state` is the state after the batch. The server cannot open
/// it; it checks the recipient, that the device is current, and the length.
pub fn wrap_covers_added_device(state: &AccountState, device: &DeviceId, data: &[u8]) -> bool {
    state.current_epoch().is_some()
        && data.len() == WRAPPED_KEY_LEN
        && state.device(device).is_some_and(|d| d.is_current())
}

/// Server side: whether the wrapped keys of an append call fit the admitted batch
/// ([`crate::devicelog::AccountState::admit_batch`]): a rotation carries one wrap per current
/// device and no device wrap; an added device carries exactly its own wrap of the current
/// epoch (none while the account has no epoch) and no rotation wraps.
pub fn append_wraps_fit<'a>(
    batch: &AdmittedBatch,
    wraps: impl IntoIterator<Item = (&'a DeviceId, &'a [u8])>,
    device_wrap: Option<(&DeviceId, &[u8])>,
) -> bool {
    let mut wraps = wraps.into_iter().peekable();
    match &batch.shape {
        BatchShape::Rotation { .. } => {
            device_wrap.is_none() && wraps_cover_current_devices(&batch.state, wraps)
        }
        BatchShape::AddDevice { device } => {
            if wraps.peek().is_some() {
                return false;
            }
            match (batch.state.current_epoch(), device_wrap) {
                (None, None) => true,
                (Some(_), Some((recipient, data))) => {
                    recipient == device && wrap_covers_added_device(&batch.state, device, data)
                }
                _ => false,
            }
        }
        BatchShape::Recovery { device, epoch, .. } => {
            if !wraps_cover_current_devices(&batch.state, wraps) {
                return false;
            }
            // The new device's wrap of the epoch before the batch, if the account had one.
            let before = epoch.0.checked_sub(1).filter(|e| *e > 0);
            match (before, device_wrap) {
                (None, None) => true,
                (Some(_), Some((recipient, data))) => {
                    recipient == device && wrap_covers_added_device(&batch.state, device, data)
                }
                _ => false,
            }
        }
    }
}

/// The recovery in one append call (module docs; [`crate::devicelog::BatchShape::Recovery`]):
/// the recovery device adds the person's new device, which removes `targets` and rotates. The
/// new device's keys are made on the new installation before; its entries are signed with them.
#[derive(Debug)]
pub struct Recovery {
    /// The add device entry (signed by the recovery device), the remove device entries and the
    /// rotate entry (signed by the new device), in order.
    pub entries: Vec<Vec<u8>>,
    /// The new device's wrap of the epoch before the batch, which the recovery device holds;
    /// `None` while the account has no epoch.
    pub device_wrap: Option<Vec<u8>>,
    /// The rotation; its wraps go to every device current after the batch.
    pub rotation: Rotation,
    /// The verified state after the batch, to apply once the server accepted it.
    pub state: AccountState,
    /// The new device's permit for the barrier commits after the removal.
    pub permit: BarrierPermit,
}

/// Builds the recovery batch. `recovery` signs as the current recovery device `recovery_id`,
/// `device` is the new device with the keys of `identity`, `current` the secret of the log's
/// current epoch (which the recovery device unwrapped). `targets` must not be empty unless a
/// rotation is due: the new device always rotates, and a rotation needs a removal before it.
#[allow(clippy::too_many_arguments)]
pub fn recover(
    state: &AccountState,
    recovery: &DeviceIdentity,
    recovery_id: DeviceId,
    identity: &DeviceIdentity,
    device: LogDevice,
    targets: &[DeviceId],
    current: Option<&AccountSecret>,
    issued_at_ms: u64,
    entropy: &mut impl Entropy,
) -> Result<Recovery, RotateError> {
    if device.keys != identity.public_keys() || device.recovery {
        return Err(LogError::InvalidKey.into());
    }
    let addition = add_device(
        state,
        recovery,
        recovery_id,
        issued_at_ms,
        device,
        current,
        entropy,
    )?;
    let mut after = state.clone();
    after.apply(&addition.entry)?;
    let mut entries = Vec::with_capacity(targets.len() + 2);
    entries.push(addition.entry);
    for target in targets {
        let entry = after.next_entry(
            identity,
            device.id,
            issued_at_ms,
            EntryKind::RemoveDevice(*target),
        )?;
        after.apply(&entry)?;
        entries.push(entry);
    }
    let rotation = rotate(&after, identity, device.id, issued_at_ms, entropy)?;
    after.apply(&rotation.entry)?;
    entries.push(rotation.entry.clone());
    let permit = BarrierPermit {
        account: *after.account(),
        removal_index: after.last_removal_index(),
        holder: device.id,
        folder: None,
    };
    Ok(Recovery {
        entries,
        device_wrap: addition.wrap,
        rotation,
        state: after,
        permit,
    })
}

/// Server side: whether a rotation's wraps go to exactly the current devices of the log, one
/// each, with the right length. The server cannot open them; it checks only the recipients.
pub fn wraps_cover_current_devices<'a>(
    state: &AccountState,
    wraps: impl IntoIterator<Item = (&'a DeviceId, &'a [u8])>,
) -> bool {
    let mut recipients = std::collections::BTreeSet::new();
    for (device, data) in wraps {
        if data.len() != WRAPPED_KEY_LEN || !recipients.insert(*device) {
            return false;
        }
    }
    let current: std::collections::BTreeSet<DeviceId> =
        state.current_devices().map(|d| d.id).collect();
    recipients == current
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devicelog::tests::{created, dev, ACCOUNT};
    use crate::devicelog::LogDevice;
    use crate::entropy::{FixedEntropy, OsEntropy};

    #[test]
    fn wrap_unwrap_and_commitment() {
        let a = dev(1);
        let secret = AccountSecret::generate(&mut OsEntropy).unwrap();
        let commitment = secret.commitment(&ACCOUNT, Epoch(1));
        let kem = a.identity.public_keys().kem;
        let data = wrap(&secret, &ACCOUNT, Epoch(1), &a.id, &kem, &mut OsEntropy).unwrap();
        assert_eq!(data.len(), WRAPPED_KEY_LEN);
        let back = unwrap(&a.identity, &ACCOUNT, Epoch(1), &a.id, &data, &commitment).unwrap();
        assert_eq!(back, secret);

        // Another epoch, device or account in the context: does not open.
        assert_eq!(
            unwrap(&a.identity, &ACCOUNT, Epoch(2), &a.id, &data, &commitment),
            Err(WrapError::Open)
        );
        assert_eq!(
            unwrap(
                &a.identity,
                &ACCOUNT,
                Epoch(1),
                &DeviceId::from_bytes([9; 16]),
                &data,
                &commitment
            ),
            Err(WrapError::Open)
        );
        assert_eq!(
            unwrap(
                &a.identity,
                &AccountId::from_bytes([1; 16]),
                Epoch(1),
                &a.id,
                &data,
                &commitment
            ),
            Err(WrapError::Open)
        );
        // Another device's key.
        let b = dev(2);
        assert_eq!(
            unwrap(&b.identity, &ACCOUNT, Epoch(1), &a.id, &data, &commitment),
            Err(WrapError::Open)
        );
        // A server wraps some other secret: opens, but the commitment refuses it.
        let other = AccountSecret::generate(&mut OsEntropy).unwrap();
        let fake = wrap(&other, &ACCOUNT, Epoch(1), &a.id, &kem, &mut OsEntropy).unwrap();
        assert_eq!(
            unwrap(&a.identity, &ACCOUNT, Epoch(1), &a.id, &fake, &commitment),
            Err(WrapError::Commitment(1))
        );
        // Format.
        let mut bad = data.clone();
        bad[0] = 2;
        assert_eq!(
            unwrap(&a.identity, &ACCOUNT, Epoch(1), &a.id, &bad, &commitment),
            Err(WrapError::Version(2))
        );
        assert_eq!(
            unwrap(
                &a.identity,
                &ACCOUNT,
                Epoch(1),
                &a.id,
                &data[..80],
                &commitment
            ),
            Err(WrapError::Malformed)
        );
        let mut flipped = data;
        flipped[60] ^= 1;
        assert_eq!(
            unwrap(
                &a.identity,
                &ACCOUNT,
                Epoch(1),
                &a.id,
                &flipped,
                &commitment
            ),
            Err(WrapError::Open)
        );
    }

    #[test]
    fn wrap_needs_one_block_of_randomness() {
        let a = dev(1);
        let secret = AccountSecret::generate(&mut OsEntropy).unwrap();
        let kem = a.identity.public_keys().kem;
        assert!(matches!(
            wrap(
                &secret,
                &ACCOUNT,
                Epoch(1),
                &a.id,
                &kem,
                &mut FixedEntropy::counting(0, 31)
            ),
            Err(WrapError::Entropy(_))
        ));
        assert_eq!(
            wrap(
                &secret,
                &ACCOUNT,
                Epoch(1),
                &a.id,
                &PublicKey::from_bytes([0; 32]),
                &mut OsEntropy
            ),
            Err(WrapError::RecipientKey)
        );
    }

    #[test]
    fn rotation_wraps_to_every_current_device_and_keys_bind_the_log() {
        let a = dev(1);
        let r = dev(2);
        let mut state = created(&a);
        let entry = state
            .next_entry(
                &a.identity,
                a.id,
                0,
                EntryKind::AddDevice(LogDevice::of(&r.identity, &ACCOUNT, r.id, true)),
            )
            .unwrap();
        state.apply(&entry).unwrap();
        let rotation = rotate(&state, &a.identity, a.id, 0, &mut OsEntropy).unwrap();
        assert_eq!(rotation.epoch, Epoch(1));
        assert_eq!(rotation.wraps.len(), 2);
        assert!(wraps_cover_current_devices(
            &state,
            rotation.wraps.iter().map(|(d, w)| (d, w.as_slice()))
        ));
        assert!(!wraps_cover_current_devices(
            &state,
            rotation
                .wraps
                .iter()
                .take(1)
                .map(|(d, w)| (d, w.as_slice()))
        ));
        state.apply(&rotation.entry).unwrap();
        let record = *state.current_epoch().unwrap();
        for (device, data) in &rotation.wraps {
            let identity = if *device == a.id {
                &a.identity
            } else {
                &r.identity
            };
            let secret = unwrap(
                identity,
                &ACCOUNT,
                Epoch(1),
                device,
                data,
                &record.commitment,
            )
            .unwrap();
            assert_eq!(secret, rotation.secret);
        }
        let key = AccountKey::for_epoch(&state, &rotation.secret, Epoch(1)).unwrap();
        assert_eq!(key.epoch(), Epoch(1));
        assert!(!format!("{key:?}").contains(&format!("{:?}", key.bytes())));
        let other = AccountSecret::generate(&mut OsEntropy).unwrap();
        assert_eq!(
            AccountKey::for_epoch(&state, &other, Epoch(1)).unwrap_err(),
            WrapError::Commitment(1)
        );
        assert_eq!(
            AccountKey::for_epoch(&state, &rotation.secret, Epoch(2)).unwrap_err(),
            WrapError::UnknownEpoch(2)
        );
        // A forked log (other rotation hash) gives another key from the same secret.
        let forked = AccountKey::derive(
            &rotation.secret,
            &ACCOUNT,
            Epoch(1),
            &LogHash::from_bytes([1; 32]),
        )
        .unwrap();
        assert_ne!(forked.bytes(), key.bytes());
        assert_eq!(format!("{:?}", rotation.secret), "AccountSecret(..)");
    }

    fn pairs(wraps: &[(DeviceId, Vec<u8>)]) -> Vec<(&DeviceId, &[u8])> {
        wraps.iter().map(|(d, w)| (d, w.as_slice())).collect()
    }

    #[test]
    fn removal_and_rotation_go_in_one_call_with_wraps_for_the_devices_that_stay() {
        let a = dev(1);
        let b = dev(2);
        let c = dev(3);
        let mut state = created(&a);
        for new in [&b, &c] {
            let addition = add_device(
                &state,
                &a.identity,
                a.id,
                0,
                LogDevice::of(&new.identity, &ACCOUNT, new.id, false),
                None,
                &mut OsEntropy,
            )
            .unwrap();
            assert!(addition.wrap.is_none(), "no epoch yet");
            let admitted = state
                .admit_batch([addition.entry.as_slice()], &a.id)
                .unwrap();
            assert!(append_wraps_fit(&admitted, [], None));
            state = admitted.state;
        }
        let removal =
            remove_devices(&state, &a.identity, a.id, 0, &[b.id], &mut OsEntropy).unwrap();
        assert_eq!(removal.entries.len(), 2);
        let admitted = state
            .admit_batch(removal.entries.iter().map(Vec::as_slice), &a.id)
            .unwrap();
        assert_eq!(admitted.state.head(), removal.state.head());
        let wraps = &removal.rotation.wraps;
        assert_eq!(wraps.len(), 2, "a and c, not b");
        assert!(wraps.iter().all(|(d, _)| *d != b.id));
        assert!(append_wraps_fit(&admitted, pairs(wraps), None));
        assert!(!append_wraps_fit(&admitted, pairs(&wraps[..1]), None));
        let device_wrap = (&wraps[0].0, wraps[0].1.as_slice());
        assert!(!append_wraps_fit(
            &admitted,
            pairs(wraps),
            Some(device_wrap)
        ));
        // A wrap to the removed device is refused.
        let mut to_b = wraps.clone();
        to_b[0].0 = b.id;
        assert!(!append_wraps_fit(&admitted, pairs(&to_b), None));
        // Every device that stays opens the new secret.
        let record = *removal.state.current_epoch().unwrap();
        let (device, data) = wraps.iter().find(|(d, _)| *d == c.id).unwrap();
        let secret = unwrap(
            &c.identity,
            &ACCOUNT,
            record.epoch,
            device,
            data,
            &record.commitment,
        )
        .unwrap();
        assert_eq!(secret, removal.rotation.secret);
    }

    #[test]
    fn an_added_device_gets_exactly_one_wrap_of_the_current_epoch() {
        let a = dev(1);
        let b = dev(2);
        let mut state = created(&a);
        let rotation = rotate(&state, &a.identity, a.id, 0, &mut OsEntropy).unwrap();
        state.apply(&rotation.entry).unwrap();
        let device = LogDevice::of(&b.identity, &ACCOUNT, b.id, false);
        // The issuer must hold the current secret, and the right one.
        assert!(matches!(
            add_device(&state, &a.identity, a.id, 0, device, None, &mut OsEntropy),
            Err(RotateError::Wrap(WrapError::UnknownEpoch(1)))
        ));
        let other = AccountSecret::generate(&mut OsEntropy).unwrap();
        assert!(matches!(
            add_device(
                &state,
                &a.identity,
                a.id,
                0,
                device,
                Some(&other),
                &mut OsEntropy
            ),
            Err(RotateError::Wrap(WrapError::Commitment(1)))
        ));
        let addition = add_device(
            &state,
            &a.identity,
            a.id,
            0,
            device,
            Some(&rotation.secret),
            &mut OsEntropy,
        )
        .unwrap();
        let wrap_b = addition.wrap.clone().unwrap();
        let admitted = state
            .admit_batch([addition.entry.as_slice()], &a.id)
            .unwrap();
        assert!(append_wraps_fit(
            &admitted,
            [],
            Some((&b.id, wrap_b.as_slice()))
        ));
        assert!(
            !append_wraps_fit(&admitted, [], None),
            "the wrap is required"
        );
        assert!(!append_wraps_fit(
            &admitted,
            [],
            Some((&a.id, wrap_b.as_slice()))
        ));
        assert!(!append_wraps_fit(
            &admitted,
            [],
            Some((&b.id, &wrap_b[..80]))
        ));
        assert!(!append_wraps_fit(
            &admitted,
            [(&b.id, wrap_b.as_slice())],
            Some((&b.id, wrap_b.as_slice()))
        ));
        assert!(wrap_covers_added_device(&admitted.state, &b.id, &wrap_b));
        assert!(
            !wrap_covers_added_device(&state, &b.id, &wrap_b),
            "not listed yet"
        );
        // The new device opens it against the log's commitment, without a rotation.
        let record = *admitted.state.current_epoch().unwrap();
        assert_eq!(record.epoch, Epoch(1));
        let secret = unwrap(
            &b.identity,
            &ACCOUNT,
            Epoch(1),
            &b.id,
            &wrap_b,
            &record.commitment,
        )
        .unwrap();
        assert_eq!(secret, rotation.secret);
    }
}
