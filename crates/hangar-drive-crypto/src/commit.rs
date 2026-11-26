//! Signed commits and the verification of a folder's first-parent chain (ADR 0001, sections 3
//! and 4).
//!
//! # Format (version 1)
//!
//! ```text
//! body = field("hangar-drive/v1/commit") || field(0x01) || field(account) || field(folder)
//!        || field(height, u64) || field(parents: count (u8) || count x commit id)
//!        || field(root directory node id) || field(generation, u32) || field(device)
//!        || field(log head index, u64) || field(log head hash) || field(counter, u64)
//!        || field(flags, u32; bit 0: re-anchor, bit 1: side commit)
//!        || field(seen: count (u8) || count x (device (16) || commit id (32)))
//! commit id = SHA-256( field("hangar-drive/v1/commit-id") || body )
//! wire      = body || Ed25519 signature of the device over field("hangar-drive/v1/commit-sig") || body
//! ```
//!
//! The format allows up to 8 parents and a seen vector; version 1 writes and accepts at most two
//! parents and only an empty seen vector, and refuses anything else when decoding. Of `flags`
//! it knows two bits and refuses the others:
//!
//! - bit 0, the re-anchor mark: only on a commit with exactly one parent that is not a side
//!   commit. No sync rule reads the mark; the timeline shows it.
//! - bit 1, the side commit mark: set on every side commit and on nothing else, inside the
//!   signed body, so a server can neither present a side commit as a head nor a head as a side
//!   commit. A side commit has exactly one parent and no re-anchor bit.
//!
//! The first commit of a folder has no parent and height 1; every other commit's height is one
//! more than the highest height of its parents.
//!
//! # Verification of a commit
//!
//! [`SignedCommit::verify_signer`]: this account and folder, a log head this device verified
//! ([`CommitError::AheadOfLog`] otherwise: fetch and verify the log first), the same hash there
//! ([`CommitError::Fork`]), a signer the log vouches for at that head and that is not a recovery
//! device, and the signature.
//!
//! # The verified chain and the frontier
//!
//! A device keeps per folder a [`FolderView`]: the list of every head on the first-parent
//! chain it verified ([`ChainEntry`]: commit ID, height, folder sequence, generation and log
//! head index), whose last entry is its frontier, and per device the highest counter it
//! accepted in this folder (its marks). [`FolderView::verify_delta`] accepts the commits of a
//! delta pull only if the first-parent chain from every new head reaches the frontier through
//! commits it verifies, with:
//!
//! - each head's first parent the previous head (the frontier for the first one); otherwise, and
//!   whenever a body on the chain is missing or a sequence is not above the frontier's, it
//!   refuses with [`ChainError::OlderState`] ("the server shows an older state"). Fail closed:
//!   it never accepts a head it cannot connect, and an error changes nothing;
//! - folder sequences increasing, heights as above;
//! - **nothing goes back** along the chain: generation and log head index at least the first
//!   parent's;
//! - every counter above that device's mark;
//! - a generation the device's ring holds;
//! - **side commits:** a head with two parents is a merge commit, its second parent the side
//!   commit uploaded in the same call (same sequence), signed by the same device, with the side
//!   bit, a counter above the mark and below the merge commit's, one parent that is an earlier
//!   head on the verified chain, a height one above that head's, and generation and log head
//!   index at least that head's. A side commit is never a head (a head with the side bit is
//!   refused) and is not part of the chain;
//! - **removed signers** (ADR 0001, section 4, "Removing a device"): a head signed by a device
//!   the verified log has removed since is accepted only if a later head of the same delta,
//!   signed by a current device, names a log head at or after that removal. After every
//!   removal and its rotation the removing device writes such a **barrier commit** per folder
//!   ([`Commit::barrier`]): the same tree on the current head, with the new log head and the new
//!   generation. A removed device whose key leaked can sign a commit that names a log head from
//!   before its removal; without a barrier after it, no device takes that commit in, and after
//!   the barrier "nothing goes back" refuses it. The device verifies the whole delta up to the
//!   server's sequence (every page) in one call, so a barrier on a later page counts. The
//!   removing device itself builds the barrier with [`FolderView::verify_delta_before_barrier`],
//!   which skips only this rule.
//!
//! Marks are kept per folder: a device's counter rises across all its commits, but delta pulls of
//! different folders arrive in any order.
//!
//! # Server checks
//!
//! The server verifies each commit of a call with [`SignedCommit::verify_for_server`]: the same
//! as [`SignedCommit::verify_signer`] plus that the signer is a current device of the log when
//! the call arrives, whatever log head the commit names.
//!
//! # Re-anchor
//!
//! After "the server shows an older state" and only after the person confirmed,
//! [`FolderView::reanchor_base`] verifies the server's head H and its first-parent chain down to
//! the newest commit that is in the verified chain (the base A; `None` for the empty tree). The
//! commits of that part may carry counters below this device's marks, because they are older
//! than its frontier; within the part counters still rise per device, and marks are never
//! lowered. [`FolderView::apply_reanchor`] then accepts the device's own merge commit on H as the
//! new frontier, with its lower height and sequence. The heads of the old chain after the base
//! are remembered as discarded ([`FolderView::discarded`]); no later delta or re-anchor may
//! bring one of them back as a head.

use std::collections::{BTreeMap, BTreeSet};

use hangar_drive_protocol::api::{CommitRole, DeltaCommit};
use hangar_drive_protocol::ids::{
    AccountId, CommitId, DeviceId, FolderId, Generation, LogHash, LogHead, ObjectId, Signature,
};
use thiserror::Error;

use crate::devicelog::AccountState;
use crate::encoding::{sha256, Reader, Writer};
use crate::identity::{verify, DeviceIdentity};

const LABEL_COMMIT: &[u8] = b"hangar-drive/v1/commit";
const LABEL_COMMIT_ID: &[u8] = b"hangar-drive/v1/commit-id";
const LABEL_COMMIT_SIG: &[u8] = b"hangar-drive/v1/commit-sig";
const COMMIT_VERSION: u8 = 1;
/// Parents the format can hold.
pub const FORMAT_MAX_PARENTS: usize = 8;
/// Parents version 1 writes and accepts.
pub const MAX_PARENTS: usize = 2;
/// Seen vector entries the format can hold.
pub const FORMAT_MAX_SEEN: usize = 64;
const SIGNATURE_LEN: usize = 64;
/// `flags` bit 0 of a commit: a re-anchor.
const FLAG_REANCHOR: u32 = 1;
/// `flags` bit 1 of a commit: a side commit.
const FLAG_SIDE: u32 = 1 << 1;
const FLAGS_KNOWN: u32 = FLAG_REANCHOR | FLAG_SIDE;

/// Why a commit was refused on its own.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum CommitError {
    /// Not a commit of this format.
    #[error("the commit is malformed")]
    Malformed,
    /// A commit format version this crate does not know.
    #[error("commit format version {0} is not supported")]
    Version(u8),
    /// More than two parents.
    #[error("version 1 accepts at most two parents")]
    TooManyParents,
    /// A non-empty seen vector.
    #[error("version 1 accepts only an empty seen vector")]
    SeenNotEmpty,
    /// Unknown `flags` bits.
    #[error("unknown commit flag bits {0:#x}")]
    Flags(u32),
    /// The re-anchor bit on a first, merge or side commit.
    #[error("only a commit with one parent may be a re-anchor")]
    ReanchorFlag,
    /// The side bit on a commit without exactly one parent.
    #[error("only a commit with one parent may be a side commit")]
    SideFlag,
    /// Server side: the signer is no longer a current device.
    #[error("the signer is no longer a device of the account")]
    SignerRemoved,
    /// Height 1 with parents, or a higher height without.
    #[error("the commit's height does not fit its parents")]
    Height,
    /// Another account.
    #[error("the commit belongs to another account")]
    AccountMismatch,
    /// Another folder.
    #[error("the commit belongs to another folder")]
    FolderMismatch,
    /// The commit names a log head this device has not verified: fetch the log first.
    #[error("the commit names log entry {index}, which this device has not verified yet")]
    AheadOfLog {
        /// The named head index.
        index: u64,
    },
    /// The named log head's hash differs from this device's log.
    #[error("the commit's log head differs from this device's log at entry {index}")]
    Fork {
        /// The index.
        index: u64,
    },
    /// The signer was not a valid, non-recovery device at the named log head.
    #[error("the signer was not a valid device at the commit's log head")]
    SignerNotValid,
    /// The signature does not verify.
    #[error("the commit's signature does not verify")]
    Signature,
}

/// A commit's content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// The account.
    pub account: AccountId,
    /// The folder.
    pub folder: FolderId,
    /// 1 for the first commit, else one above the highest parent.
    pub height: u64,
    /// No parent (first commit), the base (normal or side commit), or the current head and the
    /// device's side commit (merge commit).
    pub parents: Vec<CommitId>,
    /// The root directory node.
    pub root: ObjectId,
    /// The folder key generation of new objects.
    pub generation: Generation,
    /// The writing device.
    pub device: DeviceId,
    /// The device's verified log head.
    pub log_head: LogHead,
    /// The device's counter, rising over all its commits.
    pub counter: u64,
    /// `flags` bit 0: the commit of a re-anchor (only on a commit with exactly one parent).
    pub reanchor: bool,
    /// `flags` bit 1: a side commit (exactly one parent, never a head).
    pub side: bool,
}

/// What every commit a device writes names besides its parents and height.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitContent {
    /// The root directory node.
    pub root: ObjectId,
    /// The folder key generation ([`crate::folder_keys::writable_generation`]).
    pub generation: Generation,
    /// The writing device.
    pub device: DeviceId,
    /// Its newest verified log head.
    pub log_head: LogHead,
    /// The next number of its [`CommitCounter`].
    pub counter: u64,
}

impl Commit {
    fn with(
        account: AccountId,
        folder: FolderId,
        height: u64,
        parents: Vec<CommitId>,
        content: CommitContent,
    ) -> Self {
        Self {
            account,
            folder,
            height,
            parents,
            root: content.root,
            generation: content.generation,
            device: content.device,
            log_head: content.log_head,
            counter: content.counter,
            reanchor: false,
            side: false,
        }
    }

    /// The first commit of a folder.
    pub fn first(account: AccountId, folder: FolderId, content: CommitContent) -> Self {
        Self::with(account, folder, 1, Vec::new(), content)
    }

    /// The device's side commit on `base`, the head it last verified: its local state, uploaded
    /// only with the merge commit that names it ([`Commit::merge`]). Carries the side bit.
    pub fn side(
        account: AccountId,
        folder: FolderId,
        base: &ChainEntry,
        content: CommitContent,
    ) -> Self {
        Self {
            side: true,
            ..Self::on(account, folder, base, content)
        }
    }

    /// The barrier commit after a removal (module docs): a normal commit on the verified head
    /// `head` at `sequence` with the same tree, written by the removing device once the removal
    /// and its rotation are accepted, naming the new log head and the new generation
    /// ([`crate::folder_keys::reseal_after_removal`] made it).
    pub fn barrier(
        head: &SignedCommit,
        sequence: u64,
        generation: Generation,
        device: DeviceId,
        log_head: LogHead,
        counter: u64,
    ) -> Self {
        let c = &head.commit;
        Self::on(
            c.account,
            c.folder,
            &ChainEntry::of(head, sequence),
            CommitContent {
                root: c.root,
                generation,
                device,
                log_head,
                counter,
            },
        )
    }

    /// A normal commit on `base`, the head the device last verified.
    pub fn on(
        account: AccountId,
        folder: FolderId,
        base: &ChainEntry,
        content: CommitContent,
    ) -> Self {
        Self::with(
            account,
            folder,
            base.height.saturating_add(1),
            vec![base.commit],
            content,
        )
    }

    /// The re-anchor commit on the server's head H (module docs): a normal commit with the
    /// single parent H and `flags` bit 0 set.
    pub fn reanchor(
        account: AccountId,
        folder: FolderId,
        head: &ChainEntry,
        content: CommitContent,
    ) -> Self {
        Self {
            reanchor: true,
            ..Self::on(account, folder, head, content)
        }
    }

    /// A merge commit: first parent the current server head, second the device's side commit.
    pub fn merge(
        account: AccountId,
        folder: FolderId,
        head: &ChainEntry,
        side: &SignedCommit,
        content: CommitContent,
    ) -> Self {
        Self::with(
            account,
            folder,
            head.height.max(side.commit.height).saturating_add(1),
            vec![head.commit, side.id],
            content,
        )
    }

    fn check_shape(&self) -> Result<(), CommitError> {
        if self.parents.len() > MAX_PARENTS {
            return Err(CommitError::TooManyParents);
        }
        if self.parents.len() == 2 && self.parents[0] == self.parents[1] {
            return Err(CommitError::Malformed);
        }
        if self.parents.is_empty() != (self.height == 1) || self.height == 0 {
            return Err(CommitError::Height);
        }
        if self.reanchor && (self.parents.len() != 1 || self.side) {
            return Err(CommitError::ReanchorFlag);
        }
        if self.side && self.parents.len() != 1 {
            return Err(CommitError::SideFlag);
        }
        if self.generation.0 == 0 || self.counter == 0 || self.log_head.index == 0 {
            return Err(CommitError::Malformed);
        }
        Ok(())
    }

    fn flags(&self) -> u32 {
        let mut flags = 0;
        if self.reanchor {
            flags |= FLAG_REANCHOR;
        }
        if self.side {
            flags |= FLAG_SIDE;
        }
        flags
    }

    fn body(&self) -> Vec<u8> {
        let mut parents = Writer::new();
        parents.u8(u8::try_from(self.parents.len()).unwrap_or(u8::MAX));
        for parent in &self.parents {
            parents.raw(parent.as_bytes());
        }
        let mut w = Writer::new();
        w.field(LABEL_COMMIT)
            .field_u8(COMMIT_VERSION)
            .field(self.account.as_bytes())
            .field(self.folder.as_bytes())
            .field_u64(self.height)
            .field(&parents.into_bytes())
            .field(self.root.as_bytes())
            .field_u32(self.generation.0)
            .field(self.device.as_bytes())
            .field_u64(self.log_head.index)
            .field(self.log_head.hash.as_bytes())
            .field_u64(self.counter)
            .field_u32(self.flags())
            .field(&[0]);
        w.into_bytes()
    }

    /// Signs the commit with the writing device's keys.
    pub fn sign(self, identity: &DeviceIdentity) -> Result<SignedCommit, CommitError> {
        self.check_shape()?;
        let body = self.body();
        let signature = Signature::from_bytes(identity.sign(&signed_message(&body)));
        let id = commit_id(&body);
        let mut wire = body;
        wire.extend_from_slice(signature.as_bytes());
        Ok(SignedCommit {
            commit: self,
            id,
            signature,
            wire,
        })
    }
}

fn commit_id(body: &[u8]) -> CommitId {
    let mut w = Writer::with_capacity(body.len() + 40);
    w.field(LABEL_COMMIT_ID).raw(body);
    CommitId::from_bytes(sha256(&w.into_bytes()))
}

fn signed_message(body: &[u8]) -> Vec<u8> {
    let mut w = Writer::with_capacity(body.len() + 40);
    w.field(LABEL_COMMIT_SIG).raw(body);
    w.into_bytes()
}

/// A signed commit with its ID and wire bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedCommit {
    /// The content.
    pub commit: Commit,
    /// SHA-256 of the body.
    pub id: CommitId,
    /// The device's signature.
    pub signature: Signature,
    /// Body and signature, as uploaded.
    pub wire: Vec<u8>,
}

impl SignedCommit {
    /// Reads a commit strictly (module docs). Checks no signature.
    pub fn decode(wire: &[u8]) -> Result<Self, CommitError> {
        let body_len = wire
            .len()
            .checked_sub(SIGNATURE_LEN)
            .ok_or(CommitError::Malformed)?;
        let (body, signature) = wire.split_at(body_len);
        let signature = Signature::from_slice(signature).ok_or(CommitError::Malformed)?;
        let mut r = Reader::new(body);
        if r.field() != Some(LABEL_COMMIT) {
            return Err(CommitError::Malformed);
        }
        let version = r.field_u8().ok_or(CommitError::Malformed)?;
        if version != COMMIT_VERSION {
            return Err(CommitError::Version(version));
        }
        let commit = read_commit(&mut r)?;
        r.finish().ok_or(CommitError::Malformed)?;
        commit.check_shape()?;
        if commit.body() != body {
            return Err(CommitError::Malformed);
        }
        Ok(Self {
            id: commit_id(body),
            commit,
            signature,
            wire: wire.to_vec(),
        })
    }

    fn body(&self) -> &[u8] {
        &self.wire[..self.wire.len() - SIGNATURE_LEN]
    }

    /// Checks account, folder, log head and signature against the verified log (module docs).
    pub fn verify_signer(
        &self,
        state: &AccountState,
        folder: &FolderId,
    ) -> Result<(), CommitError> {
        let c = &self.commit;
        if c.account != *state.account() {
            return Err(CommitError::AccountMismatch);
        }
        if c.folder != *folder {
            return Err(CommitError::FolderMismatch);
        }
        if c.log_head.index > state.len() {
            return Err(CommitError::AheadOfLog {
                index: c.log_head.index,
            });
        }
        if !state.contains(&c.log_head) {
            return Err(CommitError::Fork {
                index: c.log_head.index,
            });
        }
        let signer = state
            .signer_at(&c.device, c.log_head.index)
            .ok_or(CommitError::SignerNotValid)?;
        if !verify(
            &signer.keys.sign,
            &signed_message(self.body()),
            self.signature.as_bytes(),
        ) {
            return Err(CommitError::Signature);
        }
        Ok(())
    }

    /// Server side, for every commit of a commit call: [`SignedCommit::verify_signer`] against
    /// the server's verified log plus that the signer is a current device of it now (module
    /// docs). A removed device's commit is refused whatever log head it names.
    pub fn verify_for_server(
        &self,
        state: &AccountState,
        folder: &FolderId,
    ) -> Result<(), CommitError> {
        self.verify_signer(state, folder)?;
        if !state
            .device(&self.commit.device)
            .is_some_and(|d| d.is_current())
        {
            return Err(CommitError::SignerRemoved);
        }
        Ok(())
    }
}

fn read_commit(r: &mut Reader<'_>) -> Result<Commit, CommitError> {
    let m = || CommitError::Malformed;
    let account = AccountId::from_bytes(r.field_fixed().ok_or_else(m)?);
    let folder = FolderId::from_bytes(r.field_fixed().ok_or_else(m)?);
    let height = r.field_u64().ok_or_else(m)?;
    let parents = {
        let mut p = Reader::new(r.field().ok_or_else(m)?);
        let count = usize::from(p.u8().ok_or_else(m)?);
        if count > FORMAT_MAX_PARENTS {
            return Err(CommitError::Malformed);
        }
        if p.remaining() != 32 * count {
            return Err(CommitError::Malformed);
        }
        if count > MAX_PARENTS {
            return Err(CommitError::TooManyParents);
        }
        let mut parents = Vec::with_capacity(count);
        for _ in 0..count {
            parents.push(CommitId::from_bytes(p.raw().ok_or_else(m)?));
        }
        parents
    };
    let root = ObjectId::from_bytes(r.field_fixed().ok_or_else(m)?);
    let generation = Generation(r.field_u32().ok_or_else(m)?);
    let device = DeviceId::from_bytes(r.field_fixed().ok_or_else(m)?);
    let index = r.field_u64().ok_or_else(m)?;
    let hash = LogHash::from_bytes(r.field_fixed().ok_or_else(m)?);
    let counter = r.field_u64().ok_or_else(m)?;
    let flags = r.field_u32().ok_or_else(m)?;
    if flags & !FLAGS_KNOWN != 0 {
        return Err(CommitError::Flags(flags & !FLAGS_KNOWN));
    }
    let mut seen = Reader::new(r.field().ok_or_else(m)?);
    let count = usize::from(seen.u8().ok_or_else(m)?);
    if count > FORMAT_MAX_SEEN || seen.remaining() != 48 * count {
        return Err(CommitError::Malformed);
    }
    if count > 0 {
        return Err(CommitError::SeenNotEmpty);
    }
    Ok(Commit {
        account,
        folder,
        height,
        parents,
        root,
        generation,
        device,
        log_head: LogHead { index, hash },
        counter,
        reanchor: flags & FLAG_REANCHOR != 0,
        side: flags & FLAG_SIDE != 0,
    })
}

/// A device's commit counter. The app stores [`CommitCounter::last`] before it uploads the
/// commit with that number, so a restart never reuses one.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CommitCounter {
    last: u64,
}

impl CommitCounter {
    /// Goes on after `last` (0: none yet).
    pub fn resume(last: u64) -> Self {
        Self { last }
    }

    /// The highest number used so far, to store.
    pub fn last(&self) -> u64 {
        self.last
    }

    /// The next number; `None` once every `u64` was used.
    pub fn take(&mut self) -> Option<u64> {
        self.last = self.last.checked_add(1)?;
        Some(self.last)
    }
}

/// One head on the verified first-parent chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainEntry {
    /// The commit.
    pub commit: CommitId,
    /// Its height.
    pub height: u64,
    /// The folder sequence of its call.
    pub sequence: u64,
    /// Its generation.
    pub generation: Generation,
    /// Its log head index.
    pub log_index: u64,
}

impl ChainEntry {
    fn of(commit: &SignedCommit, sequence: u64) -> Self {
        Self {
            commit: commit.id,
            height: commit.commit.height,
            sequence,
            generation: commit.commit.generation,
            log_index: commit.commit.log_head.index,
        }
    }
}

/// Why commits of a folder were refused. Nothing was accepted.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ChainError {
    /// One commit on its own.
    #[error(transparent)]
    Commit(#[from] CommitError),
    /// The server shows an older state: a head that does not reach the frontier, a missing body
    /// on the chain, or a replayed sequence.
    #[error("the server shows an older state of this folder")]
    OlderState,
    /// Sequences out of order within the delta.
    #[error("the delta's folder sequences are out of order")]
    Sequence,
    /// A height that does not fit the parents.
    #[error("a commit's height does not fit its parents")]
    Height,
    /// A generation below the first parent's.
    #[error("a commit goes back to an older key generation")]
    GenerationBack,
    /// A log head below the first parent's.
    #[error("a commit goes back to an older device log head")]
    LogHeadBack,
    /// A generation the device's ring does not hold yet: fetch the newer ring.
    #[error("a commit uses generation {0}, which this device's ring does not hold")]
    UnknownGeneration(u32),
    /// A counter at or below the device's mark.
    #[error("a commit's counter is not above its device's mark")]
    Counter,
    /// A merge commit whose side commit is not in the delta.
    #[error("a merge commit's side commit is missing")]
    SideMissing,
    /// A side commit no merge commit of its call names, or a second one in a call.
    #[error("a side commit is not named by its merge commit")]
    SideUnexpected,
    /// A side commit that breaks the side commit rules.
    #[error("a side commit breaks the side commit rules")]
    SideRule,
    /// A stored view that is not a valid chain.
    #[error("the stored folder view is not a valid chain")]
    InvalidView,
    /// A head with the side bit.
    #[error("a side commit is presented as a head")]
    SideAsHead,
    /// A head signed by a removed device without a later barrier commit in the delta.
    #[error("a head of a removed device has no barrier commit after it")]
    RemovedSigner,
    /// A head this device discarded at a re-anchor.
    #[error("the server presents a head this device discarded at a re-anchor")]
    Discarded,
}

/// What a device verified of one folder (module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FolderView {
    account: AccountId,
    folder: FolderId,
    chain: Vec<ChainEntry>,
    positions: BTreeMap<CommitId, usize>,
    marks: BTreeMap<DeviceId, u64>,
    discarded: BTreeSet<CommitId>,
}

/// The accepted part of a delta.
#[derive(Debug, Clone)]
pub struct DeltaOutcome {
    /// The view with the new heads; the caller stores it and moves its folder cursor to the
    /// frontier's sequence.
    pub view: FolderView,
    /// The new heads in order.
    pub heads: Vec<SignedCommit>,
    /// Their side commits.
    pub sides: Vec<SignedCommit>,
}

/// The verified server state for a re-anchor (module docs).
#[derive(Debug, Clone)]
pub struct ReanchorBase {
    /// The server's head H.
    pub head: ChainEntry,
    /// The base A: the newest commit of H's chain in the verified chain; `None` for the empty
    /// tree.
    pub base: Option<ChainEntry>,
    /// The verified commits after A up to H, in order (heads only).
    pub segment: Vec<SignedCommit>,
    /// Their side commits.
    pub sides: Vec<SignedCommit>,
    segment_entries: Vec<ChainEntry>,
    marks: BTreeMap<DeviceId, u64>,
}

struct Parsed {
    sequence: u64,
    commit: SignedCommit,
}

/// Parses and verifies every commit of a delta on its own; heads in order and sides by
/// sequence.
fn parse_delta(
    state: &AccountState,
    folder: &FolderId,
    delta: &[DeltaCommit],
) -> Result<(Vec<Parsed>, BTreeMap<u64, Parsed>), ChainError> {
    let mut heads: Vec<Parsed> = Vec::new();
    let mut sides = BTreeMap::new();
    let mut last_sequence = 0u64;
    for item in delta {
        if item.sequence < last_sequence {
            return Err(ChainError::Sequence);
        }
        last_sequence = item.sequence;
        let commit = SignedCommit::decode(item.commit.as_bytes())?;
        commit.verify_signer(state, folder)?;
        let parsed = Parsed {
            sequence: item.sequence,
            commit,
        };
        match item.role {
            CommitRole::Head => {
                if heads.last().is_some_and(|h| h.sequence >= item.sequence) {
                    return Err(ChainError::Sequence);
                }
                heads.push(parsed);
            }
            CommitRole::Side => {
                if sides.insert(item.sequence, parsed).is_some() {
                    return Err(ChainError::SideUnexpected);
                }
            }
        }
    }
    Ok((heads, sides))
}

/// Checks one head (and its side commit) on `prev` and advances the marks.
fn step(
    prev: Option<&ChainEntry>,
    head: &Parsed,
    side: Option<&Parsed>,
    newest_generation: Generation,
    marks: &mut BTreeMap<DeviceId, u64>,
    side_base: &dyn Fn(&CommitId) -> Option<ChainEntry>,
) -> Result<ChainEntry, ChainError> {
    let c = &head.commit.commit;
    if c.side {
        return Err(ChainError::SideAsHead);
    }
    if c.generation > newest_generation {
        return Err(ChainError::UnknownGeneration(c.generation.0));
    }
    let Some(prev) = prev else {
        if !c.parents.is_empty() || side.is_some() {
            return Err(ChainError::OlderState);
        }
        bump(marks, c.device, c.counter)?;
        return Ok(ChainEntry::of(&head.commit, head.sequence));
    };
    if c.parents.first() != Some(&prev.commit) || head.sequence <= prev.sequence {
        return Err(ChainError::OlderState);
    }
    if c.generation < prev.generation {
        return Err(ChainError::GenerationBack);
    }
    if c.log_head.index < prev.log_index {
        return Err(ChainError::LogHeadBack);
    }
    match (c.parents.get(1), side) {
        (None, None) => {
            if c.height != prev.height + 1 {
                return Err(ChainError::Height);
            }
        }
        (None, Some(_)) => return Err(ChainError::SideUnexpected),
        (Some(_), None) => return Err(ChainError::SideMissing),
        (Some(second), Some(side)) => {
            let s = &side.commit.commit;
            if side.commit.id != *second {
                return Err(ChainError::SideMissing);
            }
            if s.device != c.device
                || !s.side
                || s.parents.len() != 1
                || s.reanchor
                || side.sequence != head.sequence
            {
                return Err(ChainError::SideRule);
            }
            let base = side_base(&s.parents[0]).ok_or(ChainError::SideRule)?;
            if s.height != base.height + 1 || s.counter >= c.counter {
                return Err(ChainError::SideRule);
            }
            // Nothing goes back from the side commit's base either.
            if s.generation < base.generation || s.log_head.index < base.log_index {
                return Err(ChainError::SideRule);
            }
            if c.height != prev.height.max(s.height) + 1 {
                return Err(ChainError::Height);
            }
            if s.generation > newest_generation {
                return Err(ChainError::UnknownGeneration(s.generation.0));
            }
            bump(marks, s.device, s.counter)?;
        }
    }
    bump(marks, c.device, c.counter)?;
    Ok(ChainEntry::of(&head.commit, head.sequence))
}

/// The removed signer rule (module docs): every head of a device the log has removed is
/// followed, later in the same delta, by a head of a current device that names a log head at
/// or after the removal.
fn check_removed_signers<'a>(
    state: &AccountState,
    heads: impl Iterator<Item = &'a SignedCommit>,
) -> Result<(), ChainError> {
    let heads: Vec<&SignedCommit> = heads.collect();
    // From the end: the newest log head index named by a current device after each position.
    let mut covered_from = 0u64;
    for head in heads.iter().rev() {
        let c = &head.commit;
        match state.device(&c.device).and_then(|d| d.removed_at) {
            Some(removed_at) => {
                if covered_from < removed_at {
                    return Err(ChainError::RemovedSigner);
                }
            }
            None => covered_from = covered_from.max(c.log_head.index),
        }
    }
    Ok(())
}

fn bump(
    marks: &mut BTreeMap<DeviceId, u64>,
    device: DeviceId,
    counter: u64,
) -> Result<(), ChainError> {
    let mark = marks.entry(device).or_insert(0);
    if counter <= *mark {
        return Err(ChainError::Counter);
    }
    *mark = counter;
    Ok(())
}

impl FolderView {
    /// A folder this device has verified nothing of yet.
    pub fn new(account: AccountId, folder: FolderId) -> Self {
        Self {
            account,
            folder,
            chain: Vec::new(),
            positions: BTreeMap::new(),
            marks: BTreeMap::new(),
            discarded: BTreeSet::new(),
        }
    }

    /// A view from storage; refuses a chain whose heights and sequences do not rise, that
    /// repeats a commit, or that holds a discarded head.
    pub fn restore(
        account: AccountId,
        folder: FolderId,
        chain: Vec<ChainEntry>,
        marks: BTreeMap<DeviceId, u64>,
        discarded: BTreeSet<CommitId>,
    ) -> Result<Self, ChainError> {
        if chain
            .windows(2)
            .any(|w| w[1].height <= w[0].height || w[1].sequence <= w[0].sequence)
        {
            return Err(ChainError::InvalidView);
        }
        let mut positions = BTreeMap::new();
        for (at, entry) in chain.iter().enumerate() {
            if positions.insert(entry.commit, at).is_some() || discarded.contains(&entry.commit) {
                return Err(ChainError::InvalidView);
            }
        }
        Ok(Self {
            account,
            folder,
            chain,
            positions,
            marks,
            discarded,
        })
    }

    /// The heads this device dropped from its chain at a re-anchor (module docs), to store.
    pub fn discarded(&self) -> &BTreeSet<CommitId> {
        &self.discarded
    }

    /// The folder.
    pub fn folder(&self) -> &FolderId {
        &self.folder
    }

    /// The account.
    pub fn account(&self) -> &AccountId {
        &self.account
    }

    /// The frontier: the last head this device verified.
    pub fn frontier(&self) -> Option<&ChainEntry> {
        self.chain.last()
    }

    /// The verified first-parent chain, oldest first.
    pub fn chain(&self) -> &[ChainEntry] {
        &self.chain
    }

    /// The entry of `commit` on the verified chain.
    pub fn entry(&self, commit: &CommitId) -> Option<&ChainEntry> {
        self.positions
            .get(commit)
            .and_then(|&at| self.chain.get(at))
    }

    /// The highest counter accepted per device.
    pub fn marks(&self) -> &BTreeMap<DeviceId, u64> {
        &self.marks
    }

    /// Refuses a server whose folder sequence is below this device's frontier: an older state.
    pub fn check_server_sequence(&self, server_sequence: u64) -> Result<(), ChainError> {
        match self.frontier() {
            Some(frontier) if server_sequence < frontier.sequence => Err(ChainError::OlderState),
            _ => Ok(()),
        }
    }

    fn push(&mut self, entry: ChainEntry) {
        self.positions.insert(entry.commit, self.chain.len());
        self.chain.push(entry);
    }

    /// Verifies the commits of a delta pull after this view's frontier (module docs).
    /// `newest_generation` is the newest generation of the folder's ring this device holds.
    /// `delta` is everything up to the server's sequence, every page of the pull.
    pub fn verify_delta(
        &self,
        state: &AccountState,
        newest_generation: Generation,
        delta: &[DeltaCommit],
    ) -> Result<DeltaOutcome, ChainError> {
        self.verify(state, newest_generation, delta, true)
    }

    /// [`FolderView::verify_delta`] without the removed signer rule, for the removing device
    /// only: right after its removal and rotation were accepted it verifies the folder's delta
    /// with this and writes the barrier commit ([`Commit::barrier`]) on the head it returns.
    /// Every other rule applies. Called anywhere else it would let a removed device's
    /// backdated commit in; it never moves the frontier on its own, the caller stores only the
    /// view of its accepted barrier ([`FolderView::accept_published`]).
    pub fn verify_delta_before_barrier(
        &self,
        state: &AccountState,
        newest_generation: Generation,
        delta: &[DeltaCommit],
    ) -> Result<DeltaOutcome, ChainError> {
        self.verify(state, newest_generation, delta, false)
    }

    fn verify(
        &self,
        state: &AccountState,
        newest_generation: Generation,
        delta: &[DeltaCommit],
        removed_rule: bool,
    ) -> Result<DeltaOutcome, ChainError> {
        if state.account() != &self.account {
            return Err(CommitError::AccountMismatch.into());
        }
        let (heads, mut sides) = parse_delta(state, &self.folder, delta)?;
        if removed_rule {
            check_removed_signers(state, heads.iter().map(|h| &h.commit))?;
        }
        let mut view = self.clone();
        let mut accepted_heads = Vec::with_capacity(heads.len());
        let mut accepted_sides = Vec::new();
        for head in heads {
            if self.discarded.contains(&head.commit.id) {
                return Err(ChainError::Discarded);
            }
            let side = sides.remove(&head.sequence);
            let mut marks = view.marks.clone();
            let entry = {
                let lookup = |id: &CommitId| view.entry(id).copied();
                step(
                    view.frontier(),
                    &head,
                    side.as_ref(),
                    newest_generation,
                    &mut marks,
                    &lookup,
                )?
            };
            view.marks = marks;
            view.push(entry);
            if let Some(side) = side {
                accepted_sides.push(side.commit);
            }
            accepted_heads.push(head.commit);
        }
        if !sides.is_empty() {
            return Err(ChainError::SideUnexpected);
        }
        Ok(DeltaOutcome {
            view,
            heads: accepted_heads,
            sides: accepted_sides,
        })
    }

    /// Accepts this device's own commit call after the server accepted it at `sequence`:
    /// the same rules as for a delta.
    pub fn accept_published(
        &self,
        state: &AccountState,
        newest_generation: Generation,
        head: &SignedCommit,
        side: Option<&SignedCommit>,
        sequence: u64,
    ) -> Result<FolderView, ChainError> {
        let mut delta = Vec::with_capacity(2);
        if let Some(side) = side {
            delta.push(DeltaCommit {
                sequence,
                role: CommitRole::Side,
                commit: side.wire.clone().into(),
            });
        }
        delta.push(DeltaCommit {
            sequence,
            role: CommitRole::Head,
            commit: head.wire.clone().into(),
        });
        Ok(self.verify_delta(state, newest_generation, &delta)?.view)
    }

    /// The number of verified chain entries up to and including `base` (0 for none).
    fn kept_until(&self, base: Option<&ChainEntry>) -> usize {
        base.and_then(|b| self.positions.get(&b.commit))
            .map_or(0, |&at| at + 1)
    }

    /// Verifies the server's head and its chain down to the base for a re-anchor that the
    /// person confirmed (module docs). `delta` holds the server's commits after the base up to
    /// and including its head H, the last head of the delta; heads before the base and their
    /// side commits may be part of it and are ignored.
    pub fn reanchor_base(
        &self,
        state: &AccountState,
        newest_generation: Generation,
        delta: &[DeltaCommit],
    ) -> Result<ReanchorBase, ChainError> {
        if state.account() != &self.account {
            return Err(CommitError::AccountMismatch.into());
        }
        let (heads, mut sides) = parse_delta(state, &self.folder, delta)?;
        let last = heads.last().ok_or(ChainError::OlderState)?;

        // H itself on the verified chain: the plain restore of an older state.
        if let Some(entry) = self.entry(&last.commit.id) {
            return Ok(ReanchorBase {
                head: *entry,
                base: Some(*entry),
                segment: Vec::new(),
                sides: Vec::new(),
                segment_entries: Vec::new(),
                marks: self.marks.clone(),
            });
        }

        // Back from H by first parents until the verified chain or the first commit. Each step
        // goes to an earlier position of the delta, so the walk ends.
        let by_id: BTreeMap<CommitId, usize> = heads
            .iter()
            .enumerate()
            .map(|(at, h)| (h.commit.id, at))
            .collect();
        let mut order = vec![heads.len() - 1];
        let base = loop {
            let at = order[order.len() - 1];
            match heads[at].commit.commit.parents.first() {
                None => break None,
                Some(parent) => {
                    if let Some(entry) = self.entry(parent) {
                        break Some(*entry);
                    }
                    let next = *by_id.get(parent).ok_or(ChainError::OlderState)?;
                    if next >= at {
                        return Err(ChainError::Sequence);
                    }
                    order.push(next);
                }
            }
        };
        order.reverse();
        if order
            .iter()
            .any(|&at| self.discarded.contains(&heads[at].commit.id))
        {
            return Err(ChainError::Discarded);
        }
        check_removed_signers(state, order.iter().map(|&at| &heads[at].commit))?;

        // Forward over the segment with the normal rules; counters rise within the segment, not
        // necessarily above this device's marks.
        let kept = &self.chain[..self.kept_until(base.as_ref())];
        let mut segment_marks = BTreeMap::new();
        let mut entries: Vec<ChainEntry> = Vec::with_capacity(order.len());
        let mut segment = Vec::with_capacity(order.len());
        let mut segment_sides = Vec::new();
        let mut prev = base;
        for &at in &order {
            let head = &heads[at];
            let side = sides.remove(&head.sequence);
            let entry = {
                let lookup = |id: &CommitId| {
                    kept.iter()
                        .chain(entries.iter())
                        .find(|e| e.commit == *id)
                        .copied()
                };
                step(
                    prev.as_ref(),
                    head,
                    side.as_ref(),
                    newest_generation,
                    &mut segment_marks,
                    &lookup,
                )?
            };
            if let Some(side) = side {
                segment_sides.push(side.commit);
            }
            segment.push(head.commit.clone());
            entries.push(entry);
            prev = Some(entry);
        }
        // A side commit whose sequence no head of the delta has belongs to no call.
        if sides
            .keys()
            .any(|sequence| !heads.iter().any(|h| h.sequence == *sequence))
        {
            return Err(ChainError::SideUnexpected);
        }
        let head = *entries.last().ok_or(ChainError::OlderState)?;
        let mut marks = self.marks.clone();
        for (device, counter) in segment_marks {
            let mark = marks.entry(device).or_insert(0);
            *mark = (*mark).max(counter);
        }
        Ok(ReanchorBase {
            head,
            base,
            segment,
            sides: segment_sides,
            segment_entries: entries,
            marks,
        })
    }

    /// Accepts the device's own re-anchor commit, a normal commit with the single parent H,
    /// after the server accepted it at `sequence`. The verified chain becomes the old chain up
    /// to the base, the segment, and the new commit, which is the new frontier with its lower
    /// height and sequence. The commit's counter must be above every mark.
    pub fn apply_reanchor(
        &self,
        state: &AccountState,
        newest_generation: Generation,
        base: &ReanchorBase,
        own: &SignedCommit,
        sequence: u64,
    ) -> Result<FolderView, ChainError> {
        own.verify_signer(state, &self.folder)?;
        if !own.commit.reanchor {
            return Err(CommitError::ReanchorFlag.into());
        }
        let kept = self.kept_until(base.base.as_ref());
        let mut chain = self.chain[..kept].to_vec();
        chain.extend_from_slice(&base.segment_entries);
        if chain.last().map(|e| e.commit) != Some(base.head.commit) {
            return Err(ChainError::OlderState);
        }
        // The old chain after the base leaves the history for good (L2: never a head again).
        let mut discarded = self.discarded.clone();
        discarded.extend(self.chain[kept..].iter().map(|e| e.commit));
        let mut view = FolderView::restore(
            self.account,
            self.folder,
            chain,
            base.marks.clone(),
            discarded,
        )?;
        let own = Parsed {
            sequence,
            commit: own.clone(),
        };
        let mut marks = view.marks.clone();
        let entry = step(
            Some(&base.head),
            &own,
            None,
            newest_generation,
            &mut marks,
            &|_: &CommitId| None,
        )?;
        view.marks = marks;
        view.push(entry);
        Ok(view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devicelog::tests::{dev, Dev, ACCOUNT};
    use crate::devicelog::{EntryKind, LogDevice, LogError};
    use crate::record::tests::setup;
    use hangar_drive_protocol::ids::Blob;

    const FOLDER: FolderId = FolderId::from_bytes([3; 16]);
    const G1: Generation = Generation(1);

    struct World {
        a: Dev,
        b: Dev,
        state: AccountState,
        counters: BTreeMap<DeviceId, u64>,
    }

    fn world() -> World {
        let s = setup();
        World {
            a: s.a,
            b: s.b,
            state: s.state,
            counters: BTreeMap::new(),
        }
    }

    impl World {
        /// The next commit content of `device` (its counter rises by one).
        fn content(&mut self, device: DeviceId, root: u8, generation: Generation) -> CommitContent {
            let counter = self.counters.entry(device).or_insert(0);
            *counter += 1;
            CommitContent {
                root: ObjectId::from_bytes([root; 32]),
                generation,
                device,
                log_head: self.state.head().unwrap(),
                counter: *counter,
            }
        }
    }

    fn head(c: &SignedCommit, sequence: u64) -> DeltaCommit {
        DeltaCommit {
            sequence,
            role: CommitRole::Head,
            commit: Blob(c.wire.clone()),
        }
    }

    fn side(c: &SignedCommit, sequence: u64) -> DeltaCommit {
        DeltaCommit {
            sequence,
            role: CommitRole::Side,
            commit: Blob(c.wire.clone()),
        }
    }

    /// Commits c1 (a), c2 (b), c3 (a) at sequences 1 to 3, verified by a fresh view.
    fn linear(w: &mut World) -> (FolderView, Vec<SignedCommit>) {
        let (a, b) = (w.a.id, w.b.id);
        let c1 = Commit::first(ACCOUNT, FOLDER, w.content(a, 1, G1))
            .sign(&w.a.identity)
            .unwrap();
        let c2 = Commit::on(
            ACCOUNT,
            FOLDER,
            &ChainEntry::of(&c1, 1),
            w.content(b, 2, G1),
        )
        .sign(&w.b.identity)
        .unwrap();
        let c3 = Commit::on(
            ACCOUNT,
            FOLDER,
            &ChainEntry::of(&c2, 2),
            w.content(a, 3, G1),
        )
        .sign(&w.a.identity)
        .unwrap();
        let outcome = FolderView::new(ACCOUNT, FOLDER)
            .verify_delta(&w.state, G1, &[head(&c1, 1), head(&c2, 2), head(&c3, 3)])
            .unwrap();
        (outcome.view, vec![c1, c2, c3])
    }

    /// A body with `parents`, `height` and a raw `seen` field, signed by a.
    fn hand_made(w: &World, parents: &[CommitId], height: u64, seen: &[u8]) -> Vec<u8> {
        hand_made_flags(w, parents, height, 0, seen)
    }

    /// [`hand_made`] with `flags`.
    fn hand_made_flags(
        w: &World,
        parents: &[CommitId],
        height: u64,
        flags: u32,
        seen: &[u8],
    ) -> Vec<u8> {
        let mut p = Writer::new();
        p.u8(u8::try_from(parents.len()).unwrap());
        for parent in parents {
            p.raw(parent.as_bytes());
        }
        let log_head = w.state.head().unwrap();
        let mut b = Writer::new();
        b.field(LABEL_COMMIT)
            .field_u8(1)
            .field(ACCOUNT.as_bytes())
            .field(FOLDER.as_bytes())
            .field_u64(height)
            .field(&p.into_bytes())
            .field(&[1; 32])
            .field_u32(1)
            .field(w.a.id.as_bytes())
            .field_u64(log_head.index)
            .field(log_head.hash.as_bytes())
            .field_u64(1)
            .field_u32(flags)
            .field(seen);
        let body = b.into_bytes();
        let mut wire = body.clone();
        wire.extend_from_slice(&w.a.identity.sign(&signed_message(&body)));
        wire
    }

    #[test]
    fn format_round_trip_and_strict_decoding() {
        let mut w = world();
        let a = w.a.id;
        let c = Commit::first(ACCOUNT, FOLDER, w.content(a, 1, G1))
            .sign(&w.a.identity)
            .unwrap();
        let back = SignedCommit::decode(&c.wire).unwrap();
        assert_eq!(back, c);
        assert_eq!(back.verify_signer(&w.state, &FOLDER), Ok(()));
        // The hand-made encoder agrees with the real one.
        assert!(SignedCommit::decode(&hand_made(&w, &[], 1, &[0])).is_ok());
        let mut longer = c.wire.clone();
        longer.insert(c.wire.len() - 64, 0);
        assert!(SignedCommit::decode(&longer).is_err());
        for cut in [0, 10, c.wire.len() - 65, c.wire.len() - 1] {
            assert!(SignedCommit::decode(&c.wire[..cut]).is_err(), "cut {cut}");
        }
        let mut v2 = c.wire.clone();
        v2[4 + LABEL_COMMIT.len() + 4] = 2;
        assert_eq!(SignedCommit::decode(&v2), Err(CommitError::Version(2)));
    }

    #[test]
    fn version_1_refuses_three_parents_a_seen_vector_and_bad_heights() {
        let w = world();
        let p = |b| CommitId::from_bytes([b; 32]);
        assert_eq!(
            SignedCommit::decode(&hand_made(&w, &[p(1), p(2), p(3)], 2, &[0])),
            Err(CommitError::TooManyParents)
        );
        let nine: Vec<CommitId> = (1..=9).map(p).collect();
        assert_eq!(
            SignedCommit::decode(&hand_made(&w, &nine, 2, &[0])),
            Err(CommitError::Malformed)
        );
        let mut seen = vec![1u8];
        seen.extend_from_slice(&[5; 48]);
        assert_eq!(
            SignedCommit::decode(&hand_made(&w, &[p(1)], 2, &seen)),
            Err(CommitError::SeenNotEmpty)
        );
        assert_eq!(
            SignedCommit::decode(&hand_made(&w, &[p(1)], 2, &[1])),
            Err(CommitError::Malformed)
        );
        assert_eq!(
            SignedCommit::decode(&hand_made(&w, &[p(1)], 1, &[0])),
            Err(CommitError::Height)
        );
        assert_eq!(
            SignedCommit::decode(&hand_made(&w, &[], 2, &[0])),
            Err(CommitError::Height)
        );
        assert_eq!(
            SignedCommit::decode(&hand_made(&w, &[p(1), p(1)], 2, &[0])),
            Err(CommitError::Malformed)
        );
        let mut too_many = Commit::first(
            ACCOUNT,
            FOLDER,
            CommitContent {
                root: ObjectId::from_bytes([1; 32]),
                generation: G1,
                device: w.a.id,
                log_head: w.state.head().unwrap(),
                counter: 1,
            },
        );
        too_many.parents = vec![p(1), p(2), p(3)];
        too_many.height = 2;
        assert_eq!(
            too_many.sign(&w.a.identity),
            Err(CommitError::TooManyParents)
        );
    }

    #[test]
    fn signer_rules_and_forgeries() {
        let mut w = world();
        let (a, b) = (w.a.id, w.b.id);
        let good = Commit::first(ACCOUNT, FOLDER, w.content(a, 1, G1));
        let forged = good.clone().sign(&w.b.identity).unwrap();
        assert_eq!(
            forged.verify_signer(&w.state, &FOLDER),
            Err(CommitError::Signature)
        );
        let signed = good.clone().sign(&w.a.identity).unwrap();
        assert_eq!(
            signed.verify_signer(&w.state, &FolderId::from_bytes([9; 16])),
            Err(CommitError::FolderMismatch)
        );
        let mut other_account = good.clone();
        other_account.account = AccountId::from_bytes([9; 16]);
        let other_account = other_account.sign(&w.a.identity).unwrap();
        assert_eq!(
            other_account.verify_signer(&w.state, &FOLDER),
            Err(CommitError::AccountMismatch)
        );
        // A flipped root after signing.
        let mut tampered = signed.wire.clone();
        let root_at =
            tampered.len() - 64 - 4 - 1 - 4 - 8 - 4 - 32 - 4 - 8 - 4 - 16 - 4 - 4 - 4 - 32 + 4;
        tampered[root_at] ^= 1;
        let tampered = SignedCommit::decode(&tampered).unwrap();
        assert_eq!(
            tampered.verify_signer(&w.state, &FOLDER),
            Err(CommitError::Signature)
        );
        let mut ahead = good.clone();
        ahead.log_head.index += 1;
        let ahead = ahead.sign(&w.a.identity).unwrap();
        assert_eq!(
            ahead.verify_signer(&w.state, &FOLDER),
            Err(CommitError::AheadOfLog {
                index: w.state.len() + 1
            })
        );
        let mut forked = good;
        forked.log_head.hash = LogHash::from_bytes([9; 32]);
        let forked = forked.sign(&w.a.identity).unwrap();
        assert_eq!(
            forked.verify_signer(&w.state, &FOLDER),
            Err(CommitError::Fork {
                index: w.state.len()
            })
        );
        // A removed device naming a log head after its removal.
        let entry = w
            .state
            .next_entry(&w.a.identity, a, 0, EntryKind::RemoveDevice(b))
            .unwrap();
        w.state.apply(&entry).unwrap();
        let late = Commit::first(ACCOUNT, FOLDER, w.content(b, 1, G1))
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            late.verify_signer(&w.state, &FOLDER),
            Err(CommitError::SignerNotValid)
        );
    }

    #[test]
    fn recovery_devices_sign_no_commits() {
        let mut w = world();
        let r = dev(7);
        let entry = w
            .state
            .next_entry(
                &w.a.identity,
                w.a.id,
                0,
                EntryKind::AddDevice(LogDevice::of(&r.identity, &ACCOUNT, r.id, true)),
            )
            .unwrap();
        w.state.apply(&entry).unwrap();
        let c = Commit::first(ACCOUNT, FOLDER, w.content(r.id, 1, G1))
            .sign(&r.identity)
            .unwrap();
        assert_eq!(
            c.verify_signer(&w.state, &FOLDER),
            Err(CommitError::SignerNotValid)
        );
        // A removal makes the log refuse new devices until the rotation (checked here once more,
        // because a commit's log head then names the removal).
        let entry = w
            .state
            .next_entry(&w.a.identity, w.a.id, 0, EntryKind::RemoveDevice(w.b.id))
            .unwrap();
        w.state.apply(&entry).unwrap();
        let n = dev(8);
        assert_eq!(
            w.state
                .next_entry(
                    &w.a.identity,
                    w.a.id,
                    0,
                    EntryKind::AddDevice(LogDevice::of(&n.identity, &ACCOUNT, n.id, false))
                )
                .unwrap_err(),
            LogError::RotationDue
        );
    }

    #[test]
    fn a_linear_chain_verifies_and_moves_the_frontier() {
        let mut w = world();
        let (view, commits) = linear(&mut w);
        assert_eq!(view.chain().len(), 3);
        let frontier = view.frontier().unwrap();
        assert_eq!(frontier.commit, commits[2].id);
        assert_eq!(frontier.sequence, 3);
        assert_eq!(frontier.height, 3);
        assert_eq!(view.marks().get(&w.a.id), Some(&2));
        assert_eq!(view.marks().get(&w.b.id), Some(&1));
        let same = view.verify_delta(&w.state, G1, &[]).unwrap();
        assert_eq!(same.view, view);
        assert_eq!(view.check_server_sequence(3), Ok(()));
        assert_eq!(view.check_server_sequence(2), Err(ChainError::OlderState));
    }

    #[test]
    fn fail_closed_on_heads_that_do_not_reach_the_frontier() {
        let mut w = world();
        let (a, b) = (w.a.id, w.b.id);
        let (view, commits) = linear(&mut w);
        let frontier = *view.frontier().unwrap();
        // A replayed old head.
        assert_eq!(
            view.verify_delta(&w.state, G1, &[head(&commits[1], 4)])
                .unwrap_err(),
            ChainError::OlderState
        );
        // A fork from c2 that skips the frontier.
        let e2 = view.chain()[1];
        let fork = Commit::on(ACCOUNT, FOLDER, &e2, w.content(b, 9, G1))
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[head(&fork, 4)])
                .unwrap_err(),
            ChainError::OlderState
        );
        // A missing body: c5 on c4, c4 withheld.
        let c4 = Commit::on(ACCOUNT, FOLDER, &frontier, w.content(a, 4, G1))
            .sign(&w.a.identity)
            .unwrap();
        let c5 = Commit::on(
            ACCOUNT,
            FOLDER,
            &ChainEntry::of(&c4, 4),
            w.content(a, 5, G1),
        )
        .sign(&w.a.identity)
        .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[head(&c5, 5)])
                .unwrap_err(),
            ChainError::OlderState
        );
        // A sequence not above the frontier's.
        assert_eq!(
            view.verify_delta(&w.state, G1, &[head(&c4, 3)])
                .unwrap_err(),
            ChainError::OlderState
        );
        // Reordered.
        assert_eq!(
            view.verify_delta(&w.state, G1, &[head(&c5, 5), head(&c4, 4)])
                .unwrap_err(),
            ChainError::Sequence
        );
        // The honest order passes; a broken commit in the middle accepts nothing.
        let ok = view
            .verify_delta(&w.state, G1, &[head(&c4, 4), head(&c5, 5)])
            .unwrap();
        assert_eq!(ok.view.frontier().unwrap().commit, c5.id);
        let mut bad = c5.wire.clone();
        bad[100] ^= 1;
        let broken = DeltaCommit {
            sequence: 5,
            role: CommitRole::Head,
            commit: Blob(bad),
        };
        assert!(view
            .verify_delta(&w.state, G1, &[head(&c4, 4), broken])
            .is_err());
        assert_eq!(view.frontier(), Some(&frontier));
        // Another folder's commit.
        let elsewhere = Commit::on(
            ACCOUNT,
            FolderId::from_bytes([8; 16]),
            &frontier,
            w.content(a, 6, G1),
        )
        .sign(&w.a.identity)
        .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[head(&elsewhere, 4)])
                .unwrap_err(),
            ChainError::Commit(CommitError::FolderMismatch)
        );
    }

    #[test]
    fn a_fresh_device_needs_the_chain_from_the_first_commit() {
        let mut w = world();
        let (_, commits) = linear(&mut w);
        let fresh = FolderView::new(ACCOUNT, FOLDER);
        assert_eq!(
            fresh
                .verify_delta(&w.state, G1, &[head(&commits[1], 2), head(&commits[2], 3)])
                .unwrap_err(),
            ChainError::OlderState
        );
    }

    #[test]
    fn nothing_goes_back_generation_and_log_head() {
        let mut w = world();
        let a = w.a.id;
        let g2 = Generation(2);
        let c1 = Commit::first(ACCOUNT, FOLDER, w.content(a, 1, g2))
            .sign(&w.a.identity)
            .unwrap();
        let view = FolderView::new(ACCOUNT, FOLDER)
            .verify_delta(&w.state, g2, &[head(&c1, 1)])
            .unwrap()
            .view;
        let e1 = *view.frontier().unwrap();
        let back = Commit::on(ACCOUNT, FOLDER, &e1, w.content(a, 2, G1))
            .sign(&w.a.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, g2, &[head(&back, 2)])
                .unwrap_err(),
            ChainError::GenerationBack
        );
        let ahead = Commit::on(ACCOUNT, FOLDER, &e1, w.content(a, 2, Generation(3)))
            .sign(&w.a.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, g2, &[head(&ahead, 2)])
                .unwrap_err(),
            ChainError::UnknownGeneration(3)
        );
        // The log grows; c2 names the newer head, c3 the older one again.
        let earlier = w.state.head().unwrap();
        let n = dev(8);
        let entry = w
            .state
            .next_entry(
                &w.a.identity,
                a,
                0,
                EntryKind::AddDevice(LogDevice::of(&n.identity, &ACCOUNT, n.id, false)),
            )
            .unwrap();
        let mut older_state = w.state.clone();
        w.state.apply(&entry).unwrap();
        let c2 = Commit::on(ACCOUNT, FOLDER, &e1, w.content(a, 3, g2))
            .sign(&w.a.identity)
            .unwrap();
        // A device whose log is behind must fetch it first.
        assert_eq!(
            view.verify_delta(&older_state, g2, &[head(&c2, 2)])
                .unwrap_err(),
            ChainError::Commit(CommitError::AheadOfLog {
                index: w.state.len()
            })
        );
        older_state.apply(&entry).unwrap();
        let view2 = view
            .verify_delta(&w.state, g2, &[head(&c2, 2)])
            .unwrap()
            .view;
        let mut content = w.content(a, 4, g2);
        content.log_head = earlier;
        let c3 = Commit::on(ACCOUNT, FOLDER, view2.frontier().unwrap(), content)
            .sign(&w.a.identity)
            .unwrap();
        assert_eq!(
            view2
                .verify_delta(&w.state, g2, &[head(&c3, 3)])
                .unwrap_err(),
            ChainError::LogHeadBack
        );
    }

    #[test]
    fn counters_must_rise_per_device() {
        let mut w = world();
        let a = w.a.id;
        let (view, _) = linear(&mut w);
        let frontier = *view.frontier().unwrap();
        let mut content = w.content(a, 7, G1);
        content.counter = 2;
        let replayed = Commit::on(ACCOUNT, FOLDER, &frontier, content)
            .sign(&w.a.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[head(&replayed, 4)])
                .unwrap_err(),
            ChainError::Counter
        );
        let ok = Commit::on(ACCOUNT, FOLDER, &frontier, w.content(a, 7, G1))
            .sign(&w.a.identity)
            .unwrap();
        assert!(view.verify_delta(&w.state, G1, &[head(&ok, 4)]).is_ok());
    }

    #[test]
    fn heights_must_fit() {
        let mut w = world();
        let a = w.a.id;
        let (view, _) = linear(&mut w);
        let mut wrong = Commit::on(
            ACCOUNT,
            FOLDER,
            view.frontier().unwrap(),
            w.content(a, 7, G1),
        );
        wrong.height += 1;
        let wrong = wrong.sign(&w.a.identity).unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[head(&wrong, 4)])
                .unwrap_err(),
            ChainError::Height
        );
    }

    /// b's side commit on c2 (an earlier head) and its merge on the frontier c3.
    fn merge_on_frontier(w: &mut World, view: &FolderView) -> (SignedCommit, SignedCommit) {
        let b = w.b.id;
        let e2 = view.chain()[1];
        let frontier = *view.frontier().unwrap();
        let s = Commit::side(ACCOUNT, FOLDER, &e2, w.content(b, 8, G1))
            .sign(&w.b.identity)
            .unwrap();
        let m = Commit::merge(ACCOUNT, FOLDER, &frontier, &s, w.content(b, 9, G1))
            .sign(&w.b.identity)
            .unwrap();
        (s, m)
    }

    #[test]
    fn side_commits_follow_their_rules() {
        let mut w = world();
        let (view, _) = linear(&mut w);
        let (s, m) = merge_on_frontier(&mut w, &view);
        let outcome = view
            .verify_delta(&w.state, G1, &[side(&s, 4), head(&m, 4)])
            .unwrap();
        assert_eq!(outcome.view.frontier().unwrap().commit, m.id);
        assert_eq!(outcome.sides, vec![s.clone()]);
        assert!(outcome.view.entry(&s.id).is_none(), "never on the chain");
        assert_eq!(outcome.view.marks().get(&w.b.id), Some(&3));
        assert_eq!(outcome.view.frontier().unwrap().height, 4);
        assert_eq!(
            view.verify_delta(&w.state, G1, &[head(&m, 4)]).unwrap_err(),
            ChainError::SideMissing
        );
        assert_eq!(
            view.verify_delta(&w.state, G1, &[side(&s, 4)]).unwrap_err(),
            ChainError::SideUnexpected
        );
        assert_eq!(
            view.verify_delta(&w.state, G1, &[side(&s, 4), head(&m, 5)])
                .unwrap_err(),
            ChainError::SideMissing
        );
        assert_eq!(
            view.verify_delta(&w.state, G1, &[side(&s, 4), side(&s, 4), head(&m, 4)])
                .unwrap_err(),
            ChainError::SideUnexpected
        );
        // A side commit as the new head of a normal call.
        assert_eq!(
            view.verify_delta(&w.state, G1, &[head(&s, 4)]).unwrap_err(),
            ChainError::SideAsHead
        );
    }

    #[test]
    fn side_commit_rule_violations_are_refused() {
        let mut w = world();
        let (a, b) = (w.a.id, w.b.id);
        let (view, _) = linear(&mut w);
        let e2 = view.chain()[1];
        let frontier = *view.frontier().unwrap();
        // Signed by another device than the merge commit.
        let s = Commit::side(ACCOUNT, FOLDER, &e2, w.content(a, 8, G1))
            .sign(&w.a.identity)
            .unwrap();
        let m = Commit::merge(ACCOUNT, FOLDER, &frontier, &s, w.content(b, 9, G1))
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[side(&s, 4), head(&m, 4)])
                .unwrap_err(),
            ChainError::SideRule
        );
        // On a commit that never was a head.
        let unknown = ChainEntry {
            commit: CommitId::from_bytes([0xee; 32]),
            height: 2,
            sequence: 2,
            generation: G1,
            log_index: 1,
        };
        let s = Commit::side(ACCOUNT, FOLDER, &unknown, w.content(b, 8, G1))
            .sign(&w.b.identity)
            .unwrap();
        let m = Commit::merge(ACCOUNT, FOLDER, &frontier, &s, w.content(b, 9, G1))
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[side(&s, 4), head(&m, 4)])
                .unwrap_err(),
            ChainError::SideRule
        );
        // A counter above the merge commit's.
        let mut sc = w.content(b, 8, G1);
        let mut mc = w.content(b, 9, G1);
        std::mem::swap(&mut sc.counter, &mut mc.counter);
        let s = Commit::side(ACCOUNT, FOLDER, &e2, sc)
            .sign(&w.b.identity)
            .unwrap();
        let m = Commit::merge(ACCOUNT, FOLDER, &frontier, &s, mc)
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[side(&s, 4), head(&m, 4)])
                .unwrap_err(),
            ChainError::SideRule
        );
        // A counter at b's mark.
        let mut sc = w.content(b, 8, G1);
        sc.counter = 1;
        let s = Commit::side(ACCOUNT, FOLDER, &e2, sc)
            .sign(&w.b.identity)
            .unwrap();
        let m = Commit::merge(ACCOUNT, FOLDER, &frontier, &s, w.content(b, 9, G1))
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[side(&s, 4), head(&m, 4)])
                .unwrap_err(),
            ChainError::Counter
        );
        // A side commit with two parents (itself a merge).
        let inner = Commit::on(ACCOUNT, FOLDER, &e2, w.content(b, 10, G1))
            .sign(&w.b.identity)
            .unwrap();
        let s = Commit::merge(ACCOUNT, FOLDER, &e2, &inner, w.content(b, 11, G1))
            .sign(&w.b.identity)
            .unwrap();
        let m = Commit::merge(ACCOUNT, FOLDER, &frontier, &s, w.content(b, 12, G1))
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[side(&s, 4), head(&m, 4)])
                .unwrap_err(),
            ChainError::SideRule
        );
    }

    #[test]
    fn publishing_moves_the_frontier_through_the_same_rules() {
        let mut w = world();
        let a = w.a.id;
        let (view, _) = linear(&mut w);
        let mine = Commit::on(
            ACCOUNT,
            FOLDER,
            view.frontier().unwrap(),
            w.content(a, 4, G1),
        )
        .sign(&w.a.identity)
        .unwrap();
        let next = view.accept_published(&w.state, G1, &mine, None, 4).unwrap();
        assert_eq!(next.frontier().unwrap().commit, mine.id);
        let (s, m) = merge_on_frontier(&mut w, &view);
        let merged = view
            .accept_published(&w.state, G1, &m, Some(&s), 4)
            .unwrap();
        assert_eq!(merged.frontier().unwrap().commit, m.id);
        assert_eq!(
            view.accept_published(&w.state, G1, &m, None, 4)
                .unwrap_err(),
            ChainError::SideMissing
        );
    }

    #[test]
    fn reanchor_after_an_older_server_state() {
        let mut w = world();
        let (a, b) = (w.a.id, w.b.id);
        let (view, commits) = linear(&mut w);
        // The server was restored to the state after c2, and b then wrote c3' on c2.
        let e2 = view.chain()[1];
        let c3b = Commit::on(ACCOUNT, FOLDER, &e2, w.content(b, 30, G1))
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[head(&c3b, 3)])
                .unwrap_err(),
            ChainError::OlderState
        );
        let base = view
            .reanchor_base(
                &w.state,
                G1,
                &[head(&commits[0], 1), head(&commits[1], 2), head(&c3b, 3)],
            )
            .unwrap();
        assert_eq!(base.base.map(|e| e.commit), Some(commits[1].id));
        assert_eq!(base.head.commit, c3b.id);
        assert_eq!(base.segment, vec![c3b.clone()]);
        let own = Commit::reanchor(ACCOUNT, FOLDER, &base.head, w.content(a, 31, G1))
            .sign(&w.a.identity)
            .unwrap();
        let anchored = view.apply_reanchor(&w.state, G1, &base, &own, 4).unwrap();
        let ids: Vec<CommitId> = anchored.chain().iter().map(|e| e.commit).collect();
        assert_eq!(ids, vec![commits[0].id, commits[1].id, c3b.id, own.id]);
        assert_eq!(anchored.frontier().unwrap().height, 4);
        assert!(
            anchored.marks()[&a] >= view.marks()[&a],
            "marks never go down"
        );
        // The own commit must be above the marks.
        let mut low = w.content(a, 32, G1);
        low.counter = 1;
        let low = Commit::reanchor(ACCOUNT, FOLDER, &base.head, low)
            .sign(&w.a.identity)
            .unwrap();
        assert_eq!(
            view.apply_reanchor(&w.state, G1, &base, &low, 4)
                .unwrap_err(),
            ChainError::Counter
        );
        // And on H, nothing else.
        let elsewhere = Commit::reanchor(ACCOUNT, FOLDER, &e2, w.content(a, 33, G1))
            .sign(&w.a.identity)
            .unwrap();
        assert_eq!(
            view.apply_reanchor(&w.state, G1, &base, &elsewhere, 4)
                .unwrap_err(),
            ChainError::OlderState
        );
    }

    #[test]
    fn reanchor_segment_may_hold_counters_below_the_marks() {
        let mut w = world();
        let a = w.a.id;
        let (view, commits) = linear(&mut w);
        // A commit by a on c2 with counter 2, which a's mark (2, from c3) already holds: an older
        // commit of the restored server, not a replay of a newer one.
        let mut content = w.content(a, 60, G1);
        content.counter = 2;
        let e2 = view.chain()[1];
        let older = Commit::on(ACCOUNT, FOLDER, &e2, content)
            .sign(&w.a.identity)
            .unwrap();
        assert!(view.verify_delta(&w.state, G1, &[head(&older, 3)]).is_err());
        let base = view
            .reanchor_base(&w.state, G1, &[head(&older, 3)])
            .unwrap();
        assert_eq!(base.base.map(|e| e.commit), Some(commits[1].id));
        // Within the segment counters still rise per device.
        let mut again = w.content(a, 61, G1);
        again.counter = 2;
        let next = Commit::on(ACCOUNT, FOLDER, &ChainEntry::of(&older, 3), again)
            .sign(&w.a.identity)
            .unwrap();
        assert_eq!(
            view.reanchor_base(&w.state, G1, &[head(&older, 3), head(&next, 4)])
                .unwrap_err(),
            ChainError::Counter
        );
    }

    #[test]
    fn reanchor_on_a_plain_restore_and_on_an_unknown_history() {
        let mut w = world();
        let (a, b) = (w.a.id, w.b.id);
        let (view, commits) = linear(&mut w);
        let base = view
            .reanchor_base(&w.state, G1, &[head(&commits[1], 2)])
            .unwrap();
        assert_eq!(base.base.map(|e| e.commit), Some(commits[1].id));
        assert_eq!(base.head.commit, commits[1].id);
        let own = Commit::reanchor(ACCOUNT, FOLDER, &base.head, w.content(a, 40, G1))
            .sign(&w.a.identity)
            .unwrap();
        let anchored = view.apply_reanchor(&w.state, G1, &base, &own, 3).unwrap();
        assert_eq!(anchored.chain().len(), 3);
        assert_eq!(anchored.frontier().unwrap().commit, own.id);

        // Nothing in common: the base is the empty tree.
        let other = Commit::first(ACCOUNT, FOLDER, w.content(b, 50, G1))
            .sign(&w.b.identity)
            .unwrap();
        let base = view
            .reanchor_base(&w.state, G1, &[head(&other, 1)])
            .unwrap();
        assert!(base.base.is_none());
        let own = Commit::reanchor(ACCOUNT, FOLDER, &base.head, w.content(a, 51, G1))
            .sign(&w.a.identity)
            .unwrap();
        let anchored = view.apply_reanchor(&w.state, G1, &base, &own, 2).unwrap();
        let ids: Vec<CommitId> = anchored.chain().iter().map(|e| e.commit).collect();
        assert_eq!(ids, vec![other.id, own.id]);

        // A missing body and a forgery are refused even for a re-anchor.
        let c2 = Commit::on(
            ACCOUNT,
            FOLDER,
            &ChainEntry::of(&other, 1),
            w.content(b, 52, G1),
        )
        .sign(&w.b.identity)
        .unwrap();
        assert_eq!(
            view.reanchor_base(&w.state, G1, &[head(&c2, 2)])
                .unwrap_err(),
            ChainError::OlderState
        );
        let forged = Commit::first(ACCOUNT, FOLDER, w.content(a, 53, G1))
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            view.reanchor_base(&w.state, G1, &[head(&forged, 1)])
                .unwrap_err(),
            ChainError::Commit(CommitError::Signature)
        );
        assert_eq!(
            view.reanchor_base(&w.state, G1, &[]).unwrap_err(),
            ChainError::OlderState
        );
    }

    #[test]
    fn views_restore_only_valid_chains() {
        let mut w = world();
        let (view, _) = linear(&mut w);
        let restored = FolderView::restore(
            ACCOUNT,
            FOLDER,
            view.chain().to_vec(),
            view.marks().clone(),
            BTreeSet::new(),
        )
        .unwrap();
        assert_eq!(restored, view);
        let mut swapped = view.chain().to_vec();
        swapped.swap(0, 1);
        assert_eq!(
            FolderView::restore(ACCOUNT, FOLDER, swapped, BTreeMap::new(), BTreeSet::new()),
            Err(ChainError::InvalidView)
        );
    }

    #[test]
    fn reanchor_mark_rules() {
        let mut w = world();
        let (a, b) = (w.a.id, w.b.id);
        let (view, _) = linear(&mut w);
        let p = |byte| CommitId::from_bytes([byte; 32]);
        // Unknown bits, and the mark on a first or merge commit, are refused when decoding.
        assert_eq!(
            SignedCommit::decode(&hand_made_flags(&w, &[p(1)], 2, 4, &[0])),
            Err(CommitError::Flags(4))
        );
        assert_eq!(
            SignedCommit::decode(&hand_made_flags(&w, &[], 1, 1, &[0])),
            Err(CommitError::ReanchorFlag)
        );
        assert_eq!(
            SignedCommit::decode(&hand_made_flags(&w, &[p(1), p(2)], 2, 1, &[0])),
            Err(CommitError::ReanchorFlag)
        );
        let marked = SignedCommit::decode(&hand_made_flags(&w, &[p(1)], 2, 1, &[0])).unwrap();
        assert!(marked.commit.reanchor);
        // The mark is signed: flipping it breaks the commit ID and the signature.
        let frontier = *view.frontier().unwrap();
        let normal = Commit::on(ACCOUNT, FOLDER, &frontier, w.content(a, 70, G1))
            .sign(&w.a.identity)
            .unwrap();
        let re = Commit {
            reanchor: true,
            ..normal.commit.clone()
        }
        .sign(&w.a.identity)
        .unwrap();
        assert_ne!(re.id, normal.id);
        let mut forged = normal.commit.clone();
        forged.reanchor = true;
        let mut wire = forged.body();
        wire.extend_from_slice(normal.signature.as_bytes());
        assert_eq!(
            SignedCommit::decode(&wire)
                .unwrap()
                .verify_signer(&w.state, &FOLDER),
            Err(CommitError::Signature)
        );
        // Other devices see a marked head as a normal new head.
        assert!(view.verify_delta(&w.state, G1, &[head(&re, 4)]).is_ok());
        // A marked side commit is refused.
        let e2 = view.chain()[1];
        let s = Commit::reanchor(ACCOUNT, FOLDER, &e2, w.content(b, 71, G1))
            .sign(&w.b.identity)
            .unwrap();
        let m = Commit::merge(ACCOUNT, FOLDER, &frontier, &s, w.content(b, 72, G1))
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[side(&s, 4), head(&m, 4)])
                .unwrap_err(),
            ChainError::SideRule
        );
        // The re-anchor step needs the mark on the device's own commit.
        let base = view
            .reanchor_base(&w.state, G1, &[head(&normal, 4)])
            .unwrap();
        let unmarked = Commit::on(ACCOUNT, FOLDER, &base.head, w.content(a, 73, G1))
            .sign(&w.a.identity)
            .unwrap();
        assert_eq!(
            view.apply_reanchor(&w.state, G1, &base, &unmarked, 5)
                .unwrap_err(),
            ChainError::Commit(CommitError::ReanchorFlag)
        );
    }

    #[test]
    fn the_side_bit_is_signed_and_checked() {
        let mut w = world();
        let b = w.b.id;
        let (view, _) = linear(&mut w);
        let p = |byte| CommitId::from_bytes([byte; 32]);
        let marked = SignedCommit::decode(&hand_made_flags(&w, &[p(1)], 2, 2, &[0])).unwrap();
        assert!(marked.commit.side && !marked.commit.reanchor);
        assert_eq!(
            SignedCommit::decode(&hand_made_flags(&w, &[], 1, 2, &[0])),
            Err(CommitError::SideFlag)
        );
        assert_eq!(
            SignedCommit::decode(&hand_made_flags(&w, &[p(1), p(2)], 2, 2, &[0])),
            Err(CommitError::SideFlag)
        );
        assert_eq!(
            SignedCommit::decode(&hand_made_flags(&w, &[p(1)], 2, 3, &[0])),
            Err(CommitError::ReanchorFlag)
        );
        // A side commit without the bit, uploaded as one, is refused.
        let e2 = view.chain()[1];
        let frontier = *view.frontier().unwrap();
        let unmarked = Commit::on(ACCOUNT, FOLDER, &e2, w.content(b, 8, G1))
            .sign(&w.b.identity)
            .unwrap();
        let m = Commit::merge(ACCOUNT, FOLDER, &frontier, &unmarked, w.content(b, 9, G1))
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, G1, &[side(&unmarked, 4), head(&m, 4)])
                .unwrap_err(),
            ChainError::SideRule
        );
        // Flipping the bit after signing breaks the signature.
        let s = Commit::side(ACCOUNT, FOLDER, &e2, w.content(b, 10, G1))
            .sign(&w.b.identity)
            .unwrap();
        let mut forged = s.commit.clone();
        forged.side = false;
        let mut wire = forged.body();
        wire.extend_from_slice(s.signature.as_bytes());
        assert_eq!(
            SignedCommit::decode(&wire)
                .unwrap()
                .verify_signer(&w.state, &FOLDER),
            Err(CommitError::Signature)
        );
    }

    #[test]
    fn nothing_goes_back_from_a_side_commits_base() {
        let mut w = world();
        let (a, b) = (w.a.id, w.b.id);
        let g2 = Generation(2);
        let (view, _) = linear(&mut w);
        let old_head = w.state.head().unwrap();
        let n = dev(8);
        let entry = w
            .state
            .next_entry(
                &w.a.identity,
                a,
                0,
                EntryKind::AddDevice(LogDevice::of(&n.identity, &ACCOUNT, n.id, false)),
            )
            .unwrap();
        w.state.apply(&entry).unwrap();
        // c4 on the frontier names the newer log head and generation 2.
        let c4 = Commit::on(
            ACCOUNT,
            FOLDER,
            view.frontier().unwrap(),
            w.content(a, 4, g2),
        )
        .sign(&w.a.identity)
        .unwrap();
        let view = view
            .verify_delta(&w.state, g2, &[head(&c4, 4)])
            .unwrap()
            .view;
        let e4 = *view.frontier().unwrap();
        let merge_on = |w: &mut World, s: &SignedCommit| {
            Commit::merge(ACCOUNT, FOLDER, &e4, s, w.content(b, 21, g2))
                .sign(&w.b.identity)
                .unwrap()
        };
        let older_generation = Commit::side(ACCOUNT, FOLDER, &e4, w.content(b, 20, G1))
            .sign(&w.b.identity)
            .unwrap();
        let m = merge_on(&mut w, &older_generation);
        assert_eq!(
            view.verify_delta(&w.state, g2, &[side(&older_generation, 5), head(&m, 5)])
                .unwrap_err(),
            ChainError::SideRule
        );
        let mut content = w.content(b, 22, g2);
        content.log_head = old_head;
        let older_log = Commit::side(ACCOUNT, FOLDER, &e4, content)
            .sign(&w.b.identity)
            .unwrap();
        let m = merge_on(&mut w, &older_log);
        assert_eq!(
            view.verify_delta(&w.state, g2, &[side(&older_log, 5), head(&m, 5)])
                .unwrap_err(),
            ChainError::SideRule
        );
        let fine = Commit::side(ACCOUNT, FOLDER, &e4, w.content(b, 23, g2))
            .sign(&w.b.identity)
            .unwrap();
        let m = merge_on(&mut w, &fine);
        assert!(view
            .verify_delta(&w.state, g2, &[side(&fine, 5), head(&m, 5)])
            .is_ok());
    }

    #[test]
    fn a_removed_signers_head_needs_a_later_barrier() {
        let mut w = world();
        let (a, b) = (w.a.id, w.b.id);
        let g2 = Generation(2);
        let (view, _) = linear(&mut w);
        // b's head names the log before its removal, as a leaked key could after it.
        let c4 = Commit::on(
            ACCOUNT,
            FOLDER,
            view.frontier().unwrap(),
            w.content(b, 4, G1),
        )
        .sign(&w.b.identity)
        .unwrap();
        assert!(view.verify_delta(&w.state, G1, &[head(&c4, 4)]).is_ok());
        assert_eq!(c4.verify_for_server(&w.state, &FOLDER), Ok(()));
        let removal = crate::epoch::remove_devices(
            &w.state,
            &w.a.identity,
            a,
            0,
            &[b],
            &mut crate::entropy::OsEntropy,
        )
        .unwrap();
        w.state = removal.state;
        let removed_at = 4;
        assert_eq!(w.state.device(&b).unwrap().removed_at, Some(removed_at));

        // Without a barrier: refused by devices, and by the server at once.
        assert_eq!(
            view.verify_delta(&w.state, g2, &[head(&c4, 4)])
                .unwrap_err(),
            ChainError::RemovedSigner
        );
        assert_eq!(
            c4.verify_for_server(&w.state, &FOLDER),
            Err(CommitError::SignerRemoved)
        );
        // A later head of b itself is no barrier, also backdated.
        let before_removal = LogHead {
            index: 3,
            hash: *w.state.hash_at(3).unwrap(),
        };
        let mut content = w.content(b, 5, G1);
        content.log_head = before_removal;
        let c5 = Commit::on(ACCOUNT, FOLDER, &ChainEntry::of(&c4, 4), content)
            .sign(&w.b.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, g2, &[head(&c4, 4), head(&c5, 5)])
                .unwrap_err(),
            ChainError::RemovedSigner
        );
        // A head of a current device that names a log head before the removal is no barrier.
        let mut early = w.content(a, 6, G1);
        early.log_head = LogHead {
            index: 3,
            hash: *w.state.hash_at(3).unwrap(),
        };
        let not_barrier = Commit::on(ACCOUNT, FOLDER, &ChainEntry::of(&c4, 4), early)
            .sign(&w.a.identity)
            .unwrap();
        assert_eq!(
            view.verify_delta(&w.state, g2, &[head(&c4, 4), head(&not_barrier, 5)])
                .unwrap_err(),
            ChainError::RemovedSigner
        );

        // The removing device verifies the delta before its barrier and writes the barrier on
        // the head it found: same tree, new log head and generation.
        let before = view
            .verify_delta_before_barrier(&w.state, g2, &[head(&c4, 4)])
            .unwrap();
        assert_eq!(before.heads, vec![c4.clone()]);
        let counter = w.content(a, 0, g2).counter;
        let barrier = Commit::barrier(&c4, 4, g2, a, w.state.head().unwrap(), counter)
            .sign(&w.a.identity)
            .unwrap();
        assert_eq!(barrier.commit.root, c4.commit.root);
        assert_eq!(barrier.commit.parents, vec![c4.id]);
        assert_eq!(barrier.commit.log_head.index, 5);
        assert_eq!(barrier.verify_for_server(&w.state, &FOLDER), Ok(()));
        let published = view
            .accept_published(&w.state, g2, &barrier, None, 5)
            .unwrap_err();
        assert_eq!(
            published,
            ChainError::OlderState,
            "c4 is not on the view yet"
        );
        // Every device takes c4 in together with the barrier after it.
        let outcome = view
            .verify_delta(&w.state, g2, &[head(&c4, 4), head(&barrier, 5)])
            .unwrap();
        assert_eq!(outcome.view.frontier().unwrap().commit, barrier.id);
        // A head of the removed device after the barrier goes back in the log and is refused.
        let late = Commit::on(
            ACCOUNT,
            FOLDER,
            outcome.view.frontier().unwrap(),
            w.content(b, 7, G1),
        )
        .sign(&w.b.identity)
        .unwrap();
        assert!(outcome
            .view
            .verify_delta(&w.state, g2, &[head(&late, 6)])
            .is_err());
    }

    #[test]
    fn discarded_heads_never_come_back() {
        let mut w = world();
        let (a, b) = (w.a.id, w.b.id);
        let (view, commits) = linear(&mut w);
        let e2 = view.chain()[1];
        let c3b = Commit::on(ACCOUNT, FOLDER, &e2, w.content(b, 30, G1))
            .sign(&w.b.identity)
            .unwrap();
        let base = view.reanchor_base(&w.state, G1, &[head(&c3b, 3)]).unwrap();
        let own = Commit::reanchor(ACCOUNT, FOLDER, &base.head, w.content(a, 31, G1))
            .sign(&w.a.identity)
            .unwrap();
        let anchored = view.apply_reanchor(&w.state, G1, &base, &own, 4).unwrap();
        assert!(anchored.discarded().contains(&commits[2].id));
        assert_eq!(anchored.discarded().len(), 1);
        // The old c3 as a segment head of another re-anchor, or in a delta.
        assert_eq!(
            anchored
                .reanchor_base(&w.state, G1, &[head(&commits[2], 5)])
                .unwrap_err(),
            ChainError::Discarded
        );
        assert_eq!(
            anchored
                .verify_delta(&w.state, G1, &[head(&commits[2], 5)])
                .unwrap_err(),
            ChainError::Discarded
        );
        // Stored and restored with the view.
        let restored = FolderView::restore(
            ACCOUNT,
            FOLDER,
            anchored.chain().to_vec(),
            anchored.marks().clone(),
            anchored.discarded().clone(),
        )
        .unwrap();
        assert_eq!(restored, anchored);
        let mut bad = anchored.discarded().clone();
        bad.insert(own.id);
        assert_eq!(
            FolderView::restore(
                ACCOUNT,
                FOLDER,
                anchored.chain().to_vec(),
                anchored.marks().clone(),
                bad
            ),
            Err(ChainError::InvalidView)
        );
    }

    #[test]
    fn counter_resumes() {
        let mut counter = CommitCounter::resume(5);
        assert_eq!(counter.take(), Some(6));
        assert_eq!(counter.last(), 6);
        assert_eq!(CommitCounter::resume(u64::MAX).take(), None);
    }
}
