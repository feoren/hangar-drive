//! Wire types of the server API (ADR 0001, sections 3 and 6), all JSON under `/api/v1`.
//!
//! Requests refuse unknown fields, so a typo is an error and not a silently ignored value.
//! Replies ignore unknown fields, so a newer server can add some without breaking an older app.
//! Binary values travel as [`Blob`] (base64url); their formats are checked by
//! `hangar-drive-crypto`, never trusted from JSON alone. Every request with lists has a
//! `validate` method that checks counts and duplicates; the server calls it before anything
//! else.
//!
//! | Method and path | Request | Reply |
//! | --- | --- | --- |
//! | `POST /api/v1/accounts` | [`CreateAccountRequest`] | [`CreateAccountResponse`] |
//! | `POST /api/v1/session/challenge` | [`ChallengeRequest`] | [`ChallengeResponse`] |
//! | `POST /api/v1/session/proof` | [`ProofRequest`] | [`SessionResponse`] |
//! | `GET /api/v1/account/log?after=N` | | [`LogPage`] |
//! | `POST /api/v1/account/log` | [`LogAppendRequest`] | [`LogAppendResponse`] |
//! | `GET /api/v1/account/epochs/{epoch}/key` | | [`WrappedKeyResponse`] |
//! | `GET`, `PUT /api/v1/account/records/{kind}[/{folder}]` | [`RecordPut`] | [`RecordResponse`] |
//! | `GET /api/v1/account/feed?after=N` | | [`FeedPage`] |
//! | `GET /api/v1/account/events` (SSE) | | [`SequenceEvent`] per event |
//! | `PUT /api/v1/pairing/{pairing id}` | | [`PairingReservation`] |
//! | `POST /api/v1/pairing/{pairing id}` | [`PairingRequest`] | `204` |
//! | `GET /api/v1/pairing/{pairing id}` | | [`PairingRequest`] |
//! | `DELETE /api/v1/pairing/{pairing id}` | | `204` |
//! | `POST /api/v1/folders/{folder}/objects/missing` | [`MissingObjectsRequest`] | [`MissingObjectsResponse`] |
//! | `PUT /api/v1/folders/{folder}/objects/{id}` | object bytes | [`UploadResponse`] |
//! | `GET /api/v1/folders/{folder}/objects/{id}` | | object bytes |
//! | `POST /api/v1/folders/{folder}/commit` | [`CommitRequest`] | [`CommitResponse`] |
//! | `GET /api/v1/folders/{folder}/commits?after=N` | | [`DeltaPage`] |
//! | `POST /api/v1/folders/{folder}/retire` | | `204` |
//! | `DELETE /api/v1/folders/{folder}/retire` (brings a retired folder back) | | `204` |
//!
//! Every error reply is an [`ErrorBody`] with the HTTP status of [`ErrorCode::http_status`].
//! Tokens travel only in the `Authorization: Bearer` header, never in a path or query.
//!
//! # Session scopes
//!
//! A session of a regular device may make every call. A session of a recovery device
//! ([`SessionScope::Recovery`]) may make exactly these, and the server refuses every other one
//! with [`ErrorCode::Forbidden`]:
//!
//! - `GET /api/v1/account/log`;
//! - `GET /api/v1/account/epochs/{epoch}/key` for every epoch, which answers only with the
//!   recovery device's own wrapped key;
//! - one `POST /api/v1/account/log` in the life of the session, with exactly one entry and the
//!   new device's wrapped key ([`SessionScope::check_append`]). The device log verifier then
//!   checks that a recovery device's entry adds a regular device and nothing else.
//!
//! That is the one step of a recovery (ADR 0001, section 4): the new installation, once added,
//! removes the lost devices and the used recovery device and rotates the epoch.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ids::{
    AccountId, Blob, Challenge, CommitId, DeviceId, Epoch, FolderId, InviteToken, LogHead,
    ObjectId, PairingId, PublicKey, ServerId, SessionToken, Signature,
};

/// Prefix of every path of this protocol version.
pub const API_PREFIX: &str = "/api/v1";
/// `POST`: create an account with an invite.
pub const ACCOUNTS_PATH: &str = "/api/v1/accounts";
/// `POST`: ask for a session challenge.
pub const CHALLENGE_PATH: &str = "/api/v1/session/challenge";
/// `POST`: answer the challenge and get a session token.
pub const PROOF_PATH: &str = "/api/v1/session/proof";
/// `GET` with `?after=N`: device log entries after index N. `POST`: append entries.
pub const LOG_PATH: &str = "/api/v1/account/log";
/// `GET` with `?after=N`: account change feed after sequence N.
pub const FEED_PATH: &str = "/api/v1/account/feed";
/// `GET`: the account's SSE stream of [`SequenceEvent`].
pub const EVENTS_PATH: &str = "/api/v1/account/events";

/// Path of this device's wrapped secret of `epoch`.
pub fn epoch_key_path(epoch: Epoch) -> String {
    format!("{API_PREFIX}/account/epochs/{}/key", epoch.0)
}

/// Path of an account record.
pub fn record_path(key: &RecordKey) -> String {
    match key.folder {
        Some(folder) => format!("{API_PREFIX}/account/records/{}/{folder}", key.kind.label()),
        None => format!("{API_PREFIX}/account/records/{}", key.kind.label()),
    }
}

/// Path of a pairing slot: `PUT` reserves it (the inviting device, with its session), `POST`
/// fills it once (the new device, without a session), `GET` reads it (the reserving account).
pub fn pairing_path(pairing: &PairingId) -> String {
    format!("{API_PREFIX}/pairing/{pairing}")
}

/// Path of `objects/missing` of a folder.
pub fn missing_objects_path(folder: &FolderId) -> String {
    format!("{API_PREFIX}/folders/{folder}/objects/missing")
}

/// Path of one object of a folder.
pub fn object_path(folder: &FolderId, id: &ObjectId) -> String {
    format!("{API_PREFIX}/folders/{folder}/objects/{id}")
}

/// Path of a folder's commit call.
pub fn commit_path(folder: &FolderId) -> String {
    format!("{API_PREFIX}/folders/{folder}/commit")
}

/// Path of a folder's delta pull.
pub fn commits_path(folder: &FolderId) -> String {
    format!("{API_PREFIX}/folders/{folder}/commits")
}

/// Path of a folder's retire call.
pub fn retire_path(folder: &FolderId) -> String {
    format!("{API_PREFIX}/folders/{folder}/retire")
}

/// Object IDs one `objects/missing` call may ask about.
pub const MAX_MISSING_QUERY: usize = 4096;
/// Object IDs one reference delta may list, added and dropped together.
pub const MAX_REFERENCE_DELTA_IDS: usize = 1 << 20;
/// Log entries one append call may carry: removals and the rotation that must follow them in
/// the same call, or one added device.
pub const MAX_APPEND_ENTRIES: usize = 16;
/// Bytes of one wrapped epoch secret (`hangar-drive-crypto`, `epoch`).
pub const WRAPPED_KEY_LEN: usize = 81;
/// Wrapped keys one append call may carry: one per device of the account.
pub const MAX_WRAPPED_KEYS: usize = 64;
/// Log entries one log page holds.
pub const MAX_LOG_PAGE: usize = 512;
/// Commits one delta page holds.
pub const MAX_DELTA_PAGE: usize = 512;
/// Entries one feed page holds.
pub const MAX_FEED_PAGE: usize = 512;
/// Bytes of a device name in a pairing request (UTF-8).
pub const MAX_DEVICE_NAME_LEN: usize = 128;

/// Why a request was refused before it reached any logic.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RequestError {
    /// More items than the protocol allows.
    #[error("the request lists too many items")]
    TooMany,
    /// A list that must not be empty is.
    #[error("the request lists nothing")]
    Empty,
    /// The same ID twice in a list.
    #[error("the request lists an id twice")]
    Duplicate,
    /// A field outside its allowed range.
    #[error("a field of the request is out of range")]
    Invalid,
}

fn unique<T: Ord>(items: impl IntoIterator<Item = T>) -> Result<(), RequestError> {
    let mut seen = BTreeSet::new();
    for item in items {
        if !seen.insert(item) {
            return Err(RequestError::Duplicate);
        }
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------
// Accounts and sessions
// ------------------------------------------------------------------------------------------

/// Creates an account: the operator's invite, the new account ID and the device log's first
/// entry, which lists the creating device.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAccountRequest {
    /// Single use, expiring.
    pub invite: InviteToken,
    /// Chosen by the client at random; the server refuses a duplicate.
    pub account: AccountId,
    /// Entry 1 of the device log (create).
    pub genesis: Blob,
}

/// The created account's server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAccountResponse {
    /// The server's ID, which the client pins.
    pub server: ServerId,
}

/// Asks for a challenge to sign in as `device` of `account`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    /// The account.
    pub account: AccountId,
    /// The device that signs in.
    pub device: DeviceId,
}

/// A fresh challenge, valid once and for a short time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The server's ID, part of the signed statement.
    pub server: ServerId,
    /// 32 random bytes.
    pub challenge: Challenge,
    /// Seconds until the challenge expires.
    pub expires_in_secs: u32,
}

/// The device's signature over the session statement (`hangar-drive-crypto`, `session`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofRequest {
    /// The account.
    pub account: AccountId,
    /// The device that signs in.
    pub device: DeviceId,
    /// The challenge it answers.
    pub challenge: Challenge,
    /// The base URL the device connects to (`hangar_drive_crypto::session::base_url`), part of
    /// the signed statement. A server with a public URL refuses every other one, so a host that
    /// relays a sign-in under the real server ID cannot hand on the session.
    pub server_url: String,
    /// Ed25519 signature with the device's key from the account log.
    pub signature: Signature,
    /// The length of the device log this device verified (its head's index). Not part of the
    /// signed statement and only a hint: a server that answers [`ErrorCode::DeviceRemoved`]
    /// sends the entries after it up to the removal ([`ErrorBody::removal_log`]), which the
    /// device checks from its own verified head (security review H2). A wrong value only costs
    /// the device the automatic forgetting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_length: Option<u64>,
}

/// A session: the bearer token and its lifetime.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionResponse {
    /// Sent as `Authorization: Bearer <token>`; the server keeps only its SHA-256.
    pub token: SessionToken,
    /// Seconds until the token expires (about an hour); renewed by a new proof.
    pub expires_in_secs: u32,
}

// ------------------------------------------------------------------------------------------
// Device log, epochs, records
// ------------------------------------------------------------------------------------------

/// Device log entries in order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogPage {
    /// Index of the first entry in `entries` (from 1).
    pub first_index: u64,
    /// The entries, at most [`MAX_LOG_PAGE`].
    pub entries: Vec<Blob>,
    /// The log's length on the server.
    pub length: u64,
}

/// One device's wrapped epoch secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrappedKeyEntry {
    /// The recipient.
    pub device: DeviceId,
    /// The wrapped key (81 bytes).
    pub data: Blob,
}

/// Appends entries to the device log in one transaction. The server admits the entries as one
/// batch (`hangar-drive-crypto`, `AccountState::admit_batch`), which allows exactly two shapes:
///
/// - **Rotation:** zero or more removals, then one rotate entry, with a wrapped key in `wraps`
///   for every device that is current after the batch, recovery devices included. A removal
///   therefore always comes with its rotation in the same call.
/// - **Added device:** one add device entry with `device_wrap`, the wrapped secret of the
///   current epoch for the new device (none while the account has no epoch yet). Adding a
///   device does not rotate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogAppendRequest {
    /// The entries in order, 1 to [`MAX_APPEND_ENTRIES`].
    pub entries: Vec<Blob>,
    /// Wrapped keys of the rotation among `entries`, if any.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wraps: Vec<WrappedKeyEntry>,
    /// The new device's wrapped key of the current epoch, with an add device entry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_wrap: Option<WrappedKeyEntry>,
}

impl LogAppendRequest {
    /// Counts, wrapped key sizes, duplicate recipients, and never both kinds of wrapped keys.
    /// Which entries the batch holds and whether the wrapped keys fit them is checked by the
    /// device log verifier and `hangar-drive-crypto::epoch::append_wraps_fit`.
    pub fn validate(&self) -> Result<(), RequestError> {
        if self.entries.is_empty() {
            return Err(RequestError::Empty);
        }
        if self.entries.len() > MAX_APPEND_ENTRIES || self.wraps.len() > MAX_WRAPPED_KEYS {
            return Err(RequestError::TooMany);
        }
        if !self.wraps.is_empty() && self.device_wrap.is_some() {
            return Err(RequestError::Invalid);
        }
        if self
            .wraps
            .iter()
            .chain(self.device_wrap.iter())
            .any(|w| w.data.0.len() != WRAPPED_KEY_LEN)
        {
            return Err(RequestError::Invalid);
        }
        unique(self.wraps.iter().map(|w| w.device))
    }
}

/// Why a session's scope refused a call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ScopeError {
    /// The call is outside the session's scope.
    #[error("this session may not make this call")]
    NotAllowed,
    /// A recovery session already made its one append.
    #[error("this recovery session already added its device")]
    AppendUsed,
    /// A recovery append must carry exactly one entry and the new device's wrapped key.
    #[error("a recovery session may only add one regular device")]
    AppendShape,
}

/// The calls of the API, for the session scope (module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiCall {
    /// `GET /api/v1/account/log`.
    GetLog,
    /// `POST /api/v1/account/log`.
    AppendLog,
    /// `GET /api/v1/account/epochs/{epoch}/key`: the session device's own wrapped key.
    GetOwnEpochKey,
    /// `GET /api/v1/account/records/...`.
    GetRecord,
    /// `PUT /api/v1/account/records/...`.
    PutRecord,
    /// `GET /api/v1/account/feed`.
    GetFeed,
    /// `GET /api/v1/account/events`.
    Events,
    /// `PUT /api/v1/pairing/{pairing id}`: the inviting device reserves the slot before it
    /// shows the offer; a new device can post only into a reserved, empty slot.
    ReservePairing,
    /// `GET /api/v1/pairing/{pairing id}` (the inviting device fetches the request).
    GetPairing,
    /// `DELETE /api/v1/pairing/{pairing id}`: the inviting device closes its slot once the
    /// person answered the request, so the request does not wait on the server until it expires.
    ClosePairing,
    /// `POST /api/v1/folders/{folder}/objects/missing`.
    MissingObjects,
    /// `PUT /api/v1/folders/{folder}/objects/{id}`.
    PutObject,
    /// `GET /api/v1/folders/{folder}/objects/{id}`.
    GetObject,
    /// `POST /api/v1/folders/{folder}/commit`.
    Commit,
    /// `GET /api/v1/folders/{folder}/commits`.
    GetCommits,
    /// `POST /api/v1/folders/{folder}/retire`, and `DELETE` on the same path, which brings a
    /// retired folder back: one folder lifecycle call.
    Retire,
}

/// What a session may do (module docs). The server sets it at sign-in from the verified device
/// log (recovery device or not) and keeps it with the session's token hash. Calls without a
/// session (creating an account, the challenge and proof, a new device's pairing request) are
/// outside every scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionScope {
    /// A regular device: every call.
    Device,
    /// A recovery device: the log, its own wrapped keys and one append.
    Recovery {
        /// The one append was made.
        appended: bool,
    },
}

impl SessionScope {
    /// The scope of a device that signs in; `recovery` comes from the verified device log.
    pub const fn for_device(recovery: bool) -> Self {
        if recovery {
            SessionScope::Recovery { appended: false }
        } else {
            SessionScope::Device
        }
    }

    /// Whether the session may make `call` at all. An append of a recovery session also needs
    /// [`SessionScope::check_append`].
    pub const fn allows(self, call: ApiCall) -> bool {
        match self {
            SessionScope::Device => true,
            SessionScope::Recovery { appended } => match call {
                ApiCall::GetLog | ApiCall::GetOwnEpochKey => true,
                ApiCall::AppendLog => !appended,
                _ => false,
            },
        }
    }

    /// Checks an append of this session before the device log verifier sees it: a recovery
    /// session appends once, exactly one entry with the new device's wrapped key.
    pub fn check_append(self, request: &LogAppendRequest) -> Result<(), ScopeError> {
        match self {
            SessionScope::Device => Ok(()),
            SessionScope::Recovery { appended: true } => Err(ScopeError::AppendUsed),
            SessionScope::Recovery { appended: false } => {
                if request.entries.len() != 1
                    || !request.wraps.is_empty()
                    || request.device_wrap.is_none()
                {
                    return Err(ScopeError::AppendShape);
                }
                Ok(())
            }
        }
    }

    /// Records an accepted append. The server calls it in the transaction that stores the
    /// entry, so a recovery session cannot append twice.
    pub fn record_append(&mut self) {
        if let SessionScope::Recovery { appended } = self {
            *appended = true;
        }
    }

    /// [`SessionScope::allows`] as a result.
    pub const fn require(self, call: ApiCall) -> Result<(), ScopeError> {
        if self.allows(call) {
            Ok(())
        } else {
            Err(ScopeError::NotAllowed)
        }
    }
}

/// The log after an append.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogAppendResponse {
    /// The new head.
    pub head: LogHead,
}

/// This device's wrapped secret of one epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedKeyResponse {
    /// The epoch.
    pub epoch: Epoch,
    /// The wrapped key (81 bytes).
    pub data: Blob,
}

/// What a sealed account record is. Part of the record's associated data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RecordKind {
    /// A folder's key ring (record ID: the folder).
    #[serde(rename = "folder-keys")]
    FolderKeys,
    /// The account's folder list with names.
    #[serde(rename = "folders")]
    Folders,
    /// Names of the account's devices.
    #[serde(rename = "device-names")]
    DeviceNames,
}

impl RecordKind {
    /// The label in paths and associated data.
    pub const fn label(self) -> &'static str {
        match self {
            RecordKind::FolderKeys => "folder-keys",
            RecordKind::Folders => "folders",
            RecordKind::DeviceNames => "device-names",
        }
    }

    /// Whether records of this kind belong to one folder.
    pub const fn per_folder(self) -> bool {
        matches!(self, RecordKind::FolderKeys)
    }
}

/// Which record: a kind and, for per-folder kinds, the folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordKey {
    /// The kind.
    pub kind: RecordKind,
    /// The folder, exactly for per-folder kinds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub folder: Option<FolderId>,
}

impl RecordKey {
    /// The key of `kind` for `folder`; `None` if the kind needs a folder and none is given or
    /// the other way round.
    pub fn new(kind: RecordKind, folder: Option<FolderId>) -> Option<Self> {
        (kind.per_folder() == folder.is_some()).then_some(Self { kind, folder })
    }

    /// The record ID bytes in the associated data: the folder's 16 bytes, or empty.
    pub fn id_bytes(&self) -> Vec<u8> {
        self.folder
            .map(|f| f.as_bytes().to_vec())
            .unwrap_or_default()
    }
}

/// Stores a new version of a record. The server accepts only `version` = its version + 1
/// (compare and swap), so two devices cannot both write one version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordPut {
    /// The record's new version, from 1.
    pub version: u64,
    /// The sealed record.
    pub data: Blob,
}

/// A stored record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordResponse {
    /// Which record.
    pub key: RecordKey,
    /// Its version.
    pub version: u64,
    /// The sealed record.
    pub data: Blob,
}

// ------------------------------------------------------------------------------------------
// Pairing
// ------------------------------------------------------------------------------------------

/// A new device's request to join, routed by the pairing ID. `tag` is the HMAC under the
/// pairing secret, which the server never learns, and the device name travels sealed under a
/// key derived from the same secret (`hangar_drive_crypto::pairing`), so the server never sees
/// it either: device names are sealed records everywhere else (ADR 0001, section 4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PairingRequest {
    /// The new device's ID.
    pub device: DeviceId,
    /// Its Ed25519 key.
    pub sign: PublicKey,
    /// Its X25519 key.
    pub kem: PublicKey,
    /// Its proof of possession.
    pub proof: Signature,
    /// Its name, shown in `Add device <name>?`, sealed: a 24-byte nonce, then the
    /// XChaCha20-Poly1305 ciphertext of the UTF-8 name with its 16-byte tag.
    pub sealed_name: Blob,
    /// HMAC-SHA-256 under the pairing MAC key.
    pub tag: Blob,
}

/// Bytes a sealed device name adds to its padded part: the nonce and the AEAD tag.
pub const SEALED_NAME_OVERHEAD: usize = 24 + 16;
/// The padded part of the shortest sealed name: the Padmé length of an 8-byte length and one
/// byte of name (security review N13; checked against the crypto crate's Padmé by its tests).
pub const SEALED_NAME_MIN_PADDED: usize = 10;
/// The padded part of the longest sealed name: the Padmé length of an 8-byte length and
/// [`MAX_DEVICE_NAME_LEN`] bytes of name.
pub const SEALED_NAME_MAX_PADDED: usize = 144;

/// Reserved pairing slots one account may hold at a time.
pub const MAX_OPEN_PAIRINGS: usize = 4;

/// The reply to `PUT /api/v1/pairing/{pairing id}`: the slot is reserved for the session's
/// account until it expires with the offer. Reserving it again from the same account is
/// idempotent; a slot of another account is [`ErrorCode::AlreadyExists`], and more than
/// [`MAX_OPEN_PAIRINGS`] open slots are [`ErrorCode::RateLimited`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingReservation {
    /// Seconds until the slot expires.
    pub expires_in_secs: u32,
}

impl PairingRequest {
    /// The sizes of the sealed name (one to [`MAX_DEVICE_NAME_LEN`] bytes of name, padded) and
    /// of the tag. The name itself and its padding are checked by the inviting device once it
    /// opened it ([`crate::name::check_display_name`]); the server cannot read it.
    pub fn validate(&self) -> Result<(), RequestError> {
        let names = SEALED_NAME_OVERHEAD + SEALED_NAME_MIN_PADDED
            ..=SEALED_NAME_OVERHEAD + SEALED_NAME_MAX_PADDED;
        if !names.contains(&self.sealed_name.0.len()) || self.tag.0.len() != 32 {
            return Err(RequestError::Invalid);
        }
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------
// Objects and commits
// ------------------------------------------------------------------------------------------

/// Which of these objects does the server lack in the folder?
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MissingObjectsRequest {
    /// 1 to [`MAX_MISSING_QUERY`] distinct IDs.
    pub ids: Vec<ObjectId>,
}

impl MissingObjectsRequest {
    /// Counts and duplicates.
    pub fn validate(&self) -> Result<(), RequestError> {
        if self.ids.is_empty() {
            return Err(RequestError::Empty);
        }
        if self.ids.len() > MAX_MISSING_QUERY {
            return Err(RequestError::TooMany);
        }
        unique(self.ids.iter())
    }
}

/// The IDs of the request the server does not hold, in request order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissingObjectsResponse {
    /// The missing IDs.
    pub missing: Vec<ObjectId>,
}

/// The reply to an upload. The upload is idempotent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UploadResponse {
    /// False if the server already held the object.
    pub stored: bool,
}

/// Object IDs a commit adds and drops relative to its first parent, in the clear, for
/// retention and garbage collection.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceDelta {
    /// Objects reachable now that were not from the first parent.
    pub added: Vec<ObjectId>,
    /// Objects reachable from the first parent that are not now.
    pub dropped: Vec<ObjectId>,
}

impl ReferenceDelta {
    /// Counts, duplicates, and no ID both added and dropped.
    pub fn validate(&self) -> Result<(), RequestError> {
        if self.added.len().saturating_add(self.dropped.len()) > MAX_REFERENCE_DELTA_IDS {
            return Err(RequestError::TooMany);
        }
        unique(self.added.iter().chain(self.dropped.iter()))
    }
}

/// One signed commit with its reference delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitUpload {
    /// The commit's wire bytes (body and signature).
    pub commit: Blob,
    /// Relative to the commit's first parent.
    pub delta: ReferenceDelta,
}

/// The atomic commit call: compare and swap on the folder's head.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitRequest {
    /// The head the device expects; `None` only for the folder's first commit.
    pub expected_head: Option<CommitId>,
    /// The new head.
    pub head: CommitUpload,
    /// The device's side commit, only together with a merge commit that names it as second
    /// parent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub side: Option<CommitUpload>,
}

impl CommitRequest {
    /// The reference deltas.
    pub fn validate(&self) -> Result<(), RequestError> {
        self.head.delta.validate()?;
        if let Some(side) = &self.side {
            side.delta.validate()?;
        }
        Ok(())
    }
}

/// The accepted commit call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitResponse {
    /// The new head.
    pub head: CommitId,
    /// The folder sequence of the call.
    pub sequence: u64,
}

/// Whether a commit of a delta page is a head or a side commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitRole {
    /// Was the folder's head after its call.
    Head,
    /// A side commit, uploaded with the merge commit of the same sequence.
    Side,
}

/// One commit of a delta pull.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaCommit {
    /// The folder sequence of its call; a head and its side commit share it.
    pub sequence: u64,
    /// Head or side commit.
    pub role: CommitRole,
    /// The commit's wire bytes.
    pub commit: Blob,
}

/// Commits after a folder cursor, in sequence order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeltaPage {
    /// The commits, at most [`MAX_DELTA_PAGE`].
    pub commits: Vec<DeltaCommit>,
    /// The folder's current sequence.
    pub sequence: u64,
    /// More commits follow after the last one of this page.
    pub more: bool,
}

// ------------------------------------------------------------------------------------------
// Change feed and notices
// ------------------------------------------------------------------------------------------

/// The SSE event: only the account's new sequence. The client then pulls the feed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SequenceEvent {
    /// The account sequence.
    pub sequence: u64,
}

/// An account level change. The feed is only an index: everything it points to is verified.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FeedChange {
    /// The device log grew: fetch and verify the new entries from the anchor.
    DeviceLog {
        /// The log's new length.
        length: u64,
    },
    /// A new epoch: fetch the wrapped secret and check it against the log's commitment.
    Epoch {
        /// The epoch.
        epoch: Epoch,
    },
    /// A record changed: fetch it; the replay guard refuses an older version.
    Record {
        /// Which record.
        key: RecordKey,
        /// Its new version.
        version: u64,
    },
    /// A folder has a new head: pull the folder delta.
    FolderHead {
        /// The folder.
        folder: FolderId,
        /// Its new sequence.
        sequence: u64,
    },
    /// A folder was created: fetch the `folders` record.
    FolderCreated {
        /// The folder.
        folder: FolderId,
    },
    /// A folder was retired: fetch the `folders` record.
    FolderRetired {
        /// The folder.
        folder: FolderId,
    },
    /// A notice from the closed list of [`Notice`].
    Notice {
        /// The notice.
        notice: Notice,
    },
    /// A change type a newer server sends; this version skips it.
    #[serde(other)]
    Unknown,
}

/// A notice the app shows in its own words. The server sends no free text, so it cannot put
/// its own words into the app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Notice {
    /// A burst of replaced or dropped objects pinned the last commit before it.
    AnomalyPin {
        /// The folder.
        folder: FolderId,
        /// The pinned commit.
        commit: CommitId,
        /// When the pin ends, milliseconds since the Unix epoch (server time).
        until_ms: u64,
    },
    /// Live bytes are near or above the account quota.
    QuotaWarning {
        /// Live bytes.
        live_bytes: u64,
        /// The quota.
        quota_bytes: u64,
    },
    /// Retained bytes exceed the account quota.
    RetainedOverQuota {
        /// Retained bytes.
        retained_bytes: u64,
        /// The quota.
        quota_bytes: u64,
    },
    /// The bytes that only trees held by the minimum commit count retain reached their cap;
    /// older trees beyond it expire as if there were no minimum count.
    MinimumCountCap {
        /// Bytes held only by the minimum count.
        held_bytes: u64,
        /// The cap.
        cap_bytes: u64,
    },
    /// A device reached its upload budget.
    DeviceBudget {
        /// The device.
        device: DeviceId,
    },
    /// The account reached its upload budget.
    AccountBudget,
    /// The server is below its free disk reserve and refuses uploads.
    DiskReserve,
    /// A notice kind a newer server sends; this version shows nothing for it.
    #[serde(other)]
    Unknown,
}

/// One feed entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedEntry {
    /// The account sequence of the change.
    pub sequence: u64,
    /// The change.
    pub change: FeedChange,
}

/// Feed entries after an account cursor. The server may return only the newest entry per kind
/// and key; the client applies log, epochs and records before folder heads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeedPage {
    /// The entries, at most [`MAX_FEED_PAGE`], by sequence.
    pub entries: Vec<FeedEntry>,
    /// The account's current sequence.
    pub sequence: u64,
    /// More entries follow.
    pub more: bool,
}

// ------------------------------------------------------------------------------------------
// Errors
// ------------------------------------------------------------------------------------------

/// The closed list of error codes. The app shows its own text per code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Malformed JSON, a failed `validate`, or a bad parameter.
    BadRequest,
    /// No valid session token.
    Unauthorized,
    /// The session's account does not own the resource, or the device may not do this.
    Forbidden,
    /// No such account, folder, object, record or pairing slot.
    NotFound,
    /// The invite is unknown, used or expired.
    InviteInvalid,
    /// The challenge is unknown, used or expired.
    ChallengeInvalid,
    /// The session proof does not verify.
    ProofInvalid,
    /// The session proof verifies with the key the account log last listed for this device,
    /// but the log removed the device. Only the device itself (or a holder of its key) can
    /// produce such a proof, so nobody else learns from this code whether a device was removed.
    /// The answer carries [`ErrorBody::removal_log`]; the device forgets the account only on a
    /// removal it verified there (ADR 0001, section 6, "Sessions").
    DeviceRemoved,
    /// The account, device or folder ID is already taken.
    AlreadyExists,
    /// A log entry the device log verifier refused.
    LogEntryRefused,
    /// A record version that is not the next one.
    RecordVersion,
    /// The compare and swap failed; [`ErrorBody::current_head`] names the head.
    HeadMoved,
    /// The side commit's base is no longer retained; publish the merge with one parent.
    BaseExpired,
    /// A commit the server's checks refused (signature, parents, height, counter, generation,
    /// log head).
    CommitRefused,
    /// A reference delta names objects the server does not hold; [`ErrorBody::missing`] lists
    /// some.
    MissingObjects,
    /// The folder is retired.
    FolderRetired,
    /// The upload would exceed the account quota.
    QuotaExceeded,
    /// The device's or the account's upload budget is used up.
    BudgetExceeded,
    /// The server is below its free disk reserve.
    DiskReserve,
    /// Too large a body or object.
    TooLarge,
    /// Too many requests.
    RateLimited,
    /// A server error; details only in the server's log.
    Internal,
    /// A code a newer server sends.
    #[serde(other)]
    Unknown,
}

impl ErrorCode {
    /// The HTTP status of the reply.
    pub const fn http_status(self) -> u16 {
        match self {
            ErrorCode::BadRequest
            | ErrorCode::LogEntryRefused
            | ErrorCode::CommitRefused
            | ErrorCode::MissingObjects => 400,
            ErrorCode::Unauthorized | ErrorCode::ChallengeInvalid | ErrorCode::ProofInvalid => 401,
            ErrorCode::Forbidden | ErrorCode::InviteInvalid | ErrorCode::DeviceRemoved => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::AlreadyExists
            | ErrorCode::RecordVersion
            | ErrorCode::HeadMoved
            | ErrorCode::BaseExpired => 409,
            ErrorCode::FolderRetired => 410,
            ErrorCode::TooLarge => 413,
            ErrorCode::RateLimited => 429,
            ErrorCode::QuotaExceeded | ErrorCode::BudgetExceeded | ErrorCode::DiskReserve => 507,
            ErrorCode::Internal | ErrorCode::Unknown => 500,
        }
    }
}

/// Every error reply.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    /// What went wrong.
    pub code: ErrorCode,
    /// With [`ErrorCode::HeadMoved`]: the current head (`None`: the folder has none yet).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_head: Option<CommitId>,
    /// With [`ErrorCode::MissingObjects`]: some of the missing IDs.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing: Vec<ObjectId>,
    /// With [`ErrorCode::DeviceRemoved`], only as the answer to the proof: the device log
    /// entries after [`ProofRequest::log_length`] up to and including the entry that removed
    /// the device, at most [`MAX_LOG_PAGE`] of them (security review H2). The device verifies
    /// them from its own verified head and forgets the account only if they hold a valid
    /// removal of itself; the server's word alone never makes it forget. The entries stop at
    /// the removal, so a removed device learns nothing the account did after it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal_log: Option<LogPage>,
}

impl ErrorBody {
    /// An error with only a code.
    pub fn new(code: ErrorCode) -> Self {
        Self {
            code,
            current_head: None,
            missing: Vec::new(),
            removal_log: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::LogHash;
    use serde_json::json;

    const F: &str = "0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f";

    fn folder() -> FolderId {
        FolderId::from_bytes([0x0f; 16])
    }

    #[test]
    fn paths() {
        assert_eq!(
            object_path(&folder(), &ObjectId::from_bytes([0; 32])),
            format!("/api/v1/folders/{F}/objects/{}", "00".repeat(32))
        );
        assert_eq!(
            missing_objects_path(&folder()),
            format!("/api/v1/folders/{F}/objects/missing")
        );
        assert_eq!(
            commit_path(&folder()),
            format!("/api/v1/folders/{F}/commit")
        );
        assert_eq!(
            commits_path(&folder()),
            format!("/api/v1/folders/{F}/commits")
        );
        assert_eq!(
            retire_path(&folder()),
            format!("/api/v1/folders/{F}/retire")
        );
        assert_eq!(epoch_key_path(Epoch(3)), "/api/v1/account/epochs/3/key");
        let ring = RecordKey::new(RecordKind::FolderKeys, Some(folder())).unwrap();
        assert_eq!(
            record_path(&ring),
            format!("/api/v1/account/records/folder-keys/{F}")
        );
        let list = RecordKey::new(RecordKind::Folders, None).unwrap();
        assert_eq!(record_path(&list), "/api/v1/account/records/folders");
        assert_eq!(
            pairing_path(&PairingId::from_bytes([1; 16])),
            format!("/api/v1/pairing/{}", "01".repeat(16))
        );
        assert!(LOG_PATH.starts_with(API_PREFIX) && FEED_PATH.starts_with(API_PREFIX));
        assert!(EVENTS_PATH.starts_with(API_PREFIX) && ACCOUNTS_PATH.starts_with(API_PREFIX));
        assert!(CHALLENGE_PATH.starts_with(API_PREFIX) && PROOF_PATH.starts_with(API_PREFIX));
    }

    #[test]
    fn record_keys_match_their_kind() {
        assert!(RecordKey::new(RecordKind::FolderKeys, None).is_none());
        assert!(RecordKey::new(RecordKind::Folders, Some(folder())).is_none());
        assert!(RecordKey::new(RecordKind::DeviceNames, None).is_some());
        let key = RecordKey::new(RecordKind::FolderKeys, Some(folder())).unwrap();
        assert_eq!(key.id_bytes(), vec![0x0f; 16]);
        assert!(RecordKey::new(RecordKind::Folders, None)
            .unwrap()
            .id_bytes()
            .is_empty());
        assert_eq!(
            serde_json::to_value(key).unwrap(),
            json!({ "kind": "folder-keys", "folder": F })
        );
    }

    #[test]
    fn commit_request_json_and_validation() {
        let id = ObjectId::from_bytes([1; 32]);
        let request = CommitRequest {
            expected_head: None,
            head: CommitUpload {
                commit: Blob(vec![1, 2]),
                delta: ReferenceDelta {
                    added: vec![id],
                    dropped: vec![],
                },
            },
            side: None,
        };
        let value = serde_json::to_value(&request).unwrap();
        assert_eq!(
            value,
            json!({
                "expected_head": null,
                "head": { "commit": "AQI", "delta": { "added": ["01".repeat(32)], "dropped": [] } }
            })
        );
        let back: CommitRequest = serde_json::from_value(value).unwrap();
        assert_eq!(back, request);
        assert_eq!(request.validate(), Ok(()));

        let mut twice = request.clone();
        twice.head.delta.dropped = vec![id];
        assert_eq!(twice.validate(), Err(RequestError::Duplicate));
        let mut side = request.clone();
        side.side = Some(CommitUpload {
            commit: Blob(vec![3]),
            delta: ReferenceDelta {
                added: vec![id, id],
                dropped: vec![],
            },
        });
        assert_eq!(side.validate(), Err(RequestError::Duplicate));
    }

    #[test]
    fn requests_refuse_unknown_fields() {
        let result = serde_json::from_value::<MissingObjectsRequest>(json!({
            "ids": [], "extra": 1
        }));
        assert!(result.is_err());
        let result = serde_json::from_value::<ChallengeRequest>(json!({
            "account": F, "device": F, "admin": true
        }));
        assert!(result.is_err());
    }

    #[test]
    fn replies_ignore_unknown_fields() {
        let page: DeltaPage = serde_json::from_value(json!({
            "commits": [{ "sequence": 1, "role": "side", "commit": "AA", "later": 1 }],
            "sequence": 1, "more": false, "later": true
        }))
        .unwrap();
        assert_eq!(page.commits[0].role, CommitRole::Side);
    }

    #[test]
    fn missing_objects_validation() {
        let id = |b| ObjectId::from_bytes([b; 32]);
        assert_eq!(
            MissingObjectsRequest { ids: vec![] }.validate(),
            Err(RequestError::Empty)
        );
        assert_eq!(
            MissingObjectsRequest {
                ids: vec![id(1), id(1)]
            }
            .validate(),
            Err(RequestError::Duplicate)
        );
        let many: Vec<ObjectId> = (0..=MAX_MISSING_QUERY)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&(i as u64).to_be_bytes());
                ObjectId::from_bytes(bytes)
            })
            .collect();
        assert_eq!(
            MissingObjectsRequest { ids: many }.validate(),
            Err(RequestError::TooMany)
        );
        assert_eq!(
            MissingObjectsRequest { ids: vec![id(1)] }.validate(),
            Ok(())
        );
    }

    #[test]
    fn log_append_validation() {
        let wrap = |b| WrappedKeyEntry {
            device: DeviceId::from_bytes([b; 16]),
            data: Blob(vec![0; 81]),
        };
        let ok = LogAppendRequest {
            entries: vec![Blob(vec![1])],
            wraps: vec![wrap(1), wrap(2)],
            device_wrap: None,
        };
        assert_eq!(ok.validate(), Ok(()));
        let dup = LogAppendRequest {
            wraps: vec![wrap(1), wrap(1)],
            ..ok.clone()
        };
        assert_eq!(dup.validate(), Err(RequestError::Duplicate));
        let empty = LogAppendRequest {
            entries: vec![],
            wraps: vec![],
            device_wrap: None,
        };
        assert_eq!(empty.validate(), Err(RequestError::Empty));
        let many = LogAppendRequest {
            entries: vec![Blob(vec![1]); MAX_APPEND_ENTRIES + 1],
            wraps: vec![],
            device_wrap: None,
        };
        assert_eq!(many.validate(), Err(RequestError::TooMany));
        // Wraps are optional in JSON.
        let parsed: LogAppendRequest =
            serde_json::from_value(json!({ "entries": ["AQ"] })).unwrap();
        assert!(parsed.wraps.is_empty() && parsed.device_wrap.is_none());
        // An added device carries one wrapped key of the current epoch, never with rotation
        // wraps, and every wrapped key has the exact size.
        let add = LogAppendRequest {
            entries: vec![Blob(vec![1])],
            wraps: vec![],
            device_wrap: Some(wrap(3)),
        };
        assert_eq!(add.validate(), Ok(()));
        let both = LogAppendRequest {
            wraps: vec![wrap(1)],
            ..add.clone()
        };
        assert_eq!(both.validate(), Err(RequestError::Invalid));
        let short = LogAppendRequest {
            device_wrap: Some(WrappedKeyEntry {
                device: DeviceId::from_bytes([3; 16]),
                data: Blob(vec![0; WRAPPED_KEY_LEN - 1]),
            }),
            ..add.clone()
        };
        assert_eq!(short.validate(), Err(RequestError::Invalid));
        let value = serde_json::to_value(&add).unwrap();
        assert!(value.get("wraps").is_none());
        assert_eq!(
            serde_json::from_value::<LogAppendRequest>(value).unwrap(),
            add
        );
    }

    #[test]
    fn recovery_sessions_may_read_the_log_and_their_keys_and_add_one_device() {
        let mut scope = SessionScope::for_device(true);
        assert_eq!(scope, SessionScope::Recovery { appended: false });
        assert_eq!(SessionScope::for_device(false), SessionScope::Device);
        assert_eq!(scope.require(ApiCall::GetLog), Ok(()));
        assert!(scope.allows(ApiCall::GetOwnEpochKey));
        assert!(scope.allows(ApiCall::AppendLog));
        for call in [
            ApiCall::GetRecord,
            ApiCall::PutRecord,
            ApiCall::GetFeed,
            ApiCall::Events,
            ApiCall::ReservePairing,
            ApiCall::GetPairing,
            ApiCall::ClosePairing,
            ApiCall::MissingObjects,
            ApiCall::PutObject,
            ApiCall::GetObject,
            ApiCall::Commit,
            ApiCall::GetCommits,
            ApiCall::Retire,
        ] {
            assert_eq!(scope.require(call), Err(ScopeError::NotAllowed), "{call:?}");
            assert!(SessionScope::Device.allows(call), "{call:?}");
        }
        let wrap = WrappedKeyEntry {
            device: DeviceId::from_bytes([3; 16]),
            data: Blob(vec![0; WRAPPED_KEY_LEN]),
        };
        let add = LogAppendRequest {
            entries: vec![Blob(vec![1])],
            wraps: vec![],
            device_wrap: Some(wrap.clone()),
        };
        assert_eq!(scope.check_append(&add), Ok(()));
        let two = LogAppendRequest {
            entries: vec![Blob(vec![1]), Blob(vec![2])],
            ..add.clone()
        };
        assert_eq!(scope.check_append(&two), Err(ScopeError::AppendShape));
        let rotation = LogAppendRequest {
            wraps: vec![wrap],
            device_wrap: None,
            ..add.clone()
        };
        assert_eq!(scope.check_append(&rotation), Err(ScopeError::AppendShape));
        scope.record_append();
        assert!(!scope.allows(ApiCall::AppendLog));
        assert!(scope.allows(ApiCall::GetLog));
        assert_eq!(scope.check_append(&add), Err(ScopeError::AppendUsed));
        let mut device = SessionScope::Device;
        device.record_append();
        assert_eq!(device.check_append(&two), Ok(()));
    }

    #[test]
    fn a_pairing_reservation_names_its_lifetime() {
        let reply = PairingReservation {
            expires_in_secs: 600,
        };
        assert_eq!(
            serde_json::to_value(reply).unwrap(),
            json!({ "expires_in_secs": 600 })
        );
        assert!(SessionScope::Device.allows(ApiCall::ReservePairing));
        assert_eq!(MAX_OPEN_PAIRINGS, 4);
    }

    #[test]
    fn pairing_request_validation() {
        let request = PairingRequest {
            device: DeviceId::from_bytes([1; 16]),
            sign: PublicKey::from_bytes([2; 32]),
            kem: PublicKey::from_bytes([3; 32]),
            proof: Signature::from_bytes([4; 64]),
            sealed_name: Blob(vec![6; SEALED_NAME_OVERHEAD + 14]),
            tag: Blob(vec![5; 32]),
        };
        assert_eq!(request.validate(), Ok(()));
        let mut longest = request.clone();
        longest.sealed_name = Blob(vec![6; SEALED_NAME_OVERHEAD + SEALED_NAME_MAX_PADDED]);
        assert_eq!(longest.validate(), Ok(()));
        // An empty name, or one longer than any padded name, does not fit (security review
        // N13: the sealed name is padded with Padme).
        for len in [
            0,
            SEALED_NAME_OVERHEAD,
            SEALED_NAME_OVERHEAD + SEALED_NAME_MIN_PADDED - 1,
            SEALED_NAME_OVERHEAD + SEALED_NAME_MAX_PADDED + 1,
        ] {
            let mut bad = request.clone();
            bad.sealed_name = Blob(vec![6; len]);
            assert_eq!(bad.validate(), Err(RequestError::Invalid), "{len}");
        }
        // Nothing called a name reaches the server in the clear.
        let json = serde_json::to_value(&request).unwrap();
        assert!(json.get("sealed_name").is_some() && json.get("name").is_none());
        let mut bad = request;
        bad.tag = Blob(vec![5; 31]);
        assert_eq!(bad.validate(), Err(RequestError::Invalid));
    }

    #[test]
    fn feed_entries_and_notices() {
        let entries = vec![
            FeedEntry {
                sequence: 1,
                change: FeedChange::DeviceLog { length: 3 },
            },
            FeedEntry {
                sequence: 2,
                change: FeedChange::Epoch { epoch: Epoch(2) },
            },
            FeedEntry {
                sequence: 3,
                change: FeedChange::Record {
                    key: RecordKey::new(RecordKind::Folders, None).unwrap(),
                    version: 4,
                },
            },
            FeedEntry {
                sequence: 4,
                change: FeedChange::FolderHead {
                    folder: folder(),
                    sequence: 9,
                },
            },
            FeedEntry {
                sequence: 5,
                change: FeedChange::FolderCreated { folder: folder() },
            },
            FeedEntry {
                sequence: 6,
                change: FeedChange::FolderRetired { folder: folder() },
            },
            FeedEntry {
                sequence: 7,
                change: FeedChange::Notice {
                    notice: Notice::AnomalyPin {
                        folder: folder(),
                        commit: CommitId::from_bytes([2; 32]),
                        until_ms: 10,
                    },
                },
            },
            FeedEntry {
                sequence: 8,
                change: FeedChange::Notice {
                    notice: Notice::AccountBudget,
                },
            },
            FeedEntry {
                sequence: 9,
                change: FeedChange::Notice {
                    notice: Notice::MinimumCountCap {
                        held_bytes: 5,
                        cap_bytes: 6,
                    },
                },
            },
        ];
        let page = FeedPage {
            entries,
            sequence: 9,
            more: false,
        };
        let value = serde_json::to_value(&page).unwrap();
        assert_eq!(
            value["entries"][0],
            json!({ "sequence": 1, "change": { "type": "device_log", "length": 3 } })
        );
        assert_eq!(
            value["entries"][7]["change"],
            json!({ "type": "notice", "notice": { "kind": "account_budget" } })
        );
        assert_eq!(
            value["entries"][8]["change"]["notice"],
            json!({ "kind": "minimum_count_cap", "held_bytes": 5, "cap_bytes": 6 })
        );
        assert_eq!(serde_json::from_value::<FeedPage>(value).unwrap(), page);
    }

    #[test]
    fn unknown_feed_types_notices_and_codes_are_skipped_not_errors() {
        let change: FeedChange = serde_json::from_value(json!({ "type": "later" })).unwrap();
        assert_eq!(change, FeedChange::Unknown);
        let notice: Notice = serde_json::from_value(json!({ "kind": "later" })).unwrap();
        assert_eq!(notice, Notice::Unknown);
        let body: ErrorBody = serde_json::from_value(json!({ "code": "later" })).unwrap();
        assert_eq!(body.code, ErrorCode::Unknown);
        // Free text cannot travel in a notice.
        let notice: Notice =
            serde_json::from_value(json!({ "kind": "disk_reserve", "text": "trust me" })).unwrap();
        assert_eq!(notice, Notice::DiskReserve);
    }

    #[test]
    fn error_bodies_and_statuses() {
        let body = ErrorBody {
            code: ErrorCode::HeadMoved,
            current_head: Some(CommitId::from_bytes([3; 32])),
            missing: vec![],
            removal_log: None,
        };
        assert_eq!(
            serde_json::to_value(&body).unwrap(),
            json!({ "code": "head_moved", "current_head": "03".repeat(32) })
        );
        assert_eq!(
            serde_json::to_value(ErrorBody::new(ErrorCode::Internal)).unwrap(),
            json!({ "code": "internal" })
        );
        assert_eq!(ErrorCode::HeadMoved.http_status(), 409);
        assert_eq!(ErrorCode::Unauthorized.http_status(), 401);
        assert_eq!(ErrorCode::QuotaExceeded.http_status(), 507);
        assert_eq!(ErrorCode::RateLimited.http_status(), 429);
        assert_eq!(ErrorCode::FolderRetired.http_status(), 410);
        assert_eq!(ErrorCode::NotFound.http_status(), 404);
        // Security review H2: the log after the device's head comes with `device_removed`.
        let removed = ErrorBody {
            removal_log: Some(LogPage {
                first_index: 5,
                entries: vec![Blob(vec![1, 2])],
                length: 5,
            }),
            ..ErrorBody::new(ErrorCode::DeviceRemoved)
        };
        let value = serde_json::to_value(&removed).unwrap();
        assert_eq!(
            value,
            json!({ "code": "device_removed",
                    "removal_log": { "first_index": 5, "entries": ["AQI"], "length": 5 } })
        );
        assert_eq!(serde_json::from_value::<ErrorBody>(value).unwrap(), removed);
    }

    #[test]
    fn session_and_account_types() {
        let response: SessionResponse = serde_json::from_value(json!({
            "token": "A".repeat(42) + "A", "expires_in_secs": 3600
        }))
        .unwrap();
        assert_eq!(response.expires_in_secs, 3600);
        assert!(!format!("{response:?}").contains("AAAA"));
        let head = LogAppendResponse {
            head: LogHead {
                index: 1,
                hash: LogHash::from_bytes([0; 32]),
            },
        };
        assert_eq!(serde_json::to_value(head).unwrap()["head"]["index"], 1);
    }
}
