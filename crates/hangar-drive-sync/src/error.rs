//! The engine's error type. Module errors convert into it; the app maps it to the closed list of
//! codes the window shows ([`SyncError::code`]), never to free text from a server.

use hangar_drive_crypto::commit::{ChainError, CommitError};
use hangar_drive_crypto::devicelog::LogError;
use hangar_drive_crypto::epoch::{RotateError, WrapError};
use hangar_drive_crypto::folder_keys::{FolderKeysError, FreshnessError};
use hangar_drive_crypto::object::ObjectError;
use hangar_drive_crypto::record::GuardError;
use hangar_drive_crypto::EntropyError;
use hangar_drive_protocol::api::ErrorCode;

use crate::chunker::ChunkError;
use crate::codec::CodecError;
use crate::ports::{FsError, KeychainError, NetError, StoreError};

/// Why an engine call or a sync round failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SyncError {
    /// The server failed or refused.
    #[error(transparent)]
    Net(#[from] NetError),
    /// The file system failed.
    #[error(transparent)]
    Fs(#[from] FsError),
    /// The local index failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The keychain failed.
    #[error(transparent)]
    Keychain(#[from] KeychainError),
    /// Encoding or decoding a tree failed.
    #[error(transparent)]
    Codec(#[from] CodecError),
    /// Hashing or sealing a chunk failed.
    #[error(transparent)]
    Chunk(#[from] ChunkError),
    /// The verified chain refused the server's commits.
    #[error(transparent)]
    Chain(#[from] ChainError),
    /// A commit was refused on its own.
    #[error(transparent)]
    Commit(#[from] CommitError),
    /// The device log refused an entry.
    #[error(transparent)]
    Log(#[from] LogError),
    /// Wrapping or unwrapping an epoch secret failed.
    #[error(transparent)]
    Wrap(#[from] WrapError),
    /// A rotation failed.
    #[error(transparent)]
    Rotate(#[from] RotateError),
    /// A folder key ring or account record failed.
    #[error(transparent)]
    FolderKeys(#[from] FolderKeysError),
    /// The device may not commit to the folder yet.
    #[error(transparent)]
    Freshness(#[from] FreshnessError),
    /// The replay guard refused a record.
    #[error(transparent)]
    Guard(#[from] GuardError),
    /// An object failed.
    #[error(transparent)]
    Object(#[from] ObjectError),
    /// No randomness.
    #[error(transparent)]
    Entropy(#[from] EntropyError),
    /// The folder cannot become a sync root.
    #[error(transparent)]
    Root(#[from] crate::roots::RootError),
    /// The device is not set up (no account) or the folder is unknown.
    #[error("not set up: {0}")]
    NotSetUp(&'static str),
    /// The request does not fit the current state (for example an unknown timeline entry).
    #[error("invalid request: {0}")]
    Invalid(&'static str),
    /// This device already holds an identity or an account, so it cannot join another one
    /// (security review H1).
    #[error("this device already belongs to an account")]
    AlreadySetUp,
    /// A stored value does not decode.
    #[error("stored state is invalid: {0}")]
    Corrupt(String),
    /// The engine thread is gone.
    #[error("the sync engine stopped")]
    Stopped,
    /// The account's devices changed between the list a recovery showed and its append
    /// (security review "recovery" M1): nothing was written, and `recovery_devices` now lists
    /// the new devices to choose from.
    #[error("the account's devices changed since they were shown")]
    RecoveryListChanged,
    /// The recovery code was used before: the account's log no longer lists its recovery device
    /// as current (another device removed it, or another recovery used the code). Nothing was
    /// written.
    #[error("the recovery code was used before")]
    RecoveryCodeUsed,
    /// The recovery code or its sheet does not belong to this account (its log does not list
    /// the code's recovery device, or does not start with the sheet's genesis anchor). Nothing
    /// was written.
    #[error("the code does not belong to this account")]
    RecoveryCodeUnknown,
    /// A recovery sent its append and this device has not joined yet; resetting now would delete
    /// what may be the account's only key (follow-up review LOW 7). Only the forced reset
    /// (`EngineCore::reset_device_discarding_recovery`) goes on.
    #[error("a recovery is not finished; its device key would be lost")]
    RecoveryPending,
}

/// The closed list of codes the app shows its own text for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorKind {
    /// No connection to the server.
    Offline,
    /// The server identifies itself differently than usual (pin mismatch).
    ServerIdentity,
    /// The connection is not secure.
    Insecure,
    /// The server needs another app version.
    UpdateRequired,
    /// The server refused.
    Refused,
    /// The quota is used up.
    QuotaFull,
    /// The upload budget is used up.
    Budget,
    /// The server's disk is full.
    ServerDisk,
    /// A file is open in another program.
    Locked,
    /// The disk is full.
    DiskFull,
    /// The server shows an older state.
    OlderState,
    /// Not set up.
    NotSetUp,
    /// An invalid request.
    Invalid,
    /// The account's devices changed while the person chose which to remove in a recovery;
    /// the window shows the new list ([`SyncError::RecoveryListChanged`]).
    RecoveryListChanged,
    /// The recovery code was used before ([`SyncError::RecoveryCodeUsed`]).
    RecoveryCodeUsed,
    /// The recovery code does not belong to this account ([`SyncError::RecoveryCodeUnknown`]).
    RecoveryCodeUnknown,
    /// A reset was refused because a recovery is pending ([`SyncError::RecoveryPending`]).
    RecoveryPending,
    /// Anything else.
    Unexpected,
}

impl SyncError {
    /// The code for the window.
    pub fn code(&self) -> ErrorKind {
        match self {
            SyncError::Net(NetError::Unreachable) => ErrorKind::Offline,
            SyncError::Net(NetError::PinMismatch) => ErrorKind::ServerIdentity,
            SyncError::Net(NetError::Tls(_)) => ErrorKind::Insecure,
            SyncError::Net(NetError::Version) => ErrorKind::UpdateRequired,
            SyncError::Net(NetError::DeviceRemoved(_)) => ErrorKind::Refused,
            SyncError::Net(NetError::Server(body)) => match body.code {
                ErrorCode::QuotaExceeded => ErrorKind::QuotaFull,
                ErrorCode::BudgetExceeded => ErrorKind::Budget,
                ErrorCode::DiskReserve => ErrorKind::ServerDisk,
                _ => ErrorKind::Refused,
            },
            SyncError::Fs(FsError::Locked) => ErrorKind::Locked,
            SyncError::Fs(FsError::DiskFull) | SyncError::Store(StoreError::DiskFull) => {
                ErrorKind::DiskFull
            }
            SyncError::Chain(ChainError::OlderState) => ErrorKind::OlderState,
            SyncError::NotSetUp(_) => ErrorKind::NotSetUp,
            SyncError::Invalid(_) | SyncError::Root(_) | SyncError::AlreadySetUp => {
                ErrorKind::Invalid
            }
            SyncError::RecoveryListChanged => ErrorKind::RecoveryListChanged,
            SyncError::RecoveryCodeUsed => ErrorKind::RecoveryCodeUsed,
            SyncError::RecoveryCodeUnknown => ErrorKind::RecoveryCodeUnknown,
            SyncError::RecoveryPending => ErrorKind::RecoveryPending,
            _ => ErrorKind::Unexpected,
        }
    }

    /// Whether the error means "no connection right now".
    pub fn is_offline(&self) -> bool {
        matches!(self, SyncError::Net(e) if e.is_transient())
    }

    /// Whether the server said that this device was removed from its account: its own proof,
    /// made with its key, was answered with `DeviceRemoved` (never a mere `ProofInvalid`).
    pub fn is_device_removed(&self) -> bool {
        matches!(self, SyncError::Net(NetError::DeviceRemoved(_)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_drive_protocol::api::ErrorBody;

    #[test]
    fn codes() {
        assert_eq!(
            SyncError::Net(NetError::Unreachable).code(),
            ErrorKind::Offline
        );
        assert_eq!(
            SyncError::Net(NetError::Server(ErrorBody::new(ErrorCode::QuotaExceeded))).code(),
            ErrorKind::QuotaFull
        );
        assert_eq!(
            SyncError::Chain(ChainError::OlderState).code(),
            ErrorKind::OlderState
        );
        assert_eq!(
            SyncError::RecoveryListChanged.code(),
            ErrorKind::RecoveryListChanged
        );
        assert_eq!(
            serde_json::to_value(ErrorKind::RecoveryListChanged).unwrap(),
            "recoveryListChanged"
        );
        assert_eq!(
            SyncError::RecoveryCodeUsed.code(),
            ErrorKind::RecoveryCodeUsed
        );
        assert_eq!(
            SyncError::RecoveryCodeUnknown.code(),
            ErrorKind::RecoveryCodeUnknown
        );
        assert_eq!(
            serde_json::to_value(ErrorKind::RecoveryCodeUsed).unwrap(),
            "recoveryCodeUsed"
        );
        assert_eq!(
            serde_json::to_value(ErrorKind::RecoveryCodeUnknown).unwrap(),
            "recoveryCodeUnknown"
        );
        assert!(SyncError::Net(NetError::Unreachable).is_offline());
        let removed = SyncError::Net(NetError::DeviceRemoved(None));
        assert!(removed.is_device_removed() && !removed.is_offline());
        // The bare code from a server is not the proof's answer (security review H2).
        for other in [
            ErrorCode::DeviceRemoved,
            ErrorCode::ProofInvalid,
            ErrorCode::Unauthorized,
        ] {
            assert!(!SyncError::Net(NetError::Server(ErrorBody::new(other))).is_device_removed());
        }
    }
}
