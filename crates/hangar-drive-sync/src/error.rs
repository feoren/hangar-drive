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
    /// A stored value does not decode.
    #[error("stored state is invalid: {0}")]
    Corrupt(String),
    /// The engine thread is gone.
    #[error("the sync engine stopped")]
    Stopped,
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
            SyncError::Net(NetError::Server(body)) => match body.code {
                ErrorCode::QuotaExceeded => ErrorKind::QuotaFull,
                ErrorCode::BudgetExceeded => ErrorKind::Budget,
                ErrorCode::DiskReserve => ErrorKind::ServerDisk,
                _ => ErrorKind::Refused,
            },
            SyncError::Fs(FsError::Locked) => ErrorKind::Locked,
            SyncError::Fs(FsError::DiskFull) => ErrorKind::DiskFull,
            SyncError::Chain(ChainError::OlderState) => ErrorKind::OlderState,
            SyncError::NotSetUp(_) => ErrorKind::NotSetUp,
            SyncError::Invalid(_) | SyncError::Root(_) => ErrorKind::Invalid,
            _ => ErrorKind::Unexpected,
        }
    }

    /// Whether the error means "no connection right now".
    pub fn is_offline(&self) -> bool {
        matches!(self, SyncError::Net(e) if e.is_transient())
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
        assert!(SyncError::Net(NetError::Unreachable).is_offline());
    }
}
