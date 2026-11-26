//! The one error type of every command. Expected outcomes the person has to see are part of the
//! return values (`ApiResult`); this is for the unexpected. It serializes to
//! `{ code, kind, message }`: `code` is the window's `BackendErrorCode` (`busy`, `locked`,
//! `unexpected`, src/backend/errors.ts), `kind` the engine's closed list (`ErrorKind`) for the
//! error report, `message` an English line for the console. None of it carries a secret or a
//! server's free text.

use hangar_drive_sync::error::{ErrorKind, SyncError};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, thiserror::Error)]
#[error("{code} ({kind:?}): {message}")]
pub struct CommandError {
    pub code: &'static str,
    pub kind: ErrorKind,
    pub message: String,
}

impl CommandError {
    pub fn unexpected(message: impl Into<String>) -> Self {
        Self {
            code: "unexpected",
            kind: ErrorKind::Unexpected,
            message: message.into(),
        }
    }

    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            code: "unexpected",
            kind: ErrorKind::Invalid,
            message: message.into(),
        }
    }

    /// Another action of the same kind is running (a dialog is open).
    pub fn busy(message: impl Into<String>) -> Self {
        Self {
            code: "busy",
            kind: ErrorKind::Unexpected,
            message: message.into(),
        }
    }
}

impl From<SyncError> for CommandError {
    fn from(error: SyncError) -> Self {
        let kind = error.code();
        Self {
            code: if kind == ErrorKind::Locked {
                "locked"
            } else {
                "unexpected"
            },
            kind,
            message: error.to_string(),
        }
    }
}

impl From<tauri::Error> for CommandError {
    fn from(error: tauri::Error) -> Self {
        Self::unexpected(error.to_string())
    }
}

impl From<std::io::Error> for CommandError {
    fn from(error: std::io::Error) -> Self {
        Self::unexpected(error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hangar_drive_sync::ports::{FsError, NetError};

    #[test]
    fn errors_carry_the_window_code_and_the_engine_kind() {
        let locked = CommandError::from(SyncError::Fs(FsError::Locked));
        assert_eq!(
            serde_json::to_value(&locked).unwrap()["code"],
            serde_json::json!("locked")
        );
        let offline = CommandError::from(SyncError::Net(NetError::Unreachable));
        let json = serde_json::to_value(&offline).unwrap();
        assert_eq!(json["code"], "unexpected");
        assert_eq!(json["kind"], "offline");
        assert_eq!(
            serde_json::to_value(CommandError::busy("dialog")).unwrap()["code"],
            "busy"
        );
    }
}
