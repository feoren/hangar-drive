//! The one error type of the API: a code from the protocol's closed list and, for two codes,
//! the fields the protocol defines. Internal causes go to the server log only, never into the
//! reply.

use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hangar_drive_protocol::api::{ErrorBody, ErrorCode, LogPage};
use hangar_drive_protocol::ids::{CommitId, ObjectId};

/// Missing object IDs one error reply lists at most.
pub const MAX_MISSING_LISTED: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code:?}")]
pub struct ApiError {
    pub code: ErrorCode,
    pub current_head: Option<CommitId>,
    /// With `missing_objects`: the missing IDs; with `delta_mismatch`: the IDs of the diff that
    /// do not fit the server's live set (the protocol's one list for both).
    pub missing: Vec<ObjectId>,
    /// With `device_removed`: the device log up to the removal (security review H2).
    pub removal_log: Option<LogPage>,
    /// HTTP status other than the code's own (only 405 for a known path with another method).
    pub status: Option<StatusCode>,
    /// With `rate_limited`: seconds until the refusal clears, for `Retry-After` (the rest of a
    /// rate limit's window, 1 for a busy upload slot, [`RETRY_SOON_S`] for a folder removal).
    /// `None` for refusals without an end in sight (a busy heavy slot), which answer
    /// [`DEFAULT_RETRY_AFTER_S`].
    pub retry_after_s: Option<u64>,
}

/// `Retry-After` of a `rate_limited` reply whose cause has no window that ends.
pub const DEFAULT_RETRY_AFTER_S: u64 = 60;
/// `Retry-After` of a refusal that clears within moments: a folder whose directory is being
/// removed, an upload that raced a folder removal.
pub const RETRY_SOON_S: u64 = 2;

impl ApiError {
    pub const fn new(code: ErrorCode) -> Self {
        Self {
            code,
            current_head: None,
            missing: Vec::new(),
            removal_log: None,
            status: None,
            retry_after_s: None,
        }
    }

    /// `rate_limited`, to be tried again after `retry_after_s` seconds (at least 1), or after
    /// [`DEFAULT_RETRY_AFTER_S`] without a window.
    pub fn rate_limited(retry_after_s: Option<u64>) -> Self {
        Self {
            retry_after_s: retry_after_s.map(|s| s.max(1)),
            ..Self::new(ErrorCode::RateLimited)
        }
    }

    /// `device_removed` with the device log from the device's head up to its removal.
    pub fn device_removed(removal_log: Option<LogPage>) -> Self {
        Self {
            removal_log,
            ..Self::new(ErrorCode::DeviceRemoved)
        }
    }

    pub fn head_moved(current: Option<CommitId>) -> Self {
        Self {
            current_head: current,
            ..Self::new(ErrorCode::HeadMoved)
        }
    }

    pub fn missing(mut ids: Vec<ObjectId>) -> Self {
        ids.truncate(MAX_MISSING_LISTED);
        Self {
            missing: ids,
            ..Self::new(ErrorCode::MissingObjects)
        }
    }

    /// `delta_mismatch` with some of the IDs that do not fit the live set.
    pub fn delta_mismatch(mut ids: Vec<ObjectId>) -> Self {
        ids.truncate(MAX_MISSING_LISTED);
        Self {
            missing: ids,
            ..Self::new(ErrorCode::DeltaMismatch)
        }
    }

    /// Logs `cause` (without request content) and answers `internal`.
    pub fn internal(cause: &dyn std::fmt::Display) -> Self {
        tracing::error!(error = %cause, "internal error");
        Self::new(ErrorCode::Internal)
    }
}

impl From<ErrorCode> for ApiError {
    fn from(code: ErrorCode) -> Self {
        Self::new(code)
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(error: sqlx::Error) -> Self {
        Self::internal(&error)
    }
}

impl From<std::io::Error> for ApiError {
    fn from(error: std::io::Error) -> Self {
        Self::internal(&error)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = self.status.unwrap_or_else(|| {
            StatusCode::from_u16(self.code.http_status())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
        });
        let body = ErrorBody {
            code: self.code,
            current_head: self.current_head,
            missing: self.missing,
            removal_log: self.removal_log,
        };
        let mut response = (status, Json(body)).into_response();
        if self.code == ErrorCode::RateLimited {
            let seconds = self.retry_after_s.unwrap_or(DEFAULT_RETRY_AFTER_S).max(1);
            response
                .headers_mut()
                .insert("retry-after", HeaderValue::from(seconds));
        }
        response
    }
}

pub type ApiResult<T> = Result<T, ApiError>;
